import { mkdir, writeFile } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import { parseArgs } from "node:util";

import {
  ARTIFACT_ROOT,
  activeChildren,
  CLIENT_ROOT,
  COMPAT_ROOT,
  candidateSourceDigest,
  command,
  fileDigest,
  harnessDigest,
  readJSON,
  writeJSON,
} from "./common";
import { generateCase, generatedCaseSchema, reduceActions } from "./generated";
import { writeInventory } from "./inventory";
import {
  type Campaign,
  cleanSuite,
  matchingSuites,
  mutationCampaign,
  validSuite,
} from "./mutations";
import { type ManagedFixture, runSuite, rustExecutable, startFixture } from "./processes";
import { assuranceReport, executionSchema, policySchema } from "./report";

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.once(signal, async () => {
    for (const child of activeChildren) {
      child.kill("SIGKILL");
    }
    await Promise.allSettled([...activeChildren].map((child) => child.exited));
    process.exit(signal === "SIGINT" ? 130 : 143);
  });
}

const { positionals, values } = parseArgs({
  args: process.argv.slice(2),
  allowPositionals: true,
  strict: true,
  options: {
    tests: { type: "string", multiple: true },
    budget: { type: "string", default: "12" },
    mutation: { type: "string", multiple: true },
    "reference-only": { type: "boolean", default: false },
    "report-only": { type: "boolean", default: false },
    "skip-mutations": { type: "boolean", default: false },
    replay: { type: "string" },
    seed: { type: "string" },
    steps: { type: "string" },
    profile: { type: "string" },
    directory: { type: "string" },
    help: { type: "boolean", short: "h" },
  },
});

const verb = positionals[0] ?? "run";

if (values.help) {
  console.log(`Usage: bun run assurance [run|inventory|mutate|generate|replay|shrink|report] [options]
  --tests tests/PATH       Repeat to select scenario files/directories (default: tests)
  --budget N              Mutation/reduction budget; untested work stays unresolved
  --mutation ID           Repeat to select exact mutation IDs from inventory/baseline
  --reference-only        Two upstream fixtures for harness validation; never Rust evidence
  --report-only           Allow coverage gaps; execution errors still fail
  --skip-mutations        Produce a gap report with mutation evidence missing
  --seed N --steps N --profile NAME   Generated lifecycle parameters
  --replay FILE           Exact generated case for replay/reduction
  --directory DIRECTORY   Existing assurance run for report (other commands own a new directory)

Every run writes its inventory, scenario journal, logs, reproduction files and report.
The default strict exit is nonzero until all in-scope obligations have evidence.`);
  process.exit(0);
}

if (
  positionals.length > 1 ||
  !["run", "inventory", "mutate", "generate", "replay", "shrink", "report"].includes(verb)
) {
  throw new Error("Unknown assurance command; use --help");
}

const budget = Number(values.budget);

if (!Number.isInteger(budget) || budget < 1 || budget > 100_000) {
  throw new Error("Budget must be an integer from 1 to 100000");
}

if (values.directory && verb !== "report") {
  throw new Error("Only report accepts --directory; execution always owns a fresh run");
}

const runId = crypto.randomUUID();

const directory = values.directory
  ? resolve(values.directory)
  : join(ARTIFACT_ROOT, `${new Date().toISOString().replaceAll(":", "-")}-${runId}`);

await mkdir(directory, { recursive: true });
console.log(`Assurance artifacts: ${directory}`);

const policy = policySchema.parse(await readJSON(join(COMPAT_ROOT, "assurance-contracts.json")));

const inventoryPath = join(
  directory,
  verb === "report" ? "current-inventory.json" : "inventory.json",
);

if (verb === "generate") {
  const generated = generateCase(
    Number(values.seed ?? "1"),
    Number(values.steps ?? "12"),
    generatedCaseSchema.shape.profile.parse(values.profile ?? "default"),
  );
  await writeJSON(join(directory, "replay.json"), generated);
  console.log(`Generated ${generated.actions.length} actions: ${join(directory, "replay.json")}`);
} else {
  console.log("Inventorying the pinned upstream source and published runtime...");
  const inventory = await writeInventory(inventoryPath);
  if (verb === "inventory") {
    console.log(
      JSON.stringify(
        {
          sources: inventory.sources.length,
          surfaces: inventory.surfaces.length,
          mutations: inventory.mutations.length,
          digest: inventory.digest,
        },
        null,
        2,
      ),
    );
  } else if (verb === "report") {
    if (!values.directory) {
      throw new Error("report requires --directory from an existing run");
    }

    const execution = executionSchema.parse(await readJSON(join(directory, "execution.json")));

    if (execution.suite.harnessDigest !== (await harnessDigest())) {
      throw new Error("Harness changed since execution; collect new evidence");
    }

    if (
      execution.mode === "parity" &&
      (!execution.candidate ||
        (await fileDigest(execution.candidate.executable)) !== execution.candidate.sha256 ||
        (await candidateSourceDigest()) !== execution.candidate.sourceDigest)
    ) {
      throw new Error(
        "Rust build inputs or tested executable changed; collect new parity evidence",
      );
    }

    const report = assuranceReport(
      inventory,
      policy,
      execution.suite,
      execution.campaign,
      execution.mode,
      execution.controls,
    );
    await writeJSON(join(directory, "report.json"), report);
    console.log(JSON.stringify(report.summary, null, 2));
    process.exitCode = report.status === "complete-within-declared-scope" ? 0 : 1;
  } else {
    const paths =
      values.tests ??
      (verb === "replay" || verb === "shrink" ? ["tests/generated/lifecycle.test.ts"] : ["tests"]);

    for (const path of paths) {
      if (
        relative(join(CLIENT_ROOT, "tests"), resolve(CLIENT_ROOT, path)).startsWith("..") ||
        path.startsWith("-")
      ) {
        throw new Error("Scenario paths must be inside client-tests/tests");
      }
    }

    const owned: ManagedFixture[] = [];
    const mode = values["reference-only"] || verb === "mutate" ? "reference-only" : "parity";
    const env: Record<string, string | undefined> = {};

    if (values.seed) {
      env.COMPAT_ASSURANCE_SEEDS = values.seed;
    }

    if (values.steps) {
      env.COMPAT_ASSURANCE_STEPS = values.steps;
    }

    if (values.profile) {
      env.COMPAT_ASSURANCE_PROFILES = generatedCaseSchema.shape.profile.parse(values.profile);
    }

    if (values.replay) {
      const replay = generatedCaseSchema.parse(await readJSON(resolve(values.replay)));
      await writeJSON(join(directory, "replay.json"), replay);
      env.COMPAT_ASSURANCE_REPLAY = join(directory, "replay.json");
    }

    if ((verb === "replay" || verb === "shrink") && !env.COMPAT_ASSURANCE_REPLAY) {
      throw new Error(`${verb} requires --replay FILE`);
    }

    try {
      const controlDigest = await harnessDigest();
      console.log("Checking the harness negative controls...");
      const checked = await command(["bun", "test", "harness"], {
        cwd: CLIENT_ROOT,
        timeoutMs: 120_000,
      });
      await writeFile(join(directory, "harness-controls.log"), checked.stdout + checked.stderr, {
        mode: 0o600,
      });
      const controls = {
        runId,
        harnessDigest: controlDigest,
        code: checked.code,
        timedOut: checked.timedOut,
      };
      await writeJSON(join(directory, "harness-controls.json"), controls);

      if (checked.code !== 0 || checked.timedOut || controlDigest !== (await harnessDigest())) {
        throw new Error("Harness negative controls failed or changed; see harness-controls.log");
      }

      const left = await startFixture({
        directory,
        runId,
        inventoryPath,
        role: "oracle",
        instrument: true,
      });
      owned.push(left);
      const executable = mode === "parity" ? await rustExecutable() : undefined;
      const candidate = executable
        ? {
            executable,
            sha256: await fileDigest(executable),
            sourceDigest: await candidateSourceDigest(),
          }
        : undefined;
      const right = await startFixture({
        directory,
        runId,
        inventoryPath,
        role: "candidate",
        instrument: mode === "reference-only",
        rustExecutable: executable,
      });
      owned.push(right);
      const suite = await runSuite({
        directory: join(directory, "parity"),
        runId,
        inventory,
        left,
        right,
        paths,
        env,
      });

      if (verb === "shrink") {
        const failed = suite.outcomes.find(
          (outcome) =>
            outcome.status === "failed" &&
            ["comparison", "model", "assertion"].includes(outcome.failure ?? ""),
        );

        if (
          !failed?.signature ||
          !validSuite(suite) ||
          suite.code === 0 ||
          suite.outcomes.length !== 1
        ) {
          throw new Error(
            "Reduction needs one reproducible behavioral failure; see parity/suite.log",
          );
        }

        const original = generatedCaseSchema.parse(await readJSON(env.COMPAT_ASSURANCE_REPLAY!));
        let iteration = 0;
        const reduced = await reduceActions(
          original.actions,
          async (actions) => {
            const trial = join(directory, `reduction-${++iteration}`);
            const path = join(trial, "replay.json");
            await writeJSON(path, { ...original, actions });
            const result = await runSuite({
              directory: trial,
              runId,
              inventory,
              left,
              right,
              paths,
              env: { COMPAT_ASSURANCE_REPLAY: path },
            });
            return (
              validSuite(result) &&
              matchingSuites(suite, result) &&
              result.code !== 0 &&
              result.outcomes.length === 1 &&
              result.outcomes[0]?.signature === failed.signature
            );
          },
          budget,
        );
        await writeJSON(join(directory, "reduced.json"), {
          ...original,
          actions: reduced.actions,
        });
        await writeJSON(join(directory, "reduction.json"), {
          signature: failed.signature,
          attempts: reduced.attempts,
          exhausted: reduced.exhausted,
          originalActions: original.actions.length,
          reducedActions: reduced.actions.length,
        });
        console.log(
          `Reduced ${original.actions.length} actions to ${reduced.actions.length}; ${reduced.attempts} attempts${reduced.exhausted ? " (budget exhausted)" : ""}`,
        );
      } else {
        let campaign: Campaign | undefined;

        if ((verb === "run" || verb === "mutate") && !values["skip-mutations"]) {
          campaign = await mutationCampaign({
            directory: join(directory, "campaign"),
            runId,
            inventory,
            inventoryPath,
            paths,
            budget,
            priority: policy.contracts.flatMap((contract) => contract.mutations),
            only: values.mutation,
            env,
          });
        }

        const report = assuranceReport(inventory, policy, suite, campaign, mode, controls);

        if (
          candidate &&
          ((await fileDigest(candidate.executable)) !== candidate.sha256 ||
            (await candidateSourceDigest()) !== candidate.sourceDigest)
        ) {
          throw new Error("Rust build inputs or executable changed during execution");
        }

        await writeJSON(join(directory, "execution.json"), {
          suite,
          campaign,
          mode,
          candidate,
          controls,
        });
        Object.assign(report, { candidate });
        await writeJSON(join(directory, "report.json"), report);
        console.log(
          JSON.stringify(
            { status: report.status, ...report.summary, errors: report.errors },
            null,
            2,
          ),
        );
        const executionOK =
          cleanSuite(suite) &&
          (!campaign ||
            (!campaign.errors.length &&
              campaign.results.every((result) => result.status !== "inconclusive")));
        process.exitCode = values["report-only"]
          ? executionOK
            ? 0
            : 1
          : report.status === "complete-within-declared-scope"
            ? 0
            : 1;
      }
    } finally {
      for (const fixture of owned.reverse()) {
        await fixture.stop();
      }
    }
  }
}
