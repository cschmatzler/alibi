import { join } from "node:path";
import { writeJSON } from "./common";
import type { Inventory, SourceMutation } from "./inventory";
import { type ManagedFixture, runSuite, type SuiteResult, startFixture } from "./processes";
import { type WireMutation, wireMutationSchema } from "./wire";

export type Mutation = (SourceMutation & { kind: "source" }) | WireMutation;
export type Verdict = {
  id: string;
  kind: Mutation["kind"];
  status: "killed" | "survived" | "not-reached" | "no-change" | "inconclusive";
  killingScenarios: string[];
  reason?: string;
  execution?: SuiteResult;
};
export type Campaign = {
  schemaVersion: 1;
  runId: string;
  inventoryDigest: string;
  baseline: SuiteResult;
  confirmation?: SuiteResult;
  universe: string[];
  selected: string[];
  results: Verdict[];
  notRun: string[];
  errors: string[];
};
export function cleanSuite(suite: SuiteResult): boolean {
  return (
    validSuite(suite) &&
    suite.code === 0 &&
    suite.outcomes.every((outcome) => outcome.status === "passed")
  );
}
export function validSuite(suite: SuiteResult): boolean {
  return (
    suite.complete &&
    !suite.timedOut &&
    !suite.errors.length &&
    suite.registered.length > 0 &&
    new Set(suite.registered).size === suite.registered.length &&
    new Set(suite.outcomes.map((outcome) => outcome.name)).size === suite.outcomes.length &&
    JSON.stringify([...suite.registered].sort()) ===
      JSON.stringify(suite.outcomes.map((outcome) => outcome.name).sort())
  );
}
export function matchingSuites(left: SuiteResult, right: SuiteResult): boolean {
  return (
    left.runId === right.runId &&
    left.inventoryDigest === right.inventoryDigest &&
    left.harnessDigest === right.harnessDigest &&
    JSON.stringify([...left.registered].sort()) === JSON.stringify([...right.registered].sort())
  );
}

/** Execution failure, a changed input, and a caught regression are different evidence. */
export function classifyMutation(
  mutation: Mutation,
  baseline: SuiteResult,
  candidate: SuiteResult,
): Verdict {
  const verdict: Verdict = {
    id: mutation.id,
    kind: mutation.kind,
    status: "inconclusive",
    killingScenarios: [],
  };
  if (!cleanSuite(baseline) || !validSuite(candidate) || !matchingSuites(baseline, candidate))
    return {
      ...verdict,
      reason: "Baseline, execution, or scenario-set integrity failed",
    };
  const reached = new Set<string>(),
    changed = new Set<string>();
  if (mutation.kind === "source") {
    for (const outcome of candidate.outcomes) {
      const coverage = outcome.coverage.Rust;
      if (
        coverage?.mutation === mutation.id &&
        coverage.runId === candidate.runId &&
        coverage.inventoryDigest === candidate.inventoryDigest &&
        coverage.scenario === outcome.name &&
        coverage.mutationHits > 0
      ) {
        reached.add(outcome.name);
        changed.add(outcome.name);
      }
    }
  } else
    for (const raw of candidate.wireReceipts) {
      const receipt = raw as {
        id?: unknown;
        scenario?: unknown;
        changed?: unknown;
      };
      if (receipt.id === mutation.id && typeof receipt.scenario === "string") {
        reached.add(receipt.scenario);
        if (receipt.changed === true) changed.add(receipt.scenario);
      }
    }
  const failures = candidate.outcomes.filter((outcome) => outcome.status === "failed");
  if (
    failures.some(
      (outcome) =>
        outcome.phase !== "Rust" ||
        !["comparison", "assertion", "model"].includes(outcome.failure ?? "") ||
        !changed.has(outcome.name),
    )
  )
    return {
      ...verdict,
      reason: "Failure was not a behavioral assertion in a scenario that reached the mutation",
    };
  if (failures.length)
    return {
      ...verdict,
      status: "killed",
      killingScenarios: failures.map((outcome) => outcome.name),
    };
  if (candidate.code !== 0)
    return {
      ...verdict,
      reason: "Test runner failed without a recorded behavioral failure",
    };
  return {
    ...verdict,
    status: changed.size ? "survived" : reached.size ? "no-change" : "not-reached",
  };
}

export async function mutationCampaign(options: {
  directory: string;
  runId: string;
  inventory: Inventory;
  inventoryPath: string;
  paths: string[];
  budget: number;
  priority: string[];
  only?: string[];
  env?: Record<string, string | undefined>;
}): Promise<Campaign> {
  const owned: ManagedFixture[] = [];
  const start = async (role: string, mutation?: string) => {
    const fixture = await startFixture({
      ...options,
      role,
      instrument: true,
      mutation,
    });
    owned.push(fixture);
    return fixture;
  };
  try {
    const left = await start("oracle"),
      pristine = await start("baseline");
    const baseline = await runSuite({
      ...options,
      directory: join(options.directory, "baseline"),
      left,
      right: pristine,
      env: { ...options.env, COMPAT_ASSURANCE_DISCOVER_WIRE: "1" },
    });
    const candidates: Mutation[] = [
      ...options.inventory.mutations.map((mutation) => ({
        ...mutation,
        kind: "source" as const,
      })),
      ...baseline.wireCandidates.map((value) => wireMutationSchema.parse(value)),
    ];
    const byId = new Map(candidates.map((candidate) => [candidate.id, candidate]));
    const wanted = options.only ?? [
      ...options.priority,
      ...candidates
        .filter((candidate) => candidate.kind === "wire")
        .map((candidate) => candidate.id),
      ...candidates
        .filter((candidate) => candidate.kind === "source")
        .map((candidate) => candidate.id),
    ];
    const unknown = wanted.filter((id) => !byId.has(id));
    if (unknown.length)
      throw new Error(`Mutation identifiers do not exist in this inventory: ${unknown.join(", ")}`);
    const selected = [...new Set(wanted)].slice(0, options.budget);
    const campaign: Campaign = {
      schemaVersion: 1,
      runId: options.runId,
      inventoryDigest: options.inventory.digest,
      baseline,
      universe: [...byId.keys()],
      selected,
      results: [],
      notRun: [...byId.keys()].filter((id) => !selected.includes(id)),
      errors: [],
    };
    if (!cleanSuite(baseline)) {
      campaign.errors.push(
        "Pristine upstream baseline failed; mutation results cannot be credited",
      );
      campaign.notRun = campaign.universe;
    } else {
      for (const [index, id] of selected.entries()) {
        const mutation = byId.get(id)!,
          directory = join(options.directory, `mutation-${index}`);
        console.log(`Mutation ${index + 1}/${selected.length}: ${id}`);
        let right: ManagedFixture | undefined;
        try {
          const wirePath = join(directory, "wire.json");
          if (mutation.kind === "wire") await writeJSON(wirePath, mutation);
          right =
            mutation.kind === "source"
              ? await startFixture({
                  ...options,
                  directory,
                  role: "mutant",
                  instrument: true,
                  mutation: id,
                })
              : pristine;
          const suite = await runSuite({
            ...options,
            directory,
            left,
            right,
            env: {
              ...options.env,
              COMPAT_ASSURANCE_WIRE_MUTATION: mutation.kind === "wire" ? wirePath : undefined,
            },
          });
          // Preserve the classification inputs. Branch hit maps remain in each suite.json;
          // the aggregate keeps only the mutation reach counters and failure evidence.
          const execution = {
            ...suite,
            wireCandidates: [],
            outcomes: suite.outcomes.map((outcome) => ({
              ...outcome,
              coverage: Object.fromEntries(
                Object.entries(outcome.coverage).map(([role, coverage]) => [
                  role,
                  { ...coverage, hits: {} },
                ]),
              ),
            })),
          };
          campaign.results.push({
            ...classifyMutation(mutation, baseline, suite),
            execution,
          });
        } catch (error) {
          campaign.results.push({
            id,
            kind: mutation.kind,
            status: "inconclusive",
            killingScenarios: [],
            reason: error instanceof Error ? error.message : String(error),
          });
        } finally {
          if (right && right !== pristine) await right.stop();
        }
        await writeJSON(join(options.directory, "mutations.json"), campaign);
      }
      // A clean rerun brackets the campaign; failure invalidates apparent kills.
      campaign.confirmation = await runSuite({
        ...options,
        directory: join(options.directory, "confirmation"),
        left,
        right: pristine,
        env: options.env,
      });
      if (!cleanSuite(campaign.confirmation) || !matchingSuites(baseline, campaign.confirmation)) {
        campaign.errors.push("Pristine confirmation failed; apparent detections are inconclusive");
        campaign.results = campaign.results.map((result) =>
          result.status === "killed"
            ? {
                ...result,
                status: "inconclusive",
                reason: "Pristine confirmation failed",
              }
            : result,
        );
      }
    }
    await writeJSON(join(options.directory, "mutations.json"), campaign);
    return campaign;
  } finally {
    for (const fixture of owned.reverse()) await fixture.stop();
  }
}
