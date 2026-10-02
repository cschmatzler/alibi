import { expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { command, digest, upstreamPin } from "../support/assurance/common";
import { writeJSON } from "../support/assurance/common";
import { CoverageScope } from "../support/assurance/coverage-scope";
import {
  generateCase,
  generatedCaseSchema,
  reduceActions,
} from "../support/assurance/generated";
import {
  runtimeEvidence,
  sourceSurfaces,
  type Inventory,
  type Source,
} from "../support/assurance/inventory";
import {
  classifyMutation,
  type Campaign,
  type Mutation,
} from "../support/assurance/mutations";
import type { SuiteResult } from "../support/assurance/processes";
import { assuranceReport } from "../support/assurance/report";

test("upstream inventory discovers undeclared options, test templates and unmeasured decisions", () => {
  const text = `import { test as check, describe } from "vitest";
    export type UnseenOptions = { enabled?: boolean; nested: { quota: number }; callback: (ctx: {notAnOption: string}) => void };
    const authTest = check.extend({});
    describe("fresh upstream behavior", () => { authTest.each([1, 2])("boundary %s", () => {}); check.todo("not ported"); });
    const fixture = { test: { createUser() {} } }; fixture.test.createUser();`;
  const source: Source = {
    id: "upstream-example",
    package: "example",
    origin: "repository",
    path: "unseen.test.ts",
    sha256: digest(text),
  };
  const inventory = sourceSurfaces(source, text);
  expect(
    inventory.filter((item) => item.kind === "option").map((item) => item.name),
  ).toEqual([
    "UnseenOptions.enabled",
    "UnseenOptions.nested",
    "UnseenOptions.nested.quota",
    "UnseenOptions.callback",
  ]);
  expect(
    inventory
      .filter((item) => item.kind === "upstream-test")
      .map((item) => item.name),
  ).toEqual([
    "fresh upstream behavior > boundary %s",
    "fresh upstream behavior > not ported",
  ]);
  const runtime = runtimeEvidence(
    { ...source, path: "unloaded.mjs" },
    "export function decision(x) { if (x) return x?.field; return null; }",
  );
  expect(
    runtime.surfaces.filter((surface) => surface.kind === "branch"),
  ).toHaveLength(2);
  expect(
    runtime.surfaces.some(
      (surface) => surface.kind === "unmeasured-control-flow",
    ),
  ).toBe(true);
});

function suite(): SuiteResult {
  return {
    runId: "run",
    inventoryDigest: "inventory",
    harnessDigest: "harness",
    paths: ["tests/owner.test.ts"],
    code: 0,
    timedOut: false,
    complete: true,
    registered: ["owner"],
    outcomes: [
      {
        name: "owner",
        status: "passed",
        coverage: {
          TS: {
            schemaVersion: 1,
            runId: "run",
            version: upstreamPin.version,
            inventoryDigest: "inventory",
            scenario: "owner",
            hits: { "loaded#branch:0:0": 1 },
            loaded: ["loaded"],
            mutation: null,
            mutationHits: 0,
          },
        },
      },
    ],
    wireCandidates: [],
    wireReceipts: [],
    errors: [],
  };
}
const mutation: Mutation = {
  id: "drop-result",
  kind: "wire",
  route: "/api/auth/ok",
  method: "GET",
  operator: "drop-field",
  pointer: ["ok"],
  scenario: "owner",
};
test("mutation detection requires a reached behavioral failure and clean matching execution", () => {
  const baseline = suite(),
    candidate = suite();
  candidate.code = 1;
  candidate.outcomes[0] = {
    name: "owner",
    status: "failed",
    phase: "Rust",
    failure: "comparison",
    coverage: baseline.outcomes[0]!.coverage,
  };
  candidate.wireReceipts = [
    { id: mutation.id, scenario: "owner", changed: true },
  ];
  expect(classifyMutation(mutation, baseline, candidate).status).toBe("killed");
  for (const change of [
    (value: SuiteResult) => {
      value.timedOut = true;
    },
    (value: SuiteResult) => {
      value.complete = false;
    },
    (value: SuiteResult) => {
      value.runId = "another-run";
    },
    (value: SuiteResult) => {
      value.harnessDigest = "older-harness";
    },
    (value: SuiteResult) => {
      value.inventoryDigest = "older-source";
    },
    (value: SuiteResult) => {
      value.outcomes[0]!.failure = "scenario";
    },
    (value: SuiteResult) => {
      value.outcomes[0]!.failure = "invalid-sequence";
    },
    (value: SuiteResult) => {
      value.outcomes[0]!.phase = "TS";
    },
    (value: SuiteResult) => {
      value.wireReceipts = [
        { id: mutation.id, scenario: "unrelated", changed: true },
      ];
    },
  ]) {
    const invalid = structuredClone(candidate);
    change(invalid);
    expect(classifyMutation(mutation, baseline, invalid).status).toBe(
      "inconclusive",
    );
  }
  const survivor = suite();
  survivor.wireReceipts = candidate.wireReceipts;
  expect(classifyMutation(mutation, baseline, survivor).status).toBe(
    "survived",
  );
  survivor.wireReceipts = [
    { id: mutation.id, scenario: "owner", changed: false },
  ];
  expect(classifyMutation(mutation, baseline, survivor).status).toBe(
    "no-change",
  );
  expect(classifyMutation(mutation, baseline, suite()).status).toBe(
    "not-reached",
  );

  const sourceMutation: Mutation = {
    id: "loaded#omit-effect:1:2",
    kind: "source",
    source: "loaded",
    sourceHash: digest("loaded"),
    start: 1,
    end: 2,
    original: "x",
    replacement: "undefined",
    operator: "omit-effect",
    line: 1,
  };
  const sourceCandidate = structuredClone(candidate);
  sourceCandidate.wireReceipts = [];
  sourceCandidate.outcomes[0]!.coverage.Rust = {
    ...baseline.outcomes[0]!.coverage.TS!,
    mutation: sourceMutation.id,
    mutationHits: 1,
  };
  expect(
    classifyMutation(sourceMutation, baseline, sourceCandidate).status,
  ).toBe("killed");
  for (const change of [
    (value: SuiteResult) => {
      delete value.outcomes[0]!.coverage.Rust;
    },
    (value: SuiteResult) => {
      value.outcomes[0]!.coverage.Rust!.mutation = "another-mutation";
    },
    (value: SuiteResult) => {
      value.outcomes[0]!.coverage.Rust!.runId = "another-run";
    },
    (value: SuiteResult) => {
      value.outcomes[0]!.coverage.Rust!.inventoryDigest = "older-source";
    },
    (value: SuiteResult) => {
      value.outcomes[0]!.coverage.Rust!.scenario = "unrelated";
    },
    (value: SuiteResult) => {
      value.outcomes[0]!.coverage.Rust!.mutationHits = 0;
    },
  ]) {
    const invalid = structuredClone(sourceCandidate);
    change(invalid);
    expect(classifyMutation(sourceMutation, baseline, invalid).status).toBe(
      "inconclusive",
    );
  }
});

test("coverage reports retain unloaded branches and new upstream obligations, and reject stale acknowledgements", () => {
  const source = (id: string): Source => ({
    id,
    package: "upstream",
    path: `${id}.mjs`,
    origin: "published",
    sha256: digest(id),
  });
  const inventory: Inventory = {
    schemaVersion: 1,
    version: upstreamPin.version,
    commit: upstreamPin.commit,
    digest: "inventory",
    sources: [source("loaded")],
    surfaces: [
      {
        id: "loaded#branch:0:0",
        source: "loaded",
        kind: "branch",
        name: "arm 0",
        line: 1,
      },
      {
        id: "existing-option",
        source: "loaded",
        kind: "option",
        name: "ExistingOptions.revoke",
        line: 1,
      },
    ],
    mutations: [
      {
        id: "loaded#omit-effect:1:2",
        source: "loaded",
        sourceHash: digest("loaded"),
        start: 1,
        end: 2,
        original: "x",
        replacement: "undefined",
        operator: "omit-effect",
        line: 1,
      },
    ],
  };
  const sourceMutation = inventory.mutations[0]!;
  const policy = {
    schemaVersion: 1,
    upstreamVersion: upstreamPin.version,
    commit: upstreamPin.commit,
    excludedPackages: [],
    excludedSurfaces: [],
    equivalentMutations: [],
    contracts: [
      {
        id: "revocation",
        claim: "Revocation removes the persisted session.",
        upstream: [
          { source: "loaded", kind: "option", name: "ExistingOptions.revoke" },
        ],
        scenarios: ["owner"],
        mutations: [sourceMutation.id],
      },
    ],
  };
  const passing = suite();
  const controls = {
    runId: passing.runId,
    harnessDigest: passing.harnessDigest,
    code: 0,
    timedOut: false,
  };
  const execution = suite();
  execution.code = 1;
  execution.outcomes[0] = {
    name: "owner",
    status: "failed",
    phase: "Rust",
    failure: "comparison",
    coverage: {
      Rust: {
        ...passing.outcomes[0]!.coverage.TS!,
        mutation: sourceMutation.id,
        mutationHits: 1,
      },
    },
  };
  const campaign: Campaign = {
    schemaVersion: 1,
    runId: "run",
    inventoryDigest: "inventory",
    baseline: suite(),
    confirmation: suite(),
    universe: [sourceMutation.id],
    selected: [sourceMutation.id],
    results: [
      {
        id: sourceMutation.id,
        kind: "source",
        status: "killed",
        killingScenarios: ["owner"],
        execution,
      },
    ],
    notRun: [],
    errors: [],
  };
  const fresh = () =>
    structuredClone({ inventory, policy, passing, campaign, controls });
  const report = (fixture = fresh()) =>
    assuranceReport(
      fixture.inventory,
      fixture.policy,
      fixture.passing,
      fixture.campaign,
      "parity",
      fixture.controls,
    );
  const complete = report();
  expect(complete.status).toBe("complete-within-declared-scope");
  expect(complete.errors).toEqual([]);
  expect(complete.summary.provenContracts).toBe(1);
  expect(complete.summary.mutationDetections).toBe(1);
  expect(complete.branches).toEqual({ total: 1, reached: 1, missing: [] });

  const controlError = "Missing, stale or failing harness negative controls";
  expect(
    assuranceReport(inventory, policy, passing, campaign, "parity").errors,
  ).toContain(controlError);
  for (const invalid of [
    { ...controls, runId: "older-run" },
    { ...controls, harnessDigest: "edited-checker" },
    { ...controls, code: 1 },
    { ...controls, timedOut: true },
  ]) {
    expect(
      assuranceReport(inventory, policy, passing, campaign, "parity", invalid)
        .errors,
    ).toContain(controlError);
  }

  const expanded = fresh();
  expanded.inventory.sources.push(source("never-imported"));
  expanded.inventory.surfaces.push(
    {
      id: "never-imported#branch:0:0",
      source: "never-imported",
      kind: "branch",
      name: "arm 0",
      line: 1,
    },
    {
      id: "new-option",
      source: "never-imported",
      kind: "option",
      name: "NewOptions.revoke",
      line: 1,
    },
  );
  const uncovered = report(expanded);
  expect(uncovered.status).toBe("incomplete");
  expect(uncovered.branches).toEqual({
    total: 2,
    reached: 1,
    missing: ["never-imported#branch:0:0"],
  });
  expect(uncovered.unmapped).toEqual(["new-option"]);
  const staleFixture = fresh();
  staleFixture.passing.outcomes[0]!.coverage.TS!.runId = "previous-run";
  const stale = report(staleFixture);
  expect(stale.errors).toContain("owner: mismatched upstream branch evidence");
  expect(stale.summary.reachedBranchArms).toBe(0);
  const failed = fresh();
  failed.passing.outcomes[0]!.status = "failed";
  expect(report(failed).summary.reachedBranchArms).toBe(0);

  for (const change of [
    (value: Campaign) => {
      value.baseline.runId = "old-run";
    },
    (value: Campaign) => {
      value.confirmation!.harnessDigest = "old-harness";
    },
    (value: Campaign) => {
      value.universe = [];
    },
    (value: Campaign) => {
      value.results[0]!.status = "survived";
    },
    (value: Campaign) => {
      delete value.results[0]!.execution;
    },
  ]) {
    const invalid = fresh();
    change(invalid.campaign);
    const rejected = report(invalid);
    expect(rejected.status).toBe("incomplete");
    expect(rejected.errors).toContain(
      "Mutation campaign did not have matching provenance and clean baseline/confirmation",
    );
    expect(rejected.unresolvedMutations).toContain(sourceMutation.id);
    expect(rejected.summary.mutationDetections).toBe(0);
  }

  const unrun = fresh();
  unrun.campaign.selected = [];
  unrun.campaign.results = [];
  unrun.campaign.notRun = [sourceMutation.id];
  const incomplete = report(unrun);
  expect(incomplete.errors).toEqual([]);
  expect(incomplete.status).toBe("incomplete");
  expect(incomplete.unresolvedMutations).toEqual([sourceMutation.id]);
  expect(incomplete.summary.provenContracts).toBe(0);
});

test("generated logs replay exactly and reduction preserves the failure prerequisites", async () => {
  const generated = generateCase(42, 20);
  expect(
    generatedCaseSchema.parse(JSON.parse(JSON.stringify(generated))),
  ).toEqual(generateCase(42, 20));
  expect(generateCase(43, 20).actions).not.toEqual(generated.actions);
  const reduced = await reduceActions(generated.actions, async (actions) => {
    const created = actions.findIndex(
      (action) => action.kind === "signup" && action.session === "s0",
    );
    const deleted = actions.findIndex((action) => action.kind === "delete");
    return created >= 0 && deleted > created;
  });
  expect(reduced.exhausted).toBe(false);
  expect(reduced.actions.map((action) => action.kind)).toEqual([
    "signup",
    "delete",
  ]);
});

test("a subprocess timeout terminates descendants that keep its output pipes open", async () => {
  const started = Date.now();
  const result = await command(
    [
      process.execPath,
      "-e",
      `Bun.spawn([process.execPath, '-e', 'setTimeout(() => {}, 30000)'], { stdout: 'inherit', stderr: 'inherit' }); setTimeout(() => {}, 30000);`,
    ],
    { timeoutMs: 300 },
  );
  expect(result.timedOut).toBe(true);
  expect(result.code).not.toBe(0);
  expect(Date.now() - started).toBeLessThan(5000);
});

test("delayed upstream work cannot credit a later scenario's coverage", async () => {
  const scope = new CoverageScope(),
    counter = scope.counters({ hits: 0 });
  scope.active = "first-window";
  const pending = scope.run(async () => {
    counter.hits++;
    await Bun.sleep(20);
    counter.hits++;
  });
  expect(counter.hits).toBe(1);
  scope.reset(() => {
    counter.hits = 0;
  });
  scope.active = "next-window";
  await pending;
  expect(counter.hits).toBe(0);
  scope.run(() => {
    counter.hits++;
  });
  expect(counter.hits).toBe(1);
});

test("response mutation preserves fetch metadata independently of its changed header", async () => {
  const directory = await mkdtemp(join(tmpdir(), "compat-wire-"));
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch: () =>
      Response.json({ ok: true }, { headers: { "x-probe": "present" } }),
  });
  try {
    const path = join(directory, "mutation.json"),
      pointer = ["x-probe"];
    const id = `wire:${digest(JSON.stringify(["GET", "/api/auth/ok", "drop-header", pointer])).slice(0, 24)}`;
    await writeJSON(path, {
      id,
      kind: "wire",
      route: "/api/auth/ok",
      method: "GET",
      operator: "drop-header",
      pointer,
      scenario: "probe",
    });
    const url = new URL("/api/auth/ok", server.url).href;
    const result = await command(
      [
        process.execPath,
        "-e",
        `
      import { setAssurancePhase } from "./support/assurance/evidence";
      import { mutateTransport } from "./support/assurance/wire";
      setAssurancePhase("probe", "Rust");
      const request = new Request(process.env.COMPAT_PROBE_URL);
      const response = await mutateTransport(request, await fetch(request));
      console.log(JSON.stringify({url:response.url,cloneURL:response.clone().url,statusText:response.statusText,type:response.type,header:response.headers.get("x-probe"),body:await response.json()}));
    `,
      ],
      {
        env: {
          COMPAT_ASSURANCE_WIRE_MUTATION: path,
          COMPAT_PROBE_URL: url,
          COMPAT_ASSURANCE_EVENTS: undefined,
          COMPAT_ASSURANCE_DISCOVER_WIRE: undefined,
        },
      },
    );
    expect(result.code).toBe(0);
    const native = await fetch(url);
    expect(JSON.parse(result.stdout)).toEqual({
      url,
      cloneURL: url,
      statusText: native.statusText,
      type: native.type,
      header: null,
      body: { ok: true },
    });
  } finally {
    server.stop(true);
    await rm(directory, { recursive: true, force: true });
  }
});
