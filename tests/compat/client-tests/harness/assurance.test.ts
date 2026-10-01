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
    sources: [source("loaded"), source("never-imported")],
    surfaces: [
      {
        id: "loaded#branch:0:0",
        source: "loaded",
        kind: "branch",
        name: "arm 0",
        line: 1,
      },
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
    ],
    coverage: {},
    mutations: [],
  };
  const policy = {
    schemaVersion: 1,
    upstreamVersion: upstreamPin.version,
    commit: upstreamPin.commit,
    excludedPackages: [],
    excludedSurfaces: [],
    equivalentMutations: [],
    contracts: [],
  };
  const passing = suite();
  const report = assuranceReport(
    inventory,
    policy,
    passing,
    undefined,
    "parity",
  );
  expect(report.status).toBe("incomplete");
  const controlError = "Missing, stale or failing harness negative controls";
  expect(report.errors).toContain(controlError);
  const controls = {
    runId: passing.runId,
    harnessDigest: passing.harnessDigest,
    code: 0,
    timedOut: false,
  };
  expect(
    assuranceReport(inventory, policy, passing, undefined, "parity", controls)
      .errors,
  ).not.toContain(controlError);
  for (const invalid of [
    { ...controls, runId: "older-run" },
    { ...controls, harnessDigest: "edited-checker" },
    { ...controls, code: 1 },
    { ...controls, timedOut: true },
  ]) {
    expect(
      assuranceReport(inventory, policy, passing, undefined, "parity", invalid)
        .errors,
    ).toContain(controlError);
  }
  expect(report.branches).toEqual({
    total: 2,
    reached: 1,
    missing: ["never-imported#branch:0:0"],
  });
  expect(report.unmapped).toEqual(["new-option"]);
  passing.outcomes[0]!.coverage.TS!.runId = "previous-run";
  const stale = assuranceReport(
    inventory,
    policy,
    passing,
    undefined,
    "parity",
  );
  expect(stale.errors).toContain("owner: mismatched upstream branch evidence");
  expect(stale.summary.reachedBranchArms).toBe(0);
  passing.outcomes[0]!.status = "failed";
  expect(
    assuranceReport(inventory, policy, passing, undefined, "parity").summary
      .reachedBranchArms,
  ).toBe(0);
  const sourceMutation = {
    id: "never-imported#omit-effect:1:2",
    source: "never-imported",
    sourceHash: digest("never-imported"),
    start: 1,
    end: 2,
    original: "x",
    replacement: "undefined",
    operator: "omit-effect" as const,
    line: 1,
  };
  const truncated: Campaign = {
    schemaVersion: 1,
    runId: "run",
    inventoryDigest: "inventory",
    baseline: suite(),
    confirmation: suite(),
    universe: [],
    selected: [],
    results: [],
    notRun: [],
    errors: [],
  };
  truncated.baseline.runId = "old-run";
  truncated.confirmation!.harnessDigest = "old-harness";
  const omitted = assuranceReport(
    { ...inventory, mutations: [sourceMutation] },
    policy,
    suite(),
    truncated,
    "parity",
  );
  expect(omitted.errors).toContain(
    "Mutation campaign did not have matching provenance and clean baseline/confirmation",
  );
  expect(omitted.unresolvedMutations).toContain(sourceMutation.id);
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
