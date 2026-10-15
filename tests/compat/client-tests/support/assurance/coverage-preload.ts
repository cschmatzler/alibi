import { readFileSync } from "node:fs";
import { registerHooks } from "node:module";
import { relative } from "node:path";
import { fileURLToPath } from "node:url";

import type { FileCoverageData } from "istanbul-lib-coverage";
import { createInstrumenter } from "istanbul-lib-instrument";

import { setRequestScope } from "../../../reference-server/http";
import { serveFixture } from "../../../reference-server/http.ts";
import { digest, packageRoots, readJSON, upstreamPin, writeJSON } from "./common";
import { CoverageScope } from "./coverage-scope";
import type { Inventory } from "./inventory";

const runId = process.env.COMPAT_ASSURANCE_RUN_ID;
const readyPath = process.env.COMPAT_ASSURANCE_BRIDGE_FILE;
const inventoryPath = process.env.COMPAT_ASSURANCE_INVENTORY;

if (!runId || !readyPath || !inventoryPath) {
  throw new Error("Coverage preload requires an owned run, inventory, and bridge path");
}

const inventory = (await readJSON(inventoryPath)) as Inventory;

if (
  inventory.version !== upstreamPin.version ||
  inventory.commit !== upstreamPin.commit ||
  !inventory.digest
) {
  throw new Error("Coverage preload received an unpinned inventory");
}

const roots = await packageRoots();
const expected = new Map(inventory.sources.map((source) => [source.id, source]));
const loaded = new Set<string>();
const mutationId = process.env.COMPAT_ASSURANCE_SOURCE_MUTATION;

const mutation = mutationId
  ? inventory.mutations.find((candidate) => candidate.id === mutationId)
  : undefined;

if (mutationId && !mutation) {
  throw new Error("Unknown source mutation; regenerate the independent inventory");
}

const runtime = globalThis as typeof globalThis & {
  __compatCoverage?: Record<string, FileCoverageData>;
  __compatMutationHits?: number;
};

const scope = new CoverageScope();
let mutationHits = 0;

Object.defineProperty(runtime, "__compatMutationHits", {
  get: () => mutationHits,
  set: (value) => {
    if (scope.accepts()) {
      mutationHits = value;
    }
  },
});

runtime.__compatCoverage = new Proxy<Record<string, FileCoverageData>>(
  {},
  {
    set(target, key, value: FileCoverageData) {
      value.s = scope.counters(value.s);
      value.f = scope.counters(value.f);

      for (const [id, arms] of Object.entries(value.b)) {
        value.b[id] = scope.counters(arms);
      }

      return Reflect.set(target, key, value);
    },
  },
);

const sourceFilter = new RegExp(
  `^(?:${roots.map((root) => root.root.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})/.*\\.mjs$`,
);

registerHooks({
  load(url, context, nextLoad) {
    const result = nextLoad(url, context);
    if (!url.startsWith("file:")) return result;
    const path = fileURLToPath(url);
    if (!sourceFilter.test(path)) return result;
    const root = roots.find((root) => path.startsWith(root.root + "/"));

    if (!root) {
      throw new Error(`Unexpected oracle module: ${path}`);
    }

    const id = `npm:${root.name}/${relative(root.root, path).replaceAll("\\", "/")}`;
    const source = expected.get(id);
    const text = readFileSync(path, "utf8");

    if (!source || digest(text) !== source.sha256) {
      throw new Error(`Oracle source changed after inventory: ${id}`);
    }

    let contents = text;

    if (mutation?.source === id) {
      if (
        source.sha256 !== mutation.sourceHash ||
        text.slice(mutation.start, mutation.end) !== mutation.original
      ) {
        throw new Error("Mutation source anchor changed");
      }
      contents =
        text.slice(0, mutation.start) +
        `(globalThis.__compatMutationHits++, (${mutation.replacement}))` +
        text.slice(mutation.end);
    }

    const instrumenter = createInstrumenter({
      esModules: true,
      compact: true,
      coverageVariable: "__compatCoverage",
    });
    contents = instrumenter.instrumentSync(contents, id);
    loaded.add(id);
    return { ...result, source: contents };
  },
});

const token = crypto.randomUUID();
let active: string | null = null;

function clearCounters() {
  scope.reset(() => {
    for (const coverage of Object.values(runtime.__compatCoverage ?? {})) {
      for (const key of Object.keys(coverage.s)) {
        coverage.s[key] = 0;
      }
      for (const key of Object.keys(coverage.f)) {
        coverage.f[key] = 0;
      }
      for (const hits of Object.values(coverage.b)) {
        hits.fill(0);
      }
    }
    runtime.__compatMutationHits = 0;
  });
}

const bridge = await serveFixture({
  hostname: "127.0.0.1",
  port: 0,
  async fetch(request) {
    if (request.headers.get("authorization") !== `Bearer ${token}`) {
      return new Response(null, { status: 403 });
    }

    if (request.method !== "POST") {
      return new Response(null, { status: 405 });
    }

    const body: unknown = await request.json();

    if (
      !body ||
      typeof body !== "object" ||
      !("scenario" in body) ||
      typeof body.scenario !== "string"
    ) {
      return new Response(null, { status: 400 });
    }

    const operation = new URL(request.url).pathname;

    if (operation === "/begin") {
      if (active !== null) {
        return Response.json({ error: "overlapping scenario coverage" }, { status: 409 });
      }

      active = body.scenario;
      scope.active = crypto.randomUUID();
      clearCounters();
      return Response.json({ runId, scenario: active });
    }

    if (operation !== "/end" || active !== body.scenario) {
      return new Response(null, { status: 409 });
    }

    const hits: Record<string, number> = {};

    for (const [source, coverage] of Object.entries(runtime.__compatCoverage ?? {})) {
      for (const [id, arms] of Object.entries(coverage.b)) {
        arms.forEach((count, arm) => {
          if (count > 0) {
            hits[`${source}#branch:${id}:${arm}`] = count;
          }
        });
      }
      for (const [id, count] of Object.entries(coverage.f)) {
        if (count > 0) {
          hits[`${source}#function:${id}`] = count;
        }
      }
    }

    const response = {
      schemaVersion: 1,
      runId,
      version: upstreamPin.version,
      inventoryDigest: inventory.digest,
      scenario: active,
      hits,
      loaded: [...loaded].sort(),
      mutation: mutation?.id ?? null,
      mutationHits: runtime.__compatMutationHits,
    };
    active = null;
    scope.active = null;
    return Response.json(response);
  },
});

// AsyncLocalStorage keeps the originating window on work that outlives its request.
setRequestScope((handler) => scope.run(handler));

await writeJSON(readyPath, {
  runId,
  inventoryDigest: inventory.digest,
  url: bridge.url.origin,
  token,
});

process.on("exit", () => bridge.stop(true));
