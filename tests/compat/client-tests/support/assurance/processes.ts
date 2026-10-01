import { mkdir, open, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import {
  CLIENT_ROOT,
  REFERENCE_ROOT,
  REPO_ROOT,
  activeChildren,
  command,
  harnessDigest,
  localURL,
  readJSON,
  spawnOwned,
  writeJSON,
} from "./common";
import { coverageSchema, type ScenarioOutcome } from "./evidence";
import type { Inventory } from "./inventory";

export type ManagedFixture = {
  url: string;
  bridge?: string;
  stop(): Promise<void>;
};
function freePort(): number {
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch: () => new Response(),
  });
  const port = server.port!;
  server.stop(true);
  return port;
}
async function waitUntil(
  check: () => Promise<boolean>,
  exited: () => boolean,
  label: string,
) {
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    if (exited())
      throw new Error(`${label} exited before readiness; see its fixture log`);
    if (await check()) return;
    await Bun.sleep(100);
  }
  throw new Error(`${label} readiness timed out`);
}
export async function startFixture(options: {
  directory: string;
  runId: string;
  role: string;
  inventoryPath: string;
  instrument?: boolean;
  mutation?: string;
  rustExecutable?: string;
}): Promise<ManagedFixture> {
  await mkdir(options.directory, { recursive: true });
  const port = freePort(),
    url = `http://localhost:${port}`;
  const bridge = options.instrument
    ? join(options.directory, `${options.role}-bridge.json`)
    : undefined;
  if (bridge) await rm(bridge, { force: true });
  const log = await open(
    join(options.directory, `${options.role}-fixture.log`),
    "w",
    0o600,
  );
  const child = spawnOwned(
    options.rustExecutable
      ? [options.rustExecutable]
      : [
          process.execPath,
          "run",
          ...(options.instrument
            ? [
                `--preload=${join(CLIENT_ROOT, "support/assurance/coverage-preload.ts")}`,
              ]
            : []),
          "server.ts",
        ],
    {
      cwd: options.rustExecutable ? REPO_ROOT : REFERENCE_ROOT,
      env: {
        ...process.env,
        PORT: String(port),
        NO_PROXY: "localhost,127.0.0.1",
        no_proxy: "localhost,127.0.0.1",
        COMPAT_ASSURANCE_RUN_ID: options.runId,
        COMPAT_ASSURANCE_INVENTORY: options.inventoryPath,
        COMPAT_ASSURANCE_BRIDGE_FILE: bridge,
        COMPAT_ASSURANCE_SOURCE_MUTATION: options.mutation,
      },
      stdout: log.fd,
      stderr: log.fd,
    },
  );
  let stopped = false;
  async function stop() {
    if (stopped) return;
    stopped = true;
    if (child.exitCode === null) {
      child.kill("SIGTERM");
      await Promise.race([child.exited, Bun.sleep(2000)]);
      if (child.exitCode === null) child.kill("SIGKILL");
    }
    await child.exited;
    child.kill("SIGKILL");
    activeChildren.delete(child);
    await log.close();
  }
  try {
    await waitUntil(
      async () => {
        try {
          return (
            await fetch(`${url}/__health`, {
              signal: AbortSignal.timeout(1000),
            })
          ).ok;
        } catch {
          return false;
        }
      },
      () => child.exitCode !== null,
      options.role,
    );
    if (bridge)
      await waitUntil(
        async () => {
          try {
            const value = (await readJSON(bridge)) as { runId?: unknown };
            return value.runId === options.runId;
          } catch {
            return false;
          }
        },
        () => child.exitCode !== null,
        "coverage bridge",
      );
    return { url, bridge, stop };
  } catch (error) {
    await stop();
    throw error;
  }
}

export async function rustExecutable(): Promise<string> {
  if (process.env.COMPAT_RUST_EXECUTABLE)
    return process.env.COMPAT_RUST_EXECUTABLE;
  const build = await command(
    [
      "cargo",
      "build",
      "--locked",
      "--manifest-path",
      "tests/compat/rust-server/Cargo.toml",
      "--message-format=json-render-diagnostics",
    ],
    { cwd: REPO_ROOT, timeoutMs: 1_800_000 },
  );
  if (build.code !== 0)
    throw new Error(`Rust fixture build failed:\n${build.stderr}`);
  for (const line of build.stdout.split("\n")) {
    try {
      const message = JSON.parse(line);
      if (
        message.target?.name === "compat-rust-server" &&
        typeof message.executable === "string"
      )
        return message.executable;
    } catch {
      /* Cargo diagnostic text is not an artifact. */
    }
  }
  throw new Error("Cargo did not report the Rust fixture executable");
}

export type SuiteResult = {
  runId: string;
  inventoryDigest: string;
  harnessDigest: string;
  paths: string[];
  code: number;
  timedOut: boolean;
  complete: boolean;
  registered: string[];
  outcomes: ScenarioOutcome[];
  wireCandidates: unknown[];
  wireReceipts: unknown[];
  errors: string[];
};
export const suiteSchema = z
  .object({
    runId: z.string().min(1),
    inventoryDigest: z.string().min(1),
    harnessDigest: z.string().min(1),
    paths: z.array(z.string()).min(1),
    code: z.number().int(),
    timedOut: z.boolean(),
    complete: z.boolean(),
    registered: z.array(z.string()),
    outcomes: z.array(
      z
        .object({
          name: z.string(),
          status: z.enum(["passed", "failed"]),
          failure: z
            .enum([
              "comparison",
              "assertion",
              "model",
              "invalid-sequence",
              "scenario",
              "infrastructure",
            ])
            .optional(),
          signature: z.string().optional(),
          paths: z.array(z.string()).optional(),
          phase: z.enum(["TS", "Rust"]).optional(),
          reproduction: z.unknown().optional(),
          coverage: z
            .object({
              TS: coverageSchema.optional(),
              Rust: coverageSchema.optional(),
            })
            .strict(),
        })
        .passthrough(),
    ),
    wireCandidates: z.array(z.unknown()),
    wireReceipts: z.array(z.unknown()),
    errors: z.array(z.string()),
  })
  .strict();
export async function runSuite(options: {
  directory: string;
  runId: string;
  inventory: Inventory;
  left: ManagedFixture;
  right: ManagedFixture;
  paths: string[];
  timeoutMs?: number;
  env?: Record<string, string | undefined>;
}): Promise<SuiteResult> {
  await mkdir(options.directory, { recursive: true });
  const eventsPath = join(options.directory, "events.jsonl");
  const before = await harnessDigest();
  await Bun.write(eventsPath, "");
  const output = await command(
    [process.execPath, "test", ...options.paths, "--timeout", "60000"],
    {
      timeoutMs: options.timeoutMs ?? 1_800_000,
      env: {
        COMPAT_ASSURANCE_WIRE_MUTATION: undefined,
        COMPAT_ASSURANCE_DISCOVER_WIRE: undefined,
        COMPAT_ASSURANCE_REPLAY: undefined,
        ...options.env,
        AUTH_BASE_URL_TS: localURL(options.left.url).origin,
        AUTH_BASE_URL_RUST: localURL(options.right.url).origin,
        COMPAT_COVERAGE: "0",
        BETTER_AUTH_UPDATE_CAPABILITIES: undefined,
        COMPAT_ASSURANCE_RUN_ID: options.runId,
        COMPAT_ASSURANCE_EVENTS: eventsPath,
        COMPAT_ASSURANCE_LEFT_BRIDGE: options.left.bridge,
        COMPAT_ASSURANCE_RIGHT_BRIDGE: options.right.bridge,
      },
    },
  );
  await Bun.write(
    join(options.directory, "suite.log"),
    output.stdout + "\n" + output.stderr,
  );
  const events = (await readFile(eventsPath, "utf8"))
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
  const errors: string[] = [];
  if ((await harnessDigest()) !== before)
    errors.push("Harness changed during execution");
  const registered = events
    .filter((event) => event.event === "registered")
    .map((event) => String(event.name));
  if (!registered.length)
    errors.push("No compatibility scenarios were registered");
  if (new Set(registered).size !== registered.length)
    errors.push("Duplicate compatibility scenario names");
  if (events.some((event) => event.runId !== options.runId))
    errors.push("Stale or foreign run evidence");
  const outcomes = events
    .filter((event) => event.event === "finished")
    .map((event) => event as unknown as ScenarioOutcome);
  const completed = new Set(outcomes.map((outcome) => outcome.name));
  if (
    completed.size !== outcomes.length ||
    registered.some((name) => !completed.has(name)) ||
    outcomes.some((outcome) => !registered.includes(outcome.name))
  )
    errors.push("Scenario execution did not match the registered suite");
  const surfaceIds = new Set(
    options.inventory.surfaces.map((surface) => surface.id),
  );
  const sourceIds = new Set(
    options.inventory.sources.map((source) => source.id),
  );
  for (const outcome of outcomes)
    for (const role of ["TS", "Rust"] as const) {
      const enabled =
        role === "TS" ? !!options.left.bridge : !!options.right.bridge;
      if (!enabled) continue;
      const raw = outcome.coverage[role];
      if (!raw) {
        errors.push(
          `${outcome.name}: missing ${role} coverage acknowledgement`,
        );
        continue;
      }
      const parsed = coverageSchema.safeParse(raw);
      if (!parsed.success) {
        errors.push(`${outcome.name}: invalid reference coverage`);
        continue;
      }
      const coverage = parsed.data;
      if (
        coverage.runId !== options.runId ||
        coverage.inventoryDigest !== options.inventory.digest ||
        coverage.version !== options.inventory.version ||
        coverage.scenario !== outcome.name ||
        coverage.loaded.length === 0 ||
        coverage.loaded.some((id) => !sourceIds.has(id))
      )
        errors.push(`${outcome.name}: wrong reference coverage provenance`);
      if (
        !coverage.mutation &&
        Object.keys(coverage.hits).some((id) => !surfaceIds.has(id))
      )
        errors.push(`${outcome.name}: unrecognized coverage anchor`);
    }
  if (output.timedOut)
    errors.push(
      "Suite timed out; a timeout is never evidence of mutation detection",
    );
  if (
    output.code !== 0 &&
    outcomes.every((outcome) => outcome.status === "passed")
  )
    errors.push("Runner failed outside recorded compatibility scenarios");
  const result: SuiteResult = {
    runId: options.runId,
    inventoryDigest: options.inventory.digest,
    harnessDigest: before,
    paths: options.paths,
    code: output.code,
    timedOut: output.timedOut,
    complete: errors.length === 0,
    registered,
    outcomes,
    wireCandidates: events
      .filter((event) => event.event === "wire-candidate")
      .map((event) => event.candidate),
    wireReceipts: events.filter((event) => event.event === "wire-receipt"),
    errors,
  };
  for (const outcome of outcomes)
    if (outcome.reproduction)
      await writeJSON(
        join(options.directory, `replay-${outcomes.indexOf(outcome)}.json`),
        outcome.reproduction,
      );
  await writeJSON(join(options.directory, "suite.json"), result);
  return result;
}
