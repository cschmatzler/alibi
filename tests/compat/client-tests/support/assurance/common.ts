import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, readdir, readFile, realpath, rename, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";

export const CLIENT_ROOT = fileURLToPath(new URL("../../", import.meta.url));
export const COMPAT_ROOT = resolve(CLIENT_ROOT, "..");
export const REPO_ROOT = resolve(COMPAT_ROOT, "../..");
export const REFERENCE_ROOT = join(COMPAT_ROOT, "reference-server");
export const CACHE_ROOT = join(COMPAT_ROOT, ".cache", "assurance");
export const ARTIFACT_ROOT = join(CLIENT_ROOT, "artifacts", "assurance");
export const activeChildren = new Set<ReturnType<typeof spawnOwned>>();
export const ORACLE_PACKAGES = [
  "better-auth",
  "@better-auth/core",
  "@better-auth/api-key",
  "@better-auth/passkey",
] as const;
export const pinSchema = z
  .object({
    version: z.string(),
    commit: z.string().regex(/^[0-9a-f]{40}$/),
    archiveSha256: z.string().regex(/^[0-9a-f]{64}$/),
  })
  .strict();
export const upstreamPin = pinSchema.parse(
  JSON.parse(await readFile(join(COMPAT_ROOT, "upstream-source.json"), "utf8")),
);
const capabilityPin = z
  .object({ upstreamVersion: z.string() })
  .parse(JSON.parse(await readFile(join(COMPAT_ROOT, "capabilities.json"), "utf8")));
if (upstreamPin.version !== capabilityPin.upstreamVersion)
  throw new Error("Assurance source pin differs from capability runtime pin");

export function digest(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}
export async function fileDigest(path: string) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}
export async function readJSON(path: string): Promise<unknown> {
  return JSON.parse(await readFile(path, "utf8"));
}
export async function writeJSON(path: string, value: unknown) {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${crypto.randomUUID()}.tmp`;
  await writeFile(temporary, JSON.stringify(value, null, 2) + "\n", {
    mode: 0o600,
  });
  await rename(temporary, path);
}
export async function filesUnder(directory: string, ignore = new Set<string>()): Promise<string[]> {
  const files: string[] = [];
  for (const entry of (await readdir(directory, { withFileTypes: true })).sort((a, b) =>
    a.name.localeCompare(b.name),
  )) {
    const path = join(directory, entry.name);
    if (ignore.has(entry.name)) continue;
    if (entry.isDirectory()) files.push(...(await filesUnder(path, ignore)));
    else if (entry.isFile()) files.push(path);
    else throw new Error(`Unexpected symlink or special file in upstream inventory: ${path}`);
  }
  return files;
}
export async function packageRoots() {
  return Promise.all(
    ORACLE_PACKAGES.map(async (name) => {
      const root = await realpath(join(REFERENCE_ROOT, "node_modules", name));
      const metadata = z
        .object({ name: z.string(), version: z.string(), exports: z.unknown() })
        .parse(await readJSON(join(root, "package.json")));
      if (metadata.name !== name || metadata.version !== upstreamPin.version)
        throw new Error(`Unpinned oracle package: ${name}`);
      return { name, root, metadata };
    }),
  );
}

/** Run argv directly. Neither artifact names nor user filters are shell programs. */
export function spawnOwned(
  argv: string[],
  options: {
    cwd: string;
    env: Record<string, string | undefined>;
    stdout?: number;
    stderr?: number;
  },
) {
  const child = spawn(argv[0]!, argv.slice(1), {
    cwd: options.cwd,
    env: options.env,
    detached: process.platform !== "win32",
    stdio: ["ignore", options.stdout ?? "pipe", options.stderr ?? "pipe"],
  });
  let spawnError: Error | undefined;
  const exited = new Promise<number>((resolve) => {
    child.once("error", (error) => {
      spawnError = error;
      resolve(127);
    });
    child.once("exit", (code) => resolve(code ?? 1));
  });
  const owned = {
    get exitCode() {
      return spawnError ? 127 : (child.exitCode ?? (child.signalCode ? 1 : null));
    },
    get spawnError() {
      return spawnError;
    },
    exited,
    stdout: child.stdout,
    stderr: child.stderr,
    kill(signal: NodeJS.Signals) {
      try {
        if (child.pid && process.platform !== "win32") process.kill(-child.pid, signal);
        else child.kill(signal);
      } catch (error) {
        if (!(error && typeof error === "object" && "code" in error && error.code === "ESRCH"))
          throw error;
      }
    },
  };
  activeChildren.add(owned);
  return owned;
}
export async function command(
  argv: string[],
  options: {
    cwd?: string;
    env?: Record<string, string | undefined>;
    timeoutMs?: number;
  } = {},
) {
  const child = spawnOwned(argv, {
    cwd: options.cwd ?? CLIENT_ROOT,
    env: { ...process.env, ...options.env },
  });
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    child.kill("SIGKILL");
  }, options.timeoutMs ?? 600_000);
  try {
    async function collect(stream: AsyncIterable<Uint8Array> | null) {
      const chunks: Uint8Array[] = [];
      if (stream) for await (const chunk of stream) chunks.push(chunk);
      return Buffer.concat(chunks).toString();
    }
    const [code, stdout, stderr] = await Promise.all([
      child.exited,
      collect(child.stdout),
      collect(child.stderr),
    ]);
    return {
      code,
      stdout,
      stderr: stderr + (child.spawnError?.message ?? ""),
      timedOut,
    };
  } finally {
    clearTimeout(timer);
    child.kill("SIGKILL");
    activeChildren.delete(child);
  }
}

export async function harnessDigest() {
  const paths = [
    join(CLIENT_ROOT, "package.json"),
    join(CLIENT_ROOT, "bun.lock"),
    ...(await filesUnder(join(CLIENT_ROOT, "support"))),
    ...(await filesUnder(join(CLIENT_ROOT, "tests"))),
    ...(await filesUnder(join(CLIENT_ROOT, "harness"))),
    ...(await filesUnder(join(COMPAT_ROOT, "rust-server/src"))),
    ...(await filesUnder(REFERENCE_ROOT, new Set(["node_modules", ".cache"])).then((paths) =>
      paths.filter((path) => /\.(?:ts|json|lock)$/.test(path)),
    )),
  ];
  return digest(
    JSON.stringify(
      await Promise.all(
        paths
          .sort()
          .map(async (path) => [path.slice(COMPAT_ROOT.length), digest(await readFile(path))]),
      ),
    ),
  );
}

/** Fingerprint build inputs without reading or judging implementation semantics. */
export async function candidateSourceDigest() {
  const listing = await command(
    ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
    { cwd: REPO_ROOT },
  );
  if (listing.code !== 0) throw new Error("Cannot fingerprint Rust build inputs");
  const paths = listing.stdout
    .split("\0")
    .filter(
      (path) =>
        path &&
        (path.endsWith(".rs") ||
          /(?:^|\/)(?:Cargo\.(?:toml|lock)|rust-toolchain(?:\.toml)?)$/.test(path)),
    )
    .sort();
  const identities = [];
  for (const path of paths) {
    try {
      identities.push([path, await fileDigest(join(REPO_ROOT, path))]);
    } catch (error) {
      if (error && typeof error === "object" && "code" in error && error.code === "ENOENT")
        identities.push([path, "deleted"]);
      else throw error;
    }
  }
  return digest(JSON.stringify(identities));
}

export function localURL(value: string): URL {
  const url = new URL(value);
  if (
    url.protocol !== "http:" ||
    !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) ||
    url.username ||
    url.password
  )
    throw new Error("Assurance fixture URLs must be credential-free loopback HTTP origins");
  return url;
}
