import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join, relative } from "node:path";
import {
  CACHE_ROOT,
  REFERENCE_ROOT,
  command,
  digest,
  filesUnder,
  packageRoots,
  readJSON,
  upstreamPin,
} from "./common";

/** Authenticate installed oracle bytes against the committed npm tarball integrity. */
export async function verifiedPublishedRoots() {
  const roots = await packageRoots(),
    lock = await readFile(join(REFERENCE_ROOT, "bun.lock"), "utf8");
  await mkdir(CACHE_ROOT, { recursive: true });
  for (const root of roots) {
    const line = lock
      .split("\n")
      .find((line) =>
        line.trimStart().startsWith(`${JSON.stringify(root.name)}: [`),
      );
    const integrity = line?.match(/"(sha512-[A-Za-z0-9+/=]+)"/)?.[1];
    if (!integrity)
      throw new Error(`Missing published integrity for ${root.name}`);
    const cache = join(CACHE_ROOT, `${digest(integrity)}.tgz`);
    let bytes: Uint8Array;
    try {
      bytes = await readFile(cache);
    } catch (error) {
      if (
        !error ||
        typeof error !== "object" ||
        !("code" in error) ||
        error.code !== "ENOENT"
      )
        throw error;
      const basename = root.name.split("/").at(-1)!;
      const response = await fetch(
        `https://registry.npmjs.org/${root.name}/-/${basename}-${upstreamPin.version}.tgz`,
        { signal: AbortSignal.timeout(120_000) },
      );
      if (!response.ok)
        throw new Error(`Cannot download published oracle: ${root.name}`);
      bytes = new Uint8Array(await response.arrayBuffer());
    }
    if (
      `sha512-${createHash("sha512").update(bytes).digest("base64")}` !==
      integrity
    )
      throw new Error(`Published oracle integrity mismatch: ${root.name}`);
    await writeFile(cache, bytes);
    const extracted = await mkdtemp(join(CACHE_ROOT, "published-"));
    try {
      const unpack = await command([
        "tar",
        "-xzf",
        cache,
        "--strip-components=1",
        "--no-same-owner",
        "--no-same-permissions",
        "-C",
        extracted,
      ]);
      if (unpack.code !== 0)
        throw new Error(`Cannot unpack authenticated package: ${root.name}`);
      const expected = (await filesUnder(extracted))
        .filter(
          (path) =>
            path.includes("/dist/") || path === join(extracted, "package.json"),
        )
        .map((path) => relative(extracted, path))
        .sort();
      const installed = [
        "package.json",
        ...(await filesUnder(join(root.root, "dist"))).map((path) =>
          relative(root.root, path),
        ),
      ].sort();
      if (JSON.stringify(expected) !== JSON.stringify(installed))
        throw new Error(
          `Installed oracle file inventory differs from published package: ${root.name}`,
        );
      for (const path of expected)
        if (
          digest(await readFile(join(root.root, path))) !==
          digest(await readFile(join(extracted, path)))
        )
          throw new Error(
            `Installed oracle differs from authenticated published package: ${root.name}/${path}`,
          );
    } finally {
      await rm(extracted, { recursive: true, force: true });
    }
  }
  return roots;
}

/** The verified archive, not an editable checkout, defines the upstream denominator. */
export async function upstreamSource(): Promise<string> {
  const archive = join(CACHE_ROOT, `${upstreamPin.commit}.tar.gz`);
  await mkdir(CACHE_ROOT, { recursive: true });
  let bytes: Uint8Array;
  try {
    bytes = await readFile(archive);
  } catch (error) {
    if (
      !(error instanceof Error) ||
      !("code" in error) ||
      error.code !== "ENOENT"
    )
      throw error;
    const response = await fetch(
      `https://codeload.github.com/better-auth/better-auth/tar.gz/${upstreamPin.commit}`,
      { signal: AbortSignal.timeout(120_000) },
    );
    if (!response.ok)
      throw new Error(
        `Pinned upstream source download failed: ${response.status}`,
      );
    bytes = new Uint8Array(await response.arrayBuffer());
    if (digest(bytes) !== upstreamPin.archiveSha256)
      throw new Error("Upstream archive checksum mismatch");
    await writeFile(archive, bytes);
  }
  if (digest(bytes) !== upstreamPin.archiveSha256)
    throw new Error("Cached upstream archive checksum mismatch");
  // Always extract verified bytes anew. A previously edited cache must not become the oracle.
  const directory = await mkdtemp(join(CACHE_ROOT, "upstream-"));
  try {
    const result = await command([
      "tar",
      "-xzf",
      archive,
      "--strip-components=1",
      "--no-same-owner",
      "--no-same-permissions",
      "-C",
      directory,
    ]);
    if (result.code !== 0)
      throw new Error(`Could not extract verified source: ${result.stderr}`);
    const metadata = (await readJSON(
      join(directory, "packages/better-auth/package.json"),
    )) as { version?: unknown };
    if (metadata.version !== upstreamPin.version)
      throw new Error(
        "Repository source version does not match published oracle",
      );
    return directory;
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}
