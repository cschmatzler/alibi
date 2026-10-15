import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

/** Stable numeric labels for artifact names and synthetic phone numbers. */
export function hashLabel(value: string): bigint {
  return BigInt("0x" + createHash("sha256").update(value).digest("hex").slice(0, 16));
}

/** Evidence writers own their output directories, including fresh checkouts. */
export async function writeArtifact(path: string | URL, data: string | Uint8Array) {
  await mkdir(dirname(path instanceof URL ? fileURLToPath(path) : path), { recursive: true });
  await writeFile(path, data);
}
