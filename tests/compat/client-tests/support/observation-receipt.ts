export type ObservationReceipt = {
  scenarioName: string;
  ts: unknown;
  rust: unknown;
};

/**
 * Keep ordinary receipts byte-compatible with JSON.stringify. BigInt leaves use
 * canonical decimal strings and receipt-owned, versioned literal-key paths.
 * Nested application strings/objects never act as type tags. Only the explicit
 * decoder below restores BigInt; ordinary JSON readers still see the same roots.
 */
export function serializeObservationReceipt(receipt: ObservationReceipt): string {
  const paths = new WeakMap<object, string[]>();
  const bigintPaths: string[][] = [];
  let root = true;
  const json = JSON.stringify(
    { scenarioName: receipt.scenarioName, ts: receipt.ts, rust: receipt.rust },
    function (this: object, key, value) {
      const path = root ? [] : [...paths.get(this)!, key];
      root = false;
      if (typeof value === "bigint") {
        bigintPaths.push(path);
        return value.toString();
      }
      if (value !== null && typeof value === "object") paths.set(value, path);
      return value;
    },
    2,
  );
  if (!bigintPaths.length) return json;
  return JSON.stringify(
    { ...JSON.parse(json), bigintEncoding: { version: 1, paths: bigintPaths } },
    null,
    2,
  );
}

/** Decode only explicitly listed BigInt leaves, after validating all metadata. */
export function parseObservationReceipt(json: string): ObservationReceipt {
  const receipt = JSON.parse(json);
  const invalid = () => new Error("Invalid observation receipt BigInt encoding");
  if (
    receipt === null ||
    typeof receipt !== "object" ||
    Array.isArray(receipt) ||
    typeof receipt.scenarioName !== "string" ||
    !Object.hasOwn(receipt, "ts") ||
    !Object.hasOwn(receipt, "rust")
  ) {
    throw invalid();
  }
  if (!Object.hasOwn(receipt, "bigintEncoding")) return receipt;
  const encoding = receipt.bigintEncoding;
  if (
    encoding === null ||
    typeof encoding !== "object" ||
    Array.isArray(encoding) ||
    encoding.version !== 1 ||
    Object.keys(encoding).some((key) => key !== "version" && key !== "paths") ||
    !Array.isArray(encoding.paths) ||
    !encoding.paths.length
  ) {
    throw invalid();
  }
  const seen = new Set<string>();
  const leaves: { parent: Record<string, unknown>; key: string; value: bigint }[] = [];
  for (const path of encoding.paths) {
    if (
      !Array.isArray(path) ||
      !path.length ||
      path.some((key) => typeof key !== "string") ||
      (path[0] !== "ts" && path[0] !== "rust")
    ) {
      throw invalid();
    }
    const identity = JSON.stringify(path);
    if (seen.has(identity)) throw invalid();
    seen.add(identity);
    let parent = receipt;
    for (const [index, key] of path.entries()) {
      if (
        parent === null ||
        typeof parent !== "object" ||
        !Object.hasOwn(parent, key) ||
        // Array paths name canonical indices, never length or index aliases.
        (Array.isArray(parent) && !/^(0|[1-9]\d*)$/.test(key))
      ) {
        throw invalid();
      }
      const value = parent[key];
      if (index === path.length - 1) {
        if (typeof value !== "string" || !/^(0|-?[1-9]\d*)$/.test(value)) throw invalid();
        leaves.push({ parent, key, value: BigInt(value) });
      } else {
        parent = value;
      }
    }
  }
  for (const { parent, key, value } of leaves) parent[key] = value;
  delete receipt.bigintEncoding;
  return receipt;
}
