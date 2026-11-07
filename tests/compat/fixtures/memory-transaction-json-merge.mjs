import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { memoryAdapter } from "../reference-server/node_modules/@better-auth/memory-adapter/dist/index.mjs";

const pkg = JSON.parse(await readFile(new URL("../reference-server/node_modules/@better-auth/memory-adapter/package.json", import.meta.url)));
assert.equal(pkg.version, "1.7.18");
const cases = [];
for (const [kind, before, after] of [
  ["nonfinite", NaN, Infinity], ["undefined-omission", { x: undefined }, {}],
  ["undefined-null", { x: undefined }, { x: null }],
  ["date-string", new Date(0), "1970-01-01T00:00:00.000Z"],
  ["key-order", { x: 1, y: 2 }, { y: 2, x: 1 }], ["negative-zero", -0, 0],
]) {
  const database = { user: [{ id: "row", name: "base", marker: before, updatedAt: new Date(0) }] };
  const adapter = memoryAdapter(database)({ advanced: { database: { generateId: false } }, user: { additionalFields: { marker: { type: "string" } } } });
  const where = [{ field: "id", value: "row" }];
  let entered, release;
  const ready = new Promise(resolve => { entered = resolve; });
  const barrier = new Promise(resolve => { release = resolve; });
  const transaction = adapter.transaction(async tx => {
    await tx.update({ model: "user", where, update: { marker: after, updatedAt: new Date(0) } });
    entered(); await barrier;
  });
  await ready;
  await adapter.update({ model: "user", where, update: { name: "concurrent", updatedAt: new Date(0) } });
  release(); await transaction;
  cases.push({ kind, wire: JSON.stringify(database.user) });
}
await writeFile(new URL("../../../crates/core/src/store/memory_transaction_json_cases.json", import.meta.url), JSON.stringify({ better_auth: pkg.version, cases }) + "\n");
console.log(`${cases.length} actual memory transaction JSON comparison cases from Better Auth ${pkg.version}`);
