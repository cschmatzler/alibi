import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { memoryAdapter } from "../reference-server/node_modules/@better-auth/memory-adapter/dist/index.mjs";

const pkg = JSON.parse(await readFile(new URL("../reference-server/node_modules/@better-auth/memory-adapter/package.json", import.meta.url)));
assert.equal(pkg.version, "1.7.18");
const database = { user: ["first", "middle", "last"].map(id => ({ id, name: "tie", email: id + "@test" })) };
const adapter = memoryAdapter(database)({ advanced: { database: { generateId: false } } });
const cases = [];
for (const [id, update] of [
  ["first", { email: "CASE@TEST" }],
  ["first", { id: "renamed-first" }],
  ["middle", { image: false }],
  ["renamed-first", { id: "renamed-first" }],
  ["renamed-first", { id: "middle" }],
]) {
  await adapter.update({ model: "user", where: [{ field: "id", value: id }], update });
  const ids = (await adapter.findMany({ model: "user" })).map(row => row.id);
  const tied = (await adapter.findMany({ model: "user", sortBy: { field: "name", direction: "asc" } })).map(row => row.id);
  const page = (await adapter.findMany({ model: "user", offset: 1, limit: 1 })).map(row => row.id);
  assert.equal(database.user.length, 3);
  assert.deepEqual(tied, ids);
  cases.push({ id, update, ids, tied, page });
}
await writeFile(new URL("../../../crates/core/src/store/memory_user_update_order_cases.json", import.meta.url),
  JSON.stringify({ better_auth: pkg.version, cases }) + "\n");
console.log(`${cases.length} memory UPDATE order cases from Better Auth ${pkg.version}`);
