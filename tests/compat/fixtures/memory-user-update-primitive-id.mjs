import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { memoryAdapter } from "../reference-server/node_modules/@better-auth/memory-adapter/dist/index.mjs";

const pkg = JSON.parse(await readFile(new URL("../reference-server/node_modules/@better-auth/memory-adapter/package.json", import.meta.url)));
assert.equal(pkg.version, "1.7.18");
const cases = [];
for (const [kind, value] of [["integer", 7], ["fractional", 7.25], ["true", true], ["infinity", Infinity], ["negative-infinity", -Infinity]]) {
  const database = { user: [] };
  const adapter = memoryAdapter(database)({ advanced: { database: { generateId: false } } });
  const where = value => [{ field: "id", value }];
  for (const [id, name] of [["target", "target"], [value, "native"], [String(value), "text"]]) {
    await adapter.create({ model: "user", data: { id, name, email: name + "@test" }, forceAllowId: true });
  }
  const updated = await adapter.update({ model: "user", where: where("target"), update: { id: value, name: "updated" } });
  assert.equal(database.user.length, 3);
  assert.equal(database.user[0].id, value);
  const native = (await adapter.findMany({ model: "user", where: where(value) })).map(row => row.name);
  const text = (await adapter.findOne({ model: "user", where: where(String(value)) })).name;
  await adapter.delete({ model: "user", where: where(String(value)) });
  const remaining = (await adapter.findMany({ model: "user" })).map(({ id, name }) => ({ id, name }));
  assert.equal(remaining.length, 2);
  cases.push({ kind, id: updated.id, name: updated.name, native, text, remaining });
}
await writeFile(new URL("../../../crates/core/src/store/memory_user_update_primitive_id_cases.json", import.meta.url), JSON.stringify({ better_auth: pkg.version, cases }) + "\n");
console.log(`${cases.length} actual memory adapter primitive UPDATE identity cases from Better Auth ${pkg.version}`);
