import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { memoryAdapter } from "../reference-server/node_modules/@better-auth/memory-adapter/dist/index.mjs";

const pkg = JSON.parse(await readFile(new URL("../reference-server/node_modules/@better-auth/memory-adapter/package.json", import.meta.url)));
assert.equal(pkg.version, "1.7.18");
const database = { user: [] };
const adapter = memoryAdapter(database)({ advanced: { database: { generateId: false } } });
const inputs = ["duplicate", "other", "duplicate", "last", 7, 7, "7"].map((id, index) => ({ id, name: `row-${index}`, email: "shared@test" }));
const rows = async () => (await adapter.findMany({ model: "user" })).map(({ id, name, email }) => ({ id, name, email }));
const byId = id => [{ field: "id", value: id }];
for (const data of inputs) {
  await adapter.create({ model: "user", data, forceAllowId: true });
}
const created = await rows();
assert.equal(created.length, inputs.length);
assert.equal(database.user.filter(row => row.id === 7).length, 2);
const numeric = (await adapter.findMany({ model: "user", where: byId(7) })).map(row => row.name);
const first = await adapter.findOne({ model: "user", where: byId("duplicate") });
assert.equal(first.name, "row-0");
const first_name = first.name;
const selected = await adapter.findMany({ model: "user", where: [{ field: "id", operator: "in", value: ["last", "duplicate", "duplicate"] }] });
const selected_names = selected.map(row => row.name);
const updated = await adapter.update({ model: "user", where: byId("duplicate"), update: { id: "other", name: "updated" } });
const after_collision = await rows();
assert.equal(updated.name, "updated");
assert.equal(after_collision.filter(row => row.id === "other").length, 3);
await adapter.update({ model: "user", where: byId("other"), update: { email: "updated@test" } });
const after_update = await rows();
await adapter.delete({ model: "user", where: byId("other") });
const after_delete = await rows();
assert.equal(after_delete.length, inputs.length - 3);
await writeFile(new URL("../../../crates/core/src/store/memory_user_duplicate_cases.json", import.meta.url), JSON.stringify({
  better_auth: pkg.version, inputs, created, numeric, first: first_name,
  selected: selected_names, after_collision, after_update, after_delete,
}) + "\n");
console.log(`Memory duplicate USER create/select/update/delete sequence from Better Auth ${pkg.version}`);
