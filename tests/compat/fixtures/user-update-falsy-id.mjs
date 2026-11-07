import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { memoryAdapter } from "../reference-server/node_modules/@better-auth/memory-adapter/dist/index.mjs";

const pkg = JSON.parse(await readFile(new URL("../reference-server/node_modules/@better-auth/memory-adapter/package.json", import.meta.url)));
assert.equal(pkg.version, "1.7.18");
const database = { user: [{ id: "fixed-user", name: "initial", email: "fixed@test" }] };
const adapter = memoryAdapter(database)({ advanced: { database: { generateId: false } } });
const cases = [];
for (const [kind, value] of [["absent", undefined], ["undefined", undefined], ["null", null], ["false", false], ["zero", 0], ["negative-zero", -0], ["nan", NaN], ["empty", ""]]) {
  const update = kind === "absent" ? { name: kind } : { id: value, name: kind };
  const output = await adapter.update({ model: "user", where: [{ field: "id", value: "fixed-user" }], update });
  assert.equal(database.user.length, 1);
  assert.equal(database.user[0].id, "fixed-user");
  assert.equal(output.id, "fixed-user");
  cases.push({ kind, id: output.id, name: output.name });
}
await writeFile(new URL("../../../crates/core/src/store/user_update_falsy_id_cases.json", import.meta.url), JSON.stringify({ better_auth: pkg.version, cases }) + "\n");
console.log(`${cases.length} actual adapter UPDATE falsy-ID cases from Better Auth ${pkg.version}`);
