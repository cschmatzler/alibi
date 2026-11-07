import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { username } from "../reference-server/node_modules/better-auth/dist/plugins/username/index.mjs";
import { memoryAdapter } from "../reference-server/node_modules/@better-auth/memory-adapter/dist/index.mjs";
import { parseUserOutput } from "../reference-server/node_modules/better-auth/dist/db/schema.mjs";

const pin = JSON.parse(await readFile(new URL("../upstream-source.json", import.meta.url)));
assert.equal(pin.commit, "38f43e390920faa400d51ff0bd18570a424d05ce");
for (const path of ["better-auth", "@better-auth/memory-adapter"]) {
  assert.equal(JSON.parse(await readFile(new URL(`../reference-server/node_modules/${path}/package.json`, import.meta.url))).version, "1.7.18");
}
const cases = [];
for (const field of ["name", "username", "displayUsername"]) {
  for (const plugin of [false, true]) {
    const input = { id: "owner", name: "Owner", email: "owner@example.com", emailVerified: false, image: null, createdAt: new Date(0), updatedAt: new Date(0), username: "owner", displayUsername: "Owner" };
    const options = { plugins: plugin ? [username()] : [], user: { additionalFields: { [field]: { type: "string", returned: false } } } };
    const adapter = memoryAdapter({ user: [input] })(options);
    const trusted = await adapter.findOne({ model: "user", where: [{ field: "id", value: "owner" }] });
    const output = parseUserOutput(options, trusted);
    assert.equal(Object.hasOwn(output, field), plugin && field !== "name");
    cases.push({ field, plugin, input, trusted, output });
  }
}
assert.equal(cases.length, 6);
await writeFile(new URL("../../../crates/core/src/store/user_output_precedence_cases.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", cases }) + "\n");
console.log(`${cases.length} actual configured/plugin user-output precedence cases`);
