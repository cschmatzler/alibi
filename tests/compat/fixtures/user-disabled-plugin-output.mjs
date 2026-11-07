import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { memoryAdapter } from "../reference-server/node_modules/@better-auth/memory-adapter/dist/index.mjs";
import { username } from "../reference-server/node_modules/better-auth/dist/plugins/username/index.mjs";
import { admin } from "../reference-server/node_modules/better-auth/dist/plugins/admin/index.mjs";
const pin = JSON.parse(await readFile(new URL("../upstream-source.json", import.meta.url)));
assert.equal(pin.commit, "38f43e390920faa400d51ff0bd18570a424d05ce");
assert.equal(JSON.parse(await readFile(new URL("../reference-server/node_modules/@better-auth/memory-adapter/package.json", import.meta.url))).version, "1.7.18");
const cases = [];
for (const [mode, plugins, additionalFields] of [
  ["none", [], {}], ["username", [username()], {}], ["admin", [admin()], {}],
  ["declared-banned", [], { banned: { type: "boolean" } }],
]) {
  const row = { id: "owner", name: "Owner", email: "owner@example.com", emailVerified: false, image: null, createdAt: new Date(0), updatedAt: new Date(0), username: null, displayUsername: null, role: null, banned: null, banReason: null, banExpires: null, twoFactorEnabled: null, isAnonymous: null, phoneNumber: null, phoneNumberVerified: null, lastLoginMethod: null };
  const adapter = memoryAdapter({ user: [row] })({ plugins, user: { additionalFields } });
  const output = await adapter.findOne({ model: "user", where: [{ field: "id", value: "owner" }] });
  cases.push({ mode, row, output });
}
await writeFile(new URL("../../../crates/core/src/store/user_disabled_plugin_output_cases.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", cases }) + "\n");
console.log(`${cases.length} actual initialized user output schema cases`);
