import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { memoryAdapter } from "../reference-server/node_modules/@better-auth/memory-adapter/dist/index.mjs";
import { parseUserOutput } from "../reference-server/node_modules/better-auth/dist/db/schema.mjs";

const pin = JSON.parse(await readFile(new URL("../upstream-source.json", import.meta.url)));
assert.equal(pin.commit, "9faf6f6a1155a6cdaf8ba2d25ce53e4f5a3fda72");
assert.equal(JSON.parse(await readFile(new URL("../reference-server/node_modules/better-auth/package.json", import.meta.url))).version, "1.7.27");
assert.equal(JSON.parse(await readFile(new URL("../reference-server/node_modules/@better-auth/memory-adapter/package.json", import.meta.url))).version, "1.7.27");
const cases = [];
for (const field of ["name", "id", "email", "emailVerified", "image", "createdAt", "updatedAt"]) {
  const input = { id: "owner", name: "Owner", email: "owner@example.com", emailVerified: false, image: null, createdAt: new Date(0), updatedAt: new Date(0) };
  const type = field.endsWith("At") ? "date" : field === "emailVerified" ? "boolean" : "string";
  const options = { user: { additionalFields: { [field]: { type, returned: false } } } };
  const adapter = memoryAdapter({ user: [input] })(options);
  const trusted = await adapter.findOne({ model: "user", where: [{ field: "id", value: "owner" }] });
  const output = parseUserOutput(options, trusted);
  assert.ok(Object.hasOwn(trusted, field));
  assert.ok(!Object.hasOwn(output, field));
  cases.push({ field, type, input, trusted, output });
}
assert.equal(cases.length, 7);
await writeFile(new URL("../../../crates/core/src/store/user_core_visibility_cases.json", import.meta.url), JSON.stringify({ better_auth: "1.7.27", cases }) + "\n");
console.log(`${cases.length} actual core user returned:false projection cases`);
