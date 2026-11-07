import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { passkey } from "../reference-server/node_modules/@better-auth/passkey/dist/index.mjs";
const pin = JSON.parse(await readFile(new URL("../upstream-source.json", import.meta.url)));
assert.equal(pin.commit, "38f43e390920faa400d51ff0bd18570a424d05ce");
assert.equal(JSON.parse(await readFile(new URL("../reference-server/node_modules/@better-auth/passkey/package.json", import.meta.url))).version, "1.7.18");
const cases = [];
for (const [mode, name, context, resolved = { id: "owner", name: "Owner" }] of [
  ["absent", undefined, undefined], ["empty", "", ""], ["spaces", " \ufeff ", " \u3000 "],
  ["high", "\ud800", "\udfff"], ["low", "\udfff", "\ud800"], ["mixed", "a\ud800b\udfff", "c\udfff"],
  ["paired", "\ud83d\ude00", "\ud83d\ude00"], ["null-name", null, "context"], ["null-context", "name", null],
  ["number-name", 7, "context"], ["number-context", "name", 7],
  ["resolver-high", undefined, "context", { id: "owner", name: "\ud800", displayName: "\udfff" }],
  ["resolver-empty-display", undefined, "context", { id: "owner", name: "\udfff", displayName: "" }],
]) {
  let stored, seen;
  const plugin = passkey({ rpID: "localhost", rpName: "Names", origin: "http://localhost", registration: {
    requireSession: false,
    resolveUser: async ({ context }) => { seen = context; return resolved; },
  } });
  const query = {};
  if (name !== undefined) query.name = name;
  if (context !== undefined) query.context = context;
  query["\ud800"] = "ignored";
  const row = { mode, query, resolved };
  let output;
  try {
    output = await plugin.endpoints.generatePasskeyRegistrationOptions({ query, context: {
      options: {}, session: null, adapter: { findMany: async () => [] },
      internalAdapter: { createVerificationValue: async value => { stored = value; } },
      createAuthCookie: () => ({ name: "challenge", attributes: {} }),
      secret: "query-oracle-secret-at-least-32-characters", appName: "Names",
    } });
  } catch (error) {
    assert.equal(error.statusCode, 400);
    row.error = { status: error.statusCode, body: error.body };
    cases.push(row);
    continue;
  }
  assert.ok(stored);
  row.user = { name: output.user.name, displayName: output.user.displayName };
  row.seen = seen;
  row.stored = JSON.parse(stored.value).context;
  row.stored_user = JSON.parse(stored.value).userData;
  row.options = structuredClone(output);
  delete row.options.challenge;
  delete row.options.user.id;
  cases.push(row);
}
assert.equal(cases.length, 13);
assert.equal(cases.filter(row => row.error).length, 4);
await writeFile(new URL("../../../crates/plugins/src/passkey/generation_query_cases.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", cases }) + "\n");
console.log(`${cases.length} actual passkey generation query endpoint cases`);
