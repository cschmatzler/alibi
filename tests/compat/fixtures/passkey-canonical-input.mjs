import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { passkey } from "../reference-server/node_modules/@better-auth/passkey/dist/index.mjs";

const pkg = JSON.parse(await readFile(new URL("../reference-server/node_modules/@better-auth/passkey/package.json", import.meta.url)));
assert.equal(pkg.version, "1.7.18");
const plugin = passkey();
const cases = [];
function record(operation, mode, input) {
  const endpoint = operation === "registration" ? "verifyPasskeyRegistration" : "updatePasskey";
  const result = plugin.endpoints[endpoint].options.body.safeParse(input);
  const row = {
    operation, mode, input,
    input_undefined: Object.keys(input).filter(key => input[key] === undefined),
    success: result.success,
  };
  if (result.success) {
    row.expected = result.data;
    row.keys = Object.keys(result.data);
    row.undefined = row.keys.filter(key => result.data[key] === undefined);
    row.wire = JSON.stringify(result.data);
  } else {
    row.error = result.error.issues.map(issue => `[body.${issue.path.join(".")}] ${issue.message}`).join("; ");
  }
  cases.push(row);
}
record("registration", "missing-response", {});
for (const response of [undefined, null, false, 0, "", [], {}]) record("registration", "response-" + typeof response + "-" + String(response), { response });
for (const [mode, name] of [
  ["undefined", undefined], ["null", null], ["false", false], ["zero", 0],
  ["empty", ""], ["space", "\ufeff \u00a0"], ["ordinary", "\ufeff key \u3000"],
  ["high-surrogate", " \ud800\ufeff"], ["low-surrogate", "\u00a0\udfff "],
  ["non-trimming-space", "\u0085key\u0085"],
]) record("registration", "name-" + mode, { response: {}, name });
for (const value of [undefined, null, false, true, 0, "false"]) record("registration", "session-" + String(value), { response: {}, createSession: value });
record("registration", "order-and-unknown-key", { createSession: true, "\ud800": "drop", name: " key ", response: {}, unknown: false });
for (const [mode, name] of [
  ["missing", undefined], ["null", null], ["false", false], ["empty", ""],
  ["space", "\ufeff \u00a0"], ["ordinary", "\ufeff key \u3000"],
  ["high-surrogate", " \ud800\ufeff"], ["low-surrogate", "\u00a0\udfff "],
  ["non-trimming-space", "\u0085key\u0085"],
]) {
  const input = { id: "credential" };
  if (mode !== "missing") input.name = name;
  record("update", "name-" + mode, input);
}
record("update", "order-and-unknown-key", { name: " key ", "\ud800": "drop", id: "credential", unknown: true });
record("update", "missing-id", { name: "key" });
assert.equal(cases.length, 36);
await writeFile(new URL("../../../crates/plugins/src/passkey/canonical_input_cases.json", import.meta.url), JSON.stringify({ better_auth: pkg.version, cases }) + "\n");
console.log(`${cases.length} passkey canonical input cases from Better Auth ${pkg.version}`);
