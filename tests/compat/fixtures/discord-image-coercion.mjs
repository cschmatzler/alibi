import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { discord } from "../reference-server/node_modules/@better-auth/core/dist/social-providers/index.mjs";

const pkg = JSON.parse(await readFile(new URL("../reference-server/node_modules/@better-auth/core/package.json", import.meta.url)));
assert.equal(pkg.version, "1.7.18");
const inputs = [];
for (const [kind, id] of [
  ["absent", undefined], ["null", null], ["false", false], ["zero", 0], ["true", true],
  ["number", 7], ["array", []], ["object", {}], ["array-text", ["x"]],
  ["bad-object", { toString: null }], ["utf16", "\ud800"],
]) {
  inputs.push([`hash-id-${kind}`, { ...(kind === "absent" ? {} : { id }), avatar: "a_hash" }]);
}
for (const [kind, id] of [
  ["decimal", "123"], ["number", 123], ["true", true], ["false", false], ["empty", ""],
  ["whitespace", " \ufeff4194304 "], ["hex", "0x800000"], ["binary", "0b10000000000000000000000"],
  ["octal", "0o20000000"], ["negative", "-1"], ["negative-rounding", "-4194305"],
  ["plus", "+4194304"], ["signed-hex", "-0x1"], ["array", []], ["array-number", [4194304]],
  ["null", null], ["fractional", 7.5], ["exponent", "1e3"], ["overflow", "9".repeat(400)],
]) {
  inputs.push([`default-id-${kind}`, { id, avatar: null, discriminator: "0" }]);
}
for (const [kind, discriminator] of [
  ["suffix", "12suffix"], ["hex", "0x10"], ["negative", -1], ["null", null], ["false", false],
  ["object", {}], ["array", []], ["array-number", [12]], ["whitespace", " \ufeff+12tail"],
  ["utf16-suffix", "2\ud800"], ["negative-zero", "-0"], ["empty", ""], ["infinity", "Infinity"],
  ["number-zero", 0], ["bad-object", { toString: null }],
]) {
  inputs.push([`discriminator-${kind}`, { id: "subject", avatar: null, discriminator }]);
}
for (const [kind, avatar] of [["absent", undefined], ["number", 7], ["false", false], ["empty", ""], ["utf16", "a_\udfff"]]) {
  inputs.push([`avatar-${kind}`, { id: "subject", ...(kind === "absent" ? {} : { avatar }) }]);
}
for (const [kind, profile] of [["null", null], ["false", false], ["true", true], ["array", []], ["text", "text"], ["zero", 0]]) {
  inputs.push([`profile-${kind}`, profile]);
}
const original = globalThis.fetch;
const cases = [];
try {
  for (const [mode, profile] of inputs) {
    globalThis.fetch = async () => new Response(JSON.stringify(profile), { headers: { "content-type": "application/json" } });
    let result;
    try {
      result = await discord({ clientId: "client", clientSecret: "secret" }).getUserInfo({ accessToken: "access" });
    } catch (error) {
      cases.push({ mode, profile, error: error.name });
      continue;
    }
    assert.equal(result.user.image, result.data.image_url);
    cases.push({ mode, profile, image: result.user.image, wire: JSON.stringify(result.user.image) });
  }
} finally {
  globalThis.fetch = original;
}
assert.equal(cases.length, 56);
await writeFile(new URL("../../../crates/plugins/src/oauth/providers/discord_image_cases.json", import.meta.url), JSON.stringify({ better_auth: pkg.version, cases }) + "\n");
console.log(`${cases.length} actual Discord image coercion cases from Better Auth ${pkg.version}`);
