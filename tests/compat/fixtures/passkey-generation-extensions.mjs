import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { passkey } from "../reference-server/node_modules/@better-auth/passkey/dist/index.mjs";
import { createPasskeyAdapters } from "./support/passkey-adapters.mjs";

const { close } = await createPasskeyAdapters();
const cases = [];
for (const operation of ["registration", "authentication"]) {
  for (const resolver of [false, true]) {
    for (const [mode, value] of [["undefined", undefined], ["null", null], ["false", false], ["zero", 0], ["number", 5], ["ascii-string", "x"], ["string", "a\ud800"], ["empty-array", []], ["array", ["usb", null]], ["object", { credProps: false, label: "\udfff" }]]) {
      const events = [];
      const plugin = passkey({ rpID: "localhost", rpName: "Names", origin: "http://localhost", [operation]: {
        requireSession: false, resolveUser: async () => ({ id: "owner", name: "Owner" }),
        extensions: resolver ? async () => { events.push("extensions"); return value; } : value,
      } });
      const context = {
        options: {}, session: operation === "authentication" ? { user: { id: "owner" }, session: { token: "session" } } : null,
        adapter: { findMany: async () => { events.push("read"); return []; } },
        internalAdapter: { createVerificationValue: async () => { events.push("publish"); } },
        createAuthCookie: () => ({ name: "challenge", attributes: {} }),
        secret: "extensions-oracle-secret-at-least-32-characters", appName: "Names",
      };
      const endpoint = operation === "registration" ? "generatePasskeyRegistrationOptions" : "generatePasskeyAuthenticationOptions";
      const output = await plugin.endpoints[endpoint]({ context });
      assert.deepEqual(events, resolver ? ["read", "extensions", "publish"] : ["read", "publish"]);
      const options = structuredClone(output);
      delete options.challenge;
      if (options.user) delete options.user.id;
      cases.push({ operation, resolver, mode, input: value, input_undefined: value === undefined, events, extensions: output.extensions, undefined: output.extensions === undefined, own: Object.hasOwn(output, "extensions"), undefined_keys: Object.keys(output).filter(key => output[key] === undefined), option_keys: Object.keys(output), wire_keys: Object.keys(JSON.parse(JSON.stringify(output))), options });
    }
  }
}
await close();
assert.equal(cases.length, 40);
await writeFile(new URL("../../../crates/plugins/src/passkey/generation_extension_cases.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", cases }) + "\n");
console.log(`${cases.length} actual extension-value and read-order cases`);
