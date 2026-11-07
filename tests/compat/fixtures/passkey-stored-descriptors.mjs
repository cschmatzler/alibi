import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { passkey } from "../reference-server/node_modules/@better-auth/passkey/dist/index.mjs";
import { createPasskeyAdapters } from "./support/passkey-adapters.mjs";

const { close } = await createPasskeyAdapters();
const cases = [];
for (const operation of ["registration", "authentication"]) {
  for (const [mode, id] of [["ordinary", "YQ"], ["padded", "YQ=="], ["embedded-padding", "Y=Q=="], ["only-padding", "==="], ["empty", ""], ["short", "a"], ["invalid-character", "a!"], ["standard-base64", "a+/b"], ["unicode", "é"]]) {
    const events = [];
    const plugin = passkey({ rpID: "localhost", origin: "http://localhost", [operation]: {
      requireSession: false, resolveUser: async () => ({ id: "owner", name: "Owner" }),
      extensions: async () => { events.push("extensions"); return {}; },
    } });
    const context = {
      options: {}, session: operation === "authentication" ? { user: { id: "owner" }, session: { token: "session" } } : null,
      adapter: { findMany: async () => { events.push("read"); return [{ credentialID: id, transports: "usb,nfc" }]; } },
      internalAdapter: { createVerificationValue: async () => { events.push("publish"); } },
      createAuthCookie: () => ({ name: "challenge", attributes: {} }),
      secret: "descriptor-oracle-secret-at-least-32-characters", appName: "Names",
    };
    const row = { operation, mode, input: id };
    try {
      const endpoint = operation === "registration" ? "generatePasskeyRegistrationOptions" : "generatePasskeyAuthenticationOptions";
      const output = await plugin.endpoints[endpoint]({ context });
      row.descriptor = (output.excludeCredentials ?? output.allowCredentials)[0];
      row.keys = Object.keys(row.descriptor);
    } catch (error) {
      assert.equal(error.name, "Error");
      row.error = true;
    }
    row.events = events;
    assert.deepEqual(events, row.error ? ["read", "extensions"] : ["read", "extensions", "publish"]);
    cases.push(row);
  }
}
await close();
assert.equal(cases.length, 18);
assert.equal(cases.filter(row => row.error).length, 6);
await writeFile(new URL("../../../crates/plugins/src/passkey/stored_descriptor_cases.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", cases }) + "\n");
console.log(`${cases.length} actual stored descriptor ID and own-key-order cases`);
