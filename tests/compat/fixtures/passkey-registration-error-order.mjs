import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { passkey } from "../reference-server/node_modules/@better-auth/passkey/dist/index.mjs";
import { createPasskeyAdapters } from "./support/passkey-adapters.mjs";
import { registrationProof } from "./support/passkey-proof.mjs";

let sequence = 0;
const { adapters, close } = await createPasskeyAdapters(() => `order-${++sequence}`);
const cases = [];
for (const [backend, adapter] of Object.entries(adapters)) {
  for (const createSession of [false, true]) {
    for (const userExists of [false, true]) {
      for (const [mode, transports] of [["valid", ["usb"]], ["scalar", false], ["bad-element", [{ toString: null }]]]) {
        if (createSession && userExists && mode === "valid") continue;
        let stored;
        const events = [];
        const plugin = passkey({ rpID: "localhost", rpName: "Names", origin: "http://localhost", registration: {
          requireSession: false, resolveUser: async () => ({ id: "owner", name: "Owner" }),
          afterVerification: async () => { events.push("callback"); },
        } });
        const context = {
          options: {}, session: null, adapter,
          authCookies: { sessionToken: { name: "session", attributes: {} }, sessionData: { name: "session-data", attributes: {} } },
          internalAdapter: {
            createVerificationValue: async row => { stored = row; },
            consumeVerificationValue: async token => token === stored.identifier ? stored : null,
            findUserById: async () => { events.push("user"); return userExists ? { id: "owner" } : null; },
            createSession: async () => { assert.fail("these cases must not reach session creation"); },
          },
          createAuthCookie: () => ({ name: "challenge", attributes: {} }),
          secret: "order-oracle-secret-at-least-32-characters", appName: "Names", logger: { error() {} },
        };
        const generated = await plugin.endpoints.generatePasskeyRegistrationOptions({ context, returnHeaders: true });
        const cookie = generated.headers.get("set-cookie").split(";")[0];
        const label = `${backend}-${createSession}-${userExists}-${mode}`;
        const response = registrationProof(generated.response.challenge, label, transports);
        const row = { backend, create_session: createSession, user_exists: userExists, mode, transports };
        try {
          await plugin.endpoints.verifyPasskeyRegistration({ body: { response, createSession }, context, headers: new Headers({ cookie, origin: "http://localhost" }) });
          row.success = true;
        } catch (error) {
          assert.ok(error.statusCode >= 400);
          row.error = { status: error.statusCode, body: error.body };
        }
        row.events = events;
        assert.deepEqual(events, createSession ? ["callback", "user"] : ["callback"]);
        row.persisted = (await adapter.findMany({ model: "passkey", where: [{ field: "credentialID", value: response.id }] })).length;
        cases.push(row);
      }
    }
  }
}
await close();
assert.equal(cases.length, 22);
await writeFile(new URL("../../../crates/plugins/src/passkey/registration_error_order_cases.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", cases }) + "\n");
console.log(`${cases.length} actual registration error-order cases`);
