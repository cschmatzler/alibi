import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { passkey } from "../reference-server/node_modules/@better-auth/passkey/dist/index.mjs";
import { createPasskeyAdapters } from "./support/passkey-adapters.mjs";
import { registrationProof } from "./support/passkey-proof.mjs";

function undefinedPaths(value, path = []) {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item, index) => item === undefined ? [[...path, index]] : undefinedPaths(item, [...path, index]));
}

let sequence = 0;
const { adapters, close } = await createPasskeyAdapters(() => `source-${++sequence}`);
const cases = [];
for (const [mode, transports] of [
  ["absent", undefined], ["undefined", undefined], ["null", null], ["empty", []],
  ["known", ["usb", "internal"]], ["high", ["\ud800"]], ["low", ["\udfff"]],
  ["nullish", [null, undefined, "usb"]], ["nested", [["usb", null], ["nfc", undefined]]],
  ["coerced", [0, false, {}, [], null]], ["empty-entries", ["", null, undefined, "nfc"]],
  ["bad-object", [{ toString: null }]], ["false", false], ["number", 7], ["string", "usb"], ["object", {}],
]) {
  for (const [backend, adapter] of Object.entries(adapters)) {
    let stored, called = false;
    const present = mode !== "absent";
    const plugin = passkey({ rpID: "localhost", rpName: "Names", origin: "http://localhost", registration: {
      requireSession: false, resolveUser: async () => ({ id: "owner", name: "Owner" }),
      afterVerification: async ({ clientData }) => {
        assert.equal(Object.hasOwn(clientData.response, "transports"), present);
        assert.deepEqual(clientData.response.transports, transports);
        called = true;
      },
    } });
    const context = {
      options: {}, session: null, adapter,
      authCookies: { sessionToken: { name: "session", attributes: {} }, sessionData: { name: "session-data", attributes: {} } },
      internalAdapter: { createVerificationValue: async row => { stored = row; }, consumeVerificationValue: async token => token === stored.identifier ? stored : null },
      createAuthCookie: () => ({ name: "challenge", attributes: {} }), secret: "transport-oracle-secret-at-least-32-characters", appName: "Names", logger: { error() {} },
    };
    const generated = await plugin.endpoints.generatePasskeyRegistrationOptions({ context, returnHeaders: true });
    const cookie = generated.headers.get("set-cookie").split(";")[0];
    const response = registrationProof(generated.response.challenge, `transport-${mode}`, transports, present);
    const row = { mode, backend, present, input: transports, undefined_paths: undefinedPaths(transports) };
    let output;
    try {
      output = await plugin.endpoints.verifyPasskeyRegistration({ body: { response }, context, headers: new Headers({ cookie, origin: "http://localhost" }) });
    } catch (error) {
      assert.equal(error.statusCode, 500);
      row.error = { status: error.statusCode, body: error.body };
    }
    assert.equal(called, true, `${mode}/${backend}: valid none attestation must reach the callback`);
    row.called = called;
    const persisted = await adapter.findMany({ model: "passkey", where: [{ field: "credentialID", value: response.id }] });
    if (row.error) {
      assert.equal(persisted.length, 0);
    } else {
      assert.equal(persisted.length, 1);
      assert.equal(persisted[0].transports, output.transports);
      row.transports = output.transports;
      row.date = output.createdAt instanceof Date;
      assert.equal(row.date, true);
      const registration = await plugin.endpoints.generatePasskeyRegistrationOptions({ context });
      row.registration_descriptor = registration.excludeCredentials.find(credential => credential.id === response.id);
      const authentication = await plugin.endpoints.generatePasskeyAuthenticationOptions({ context: { ...context, session: { user: { id: "owner" }, session: { token: "session" } } } });
      row.authentication_descriptor = authentication.allowCredentials.find(credential => credential.id === response.id);
      assert.ok(row.registration_descriptor);
      assert.ok(row.authentication_descriptor);
    }
    cases.push(row);
  }
}
await close();
assert.equal(cases.length, 32);
assert.equal(cases.filter(row => row.error).length, 10);
await writeFile(new URL("../../../crates/plugins/src/passkey/transport_cases.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", cases }) + "\n");
console.log(`${cases.length} actual passkey transport cases with genuine none attestation`);
