import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { passkey } from "../reference-server/node_modules/@better-auth/passkey/dist/index.mjs";
import { encode } from "../reference-server/node_modules/@simplewebauthn/server/esm/helpers/iso/isoCBOR.js";
import { createPasskeyAdapters } from "./support/passkey-adapters.mjs";

function undefinedPaths(value, path = []) {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item, index) => item === undefined ? [[...path, index]] : undefinedPaths(item, [...path, index]));
}

function proof(challenge, label, transports, present) {
  const id = Buffer.from(label);
  const { publicKey } = generateKeyPairSync("ed25519");
  const key = publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  const cose = encode(new Map([[1, 1], [3, -8], [-1, 6], [-2, new Uint8Array(key)]]));
  const length = Buffer.alloc(2);
  length.writeUInt16BE(id.length);
  const authData = Buffer.concat([createHash("sha256").update("localhost").digest(), Buffer.from([0x45]), Buffer.from([0, 0, 0, 1]), Buffer.alloc(16), length, id, cose]);
  const attestation = encode(new Map([["fmt", "none"], ["attStmt", new Map()], ["authData", new Uint8Array(authData)]]));
  return {
    id: id.toString("base64url"), rawId: id.toString("base64url"), type: "public-key", clientExtensionResults: {},
    response: {
      clientDataJSON: Buffer.from(JSON.stringify({ type: "webauthn.create", challenge, origin: "http://localhost" })).toString("base64url"),
      attestationObject: Buffer.from(attestation).toString("base64url"),
      ...(present ? { transports } : {}),
    },
  };
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
    const response = proof(generated.response.challenge, `transport-${mode}`, transports, present);
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
