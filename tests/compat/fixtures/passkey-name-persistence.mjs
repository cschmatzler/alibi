import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { createPasskeyAdapters } from "./support/passkey-adapters.mjs";

const { plugin, adapters, close } = await createPasskeyAdapters();
const cases = [];
for (const [mode, name] of [["ordinary", " key "], ["high", " \ud800\ufeff"], ["low", "\u00a0\udfff "], ["paired", " \ud83d\ude00 "], ["mixed", "a\ud800b\udfff"], ["non-trimming", "\u0085key\u0085"]]) {
  for (const [backend, adapter] of Object.entries(adapters)) {
    const registration = plugin.endpoints.verifyPasskeyRegistration.options.body.parse({ response: {}, name });
    const id = `${mode}-${backend}`;
    const created = await adapter.create({ model: "passkey", data: { id, name: registration.name, userId: "owner", publicKey: "public", credentialID: id, counter: 0, deviceType: "singleDevice", backedUp: false }, forceAllowId: true });
    const update = plugin.endpoints.updatePasskey.options.body.parse({ id, name: `\ufeff${name}!\u3000` });
    const renamed = await adapter.update({ model: "passkey", where: [{ field: "id", value: id }], update: { name: update.name } });
    const listed = await adapter.findMany({ model: "passkey", where: [{ field: "id", value: id }] });
    cases.push({ mode, backend, input: name, registration: registration.name, create: created.name, update_input: update.name, rename: renamed.name, list: listed[0].name });
  }
}
await close();
assert.equal(cases.length, 12);
await writeFile(new URL("../../../crates/core/src/store/passkey_name_cases.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", cases }) + "\n");
console.log(`${cases.length} actual passkey name memory/SQLite persistence cases`);
