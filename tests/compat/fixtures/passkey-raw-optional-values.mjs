import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { createPasskeyAdapters } from "./support/passkey-adapters.mjs";

const { adapters, close } = await createPasskeyAdapters();
const cases = [];
for (const field of ["name", "transports", "aaguid"]) {
  for (const [mode, value] of [["number", 42], ["boolean", true], ["array", []], ["object", {}], ["date", new Date(0)], ["utf16", "\ud800"]]) {
    for (const [backend, adapter] of Object.entries(adapters)) {
      const id = `${field}-${mode}-${backend}`;
      const data = { id, userId: "owner", publicKey: "public", credentialID: id, counter: 0, deviceType: "singleDevice", backedUp: false, createdAt: new Date(0), [field]: value };
      const row = { field, mode, backend, input: value, input_date: value instanceof Date };
      let output;
      try {
        output = await adapter.create({ model: "passkey", data, forceAllowId: true });
      } catch (error) {
        assert.equal(error.name, "TypeError");
        row.error = error.name;
      }
      const persisted = await adapter.findMany({ model: "passkey", where: [{ field: "credentialID", value: id }] });
      if (row.error) {
        assert.equal(persisted.length, 0);
      } else {
        assert.equal(persisted.length, 1);
        row.output = output[field];
        row.date = output[field] instanceof Date;
        assert.deepEqual(persisted[0][field], output[field]);
      }
      cases.push(row);
    }
  }
}
await close();
assert.equal(cases.length, 36);
assert.equal(cases.filter(row => row.error).length, 9);
await writeFile(new URL("../../../crates/core/src/store/passkey_raw_optional_cases.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", cases }) + "\n");
console.log(`${cases.length} actual passkey raw optional-value cases`);
