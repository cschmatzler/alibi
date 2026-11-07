import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { createPasskeyAdapters } from "./support/passkey-adapters.mjs";

const { adapters, close } = await createPasskeyAdapters();
const optional = ["name", "transports", "createdAt", "aaguid"];
const cases = [];
for (const mode of ["absent", "undefined", "null", "present", "empty", "date-text"]) {
  for (const [backend, adapter] of Object.entries(adapters)) {
    const id = `${mode}-${backend}`;
    const data = { id, userId: "owner", publicKey: "public", credentialID: id, counter: 0, deviceType: "singleDevice", backedUp: false };
    if (mode === "undefined") for (const field of optional) data[field] = undefined;
    if (mode === "null") for (const field of optional) data[field] = null;
    if (mode === "present" || mode === "empty" || mode === "date-text") Object.assign(data, {
      name: mode === "empty" ? "" : "Key",
      transports: mode === "empty" ? "" : "usb,nfc",
      createdAt: mode === "date-text" ? "1970-01-01T00:00:00.000Z" : new Date(0),
      aaguid: mode === "empty" ? "" : "00000000-0000-0000-0000-000000000000",
    });
    const created = await adapter.create({ model: "passkey", data, forceAllowId: true });
    const listed = await adapter.findMany({ model: "passkey", where: [{ field: "id", value: id }] });
    assert.equal(listed.length, 1);
    assert.equal(JSON.stringify(created), JSON.stringify(listed[0]));
    cases.push({
      mode, backend, input: data,
      input_date: data.createdAt instanceof Date,
      input_undefined: Object.keys(data).filter(key => data[key] === undefined),
      output: created,
      keys: Object.keys(created),
      undefined: Object.keys(created).filter(key => created[key] === undefined),
      date: created.createdAt instanceof Date,
      wire: JSON.stringify(created),
    });
  }
}
await close();
assert.equal(cases.length, 12);
await writeFile(new URL("../../../crates/core/src/store/passkey_field_presence_cases.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", cases }) + "\n");
console.log(`${cases.length} actual passkey optional-field memory/SQLite cases`);
