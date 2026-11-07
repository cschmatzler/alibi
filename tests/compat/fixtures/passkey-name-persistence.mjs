import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";
import { Kysely, SqliteDialect } from "../reference-server/node_modules/kysely/dist/index.js";
import { kyselyAdapter } from "../reference-server/node_modules/@better-auth/kysely-adapter/dist/index.mjs";
import { memoryAdapter } from "../reference-server/node_modules/@better-auth/memory-adapter/dist/index.mjs";
import { passkey } from "../reference-server/node_modules/@better-auth/passkey/dist/index.mjs";

const pin = JSON.parse(await readFile(new URL("../upstream-source.json", import.meta.url)));
assert.equal(pin.commit, "38f43e390920faa400d51ff0bd18570a424d05ce");
assert.equal(pin.version, "1.7.18");
for (const name of ["passkey", "memory-adapter", "kysely-adapter"]) {
  assert.equal(JSON.parse(await readFile(new URL(`../reference-server/node_modules/@better-auth/${name}/package.json`, import.meta.url))).version, "1.7.18");
}
const plugin = passkey();
const options = { plugins: [plugin], advanced: { database: { generateId: false } } };
const database = new DatabaseSync(":memory:");
database.exec(`CREATE TABLE passkey (id TEXT PRIMARY KEY, name TEXT, publicKey TEXT, userId TEXT, credentialID TEXT, counter INTEGER, deviceType TEXT, backedUp INTEGER, transports TEXT, createdAt TEXT, aaguid TEXT)`);
// Adapt only the synchronous node:sqlite statement ABI to Kysely's driver ABI.
const driver = {
  close() { database.close(); },
  prepare(sql) {
    const statement = database.prepare(sql);
    return {
      reader: statement.columns().length > 0,
      all(parameters) { return statement.all(...parameters); },
      run(parameters) { return statement.run(...parameters); },
    };
  },
};
const kysely = new Kysely({ dialect: new SqliteDialect({ database: driver }) });
const adapters = {
  memory: memoryAdapter({ passkey: [] })(options),
  sqlite: kyselyAdapter(kysely, { type: "sqlite" })(options),
};
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
await kysely.destroy();
assert.equal(cases.length, 12);
await writeFile(new URL("../../../crates/core/src/store/passkey_name_cases.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", cases }) + "\n");
console.log(`${cases.length} actual passkey name memory/SQLite persistence cases`);
