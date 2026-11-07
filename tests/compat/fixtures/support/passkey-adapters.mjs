import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";
import { Kysely, SqliteDialect } from "../../reference-server/node_modules/kysely/dist/index.js";
import { kyselyAdapter } from "../../reference-server/node_modules/@better-auth/kysely-adapter/dist/index.mjs";
import { memoryAdapter } from "../../reference-server/node_modules/@better-auth/memory-adapter/dist/index.mjs";
import { passkey } from "../../reference-server/node_modules/@better-auth/passkey/dist/index.mjs";

export async function createPasskeyAdapters(generateId = false) {
  const pin = JSON.parse(await readFile(new URL("../../upstream-source.json", import.meta.url)));
  assert.equal(pin.commit, "38f43e390920faa400d51ff0bd18570a424d05ce");
  assert.equal(pin.version, "1.7.18");
  for (const name of ["passkey", "memory-adapter", "kysely-adapter"]) {
    assert.equal(JSON.parse(await readFile(new URL(`../../reference-server/node_modules/@better-auth/${name}/package.json`, import.meta.url))).version, "1.7.18");
  }
  const plugin = passkey();
  const options = { plugins: [plugin], advanced: { database: { generateId } } };
  const database = new DatabaseSync(":memory:");
  database.exec(`CREATE TABLE passkey (id TEXT PRIMARY KEY, name TEXT, publicKey TEXT, userId TEXT, credentialID TEXT, counter INTEGER, deviceType TEXT, backedUp INTEGER, transports TEXT, createdAt TEXT, aaguid TEXT)`);
  // Adapt only the synchronous node:sqlite statement ABI to Kysely's driver ABI.
  const driver = {
    close() { database.close(); },
    prepare(sql) {
      const statement = database.prepare(sql);
      return {
        reader: statement.columns().length > 0,
        // Reserve the named-parameter argument so positional objects cannot shift bindings.
        all(parameters) { return statement.all({}, ...parameters); },
        run(parameters) { return statement.run({}, ...parameters); },
      };
    },
  };
  const kysely = new Kysely({ dialect: new SqliteDialect({ database: driver }) });
  return {
    plugin,
    adapters: {
      memory: memoryAdapter({ passkey: [] })(options),
      sqlite: kyselyAdapter(kysely, { type: "sqlite" })(options),
    },
    close: () => kysely.destroy(),
  };
}
