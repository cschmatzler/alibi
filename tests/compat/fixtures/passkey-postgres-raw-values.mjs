import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import pg from "../reference-server/node_modules/pg/lib/index.js";
import { Kysely, PostgresDialect } from "../reference-server/node_modules/kysely/dist/index.js";
import { kyselyAdapter } from "../reference-server/node_modules/@better-auth/kysely-adapter/dist/index.mjs";
import { passkey } from "../reference-server/node_modules/@better-auth/passkey/dist/index.mjs";

assert.ok(process.env.BETTER_AUTH_TEST_POSTGRES_URL, "requires a disposable PostgreSQL database URL");
const pin = JSON.parse(await readFile(new URL("../upstream-source.json", import.meta.url)));
assert.equal(pin.commit, "38f43e390920faa400d51ff0bd18570a424d05ce");
for (const name of ["passkey", "kysely-adapter"]) {
  assert.equal(JSON.parse(await readFile(new URL(`../reference-server/node_modules/@better-auth/${name}/package.json`, import.meta.url))).version, "1.7.18");
}
const schema = `passkey_oracle_${randomBytes(8).toString("hex")}`;
const admin = new pg.Client({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL });
await admin.connect();
await admin.query(`CREATE SCHEMA ${schema}`);
const pool = new pg.Pool({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL, options: `-csearch_path=${schema}`, max: 1 });
const db = new Kysely({ dialect: new PostgresDialect({ pool }) });
const cases = [];
try {
  await pool.query(`CREATE TABLE passkey (id TEXT PRIMARY KEY, name TEXT, "publicKey" TEXT, "userId" TEXT, "credentialID" TEXT, counter INTEGER, "deviceType" TEXT, "backedUp" BOOLEAN, transports TEXT, "createdAt" TIMESTAMPTZ, aaguid TEXT)`);
  const adapter = kyselyAdapter(db, { type: "postgres" })({ plugins: [passkey()], advanced: { database: { generateId: false } } });
  for (const field of ["name", "transports", "aaguid"]) {
    for (const [mode, value] of [
      ["number", 42], ["boolean", true], ["array", []], ["object", {}], ["date", new Date(0)], ["utf16", "\ud800"],
      ["array-values", ['quote"', "\\path", null, [42, false, {}]]],
      ["object-values", { label: "\ud800", value: [null, 42] }], ["fraction", -2.5], ["negative-zero", -0],
    ]) {
      const id = `${field}-${mode}-postgres`;
      const row = { field, mode, backend: "postgres", input: value, input_date: value instanceof Date };
      const output = await adapter.create({ model: "passkey", forceAllowId: true, data: {
        id, userId: "owner", publicKey: "public", credentialID: id, counter: 0, deviceType: "singleDevice", backedUp: false, createdAt: new Date(0), [field]: value,
      } });
      row.output = output[field];
      row.date = output[field] instanceof Date;
      const persisted = await adapter.findOne({ model: "passkey", where: [{ field: "id", value: id }] });
      assert.deepEqual(persisted[field], output[field]);
      cases.push(row);
    }
  }
} finally {
  await db.destroy();
  await admin.query(`DROP SCHEMA ${schema} CASCADE`);
  await admin.end();
}
assert.equal(cases.length, 30);
await writeFile(new URL("../../../crates/core/src/store/passkey_postgres_raw_cases.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", cases }) + "\n");
console.log(`${cases.length} actual PostgreSQL passkey raw-value cases`);
