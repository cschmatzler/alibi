import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { Kysely, MysqlDialect } from "../reference-server/node_modules/kysely/dist/index.js";
import { kyselyAdapter } from "../reference-server/node_modules/@better-auth/kysely-adapter/dist/index.mjs";
import { passkey } from "../reference-server/node_modules/@better-auth/passkey/dist/index.mjs";

assert.ok(process.env.BETTER_AUTH_TEST_MYSQL_SOCKET, "requires a disposable MySQL Unix socket");
assert.ok(process.env.MYSQL2_MODULE_URL, "requires an installed mysql2 module URL");
const mysql = (await import(process.env.MYSQL2_MODULE_URL)).default;
const driver = JSON.parse(await readFile(new URL("package.json", process.env.MYSQL2_MODULE_URL)));
const pin = JSON.parse(await readFile(new URL("../upstream-source.json", import.meta.url)));
assert.equal(pin.commit, "38f43e390920faa400d51ff0bd18570a424d05ce");
for (const name of ["passkey", "kysely-adapter"]) {
  assert.equal(JSON.parse(await readFile(new URL(`../reference-server/node_modules/@better-auth/${name}/package.json`, import.meta.url))).version, "1.7.18");
}
const database = `passkey_oracle_${randomBytes(8).toString("hex")}`;
const config = { socketPath: process.env.BETTER_AUTH_TEST_MYSQL_SOCKET, user: "root", charset: "utf8mb4", timezone: "Z", connectionLimit: 1 };
const admin = mysql.createPool(config).promise();
const [version] = await admin.query("SELECT VERSION() AS version");
await admin.query(`CREATE DATABASE ${database} CHARACTER SET utf8mb4`);
const pool = mysql.createPool({ ...config, database });
const db = new Kysely({ dialect: new MysqlDialect({ pool }) });
const cases = [];
try {
  await pool.promise().query("CREATE TABLE passkey (id VARCHAR(255) PRIMARY KEY, name TEXT, publicKey TEXT, userId VARCHAR(255), credentialID VARCHAR(255), counter INTEGER, deviceType TEXT, backedUp BOOLEAN, transports TEXT, createdAt DATETIME(3), aaguid TEXT)");
  const adapter = kyselyAdapter(db, { type: "mysql" })({ plugins: [passkey()], advanced: { database: { generateId: false } } });
  for (const field of ["name", "transports", "aaguid"]) {
    for (const [mode, value] of [
      ["number", 42], ["boolean", true], ["array", []], ["object", {}], ["date", new Date(0)], ["utf16", "\ud800"],
      ["single-array", ["usb"]], ["pair-array", ["usb", "nfc"]], ["nested-single", [[7]]], ["object-values", { x: 1 }], ["nullish-array", [null]],
      ["nan", NaN], ["infinity", Infinity], ["negative-infinity", -Infinity], ["negative-zero", -0], ["fraction", -2.5],
    ]) {
      const id = `${field}-${mode}-mysql`;
      const row = { field, mode, backend: "mysql", input: value, input_date: value instanceof Date, input_number: typeof value === "number" && !Number.isFinite(value) ? String(value) : undefined };
      let output;
      try {
        output = await adapter.create({ model: "passkey", forceAllowId: true, data: {
          id, userId: "owner", publicKey: "public", credentialID: id, counter: 0, deviceType: "singleDevice", backedUp: false, createdAt: new Date(0), [field]: value,
        } });
      } catch (error) {
        assert.ok(["ER_PARSE_ERROR", "ER_WRONG_VALUE_COUNT_ON_ROW", "ER_BAD_FIELD_ERROR"].includes(error.code));
        row.error = error.code;
      }
      const persisted = await adapter.findMany({ model: "passkey", where: [{ field: "id", value: id }] });
      if (row.error) { assert.equal(persisted.length, 0); }
      else {
        assert.equal(persisted.length, 1);
        row.output = output[field];
        row.date = output[field] instanceof Date;
        assert.deepEqual(persisted[0][field], output[field]);
      }
      cases.push(row);
    }
  }
} finally {
  await db.destroy();
  await admin.query(`DROP DATABASE ${database}`);
  await admin.end();
}
assert.equal(cases.length, 48);
assert.equal(cases.filter(row => row.error).length, 15);
await writeFile(new URL("../../../crates/core/src/store/passkey_mysql_raw_cases.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", mysql: version[0].version, mysql2: driver.version, cases }) + "\n");
console.log(`${cases.length} actual MySQL passkey raw-value cases (mysql2 ${driver.version})`);
