import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { Kysely, MysqlDialect } from "../../reference-server/node_modules/kysely/dist/index.js";

export async function createMysqlDatabase({ connectionLimit = 1 } = {}) {
  assert.ok(process.env.BETTER_AUTH_TEST_MYSQL_SOCKET, "requires a disposable MySQL Unix socket");
  assert.ok(process.env.MYSQL2_MODULE_URL, "requires an installed mysql2 module URL");
  const mysql = (await import(process.env.MYSQL2_MODULE_URL)).default;
  const driver = JSON.parse(await readFile(new URL("package.json", process.env.MYSQL2_MODULE_URL)));
  const pin = JSON.parse(await readFile(new URL("../../upstream-source.json", import.meta.url)));
  assert.equal(pin.commit, "38f43e390920faa400d51ff0bd18570a424d05ce");
  assert.equal(pin.version, "1.7.18");
  assert.equal(JSON.parse(await readFile(new URL("../../reference-server/node_modules/better-auth/package.json", import.meta.url))).version, "1.7.18");
  for (const name of ["core", "passkey", "kysely-adapter"]) {
    assert.equal(JSON.parse(await readFile(new URL(`../../reference-server/node_modules/@better-auth/${name}/package.json`, import.meta.url))).version, "1.7.18");
  }
  const database = `alibi_oracle_${randomBytes(8).toString("hex")}`;
  const config = { socketPath: process.env.BETTER_AUTH_TEST_MYSQL_SOCKET, user: "root", charset: "utf8mb4", timezone: "Z", connectionLimit };
  const admin = mysql.createPool(config).promise();
  const [version] = await admin.query("SELECT VERSION() AS version");
  await admin.query(`CREATE DATABASE ${database} CHARACTER SET utf8mb4`);
  const pool = mysql.createPool({ ...config, database });
  const db = new Kysely({ dialect: new MysqlDialect({ pool }) });
  return {
    db, pool, mysqlVersion: version[0].version, mysql2Version: driver.version,
    async close() {
      await db.destroy();
      await admin.query(`DROP DATABASE ${database}`);
      await admin.end();
    },
  };
}
