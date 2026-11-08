import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { readFile, writeFile } from "node:fs/promises";
import pg from "../reference-server/node_modules/pg/lib/index.js";
import { Kysely, PostgresDialect, SqliteDialect } from "../reference-server/node_modules/kysely/dist/index.js";
import { betterAuth } from "../reference-server/node_modules/better-auth/dist/index.mjs";
import { getMigrations } from "../reference-server/node_modules/better-auth/dist/db/get-migration.mjs";

const pin = JSON.parse(await readFile(new URL("../upstream-source.json", import.meta.url)));
assert.equal(pin.commit, "38f43e390920faa400d51ff0bd18570a424d05ce");
assert.equal(pin.version, "1.7.18");
for (const name of ["better-auth", "@better-auth/core", "@better-auth/kysely-adapter"]) {
  assert.equal(JSON.parse(await readFile(new URL(`../reference-server/node_modules/${name}/package.json`, import.meta.url))).version, "1.7.18");
}
assert.ok(process.env.BETTER_AUTH_TEST_POSTGRES_URL, "requires a disposable PostgreSQL database URL");
const sqlite = new DatabaseSync(":memory:");
const sqliteDb = new Kysely({ dialect: new SqliteDialect({ database: {
  close() { sqlite.close(); },
  prepare(sql) {
    const statement = sqlite.prepare(sql);
    return { reader: statement.columns().length > 0, all(parameters) { return statement.all({}, ...parameters); }, run(parameters) { return statement.run({}, ...parameters); } };
  },
} }) });
const schema = `account_timestamp_parameters_${randomBytes(8).toString("hex")}`;
const admin = new pg.Client({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL });
await admin.connect();
await admin.query(`CREATE SCHEMA ${schema}`);
const pool = new pg.Pool({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL, options: `-csearch_path=${schema}`, max: 1 });
const postgresDb = new Kysely({ dialect: new PostgresDialect({ pool }) });
const profiles = [];
try {
  for (const [backend, db] of [["sqlite", sqliteDb], ["postgres", postgresDb]]) {
    const options = { baseURL: "http://localhost", secret: "account-timestamp-parameters-secret-at-least-32", database: { type: backend, db } };
    await (await getMigrations(options)).runMigrations();
    const { internalAdapter } = await betterAuth(options).$context;
    const user = await internalAdapter.createUser({ name: "Timestamp", email: "account-timestamp@example.com", emailVerified: false });
    const cases = [];
    for (const operation of ["create", "update"]) {
      for (const [kind, input] of [["date", new Date("2031-02-03T04:05:06.123987Z")], ["string", "2031-02-03T04:05:06.123987Z"], ["null", null]]) {
        const accountId = `${operation}-${kind}`;
        const original = operation === "update" ? await internalAdapter.createAccount({ userId: user.id, providerId: "timestamp-provider", accountId, accessTokenExpiresAt: new Date("2030-01-01T00:00:00.123Z") }) : null;
        const account = operation === "create"
          ? await internalAdapter.createAccount({ userId: user.id, providerId: "timestamp-provider", accountId, accessTokenExpiresAt: input })
          : await internalAdapter.updateAccount(original.id, { accessTokenExpiresAt: input });
        const readback = await internalAdapter.findAccountByKey({ providerId: "timestamp-provider", accountId });
        assert.equal(readback.id, account.id);
        if (original) assert.equal(account.id, original.id);
        assert.deepEqual(readback.accessTokenExpiresAt, account.accessTokenExpiresAt);
        const stored = backend === "postgres"
          ? (await pool.query('SELECT "accessTokenExpiresAt"::text AS value FROM account WHERE id = $1', [account.id])).rows[0].value
          : (await db.selectFrom("account").select("accessTokenExpiresAt").where("id", "=", account.id).executeTakeFirstOrThrow()).accessTokenExpiresAt;
        if (input === null) assert.equal(stored, null);
        else assert.equal(account.accessTokenExpiresAt.toISOString(), "2031-02-03T04:05:06.123Z");
        cases.push({ operation, kind, input, output: account.accessTokenExpiresAt, stored });
      }
    }
    assert.equal(cases.length, 6);
    profiles.push({ backend, cases });
  }
  await writeFile(new URL("../../fixtures/account-timestamp-parameters.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", profiles }) + "\n");
  console.log("Twelve actual SQLite/PostgreSQL account timestamp parameter and nullable expiry cases");
} finally {
  await sqliteDb.destroy();
  await postgresDb.destroy();
  await admin.query(`DROP SCHEMA ${schema} CASCADE`);
  await admin.end();
}
