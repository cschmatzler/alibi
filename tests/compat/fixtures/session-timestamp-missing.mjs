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
  assert.equal(JSON.parse(await readFile(new URL(`../reference-server/node_modules/${name}/package.json`, import.meta.url))).version, pin.version);
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
const schema = `session_timestamp_missing_${randomBytes(8).toString("hex")}`;
const admin = new pg.Client({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL });
await admin.connect();
await admin.query(`CREATE SCHEMA ${schema}`);
const pool = new pg.Pool({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL, options: `-csearch_path=${schema}`, max: 1 });
const postgresDb = new Kysely({ dialect: new PostgresDialect({ pool }) });
const profiles = [];
try {
  for (const [backend, db] of [["sqlite", sqliteDb], ["postgres", postgresDb]]) {
    let events = [];
    let callbackResult;
    function event(phase, value) {
      events.push({ phase, kind: value instanceof Date ? "date" : value === null ? "null" : typeof value, value: value === undefined ? null : value });
    }
    const options = {
      baseURL: "http://localhost", secret: "session-timestamp-missing-secret-at-least-32", database: { type: backend, db },
      session: { additionalFields: { expiresAt: { type: "date", required: true, transform: { input(value) {
        event("input", value);
        return callbackResult;
      } } } } },
      databaseHooks: { session: { update: {
        before(data) { event("update.before", data.expiresAt); },
        after(data) { event("update.after", data); },
      } } },
    };
    const migrations = await getMigrations(options);
    const schemaSql = await migrations.compileMigrations();
    await migrations.runMigrations();
    const { internalAdapter } = await betterAuth(options).$context;
    const cases = [];
    for (const [inputKind, input] of [["date", new Date("2031-02-03T04:05:06.123987Z")], ["string", "2031-02-03T04:05:06.123987Z"]]) {
      for (const [resultKind, value] of [["date", new Date("2035-02-03T04:05:06.123Z")], ["string", "2035-02-03T04:05:06.123987Z"], ["invalid-string", "not-a-date"], ["null", null], ["undefined", undefined]]) {
        callbackResult = value;
        events = [];
        let outcome;
        try {
          const session = await internalAdapter.updateSession("missing-token", { expiresAt: input });
          assert.equal(session, null);
          outcome = { output: session };
        } catch (error) {
          assert.equal(backend, "postgres");
          assert.equal(resultKind, "invalid-string");
          assert.equal(error.code, "22007");
          outcome = { error: { code: error.code, message: error.message } };
        }
        const rows = await db.selectFrom("session").selectAll().execute();
        assert.equal(rows.length, 0);
        cases.push({ input_kind: inputKind, input, result_kind: resultKind, callback_result: value, events: [...events], outcome, rows: rows.length });
      }
    }
    profiles.push({ backend, schema_sql: schemaSql, cases });
  }
  await writeFile(new URL("../../fixtures/session-timestamp-missing.json", import.meta.url), JSON.stringify({ better_auth: pin.version, profiles }) + "\n");
  console.log("Twenty actual missing-session timestamp policy cases");
} finally {
  await sqliteDb.destroy();
  await postgresDb.destroy();
  await admin.query(`DROP SCHEMA ${schema} CASCADE`);
  await admin.end();
}
