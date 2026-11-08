import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { readFile, writeFile } from "node:fs/promises";
import pg from "../reference-server/node_modules/pg/lib/index.js";
import { Kysely, PostgresDialect, SqliteDialect } from "../reference-server/node_modules/kysely/dist/index.js";
import { betterAuth } from "../reference-server/node_modules/better-auth/dist/index.mjs";
import { getMigrations } from "../reference-server/node_modules/better-auth/dist/db/get-migration.mjs";
import { admin as adminPlugin } from "../reference-server/node_modules/better-auth/dist/plugins/index.mjs";

const hooks = process.argv[2] === "--hooks";
assert.ok(process.argv[2] === undefined || hooks, "unknown fixture output mode");
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
const schema = `user_timestamp_parameters_${randomBytes(8).toString("hex")}`;
const admin = new pg.Client({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL });
await admin.connect();
await admin.query(`CREATE SCHEMA ${schema}`);
const pool = new pg.Pool({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL, options: `-csearch_path=${schema}`, max: 1 });
const postgresDb = new Kysely({ dialect: new PostgresDialect({ pool }) });
const profiles = [];
try {
  for (const [backend, db] of [["sqlite", sqliteDb], ["postgres", postgresDb]]) {
    let events = [];
    function event(phase, value) {
      events.push({ phase, kind: value instanceof Date ? "date" : value === null ? "null" : typeof value, value: value === undefined ? null : value });
    }
    const options = { baseURL: "http://localhost", secret: "user-timestamp-parameters-secret-at-least-32", database: { type: backend, db }, plugins: [adminPlugin()] };
    if (hooks) {
      options.user = { additionalFields: { banExpires: { type: "date", required: false, onUpdate: () => "2031-02-03T04:05:06.123987Z", transform: { input: async value => {
        event("input", value);
        if (value == null) return value;
        return new Date(new Date(value).getTime() + 1000);
      } } } } };
      options.databaseHooks = { user: { update: {
        before: async data => { event("before", data.banExpires); },
        after: async data => { event("after", data.banExpires); },
      } } };
    }
    const migrations = await getMigrations(options);
    const schemaSql = await migrations.compileMigrations();
    await migrations.runMigrations();
    const { internalAdapter } = await betterAuth(options).$context;
    const user = await internalAdapter.createUser({ name: "Timestamp", email: "timestamp@example.com", emailVerified: false });
    const cases = [];
    for (const [action, input] of [
      ["date", new Date("2031-02-03T04:05:06.123987Z")],
      ["string", "2031-02-03T04:05:06.123987Z"],
      ["unban", undefined], ["clear", null],
    ]) {
      events = [];
      const updated = await internalAdapter.updateUser(user.id, action === "unban" ? { banned: false } : { banExpires: input, banned: true });
      const readback = await internalAdapter.findUserById(user.id);
      const raw = backend === "postgres"
        ? (await pool.query('SELECT "banExpires"::text AS value FROM "user" WHERE id = $1', [user.id])).rows[0].value
        : (await db.selectFrom("user").select("banExpires").where("id", "=", user.id).executeTakeFirstOrThrow()).banExpires;
      assert.equal(updated.id, user.id);
      assert.deepEqual(readback.banExpires, updated.banExpires);
      cases.push({ action, ...(input === undefined ? {} : { input }), banned: updated.banned, output: updated.banExpires, stored: raw, ...(hooks ? { events } : {}) });
    }
    profiles.push({ backend, schema_sql: schemaSql, cases });
  }
  const filename = hooks ? "user-timestamp-hooks" : "user-timestamp-parameters";
  await writeFile(new URL(`../../fixtures/${filename}.json`, import.meta.url), JSON.stringify({ better_auth: "1.7.18", profiles }) + "\n");
  console.log("Eight actual SQLite/PostgreSQL user timestamp parameter and direct unban cases");
} finally {
  await sqliteDb.destroy();
  await postgresDb.destroy();
  await admin.query(`DROP SCHEMA ${schema} CASCADE`);
  await admin.end();
}
