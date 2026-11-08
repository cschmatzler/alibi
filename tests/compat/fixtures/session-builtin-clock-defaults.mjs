import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { readFile, writeFile } from "node:fs/promises";
import { setTimeout } from "node:timers/promises";
import pg from "../reference-server/node_modules/pg/lib/index.js";
import { Kysely, PostgresDialect, SqliteDialect } from "../reference-server/node_modules/kysely/dist/index.js";
import { betterAuth } from "../reference-server/node_modules/better-auth/dist/index.mjs";
import { getMigrations } from "../reference-server/node_modules/better-auth/dist/db/get-migration.mjs";

const nullInput = process.argv[2] === "--null";
assert.ok(process.argv[2] === undefined || nullInput, "unknown builtin clock mode");

const pin = JSON.parse(await readFile(new URL("../upstream-source.json", import.meta.url)));
assert.equal(pin.version, "1.7.18");
assert.equal(pin.commit, "38f43e390920faa400d51ff0bd18570a424d05ce");
for (const name of ["better-auth", "@better-auth/core", "@better-auth/kysely-adapter"]) {
  assert.equal(JSON.parse(await readFile(new URL(`../reference-server/node_modules/${name}/package.json`, import.meta.url))).version, pin.version);
}
assert.ok(process.env.BETTER_AUTH_TEST_POSTGRES_URL, "requires a disposable PostgreSQL database URL");
const sqlite = new DatabaseSync(":memory:");
const sqliteDb = new Kysely({ dialect: new SqliteDialect({ database: {
  close() { sqlite.close(); },
  prepare(sql) { const statement = sqlite.prepare(sql); return { reader: statement.columns().length > 0, all(parameters) { return statement.all({}, ...parameters); }, run(parameters) { return statement.run({}, ...parameters); } }; },
} }) });
const schema = `session_builtin_undefined_${randomBytes(8).toString("hex")}`;
const admin = new pg.Client({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL });
await admin.connect();
await admin.query(`CREATE SCHEMA ${schema}`);
const pool = new pg.Pool({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL, options: `-csearch_path=${schema}`, max: 1 });
const postgresDb = new Kysely({ dialect: new PostgresDialect({ pool }) });
const profiles = [];
function clock(value) {
  if (value === null) return { kind: "null", value: null };
  if (value === undefined) return { kind: "undefined", value: null };
  assert.ok(value instanceof Date);
  return { kind: "date", value: "$clock" };
}
try {
  for (const [backend, db] of [["sqlite", sqliteDb], ["postgres", postgresDb]]) {
    let events = [];
    let hookEnd;
    const options = {
      baseURL: "http://localhost", secret: "session-builtin-undefined-secret-at-least-32", database: { type: backend, db },
      databaseHooks: { session: { create: {
        async before(data) {
          events.push({ phase: "create.before", createdAt: clock(data.createdAt), updatedAt: clock(data.updatedAt) });
          // Separate data construction from adapter defaults without replacing the clock.
          await setTimeout(20);
          hookEnd = Date.now();
        },
        after(data) {
          assert.ok(data.createdAt instanceof Date);
          assert.ok(data.updatedAt instanceof Date);
          events.push({ phase: "create.after", createdAt: "$clock", updatedAt: "$clock" });
        },
      } } },
    };
    const migrations = await getMigrations(options);
    const schemaSql = await migrations.compileMigrations();
    await migrations.runMigrations();
    const { internalAdapter } = await betterAuth(options).$context;
    const user = await internalAdapter.createUser({ name: "Builtin Undefined", email: "builtin-undefined@example.com", emailVerified: false });
    const cases = [];
    for (const field of ["createdAt", "updatedAt"]) {
      const token = `builtin-${field}-${nullInput ? "null" : "undefined"}`;
      events = [];
      let outcome;
      try {
        const session = await internalAdapter.createSession(user.id, false, { token, expiresAt: new Date("2039-01-01T00:00:00.123Z"), [field]: nullInput ? null : undefined }, true);
        const returnedAt = Date.now();
        assert.equal(field, "createdAt");
        assert.ok(session.createdAt.getTime() >= hookEnd);
        assert.ok(session.createdAt.getTime() <= returnedAt);
        assert.ok(session.updatedAt.getTime() < hookEnd);
        const readback = await internalAdapter.findSession(token);
        assert.equal(readback.session.id, session.id);
        assert.equal(readback.session.createdAt.getTime(), session.createdAt.getTime());
        assert.equal(readback.session.updatedAt.getTime(), session.updatedAt.getTime());
        outcome = { output: { createdAt: "$clock", updatedAt: "$clock" }, created_after_hook: true, created_before_return: true, updated_before_hook: true };
      } catch (error) {
        assert.equal(field, "updatedAt");
        assert.equal(error.code, backend === "postgres" ? "23502" : "ERR_SQLITE_ERROR");
        outcome = { error: { code: error.code, message: error.message } };
      }
      const rows = await db.selectFrom("session").selectAll().where("token", "=", token).execute();
      assert.equal(rows.length, field === "createdAt" ? 1 : 0);
      cases.push({ field, events: [...events], outcome, rows: rows.length });
    }
    profiles.push({ backend, schema_sql: schemaSql, cases });
  }
  const filename = nullInput ? "session-builtin-null-clocks" : "session-builtin-undefined-clocks";
  await writeFile(new URL(`../../fixtures/${filename}.json`, import.meta.url), JSON.stringify({ better_auth: pin.version, profiles }) + "\n");
  console.log(`Four actual builtin ${nullInput ? "null" : "undefined"}-clock cases with real delayed before-hooks`);
} finally {
  await sqliteDb.destroy();
  await postgresDb.destroy();
  await admin.query(`DROP SCHEMA ${schema} CASCADE`);
  await admin.end();
}
