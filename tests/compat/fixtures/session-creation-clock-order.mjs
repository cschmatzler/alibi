import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { readFile, writeFile } from "node:fs/promises";
import { setTimeout } from "node:timers/promises";
import pg from "../reference-server/node_modules/pg/lib/index.js";
import { Kysely, PostgresDialect, SqliteDialect } from "../reference-server/node_modules/kysely/dist/index.js";
import { betterAuth } from "../reference-server/node_modules/better-auth/dist/index.mjs";
import { getMigrations } from "../reference-server/node_modules/better-auth/dist/db/get-migration.mjs";

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
const schema = `session_creation_clock_order_${randomBytes(8).toString("hex")}`;
const admin = new pg.Client({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL });
await admin.connect();
await admin.query(`CREATE SCHEMA ${schema}`);
const pool = new pg.Pool({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL, options: `-csearch_path=${schema}`, max: 1 });
const postgresDb = new Kysely({ dialect: new PostgresDialect({ pool }) });
const profiles = [];
try {
  for (const [backend, db] of [["sqlite", sqliteDb], ["postgres", postgresDb]]) {
    const events = [];
    let hookEnd;
    let expiryEnd;
    let updatedStart;
    const options = {
      baseURL: "http://localhost", secret: "session-creation-clock-order-secret-at-least-32", database: { type: backend, db },
      session: { additionalFields: {
        updatedAt: { type: "date", required: true, transform: { async input(value) {
          assert.ok(value instanceof Date);
          updatedStart = Date.now();
          events.push({ phase: "input", field: "updatedAt", kind: "date", value: "$clock" });
          await setTimeout(20);
          return value;
        } } },
        expiresAt: { type: "date", required: true, transform: { async input(value) {
          assert.ok(value instanceof Date);
          events.push({ phase: "input", field: "expiresAt", kind: "date", value });
          await setTimeout(20);
          expiryEnd = Date.now();
          return value;
        } } },
      } },
      databaseHooks: { session: { create: {
        async before(data) {
          assert.equal(data.createdAt, undefined);
          assert.ok(data.updatedAt instanceof Date);
          events.push({ phase: "create.before", createdAt: { kind: "undefined", value: null }, updatedAt: { kind: "date", value: "$clock" } });
          await setTimeout(20);
          hookEnd = Date.now();
        },
        after(data) {
          assert.ok(data.createdAt instanceof Date);
          assert.ok(data.updatedAt instanceof Date);
          events.push({ phase: "create.after", createdAt: "$clock", updatedAt: "$clock", expiresAt: data.expiresAt });
        },
      } } },
    };
    const migrations = await getMigrations(options);
    const schemaSql = await migrations.compileMigrations();
    await migrations.runMigrations();
    const { internalAdapter } = await betterAuth(options).$context;
    const user = await internalAdapter.createUser({ name: "Clock Order", email: "clock-order@example.com", emailVerified: false });
    const expiresAt = new Date("2039-01-01T00:00:00.123Z");
    const session = await internalAdapter.createSession(user.id, false, { token: "creation-clock-order", expiresAt, createdAt: undefined }, true);
    assert.ok(expiryEnd >= hookEnd);
    assert.ok(updatedStart >= expiryEnd);
    assert.ok(session.createdAt.getTime() >= expiryEnd);
    assert.ok(session.createdAt.getTime() <= updatedStart);
    assert.ok(session.updatedAt.getTime() < hookEnd);
    const readback = await internalAdapter.findSession("creation-clock-order");
    assert.equal(readback.session.id, session.id);
    for (const name of ["createdAt", "updatedAt", "expiresAt"]) assert.equal(readback.session[name].getTime(), session[name].getTime());
    profiles.push({ backend, schema_sql: schemaSql, input: { expiresAt }, events, created_after_expiry: true, created_before_updated_callback: true, updated_before_hook: true, output: { createdAt: "$clock", updatedAt: "$clock", expiresAt: session.expiresAt } });
  }
  await writeFile(new URL("../../fixtures/session-creation-clock-order.json", import.meta.url), JSON.stringify({ better_auth: pin.version, profiles }) + "\n");
  console.log("Two actual creation-default ordering cases with reversed option insertion order");
} finally {
  await sqliteDb.destroy();
  await postgresDb.destroy();
  await admin.query(`DROP SCHEMA ${schema} CASCADE`);
  await admin.end();
}
