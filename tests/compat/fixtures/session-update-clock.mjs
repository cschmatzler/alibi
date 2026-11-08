import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { readFile, writeFile } from "node:fs/promises";
import pg from "../reference-server/node_modules/pg/lib/index.js";
import { Kysely, PostgresDialect, SqliteDialect } from "../reference-server/node_modules/kysely/dist/index.js";
import { betterAuth } from "../reference-server/node_modules/better-auth/dist/index.mjs";
import { getMigrations } from "../reference-server/node_modules/better-auth/dist/db/get-migration.mjs";
import { createMysqlDatabase } from "./support/mysql-database.mjs";

const pin = JSON.parse(await readFile(new URL("../upstream-source.json", import.meta.url)));
assert.equal(pin.commit, "38f43e390920faa400d51ff0bd18570a424d05ce");
assert.equal(pin.version, "1.7.18");
for (const name of ["better-auth", "@better-auth/core", "@better-auth/kysely-adapter"]) {
  assert.equal(JSON.parse(await readFile(new URL(`../reference-server/node_modules/${name}/package.json`, import.meta.url))).version, "1.7.18");
}
assert.ok(process.env.BETTER_AUTH_TEST_POSTGRES_URL, "requires a disposable PostgreSQL database URL");
const mysql = await createMysqlDatabase();
const sqlite = new DatabaseSync(":memory:");
const sqliteDb = new Kysely({ dialect: new SqliteDialect({ database: {
  close() { sqlite.close(); },
  prepare(sql) {
    const statement = sqlite.prepare(sql);
    return { reader: statement.columns().length > 0, all(parameters) { return statement.all({}, ...parameters); }, run(parameters) { return statement.run({}, ...parameters); } };
  },
} }) });
const schema = `session_update_clock_${randomBytes(8).toString("hex")}`;
const admin = new pg.Client({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL });
await admin.connect();
await admin.query(`CREATE SCHEMA ${schema}`);
const pool = new pg.Pool({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL, options: `-csearch_path=${schema}`, max: 1 });
const postgresDb = new Kysely({ dialect: new PostgresDialect({ pool }) });
const profiles = [];
try {
  for (const [backend, db] of [["sqlite", sqliteDb], ["postgres", postgresDb], ["mysql", mysql.db]]) {
    const options = { baseURL: "http://localhost", secret: "session-update-clock-source-secret-at-least-32", database: { type: backend, db } };
    await (await getMigrations(options)).runMigrations();
    const { internalAdapter } = await betterAuth(options).$context;
    const user = await internalAdapter.createUser({ name: "Clock", email: "session-update-clock@example.com", emailVerified: false });
    const cases = [];
    for (const action of ["expiry", "fields"]) {
      const expiresAt = new Date("2031-01-01T00:00:00.123Z");
      const renewedExpiry = new Date("2032-01-01T00:00:00.123Z");
      const created = await internalAdapter.createSession(user.id, false, { token: `session-clock-${action}`, expiresAt }, true);
      const updated = await internalAdapter.updateSession(created.token, action === "expiry" ? { expiresAt: renewedExpiry } : {});
      const readback = await internalAdapter.findSession(created.token);
      assert.equal(updated.id, created.id);
      assert.equal(readback.session.id, created.id);
      assert.equal(readback.user.id, user.id);
      const clock = {
        created_at_preserved: created.createdAt.getTime() === updated.createdAt.getTime(),
        updated_at_millisecond_aligned: /\.\d{3}Z$/.test(updated.updatedAt.toISOString()),
        expires_at_preserved: updated.expiresAt.getTime() === (action === "expiry" ? renewedExpiry : expiresAt).getTime(),
        readback_matches: updated.createdAt.getTime() === readback.session.createdAt.getTime() && updated.updatedAt.getTime() === readback.session.updatedAt.getTime() && updated.expiresAt.getTime() === readback.session.expiresAt.getTime(),
      };
      assert.deepEqual(clock, { created_at_preserved: true, updated_at_millisecond_aligned: true, expires_at_preserved: true, readback_matches: true });
      cases.push({ action, clock });
    }
    profiles.push({ backend, cases });
  }
  for (const profile of profiles) assert.deepEqual(profile.cases, profiles[0].cases);
  await writeFile(new URL("../../fixtures/session-update-clock.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", backends: profiles.map(profile => profile.backend), cases: profiles[0].cases }) + "\n");
  console.log("Six actual SQLite/PostgreSQL/MySQL session update/readback clock cases");
} finally {
  await sqliteDb.destroy();
  await postgresDb.destroy();
  await admin.query(`DROP SCHEMA ${schema} CASCADE`);
  await admin.end();
  await mysql.close();
}
