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
const cases = [];
const explicit = process.argv[2] === "--explicit-clock";
const postgres = process.argv[2] === "--postgres-clock";
assert.ok(process.argv[2] === undefined || explicit || postgres, "unknown fixture output mode");
async function database() {
  if (postgres) {
    assert.ok(process.env.BETTER_AUTH_TEST_POSTGRES_URL, "requires a disposable PostgreSQL database URL");
    const schema = `secondary_clock_${randomBytes(8).toString("hex")}`;
    const admin = new pg.Client({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL });
    await admin.connect();
    await admin.query(`CREATE SCHEMA ${schema}`);
    const pool = new pg.Pool({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL, options: `-csearch_path=${schema}`, max: 1 });
    const db = new Kysely({ dialect: new PostgresDialect({ pool }) });
    return { db, async close() { await db.destroy(); await admin.query(`DROP SCHEMA ${schema} CASCADE`); await admin.end(); } };
  }
  const sqlite = new DatabaseSync(":memory:");
  const db = new Kysely({ dialect: new SqliteDialect({ database: {
    close() { sqlite.close(); },
    prepare(sql) {
      const statement = sqlite.prepare(sql);
      return { reader: statement.columns().length > 0, all(parameters) { return statement.all({}, ...parameters); }, run(parameters) { return statement.run({}, ...parameters); } };
    },
  } }) });
  return { db, close: () => db.destroy() };
}
for (const persist of [false, true]) {
  const connection = await database();
  const { db } = connection;
  const cache = new Map();
  const secondaryStorage = {
    async get(key) { return cache.get(key) ?? null; },
    async set(key, value) { cache.set(key, value); },
    async delete(key) { cache.delete(key); },
  };
  try {
    const options = { baseURL: "http://localhost", secret: "session-secondary-clock-source-secret-at-least-32", database: { type: postgres ? "postgres" : "sqlite", db }, secondaryStorage, session: { storeSessionInDatabase: persist } };
    await (await getMigrations(options)).runMigrations();
    const { internalAdapter } = await betterAuth(options).$context;
    const user = await internalAdapter.createUser({ name: "Clock", email: "secondary-clock@example.com", emailVerified: false });
    for (const action of postgres ? ["expiry", "fields", "explicit"] : explicit ? ["explicit"] : ["expiry", "fields"]) {
      const token = `secondary-clock-${action}`;
      const createdAt = new Date("2020-01-01T00:00:00.123Z");
      const updatedAt = new Date("2020-02-01T00:00:00.123Z");
      const expiresAt = new Date("2031-01-01T00:00:00.123Z");
      const renewedExpiry = new Date("2032-01-01T00:00:00.123Z");
      const created = await internalAdapter.createSession(user.id, false, { token, createdAt, updatedAt, expiresAt }, true);
      assert.equal(created.updatedAt.getTime(), updatedAt.getTime());
      const suppliedClock = new Date("2030-01-01T00:00:00.123Z");
      const updated = await internalAdapter.updateSession(token, action === "expiry" ? { expiresAt: renewedExpiry } : action === "explicit" ? { updatedAt: suppliedClock } : {});
      if (action === "explicit") assert.equal(updated.updatedAt.getTime(), suppliedClock.getTime());
      const readback = await internalAdapter.findSession(token);
      const cached = JSON.parse(cache.get(token)).session;
      const stored = persist ? await db.selectFrom("session").select(["createdAt", "updatedAt", "expiresAt"]).where("token", "=", token).executeTakeFirstOrThrow() : null;
      assert.equal(updated.id, created.id);
      assert.equal(readback.session.id, created.id);
      const clock = {
        created_at_preserved: updated.createdAt.getTime() === createdAt.getTime(),
        updated_at_preserved: updated.updatedAt.getTime() === updatedAt.getTime(),
        updated_at_millisecond_aligned: /\.\d{3}Z$/.test(updated.updatedAt.toISOString()),
        expires_at_preserved: updated.expiresAt.getTime() === (action === "expiry" ? renewedExpiry : expiresAt).getTime(),
        readback_matches: readback.session.updatedAt.getTime() === updated.updatedAt.getTime() && readback.session.expiresAt.getTime() === updated.expiresAt.getTime(),
        cache_matches: cached.updatedAt === updated.updatedAt.toISOString() && cached.expiresAt === updated.expiresAt.toISOString(),
        database_clock_preserved: stored === null ? null : new Date(stored.updatedAt).getTime() === updatedAt.getTime(),
      };
      cases.push({ persist, action, clock });
    }
  } finally {
    await connection.close();
  }
}
const filename = postgres ? "session-secondary-postgres-clock" : explicit ? "session-secondary-explicit-clock" : "session-secondary-clock";
await writeFile(new URL(`../../fixtures/${filename}.json`, import.meta.url), JSON.stringify({ better_auth: "1.7.18", backend: postgres ? "postgres" : "sqlite", cases }) + "\n");
console.log(`${cases.length} actual ${postgres ? "PostgreSQL" : "SQLite"} secondary-storage session update clock cases`);
