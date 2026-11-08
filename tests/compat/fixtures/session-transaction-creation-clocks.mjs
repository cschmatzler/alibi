import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { readFile, writeFile } from "node:fs/promises";
import pg from "../reference-server/node_modules/pg/lib/index.js";
import { Kysely, PostgresDialect, SqliteDialect } from "../reference-server/node_modules/kysely/dist/index.js";
import { betterAuth } from "../reference-server/node_modules/better-auth/dist/index.mjs";
import { getMigrations } from "../reference-server/node_modules/better-auth/dist/db/get-migration.mjs";
import { getCurrentAdapter, runWithTransaction } from "../reference-server/node_modules/@better-auth/core/dist/context/transaction.mjs";

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
const schema = `session_transaction_clocks_${randomBytes(8).toString("hex")}`;
const admin = new pg.Client({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL });
await admin.connect();
await admin.query(`CREATE SCHEMA ${schema}`);
const pool = new pg.Pool({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL, options: `-csearch_path=${schema}`, max: 1 });
const postgresDb = new Kysely({ dialect: new PostgresDialect({ pool }) });
const profiles = [];
const defaultCreatedAt = "2030-01-01T00:00:00.123Z";
const hookClocks = { createdAt: "2031-01-01T00:00:00.456Z", updatedAt: "2032-01-01T00:00:00.789Z" };
try {
  for (const [backend, db] of [["sqlite", sqliteDb], ["postgres", postgresDb]]) {
    let events = [];
    const cache = new Map();
    const fields = Object.fromEntries(Object.keys(hookClocks).map(name => [name, {
      type: "date", required: true,
      ...(name === "createdAt" ? { defaultValue: new Date(defaultCreatedAt) } : {}),
      transform: { input(value) {
        assert.ok(value instanceof Date);
        events.push({ phase: "input", field: name, value });
        return new Date(value.getTime() + 1000);
      } },
    }]));
    const options = {
      baseURL: "http://localhost", secret: "session-transaction-clocks-secret-at-least-32", database: { type: backend, db, transaction: true },
      secondaryStorage: { async get(key) { return cache.get(key) ?? null; }, async set(key, value) { cache.set(key, value); }, async delete(key) { cache.delete(key); } },
      session: { storeSessionInDatabase: true, additionalFields: fields },
      databaseHooks: { session: { create: {
        before(data) {
          assert.equal(data.createdAt.toISOString(), defaultCreatedAt);
          assert.ok(data.updatedAt instanceof Date);
          events.push({ phase: "create.before", createdAt: data.createdAt, updatedAt: "$clock" });
          return { data: { ...data, createdAt: new Date(hookClocks.createdAt), updatedAt: new Date(hookClocks.updatedAt) } };
        },
        after(data) { events.push({ phase: "create.after", createdAt: data.createdAt, updatedAt: data.updatedAt }); },
      } } },
    };
    await (await getMigrations(options)).runMigrations();
    const { internalAdapter, adapter } = await betterAuth(options).$context;
    const user = await internalAdapter.createUser({ name: "Transaction Clocks", email: "transaction-clocks@example.com", emailVerified: false });
    function cachedClocks(token) {
      if (!cache.has(token)) return null;
      const session = JSON.parse(cache.get(token)).session;
      assert.equal(session.createdAt, defaultCreatedAt);
      assert.equal(session.updatedAt, "2032-01-01T00:00:01.789Z");
      return { createdAt: session.createdAt, updatedAt: session.updatedAt };
    }
    function storedClocks(session) {
      return session ? { createdAt: session.createdAt, updatedAt: session.updatedAt } : null;
    }
    const cases = [];
    for (const deferred of [false, true]) for (const action of ["commit", "rollback"]) {
      const token = `transaction-clocks-${deferred}-${action}`;
      events = [];
      let inside;
      let outcome;
      try {
        outcome = await runWithTransaction(adapter, async () => {
          const session = await internalAdapter.createSession(user.id, false, { token, expiresAt: new Date("2039-01-01T00:00:00.123Z") }, true, { deferSecondaryStorageWrites: deferred });
          events.push({ phase: "inside" });
          const stored = await (await getCurrentAdapter(adapter)).findOne({ model: "session", where: [{ field: "token", value: token }] });
          assert.equal(stored.id, session.id);
          inside = { cached: cachedClocks(token), stored: storedClocks(stored) };
          if (action === "rollback") throw new Error("transaction clocks rollback");
          return { output: storedClocks(session) };
        });
      } catch (error) {
        if (action !== "rollback") throw error;
        assert.equal(error.message, "transaction clocks rollback");
        outcome = { error: { message: error.message } };
      }
      const stored = await adapter.findOne({ model: "session", where: [{ field: "token", value: token }] });
      assert.equal(stored !== null, action === "commit");
      assert.equal(cache.has(token), action === "commit" || !deferred);
      const references = JSON.parse(cache.get(`active-sessions-${user.id}`) ?? "[]");
      assert.equal(references.some(reference => reference.token === token), action === "commit" || !deferred);
      cases.push({ deferred, action, default_created_at: defaultCreatedAt, hook_clocks: hookClocks, events: [...events], inside, outcome, cached: cachedClocks(token), stored: storedClocks(stored), referenced: references.some(reference => reference.token === token) });
    }
    profiles.push({ backend, cases });
  }
  assert.deepEqual(profiles[0].cases, profiles[1].cases);
  await writeFile(new URL("../../fixtures/session-transaction-creation-clocks.json", import.meta.url), JSON.stringify({ better_auth: pin.version, profiles }) + "\n");
  console.log("Eight actual transaction creation-clock publication cases");
} finally {
  await sqliteDb.destroy();
  await postgresDb.destroy();
  await admin.query(`DROP SCHEMA ${schema} CASCADE`);
  await admin.end();
}
