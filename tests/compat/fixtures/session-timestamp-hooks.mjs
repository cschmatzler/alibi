import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { readFile, writeFile } from "node:fs/promises";
import pg from "../reference-server/node_modules/pg/lib/index.js";
import { Kysely, PostgresDialect, SqliteDialect } from "../reference-server/node_modules/kysely/dist/index.js";
import { betterAuth } from "../reference-server/node_modules/better-auth/dist/index.mjs";
import { getMigrations } from "../reference-server/node_modules/better-auth/dist/db/get-migration.mjs";
import { getCurrentAdapter, runWithTransaction } from "../reference-server/node_modules/@better-auth/core/dist/context/transaction.mjs";

const requiredExpiry = process.argv[2] === "--omit-required";
const omitResult = process.argv[2] === "--omit" || requiredExpiry;
const secondaryString = process.argv[2] === "--secondary-string";
const deferred = process.argv[2] === "--secondary-deferred";
const transactions = process.argv[2] === "--secondary-transactions" || deferred;
const wire = process.argv[2] === "--secondary-wire";
const secondary = process.argv[2] === "--secondary" || secondaryString || transactions || wire;
assert.ok(process.argv[2] === undefined || omitResult || secondary, "unknown fixture output mode");
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
const schema = `session_timestamp_hooks_${randomBytes(8).toString("hex")}`;
const admin = new pg.Client({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL });
await admin.connect();
await admin.query(`CREATE SCHEMA ${schema}`);
const pool = new pg.Pool({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL, options: `-csearch_path=${schema}`, max: 1 });
const postgresDb = new Kysely({ dialect: new PostgresDialect({ pool }) });
const profiles = [];
try {
  for (const [backend, db] of [["sqlite", sqliteDb], ["postgres", postgresDb]]) {
    let events = [];
    let applyingInput = false;
    const cache = new Map();
    function event(phase, value) {
      events.push({ phase, kind: value instanceof Date ? "date" : value === null ? "null" : typeof value, value: value === undefined ? null : value });
    }
    const options = {
      baseURL: "http://localhost", secret: "session-timestamp-hooks-secret-at-least-32", database: { type: backend, db, transaction: transactions },
      ...(secondary ? { secondaryStorage: {
        async get(key) { return cache.get(key) ?? null; },
        async set(key, value) { cache.set(key, value); },
        async delete(key) { cache.delete(key); },
      } } : {}),
      session: { storeSessionInDatabase: secondary, additionalFields: { expiresAt: {
        type: "date", required: requiredExpiry,
        onUpdate: () => "2031-02-03T04:05:06.123987Z",
        transform: { input: async value => {
          event("input", value);
          if (omitResult && applyingInput && value != null) return undefined;
          return value == null ? value : new Date(new Date(value).getTime() + 1000);
        } },
      } } },
      databaseHooks: { session: {
        create: { before: async data => { event("create.before", data.expiresAt); }, after: async data => { event("create.after", data.expiresAt); } },
        update: { before: async data => { event("update.before", data.expiresAt); }, after: async data => { event("update.after", data?.expiresAt); } },
      } },
    };
    const migrations = await getMigrations(options);
    const schemaSql = requiredExpiry ? await migrations.compileMigrations() : undefined;
    await migrations.runMigrations();
    const { internalAdapter, adapter } = await betterAuth(options).$context;
    const user = await internalAdapter.createUser({ name: "Timestamp", email: "session-timestamp@example.com", emailVerified: false });
    const cases = [];
    if (transactions) for (const kind of ["date", "string"]) for (const action of ["commit", "rollback"]) {
      const token = `timestamp-${kind}-${action}`;
      const input = kind === "date" ? new Date("2031-02-03T04:05:06.123987Z") : "2031-02-03T04:05:06.123987Z";
      events = [];
      applyingInput = true;
      let inside;
      let outcome;
      try {
        outcome = await runWithTransaction(adapter, async () => {
          let result;
          try {
            const session = await internalAdapter.createSession(user.id, false, { token, expiresAt: input }, true, { deferSecondaryStorageWrites: deferred });
            result = { output: session.expiresAt };
          } catch (error) {
            assert.ok(kind === "string" && !deferred);
            assert.equal(error.message, "data.expiresAt.getTime is not a function");
            result = { error: { name: error.name, message: error.message } };
          }
          events.push({ phase: "inside" });
          const stored = await (await getCurrentAdapter(adapter)).findOne({ model: "session", where: [{ field: "token", value: token }] });
          inside = {
            rows: stored ? 1 : 0,
            cached: cache.has(token) ? JSON.parse(cache.get(token)).session.expiresAt : null,
          };
          if (action === "rollback") throw new Error("session expiry rollback");
          return result;
        });
      } catch (error) {
        assert.equal(action, "rollback");
        assert.equal(error.message, "session expiry rollback");
        outcome = { error: { name: error.name, message: error.message } };
      }
      const stored = await db.selectFrom("session").select("expiresAt").where("token", "=", token).executeTakeFirst();
      const cached = cache.has(token) ? JSON.parse(cache.get(token)).session.expiresAt : null;
      const referenced = cache.has(`active-sessions-${user.id}`) ? JSON.parse(cache.get(`active-sessions-${user.id}`)).find(reference => reference.token === token)?.expiresAt ?? null : null;
      cases.push({ kind, action, input, events: [...events], inside, outcome, cached, referenced, stored: stored ? new Date(stored.expiresAt) : null });
    }
    if (!transactions) for (const operation of ["create", "update"]) {
      for (const [kind, input] of [["date", new Date("2031-02-03T04:05:06.123987Z")], ["string", "2031-02-03T04:05:06.123987Z"], ...(operation === "update" ? [["omitted", undefined]] : [])]) {
        if (secondary && kind !== (secondaryString ? "string" : "date")) continue;
        const token = `timestamp-${operation}-${kind}`;
        applyingInput = false;
        const original = operation === "update" ? await internalAdapter.createSession(user.id, false, { token, expiresAt: new Date("2030-01-01T00:00:00.123Z") }, true) : null;
        events = [];
        applyingInput = true;
        const fields = kind === "omitted" ? {} : { expiresAt: input };
        let session;
        let outcome;
        try {
          session = operation === "create"
            ? await internalAdapter.createSession(user.id, false, { token, ...fields }, true)
            : await internalAdapter.updateSession(original.token, fields);
          assert.ok(session);
          outcome = { output: session.expiresAt };
        } catch (error) {
          if (secondaryString && operation === "create") {
            assert.equal(error.name, "TypeError");
            assert.equal(error.message, "data.expiresAt.getTime is not a function");
            outcome = { error: { name: error.name, message: error.message } };
          } else {
            assert.ok(omitResult && operation === "create");
            outcome = { error: { code: error.code, message: error.message } };
          }
        }
        const readback = await internalAdapter.findSession(token);
        if (secondaryString) {
          const stored = new Date((await db.selectFrom("session").select("expiresAt").where("token", "=", token).executeTakeFirst()).expiresAt);
          assert.equal(stored.toISOString(), "2031-02-03T04:05:07.123Z");
          const cached = cache.has(token) ? JSON.parse(cache.get(token)).session.expiresAt : null;
          const referenced = cache.has(`active-sessions-${user.id}`) ? JSON.parse(cache.get(`active-sessions-${user.id}`)).find(reference => reference.token === token)?.expiresAt ?? null : null;
          cases.push({ operation, kind, input, events: [...events], outcome, cached, referenced, stored, readback: readback.session.expiresAt });
        } else if (omitResult) {
          if (operation === "create") {
            if (requiredExpiry) {
              assert.equal(session, undefined);
              assert.equal(readback, null);
              assert.equal(outcome.error.code, backend === "postgres" ? "23502" : "ERR_SQLITE_ERROR");
              assert.match(outcome.error.message, /(?:not-null|NOT NULL)/);
            } else {
              assert.equal(session.expiresAt, null);
              assert.equal(readback.session.expiresAt, null);
              assert.equal(readback.session.id, session.id);
            }
          }
          else {
            assert.equal(session.expiresAt.toISOString(), "2030-01-01T00:00:01.123Z");
            assert.equal(readback.session.id, original.id);
          }
          cases.push({ operation, kind, input, events: [...events], outcome, exists: readback !== null, readback: readback?.session.expiresAt ?? null });
        } else {
          assert.equal(readback.session.id, session.id);
          assert.equal(session.expiresAt.toISOString(), "2031-02-03T04:05:07.123Z");
          assert.equal(readback.session.expiresAt.toISOString(), secondary && operation === "update" ? input.toISOString() : session.expiresAt.toISOString());
          const retained = secondary ? {
            cached: JSON.parse(cache.get(token)).session.expiresAt,
            referenced: JSON.parse(cache.get(`active-sessions-${user.id}`)).find(reference => reference.token === token).expiresAt,
            stored: new Date((await db.selectFrom("session").select("expiresAt").where("token", "=", token).executeTakeFirst()).expiresAt),
          } : {};
          if (wire) {
            const payload = JSON.parse(cache.get(token));
            payload.session.id = "$session";
            payload.session.userId = "$user";
            payload.user.id = "$user";
            for (const owner of [payload.session, payload.user]) for (const field of ["createdAt", "updatedAt"]) {
              assert.match(owner[field], /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
              owner[field] = "$clock";
            }
            retained.wire = JSON.stringify(payload);
          }
          cases.push({ operation, kind, input, events: [...events], output: session.expiresAt, readback: readback.session.expiresAt, ...retained });
        }
      }
    }
    assert.equal(cases.length, transactions ? 4 : secondary ? 2 : 5);
    profiles.push({ backend, ...(requiredExpiry ? { schema_sql: schemaSql } : {}), cases });
  }
  if (!omitResult) assert.deepEqual(profiles[0].cases, profiles[1].cases);
  const filename = wire ? "session-timestamp-hooks-secondary-wire" : transactions ? deferred ? "session-timestamp-hooks-secondary-deferred" : "session-timestamp-hooks-secondary-transactions" : secondaryString ? "session-timestamp-hooks-secondary-string" : secondary ? "session-timestamp-hooks-secondary" : requiredExpiry ? "session-timestamp-hooks-omit-required" : omitResult ? "session-timestamp-hooks-omit" : "session-timestamp-hooks";
  await writeFile(new URL(`../../fixtures/${filename}.json`, import.meta.url), JSON.stringify({ better_auth: "1.7.18", profiles }) + "\n");
  console.log(`${profiles.reduce((count, profile) => count + profile.cases.length, 0)} actual SQLite/PostgreSQL session timestamp callback cases`);
} finally {
  await sqliteDb.destroy();
  await postgresDb.destroy();
  await admin.query(`DROP SCHEMA ${schema} CASCADE`);
  await admin.end();
}
