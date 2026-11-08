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
const schema = `session_default_evaluation_${randomBytes(8).toString("hex")}`;
const admin = new pg.Client({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL });
await admin.connect();
await admin.query(`CREATE SCHEMA ${schema}`);
const pool = new pg.Pool({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL, options: `-csearch_path=${schema}`, max: 1 });
const postgresDb = new Kysely({ dialect: new PostgresDialect({ pool }) });
const profiles = [];
try {
  for (const [backend, db] of [["sqlite", sqliteDb], ["postgres", postgresDb]]) {
    let events = [];
    let factoryEnds = [];
    let hookStart;
    let hookEnd;
    const defaultValue = "2035-01-01T00:00:00.123Z";
    const options = {
      baseURL: "http://localhost", secret: "session-default-evaluation-secret-at-least-32", database: { type: backend, db },
      session: { additionalFields: { updatedAt: {
        type: "date", required: true,
        defaultValue() {
          events.push({ phase: "default" });
          // The source default API is synchronous; keep its real clock observable.
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
          factoryEnds.push(Date.now());
          return new Date(defaultValue);
        },
        transform: { input(value) {
          assert.ok(value instanceof Date);
          events.push({ phase: "input", kind: "date", value });
          return new Date(value.getTime() + 1000);
        } },
      } } },
      databaseHooks: { session: { create: {
        async before(data) {
          hookStart = Date.now();
          assert.ok(data.createdAt instanceof Date);
          assert.ok(data.createdAt.getTime() >= factoryEnds[0]);
          const value = data.updatedAt;
          events.push({ phase: "create.before", createdAt: "$clock", updatedAt: {
            kind: value instanceof Date ? "date" : value === null ? "null" : typeof value,
            value: value === undefined ? null : value,
          } });
          await setTimeout(20);
          hookEnd = Date.now();
        },
        after(data) { events.push({ phase: "create.after", createdAt: "$clock", updatedAt: data.updatedAt }); },
      } } },
    };
    await (await getMigrations(options)).runMigrations();
    const { internalAdapter } = await betterAuth(options).$context;
    const user = await internalAdapter.createUser({ name: "Default Evaluation", email: "default-evaluation@example.com", emailVerified: false });
    const cases = [];
    for (const kind of ["omitted", "date", "undefined", "null"]) {
      events = [];
      factoryEnds = [];
      const value = kind === "date" ? new Date("2031-01-01T00:00:00.123Z") : kind === "null" ? null : undefined;
      const token = `default-evaluation-${kind}`;
      const session = await internalAdapter.createSession(user.id, false, {
        token, expiresAt: new Date("2039-01-01T00:00:00.123Z"), ...(kind !== "omitted" ? { updatedAt: value } : {}),
      }, true);
      assert.equal(factoryEnds.length, ["undefined", "null"].includes(kind) ? 2 : 1);
      assert.ok(session.createdAt.getTime() >= factoryEnds[0]);
      assert.ok(session.createdAt.getTime() <= hookStart);
      assert.ok(session.createdAt.getTime() < hookEnd);
      if (factoryEnds.length === 2) assert.ok(factoryEnds[1] >= hookEnd);
      const expected = kind === "date" ? "2031-01-01T00:00:01.123Z" : "2035-01-01T00:00:01.123Z";
      assert.equal(session.updatedAt.toISOString(), expected);
      const readback = await internalAdapter.findSession(token);
      assert.equal(readback.session.id, session.id);
      assert.equal(readback.session.createdAt.getTime(), session.createdAt.getTime());
      assert.equal(readback.session.updatedAt.getTime(), session.updatedAt.getTime());
      cases.push({ kind, ...(kind !== "omitted" && kind !== "undefined" ? { input: value } : {}), default_value: defaultValue, events: [...events], factory_calls: factoryEnds.length, created_after_first_factory: true, created_before_hook: true, ...(factoryEnds.length === 2 ? { second_factory_after_hook: true } : {}), output: { createdAt: "$clock", updatedAt: session.updatedAt } });
    }
    profiles.push({ backend, cases });
  }
  assert.deepEqual(profiles[0].cases, profiles[1].cases);
  await writeFile(new URL("../../fixtures/session-creation-default-evaluation.json", import.meta.url), JSON.stringify({ better_auth: pin.version, profiles }) + "\n");
  console.log("Eight actual configured creation-default evaluation cases");
} finally {
  await sqliteDb.destroy();
  await postgresDb.destroy();
  await admin.query(`DROP SCHEMA ${schema} CASCADE`);
  await admin.end();
}
