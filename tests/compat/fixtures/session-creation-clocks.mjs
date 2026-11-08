import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { readFile, writeFile } from "node:fs/promises";
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
const schema = `session_creation_clocks_${randomBytes(8).toString("hex")}`;
const admin = new pg.Client({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL });
await admin.connect();
await admin.query(`CREATE SCHEMA ${schema}`);
const pool = new pg.Pool({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL, options: `-csearch_path=${schema}`, max: 1 });
const postgresDb = new Kysely({ dialect: new PostgresDialect({ pool }) });
const profiles = [];
const clocks = { createdAt: "2030-01-01T00:00:00.123Z", updatedAt: "2031-02-03T04:05:06.123Z" };
const defaults = { createdAt: "2028-01-01T00:00:00.456Z", updatedAt: "2029-01-01T00:00:00.789Z" };
try {
  for (const [backend, db] of [["sqlite", sqliteDb], ["postgres", postgresDb]]) {
    const cases = [];
    for (const policy of ["builtin", "declared", "custom-defaults"]) {
      const events = [];
      const fields = Object.fromEntries(Object.keys(clocks).map(name => [name, {
        type: "date", required: true,
        ...(policy === "custom-defaults" ? { defaultValue: new Date(defaults[name]) } : {}),
        transform: { input(value) {
          assert.ok(value instanceof Date);
          events.push({ phase: "input", field: name, kind: "date", value });
          return new Date(value.getTime() + 1000);
        } },
      }]));
      const options = {
        baseURL: "http://localhost", secret: "session-creation-clocks-secret-at-least-32", database: { type: backend, db },
        ...(policy !== "builtin" ? { session: { additionalFields: fields } } : {}),
        databaseHooks: { session: { create: {
          before(data) {
            const before = { phase: "create.before" };
            for (const name of Object.keys(clocks)) {
              assert.ok(data[name] instanceof Date);
              if (policy === "custom-defaults") assert.equal(data[name].toISOString(), defaults[name]);
              before[name] = { kind: "date", value: policy === "custom-defaults" ? data[name] : "$clock" };
            }
            events.push(before);
            return { data: { ...data, createdAt: new Date(clocks.createdAt), updatedAt: new Date(clocks.updatedAt) } };
          },
          after(data) { events.push({ phase: "create.after", createdAt: data.createdAt, updatedAt: data.updatedAt }); },
        } } },
      };
      await (await getMigrations(options)).runMigrations();
      const { internalAdapter } = await betterAuth(options).$context;
      const user = await internalAdapter.createUser({ name: "Creation Clocks", email: `${policy}@creation-clocks.example.com`, emailVerified: false });
      const token = `creation-clocks-${policy}`;
      const session = await internalAdapter.createSession(user.id, false, { token, expiresAt: new Date("2039-01-01T00:00:00.123Z") }, true);
      const readback = await internalAdapter.findSession(token);
      assert.equal(readback.session.id, session.id);
      for (const name of Object.keys(clocks)) assert.equal(session[name].getTime(), new Date(clocks[name]).getTime() + (policy === "builtin" ? 0 : 1000));
      const output = { createdAt: session.createdAt, updatedAt: session.updatedAt };
      cases.push({ policy, ...(policy === "custom-defaults" ? { defaults } : {}), hook_clocks: clocks, events, output, readback: { createdAt: readback.session.createdAt, updatedAt: readback.session.updatedAt } });
    }
    profiles.push({ backend, cases });
  }
  assert.deepEqual(profiles[0].cases, profiles[1].cases);
  await writeFile(new URL("../../fixtures/session-creation-clocks.json", import.meta.url), JSON.stringify({ better_auth: pin.version, profiles }) + "\n");
  console.log("Six actual session creation-clock visibility cases");
} finally {
  await sqliteDb.destroy();
  await postgresDb.destroy();
  await admin.query(`DROP SCHEMA ${schema} CASCADE`);
  await admin.end();
}
