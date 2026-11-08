import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { readFile, writeFile } from "node:fs/promises";
import pg from "../reference-server/node_modules/pg/lib/index.js";
import { Kysely, PostgresDialect, SqliteDialect } from "../reference-server/node_modules/kysely/dist/index.js";
import { betterAuth } from "../reference-server/node_modules/better-auth/dist/index.mjs";
import { getMigrations } from "../reference-server/node_modules/better-auth/dist/db/get-migration.mjs";
import { admin as adminPlugin } from "../reference-server/node_modules/better-auth/dist/plugins/index.mjs";
import { runWithTransaction } from "../reference-server/node_modules/@better-auth/core/dist/context/transaction.mjs";

const transactions = process.argv[2] === "--transactions";
const failures = process.argv[2] === "--failures";
assert.ok(process.argv[2] === undefined || transactions || failures, "unknown fixture output mode");
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
const schema = `user_update_missing_${randomBytes(8).toString("hex")}`;
const admin = new pg.Client({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL });
await admin.connect();
await admin.query(`CREATE SCHEMA ${schema}`);
const pool = new pg.Pool({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL, options: `-csearch_path=${schema}`, max: 1 });
const postgresDb = new Kysely({ dialect: new PostgresDialect({ pool }) });
const profiles = [];
try {
  for (const [backend, db] of [["sqlite", sqliteDb], ["postgres", postgresDb]]) {
    let action;
    let events = [];
    function event(phase, value) {
      events.push({ phase, kind: value instanceof Date ? "date" : value === null ? "null" : typeof value, value: value === undefined ? null : value });
    }
    const options = {
      baseURL: "http://localhost", secret: "user-update-missing-phases-secret-at-least-32", database: { type: backend, db, transaction: transactions || failures }, plugins: [adminPlugin()],
      user: { additionalFields: { banExpires: { type: "date", required: false,
        onUpdate: () => { events.push({ phase: "onUpdate" }); return "2031-02-03T04:05:06.123987Z"; },
        transform: { input: async value => {
          event("input", value);
          if (action === "input-error") throw new Error("date input veto");
          if (action === "driver-error") return "not-a-timestamp";
          if (action === "driver-quote") return "2031-02-03T04:05:06.123Z'); DROP TABLE user; --\\path";
          return value;
        } },
      } } },
      databaseHooks: { user: { update: {
        before: async data => { event("before", data.banExpires); if (action === "before-cancel") return false; },
        after: async data => { event("after", data); if (action.endsWith("after-error")) throw new Error("missing after veto"); },
      } } },
    };
    await (await getMigrations(options)).runMigrations();
    const { internalAdapter, adapter } = await betterAuth(options).$context;
    const cases = [];
    for (action of failures ? ["driver-error", "driver-quote", "after-error", "commit-after-error", "rollback-after-error"] : transactions ? ["commit", "rollback"] : ["string", "omitted", "null", "before-cancel", "input-error"]) {
      events = [];
      const input = action === "omitted" ? { banned: false } : { banExpires: action === "null" ? null : "2031-02-03T04:05:06.123987Z" };
      let outcome;
      try {
        const update = () => internalAdapter.updateUser("missing-timestamp-user", input);
        const result = transactions || action.startsWith("commit") || action.startsWith("rollback") ? await runWithTransaction(adapter, async () => {
          const result = await update();
          assert.equal(result, null);
          events.push({ phase: "inside" });
          if (action.startsWith("rollback")) throw new Error("missing update rollback");
          return result;
        }) : await update();
        assert.equal(result, null);
        outcome = { result };
      } catch (error) {
        if (action.startsWith("driver-")) {
          assert.equal(backend, "postgres");
          assert.equal(error.code, "22007");
          assert.match(error.message, action === "driver-quote" ? /DROP TABLE user/ : /not-a-timestamp/);
        } else {
          assert.ok(action === "input-error" || action.startsWith("rollback") || action.endsWith("after-error"));
          assert.equal(error.message, action.startsWith("rollback") ? "missing update rollback" : action.endsWith("after-error") ? "missing after veto" : "date input veto");
        }
        outcome = { error: error.message, ...(failures ? { code: error.code ?? null } : {}) };
      }
      const rows = await db.selectFrom("user").select("id").execute();
      assert.deepEqual(rows, []);
      cases.push({ action, input, events, outcome, rows: rows.length });
    }
    profiles.push({ backend, cases });
  }
  if (!failures) assert.deepEqual(profiles[0].cases, profiles[1].cases);
  const filename = failures ? "user-update-missing-failures" : transactions ? "user-update-missing-transactions" : "user-update-missing-phases";
  await writeFile(new URL(`../../fixtures/${filename}.json`, import.meta.url), JSON.stringify({ better_auth: "1.7.18", profiles }) + "\n");
  console.log(`${profiles.reduce((count, profile) => count + profile.cases.length, 0)} actual SQLite/PostgreSQL missing-user update callback cases`);
} finally {
  await sqliteDb.destroy();
  await postgresDb.destroy();
  await admin.query(`DROP SCHEMA ${schema} CASCADE`);
  await admin.end();
}
