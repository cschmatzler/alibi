import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import pg from "../reference-server/node_modules/pg/lib/index.js";
import { Kysely, PostgresDialect } from "../reference-server/node_modules/kysely/dist/index.js";
import { betterAuth } from "../reference-server/node_modules/better-auth/dist/index.mjs";
import { getMigrations } from "../reference-server/node_modules/better-auth/dist/db/get-migration.mjs";

const pin = JSON.parse(await readFile(new URL("../upstream-source.json", import.meta.url)));
assert.equal(pin.commit, "38f43e390920faa400d51ff0bd18570a424d05ce");
assert.equal(pin.version, "1.7.18");
for (const name of ["better-auth", "@better-auth/core", "@better-auth/kysely-adapter"]) {
  assert.equal(JSON.parse(await readFile(new URL(`../reference-server/node_modules/${name}/package.json`, import.meta.url))).version, "1.7.18");
}
const contract = JSON.parse(await readFile(new URL("../../fixtures/postgres-user-json-text.json", import.meta.url)));
assert.ok(process.env.BETTER_AUTH_TEST_POSTGRES_URL, "requires a disposable PostgreSQL database URL");
const schema = `user_text_hooks_${randomBytes(8).toString("hex")}`;
const admin = new pg.Client({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL });
await admin.connect();
await admin.query(`CREATE SCHEMA ${schema}`);
const pool = new pg.Pool({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL, options: `-csearch_path=${schema}`, max: 1 });
const db = new Kysely({ dialect: new PostgresDialect({ pool }) });
const cases = [];
let mode, events;
const before = operation => async row => {
  events.push({ phase: `${operation}.before`, metadata: row.metadata });
  if (mode.endsWith("replace")) return { data: { metadata: ["hook", { nested: true }, null] } };
  if (mode === "update-clear") return { data: { metadata: null } };
};
const after = operation => async row => {
  events.push({ phase: `${operation}.after`, metadata: row.metadata });
};
try {
  await pool.query(contract.table_sql);
  const options = {
    baseURL: "http://localhost", secret: "postgres-user-text-hooks-secret-at-least-32", database: { type: "postgres", db },
    user: { modelName: "applicationUser", additionalFields: { metadata: { type: "json", required: false } } },
    databaseHooks: { user: { create: { before: before("create"), after: after("create") }, update: { before: before("update"), after: after("update") } } },
  };
  await (await getMigrations(options)).runMigrations();
  const { internalAdapter } = await betterAuth(options).$context;
  let id;
  for (const [action, input] of [
    ["create-array", ["original", { nested: true }, null]],
    ["create-string", "original"], ["create-null", null],
    ["create-replace", { original: true }], ["update-replace", "original"], ["update-clear", 1e20],
  ]) {
    mode = action;
    events = [];
    const creating = action.startsWith("create-");
    const row = creating
      ? await internalAdapter.createUser({ name: "Text hooks", email: `${action}@text-hooks.example.com`, emailVerified: false, metadata: input })
      : await internalAdapter.updateUser(id, { metadata: input });
    if (creating) id = row.id;
    assert.equal(row.id, id);
    const { rows } = await pool.query('SELECT metadata FROM "applicationUser" WHERE id = $1', [id]);
    assert.equal(rows.length, 1);
    const operation = creating ? "create" : "update";
    assert.deepEqual(events, [{ phase: `${operation}.before`, metadata: input }, { phase: `${operation}.after`, metadata: rows[0].metadata }]);
    assert.equal(row.metadata, rows[0].metadata);
    assert.equal((await internalAdapter.findUserById(id)).metadata, rows[0].metadata);
    cases.push({ action, input, events, output: row.metadata, stored: rows[0].metadata });
  }
  assert.equal(cases.length, 6);
  await writeFile(new URL("../../fixtures/postgres-user-json-text-hooks.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", cases }) + "\n");
  console.log(`${cases.length} actual PostgreSQL TEXT metadata callback input/replacement/output cases`);
} finally {
  await db.destroy();
  await admin.query(`DROP SCHEMA ${schema} CASCADE`);
  await admin.end();
}
