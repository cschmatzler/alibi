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
assert.ok(process.env.BETTER_AUTH_TEST_POSTGRES_URL, "requires a disposable PostgreSQL database URL");
const schema = `user_json_text_oracle_${randomBytes(8).toString("hex")}`;
const admin = new pg.Client({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL });
await admin.connect();
await admin.query(`CREATE SCHEMA ${schema}`);
const pool = new pg.Pool({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL, options: `-csearch_path=${schema}`, max: 1 });
const db = new Kysely({ dialect: new PostgresDialect({ pool }) });
const cases = [];
try {
  // Existing application-owned columns are not replaced by Better Auth migrations.
  const tableSql = 'CREATE TABLE "applicationUser" (id text PRIMARY KEY, name text NOT NULL, email text NOT NULL UNIQUE, "emailVerified" boolean NOT NULL DEFAULT false, image text, "createdAt" timestamptz NOT NULL, "updatedAt" timestamptz NOT NULL, metadata text)';
  await pool.query(tableSql);
  const options = { baseURL: "http://localhost", secret: "postgres-user-json-text-secret-at-least-32", database: { type: "postgres", db },
    user: { modelName: "applicationUser", additionalFields: { metadata: { type: "json", required: false } } } };
  await (await getMigrations(options)).runMigrations();
  const type = await pool.query("SELECT data_type FROM information_schema.columns WHERE table_schema = $1 AND table_name = 'applicationUser' AND column_name = 'metadata'", [schema]);
  assert.equal(type.rows[0].data_type, "text");
  const auth = betterAuth(options);
  const { internalAdapter } = await auth.$context;
  let id;
  for (const action of ["create", "read", "update", "updated-read", "clear", "cleared-read"]) {
    const input = action === "clear" ? null : { numbers: [1e20, 1e21, 1e-6, 1e-7, -0], version: action === "create" ? "original" : "updated" };
    let row;
    if (action === "create") row = await internalAdapter.createUser({ name: "Text JSON", email: "text-json@example.com", emailVerified: false, metadata: input });
    else if (action === "update" || action === "clear") row = await internalAdapter.updateUser(id, { metadata: input });
    else row = await internalAdapter.findUserById(id);
    if (action === "create") id = row.id;
    assert.equal(row.id, id);
    const { rows } = await pool.query('SELECT metadata FROM "applicationUser" WHERE id = $1', [id]);
    assert.equal(rows.length, 1);
    assert.equal(row.metadata, rows[0].metadata);
    if (action === "create" || action === "update") assert.equal(rows[0].metadata, JSON.stringify(input));
    cases.push({ action, ...(action === "create" || action === "update" || action === "clear" ? { input } : {}), output: row.metadata, stored: rows[0].metadata });
  }
  assert.equal(cases.length, 6);
  await writeFile(new URL("../../fixtures/postgres-user-json-text.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", physical_type: "text", table_sql: tableSql, cases }) + "\n");
  console.log(`${cases.length} actual PostgreSQL application-owned TEXT JSON creation/read/update/null cases`);
} finally {
  await db.destroy();
  await admin.query(`DROP SCHEMA ${schema} CASCADE`);
  await admin.end();
}
