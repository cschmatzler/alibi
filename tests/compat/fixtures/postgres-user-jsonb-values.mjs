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
const schema = `user_jsonb_values_${randomBytes(8).toString("hex")}`;
const admin = new pg.Client({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL });
await admin.connect();
await admin.query(`CREATE SCHEMA ${schema}`);
const pool = new pg.Pool({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL, options: `-csearch_path=${schema}`, max: 1 });
const db = new Kysely({ dialect: new PostgresDialect({ pool }) });
const cases = [];
const operation = process.argv[2] ?? "create";
assert.ok(["create", "update"].includes(operation));
try {
  const options = {
    baseURL: "http://localhost", secret: "postgres-user-jsonb-values-secret-at-least-32", database: { type: "postgres", db },
    user: { modelName: "applicationUser", additionalFields: { metadata: { type: "json", required: false } } },
  };
  const migrations = await getMigrations(options);
  const schemaSql = await migrations.compileMigrations();
  await migrations.runMigrations();
  const type = await pool.query("SELECT data_type FROM information_schema.columns WHERE table_schema = $1 AND table_name = 'applicationUser' AND column_name = 'metadata'", [schema]);
  assert.equal(type.rows[0].data_type, "jsonb");
  const { internalAdapter } = await betterAuth(options).$context;
  for (const [name, input] of [
    ["object", { nested: [true, null, 1e20] }], ["array", ["a", { nested: true }, null]], ["empty-array", []],
    ["literal-string", "literal-text"], ["quoted-string", '"quoted"'], ["object-string", '{"nested":true}'],
    ["array-string", '["a",null]'], ["number-string", "42"], ["null-string", "null"],
    ["boolean", true], ["number", 1e20], ["null", null],
  ]) {
    const email = `${name}@jsonb-values.example.com`;
    const original = operation === "update"
      ? await internalAdapter.createUser({ name: "JSONB values", email, emailVerified: false, metadata: { original: true } })
      : null;
    let output = null, errorCode = null;
    try {
      const row = operation === "create"
        ? await internalAdapter.createUser({ name: "JSONB values", email, emailVerified: false, metadata: input })
        : await internalAdapter.updateUser(original.id, { metadata: input });
      if (original) assert.equal(row.id, original.id);
      output = { metadata: row.metadata };
    } catch (error) {
      assert.equal(error.code, "22P02");
      errorCode = error.code;
    }
    const readback = await internalAdapter.findUserByEmail(email);
    const { rows } = await pool.query('SELECT metadata, metadata IS NULL AS sql_null FROM "applicationUser" WHERE email = $1', [email]);
    assert.equal(rows.length, errorCode && operation === "create" ? 0 : 1);
    if (errorCode && original) assert.deepEqual(rows[0], { metadata: { original: true }, sql_null: false });
    if (!errorCode) assert.deepEqual(output, { metadata: rows[0].metadata });
    cases.push({ name, input, error_code: errorCode, output, readback: readback ? { metadata: readback.user.metadata } : null,
      row_count: rows.length, stored: rows[0] ?? null });
  }
  assert.equal(cases.length, 12);
  const filename = operation === "create" ? "postgres-user-jsonb-values.json" : "postgres-user-jsonb-updates.json";
  await writeFile(new URL(`../../fixtures/${filename}`, import.meta.url), JSON.stringify({ better_auth: "1.7.18", physical_type: "jsonb", schema_sql: schemaSql, cases }) + "\n");
  console.log(`${cases.length} actual PostgreSQL JSONB user metadata ${operation} parameter and rejection cases`);
} finally {
  await db.destroy();
  await admin.query(`DROP SCHEMA ${schema} CASCADE`);
  await admin.end();
}
