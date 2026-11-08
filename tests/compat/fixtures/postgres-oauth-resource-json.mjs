import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import pg from "../reference-server/node_modules/pg/lib/index.js";
import { Kysely, PostgresDialect } from "../reference-server/node_modules/kysely/dist/index.js";
import { betterAuth } from "../reference-server/node_modules/better-auth/dist/index.mjs";
import { getMigrations } from "../reference-server/node_modules/better-auth/dist/db/get-migration.mjs";
import { oauthProvider } from "../reference-server/node_modules/@better-auth/oauth-provider/dist/index.mjs";
import { config } from "../reference-server/probes/schema-parity.mjs";

const pin = JSON.parse(await readFile(new URL("../upstream-source.json", import.meta.url)));
assert.equal(pin.commit, "38f43e390920faa400d51ff0bd18570a424d05ce");
assert.equal(pin.version, "1.7.18");
for (const name of ["better-auth", "@better-auth/core", "@better-auth/kysely-adapter", "@better-auth/oauth-provider"]) {
  assert.equal(JSON.parse(await readFile(new URL(`../reference-server/node_modules/${name}/package.json`, import.meta.url))).version, "1.7.18");
}
assert.ok(process.env.BETTER_AUTH_TEST_POSTGRES_URL, "requires a disposable PostgreSQL database URL");
const schema = `oauth_resource_oracle_${randomBytes(8).toString("hex")}`;
const admin = new pg.Client({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL });
await admin.connect();
await admin.query(`CREATE SCHEMA ${schema}`);
const pool = new pg.Pool({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL, options: `-csearch_path=${schema}`, max: 1 });
const db = new Kysely({ dialect: new PostgresDialect({ pool }) });
const cases = [];
try {
  await (await getMigrations({ ...config, database: { type: "postgres", db } })).runMigrations();
  const auth = betterAuth({ baseURL: "http://localhost", secret: "postgres-oauth-resource-json-secret-at-least-32", database: { type: "postgres", db }, plugins: [oauthProvider({ loginPage: "/login", consentPage: "/consent", disableJwtPlugin: true })] });
  const { adapter } = await auth.$context;
  const identifier = "https://resource.example";
  let originalId;
  for (const action of ["create", "read", "sql-failure", "update", "updated-read"]) {
    const updated = action === "update" || action === "sql-failure";
    const input = { name: updated ? "Updated resource" : "Resource", allowedScopes: updated ? ["read", "write"] : ["read"],
      customClaims: { owner: "application", revision: updated ? 2 : 1 }, metadata: { nested: [null, true, "2025-02-03T04:05:06Z"] } };
    if (action === "sql-failure") await pool.query('ALTER TABLE "oauthResource" ADD CONSTRAINT reject_resource_scopes CHECK (jsonb_array_length("allowedScopes") < 2)');
    let resource = null, failed = false;
    try {
      if (action === "create") resource = await adapter.create({ model: "oauthResource", data: { identifier, ...input, createdAt: new Date("2026-01-01T00:00:00.123Z") } });
      else if (updated) resource = await adapter.update({ model: "oauthResource", where: [{ field: "identifier", value: identifier }], update: { ...input, updatedAt: new Date("2026-02-01T00:00:00.123Z") } });
      else resource = await adapter.findOne({ model: "oauthResource", where: [{ field: "identifier", value: identifier }] });
    } catch (error) { assert.equal(error.code, "23514"); assert.equal(error.constraint, "reject_resource_scopes"); failed = true; }
    assert.equal(failed, action === "sql-failure");
    if (action === "sql-failure") await pool.query('ALTER TABLE "oauthResource" DROP CONSTRAINT reject_resource_scopes');
    if (action === "create") originalId = resource.id;
    if (resource) assert.equal(resource.id, originalId);
    const output = resource && { identifier: resource.identifier, name: resource.name, allowedScopes: resource.allowedScopes, customClaims: resource.customClaims, metadata: resource.metadata };
    const { rows } = await pool.query('SELECT identifier, name, "allowedScopes", "customClaims", metadata FROM "oauthResource"');
    assert.equal(rows.length, 1);
    cases.push({ action, input, failed, output, stored: rows[0] });
  }
  assert.equal(cases.length, 5);
  await writeFile(new URL("../../fixtures/postgres-oauth-resource-json.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", cases }) + "\n");
  console.log(`${cases.length} actual PostgreSQL OAuth resource native JSON CRUD/CHECK cases`);
} finally {
  await db.destroy();
  await admin.query(`DROP SCHEMA ${schema} CASCADE`);
  await admin.end();
}
