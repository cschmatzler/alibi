import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import pg from "../reference-server/node_modules/pg/lib/index.js";
import { Kysely, PostgresDialect } from "../reference-server/node_modules/kysely/dist/index.js";
import { betterAuth } from "../reference-server/node_modules/better-auth/dist/index.mjs";
import { getMigrations } from "../reference-server/node_modules/better-auth/dist/db/get-migration.mjs";
import { oauthProvider } from "../reference-server/node_modules/@better-auth/oauth-provider/dist/index.mjs";
import { config } from "../reference-server/probes/schema-parity.mjs";

assert.equal(JSON.parse(await readFile(new URL("../upstream-source.json", import.meta.url))).commit, "38f43e390920faa400d51ff0bd18570a424d05ce");
for (const name of ["better-auth", "@better-auth/core", "@better-auth/kysely-adapter", "@better-auth/oauth-provider"]) {
  assert.equal(JSON.parse(await readFile(new URL(`../reference-server/node_modules/${name}/package.json`, import.meta.url))).version, "1.7.18");
}
assert.ok(process.env.BETTER_AUTH_TEST_POSTGRES_URL, "requires a disposable PostgreSQL database URL");
const schema = `oauth_json_oracle_${randomBytes(8).toString("hex")}`;
const admin = new pg.Client({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL });
await admin.connect();
await admin.query(`CREATE SCHEMA ${schema}`);
const pool = new pg.Pool({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL, options: `-csearch_path=${schema}`, max: 1 });
const db = new Kysely({ dialect: new PostgresDialect({ pool }) });
const cases = [];
try {
  await (await getMigrations({ ...config, database: { type: "postgres", db } })).runMigrations();
  const auth = betterAuth({ baseURL: "http://localhost", secret: "postgres-oauth-json-secret-at-least-32-characters", database: { type: "postgres", db }, plugins: [oauthProvider({ loginPage: "/login", consentPage: "/consent", disableJwtPlugin: true })] });
  const { adapter } = await auth.$context;
  const clientId = "registry-client";
  let originalId;
  for (const action of ["create", "read", "sql-failure", "update", "updated-read"]) {
    if (action === "sql-failure") await pool.query('ALTER TABLE "oauthClient" ADD CONSTRAINT reject_oauth_scope CHECK (jsonb_array_length(scopes) < 2)');
    let client = null, failed = false;
    try {
      if (action === "create") client = await adapter.create({ model: "oauthClient", data: {
        clientId, clientDiscoveryId: "registry-live", name: "Registry client", tokenEndpointAuthMethod: "none", disabled: false,
        redirectUris: ["https://app.fixture.test/callback"], scopes: ["email"], grantTypes: ["authorization_code"], responseTypes: ["code"], createdAt: new Date("2026-01-01T00:00:00.123Z"),
      } });
      else if (action === "update" || action === "sql-failure") client = await adapter.update({ model: "oauthClient", where: [{ field: "clientId", value: clientId }], update: {
        name: "Updated registry", scopes: ["email", "profile"], redirectUris: ["https://app.fixture.test/after"], grantTypes: ["authorization_code", "refresh_token"], responseTypes: ["code"], updatedAt: new Date("2026-02-01T00:00:00.123Z"),
      } });
      else client = await adapter.findOne({ model: "oauthClient", where: [{ field: "clientId", value: clientId }] });
    } catch (error) { assert.equal(error.code, "23514"); assert.equal(error.constraint, "reject_oauth_scope"); failed = true; }
    assert.equal(failed, action === "sql-failure");
    if (action === "sql-failure") await pool.query('ALTER TABLE "oauthClient" DROP CONSTRAINT reject_oauth_scope');
    if (action === "create") originalId = client.id;
    if (client) assert.equal(client.id, originalId);
    const output = client && { clientId: client.clientId, clientDiscoveryId: client.clientDiscoveryId, name: client.name,
      scopes: client.scopes, grantTypes: client.grantTypes, responseTypes: client.responseTypes, redirectUris: client.redirectUris };
    const { rows } = await pool.query('SELECT "clientId", "clientDiscoveryId", name, scopes, "grantTypes", "responseTypes", "redirectUris" FROM "oauthClient"');
    assert.equal(rows.length, 1);
    cases.push({ action, failed, output, stored: rows[0] });
  }
  assert.equal(cases.length, 5);
  await writeFile(new URL("../../fixtures/postgres-oauth-client-json.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", cases }) + "\n");
  console.log(`${cases.length} actual PostgreSQL OAuth client native JSON creation/update/failure cases`);
} finally {
  await db.destroy();
  await admin.query(`DROP SCHEMA ${schema} CASCADE`);
  await admin.end();
}
