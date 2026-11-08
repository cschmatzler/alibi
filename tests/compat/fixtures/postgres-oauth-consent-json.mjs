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
const schema = `oauth_consent_oracle_${randomBytes(8).toString("hex")}`;
const admin = new pg.Client({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL });
await admin.connect();
await admin.query(`CREATE SCHEMA ${schema}`);
const pool = new pg.Pool({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL, options: `-csearch_path=${schema}`, max: 1 });
const db = new Kysely({ dialect: new PostgresDialect({ pool }) });
const cases = [];
try {
  await (await getMigrations({ ...config, database: { type: "postgres", db } })).runMigrations();
  const auth = betterAuth({ baseURL: "http://localhost", secret: "postgres-oauth-consent-json-secret-at-least-32", database: { type: "postgres", db }, plugins: [oauthProvider({ loginPage: "/login", consentPage: "/consent", disableJwtPlugin: true })] });
  const { adapter, internalAdapter } = await auth.$context;
  const owner = await internalAdapter.createUser({ name: "Consent owner", email: "consent-json@example.com", emailVerified: false });
  const clientId = "consent-json-client";
  await adapter.create({ model: "oauthClient", data: { clientId, redirectUris: ["https://client.example/callback"], scopes: ["read"], tokenEndpointAuthMethod: "none" } });
  let originalId;
  const projection = row => row && { clientId: row.clientId, referenceId: row.referenceId, scopes: row.scopes, resources: row.resources, requestedUserInfoClaims: row.requestedUserInfoClaims };
  for (const action of ["create", "read", "sql-failure", "update", "updated-read"]) {
    const updated = action === "update" || action === "sql-failure";
    const input = { referenceId: "application-owner", scopes: updated ? ["read", "write"] : ["read"],
      resources: updated ? ["https://resource.example", "https://other.example"] : ["https://resource.example"], requestedUserInfoClaims: updated ? ["email", "name"] : ["email"] };
    if (action === "sql-failure") await pool.query('ALTER TABLE "oauthConsent" ADD CONSTRAINT reject_consent_scopes CHECK (jsonb_array_length(scopes) < 2)');
    let row = null, failed = false;
    try {
      if (action === "create") row = await adapter.create({ model: "oauthConsent", data: { clientId, userId: owner.id, ...input, createdAt: new Date("2026-01-01T00:00:00.123Z"), updatedAt: new Date("2026-01-01T00:00:00.123Z") } });
      else if (updated) row = await adapter.update({ model: "oauthConsent", where: [{ field: "id", value: originalId }], update: { ...input, updatedAt: new Date("2026-02-01T00:00:00.123Z") } });
      else row = await adapter.findOne({ model: "oauthConsent", where: [{ field: "id", value: originalId }] });
    } catch (error) { assert.equal(error.code, "23514"); assert.equal(error.constraint, "reject_consent_scopes"); failed = true; }
    assert.equal(failed, action === "sql-failure");
    if (action === "sql-failure") await pool.query('ALTER TABLE "oauthConsent" DROP CONSTRAINT reject_consent_scopes');
    if (action === "create") originalId = row.id;
    if (row) assert.equal(row.id, originalId);
    const { rows } = await pool.query('SELECT "clientId", "referenceId", scopes, resources, "requestedUserInfoClaims" FROM "oauthConsent"');
    assert.equal(rows.length, 1);
    cases.push({ action, input, failed, output: projection(row), stored: rows[0] });
  }
  assert.equal(cases.length, 5);
  await writeFile(new URL("../../fixtures/postgres-oauth-consent-json.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", cases }) + "\n");
  console.log(`${cases.length} actual PostgreSQL consent JSON create/read/CHECK/update cases`);
} finally {
  await db.destroy();
  await admin.query(`DROP SCHEMA ${schema} CASCADE`);
  await admin.end();
}
