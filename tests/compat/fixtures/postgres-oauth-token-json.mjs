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
const schema = `oauth_token_oracle_${randomBytes(8).toString("hex")}`;
const admin = new pg.Client({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL });
await admin.connect();
await admin.query(`CREATE SCHEMA ${schema}`);
const pool = new pg.Pool({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL, options: `-csearch_path=${schema}`, max: 1 });
const db = new Kysely({ dialect: new PostgresDialect({ pool }) });
const cases = [];
try {
  await (await getMigrations({ ...config, database: { type: "postgres", db } })).runMigrations();
  const auth = betterAuth({ baseURL: "http://localhost", secret: "postgres-oauth-token-json-secret-at-least-32", database: { type: "postgres", db }, plugins: [oauthProvider({ loginPage: "/login", consentPage: "/consent", disableJwtPlugin: true })] });
  const { adapter, internalAdapter } = await auth.$context;
  const owner = await internalAdapter.createUser({ name: "Token owner", email: "token-json@example.com", emailVerified: false });
  const clientId = "token-json-client";
  await adapter.create({ model: "oauthClient", data: { clientId, redirectUris: ["https://client.example/callback"], scopes: ["read"], tokenEndpointAuthMethod: "none" } });
  for (const [kind, model] of [["access", "oauthAccessToken"], ["refresh", "oauthRefreshToken"]]) {
    const token = `${kind}-token-json`;
    let originalId;
    const projection = row => row && { token: row.token, scopes: row.scopes, resources: row.resources,
      requestedUserInfoClaims: row.requestedUserInfoClaims, confirmation: row.confirmation, revoked: row.revoked ?? null };
    for (const action of ["create", "read", "sql-failure", "revoke", "revoked-read"]) {
      if (action === "sql-failure") await pool.query(`ALTER TABLE "${model}" ADD CONSTRAINT reject_token_scopes CHECK (jsonb_array_length(scopes) < 2)`);
      let row = null, failed = false;
      try {
        if (action === "create" || action === "sql-failure") row = await adapter.create({ model, data: {
          token: action === "create" ? token : `rejected-${token}`, clientId, userId: owner.id,
          scopes: action === "create" ? ["read"] : ["read", "write"], resources: ["https://resource.example"],
          requestedUserInfoClaims: ["email"], confirmation: { jkt: "application-proof" },
          createdAt: new Date("2026-01-01T00:00:00.123Z"), expiresAt: new Date("2031-01-01T00:00:00.123Z"),
        } });
        else if (action === "revoke") row = await adapter.update({ model, where: [{ field: "id", value: originalId }], update: { revoked: new Date("2030-02-03T04:05:06.789Z") } });
        else row = await adapter.findOne({ model, where: [{ field: "token", value: token }] });
      } catch (error) { assert.equal(error.code, "23514"); assert.equal(error.constraint, "reject_token_scopes"); failed = true; }
      assert.equal(failed, action === "sql-failure");
      if (action === "sql-failure") await pool.query(`ALTER TABLE "${model}" DROP CONSTRAINT reject_token_scopes`);
      if (action === "create") originalId = row.id;
      if (row) assert.equal(row.id, originalId);
      const { rows } = await pool.query(`SELECT token, scopes, resources, "requestedUserInfoClaims", confirmation, revoked FROM "${model}"`);
      assert.equal(rows.length, 1);
      cases.push({ kind, action, failed, output: projection(row), stored: rows[0] });
    }
  }
  assert.equal(cases.length, 10);
  await writeFile(new URL("../../fixtures/postgres-oauth-token-json.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", cases }) + "\n");
  console.log(`${cases.length} actual PostgreSQL access/refresh token JSON create/read/CHECK/revocation cases`);
} finally {
  await db.destroy();
  await admin.query(`DROP SCHEMA ${schema} CASCADE`);
  await admin.end();
}
