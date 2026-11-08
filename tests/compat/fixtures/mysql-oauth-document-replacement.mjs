import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { betterAuth } from "../reference-server/node_modules/better-auth/dist/index.mjs";
import { getMigrations } from "../reference-server/node_modules/better-auth/dist/db/get-migration.mjs";
import { oauthProvider } from "../reference-server/node_modules/@better-auth/oauth-provider/dist/index.mjs";
import { registerClientMetadataDocument } from "../reference-server/node_modules/@better-auth/oauth-provider/dist/internal.mjs";
import { config } from "../reference-server/probes/schema-parity.mjs";
import { createMysqlDatabase } from "./support/mysql-database.mjs";

assert.equal(JSON.parse(await readFile(new URL("../reference-server/node_modules/@better-auth/oauth-provider/package.json", import.meta.url))).version, "1.7.18");
const database = await createMysqlDatabase();
const cases = [];
try {
  await (await getMigrations({ ...config, database: { type: "mysql", db: database.db } })).runMigrations();
  const opts = { loginPage: "/login", consentPage: "/consent", disableJwtPlugin: true, scopes: ["openid", "profile"] };
  const auth = betterAuth({ baseURL: "http://localhost", secret: "mysql-oauth-document-secret-at-least-32-characters", database: { type: "mysql", db: database.db }, plugins: [oauthProvider(opts)] });
  const context = await auth.$context;
  const clientId = "https://client.example/metadata.json";
  const clientDiscoveryId = "mysql-document-owner";
  let originalId, createdAt, existing;
  for (const action of ["create", "sql-failure", "replace", "wrong-owner", "missing"]) {
    if (action !== "create" && action !== "missing") existing = await context.adapter.findOne({ model: "oauthClient", where: [{ field: "clientId", value: clientId }] });
    if (action === "sql-failure") {
      await context.adapter.update({ model: "oauthClient", where: [{ field: "clientId", value: clientId }], update: { disabled: true, skipConsent: true, enableEndSession: true, clientCredentialsScopes: ["operator-scope"] } });
      await database.pool.promise().query("ALTER TABLE oauthClient ADD CONSTRAINT reject_refreshed_document CHECK (name <> 'Refreshed')");
    }
    if (action === "missing") await context.adapter.delete({ model: "oauthClient", where: [{ field: "clientId", value: clientId }] });
    const metadata = { client_id: "ignored", client_name: action === "create" ? "Document client" : "Refreshed", redirect_uris: [action === "create" ? "https://client.example/before" : "https://client.example/after"], token_endpoint_auth_method: "none" };
    let output = null, error = null;
    try {
      const result = await registerClientMetadataDocument({ context }, opts, { metadata, clientId, clientDiscoveryId: action === "wrong-owner" ? "foreign-owner" : clientDiscoveryId, existingClient: action === "create" ? undefined : existing });
      if (action === "create") { originalId = result.client.id; createdAt = result.client.createdAt.getTime(); }
      assert.equal(result.client.id, originalId);
      assert.equal(result.client.createdAt.getTime(), createdAt);
      const client = result.client;
      output = { created: result.created, resources: result.resources, clientSecret: result.clientSecret ?? null,
        client: { clientId: client.clientId, clientDiscoveryId: client.clientDiscoveryId, name: client.name, applicationType: client.applicationType ?? null,
          scopes: client.scopes, clientCredentialsScopes: client.clientCredentialsScopes, disabled: client.disabled ?? null,
          skipConsent: client.skipConsent ?? null, enableEndSession: client.enableEndSession ?? null, redirectUris: client.redirectUris } };
    } catch (caught) {
      if (action === "sql-failure") { assert.equal(caught.code, "ER_CHECK_CONSTRAINT_VIOLATED"); error = { sql_failure: true }; }
      else { assert.equal(caught.statusCode, 400); error = caught.body; }
    }
    assert.equal(error !== null, ["sql-failure", "wrong-owner", "missing"].includes(action));
    if (action === "sql-failure") await database.pool.promise().query("ALTER TABLE oauthClient DROP CHECK reject_refreshed_document");
    const [stored] = await database.pool.promise().query("SELECT name, clientDiscoveryId, disabled, skipConsent, enableEndSession, scopes, clientCredentialsScopes, redirectUris FROM oauthClient");
    assert.equal(stored.length, action === "missing" ? 0 : 1);
    cases.push({ action, output, error, stored });
  }
  assert.equal(cases.length, 5);
  await writeFile(new URL("../../fixtures/mysql-oauth-document-replacement.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", cases }) + "\n");
  console.log(`${cases.length} actual MySQL client-document registration, replacement and rollback cases`);
} finally {
  await database.close();
}
