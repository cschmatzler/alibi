import assert from "node:assert/strict";
import { writeFile, readFile } from "node:fs/promises";
import { getMigrations } from "../reference-server/node_modules/better-auth/dist/db/get-migration.mjs";
import { scim } from "../reference-server/node_modules/@better-auth/scim/dist/index.mjs";
import { config } from "../reference-server/probes/schema-parity.mjs";
import { createMysqlDatabase } from "./support/mysql-database.mjs";

assert.equal(JSON.parse(await readFile(new URL("../reference-server/node_modules/@better-auth/scim/package.json", import.meta.url))).version, "1.7.18");
const database = await createMysqlDatabase();
try {
  const migrations = await getMigrations({ ...config, plugins: [...config.plugins, scim({
    connections: [], managedConnections: { credentialHashSecret: "mysql-scim-schema-secret-at-least-32-characters" },
  })], database: { type: "mysql", db: database.db } });
  const sql = await migrations.compileMigrations();
  await migrations.runMigrations();
  const groups = { auth: [], oauth_clients: [], sso: [], rate_limit: [], scim_managed: [], scim_binding: [], scim_canonical: [] };
  for (const statement of sql.split(';').map(sql => sql.trim()).filter(Boolean)) {
    const match = statement.match(/^create table `([^`]+)`|^create(?: unique)? index .*? on `([^`]+)`/i);
    assert.ok(match, statement);
    const table = match[1] ?? match[2];
    const group = table.startsWith("oauth") ? "oauth_clients" : table === "ssoProvider" ? "sso" : table === "rateLimit" ? "rate_limit"
      : table.startsWith("scimManaged") ? "scim_managed" : table === "scimConnectionBinding" ? "scim_binding"
      : table.startsWith("scim") ? "scim_canonical" : "auth";
    groups[group].push(`${statement};`);
  }
  const [columns] = await database.pool.promise().query(`SELECT TABLE_NAME AS tableName, COLUMN_NAME AS columnName,
    ORDINAL_POSITION AS position, COLUMN_TYPE AS type, IS_NULLABLE AS nullable, COLUMN_DEFAULT AS defaultValue,
    EXTRA AS extra FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() ORDER BY TABLE_NAME, ORDINAL_POSITION`);
  const [indexes] = await database.pool.promise().query(`SELECT TABLE_NAME AS tableName, INDEX_NAME AS indexName,
    NON_UNIQUE AS nonUnique, SEQ_IN_INDEX AS position, COLUMN_NAME AS columnName, SUB_PART AS prefixLength
    FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() ORDER BY TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX`);
  assert.equal(new Set(columns.map(row => row.tableName)).size, 35);
  assert.equal(columns.length, 375);
  assert.equal(indexes.length, 122);
  for (const [group, statements] of Object.entries(groups)) {
    assert.ok(statements.length, group);
    const suffix = group === "auth" ? "" : `_${group}`;
    await writeFile(new URL(`../../../crates/schema-registry/schema/mysql${suffix}.sql`, import.meta.url),
      `-- Generated from Better Auth 1.7.18 by mysql-schema-assets.mjs.\n\n${statements.join("\n\n")}\n`);
  }
  await writeFile(new URL("../../fixtures/schema/mysql-1.7.18.json", import.meta.url), JSON.stringify({ columns, indexes }, null, 2) + "\n");
  console.log(`${new Set(columns.map(row => row.tableName)).size} actual MySQL tables, ${columns.length} columns, ${indexes.length} index columns including managed SCIM`);
} finally {
  await database.close();
}
