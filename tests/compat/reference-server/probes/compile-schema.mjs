import { readFile } from "node:fs/promises";

import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";

import { getMigrations } from "../node_modules/better-auth/dist/db/get-migration.mjs";
import { createDatabase } from "../sqlite.ts";
import { config } from "./schema-parity.mjs";

const kind = process.argv[2] ?? "sqlite";
if (!["sqlite", "postgres"].includes(kind)) throw new Error(`Unknown dialect ${kind}`);
const inspect = process.argv[3] === "inspect";
if (kind === "postgres" && !process.env.BETTER_AUTH_TEST_POSTGRES_URL) {
  throw new Error("Set BETTER_AUTH_TEST_POSTGRES_URL to a disposable database");
}
const pool =
  kind === "postgres"
    ? new Pool({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL, max: 1 })
    : null;
const schemaName = `alibi_schema_reference_${crypto.randomUUID().replaceAll("-", "")}`;
const database =
  kind === "sqlite"
    ? createDatabase(":memory:")
    : { type: "postgres", db: new Kysely({ dialect: new PostgresDialect({ pool }) }) };
try {
  if (pool) {
    await pool.query(`CREATE SCHEMA "${schemaName}"`);
    await pool.query(`SET search_path TO "${schemaName}"`);
  }
  const migration = await getMigrations({ ...config, database });
  if (inspect) {
    await migration.runMigrations();
    const query = await readFile(
      new URL(`../../../fixtures/schema/${kind}-inspect.sql`, import.meta.url),
      "utf8",
    );
    const result =
      kind === "sqlite"
        ? Object.values(database.prepare(query).get())[0]
        : Object.values((await pool.query(query)).rows[0])[0];
    console.log(JSON.stringify(typeof result === "string" ? JSON.parse(result) : result, null, 2));
  } else console.log(await migration.compileMigrations());
} finally {
  if (pool) {
    await pool.query("SET search_path TO public");
    await pool.query(`DROP SCHEMA "${schemaName}" CASCADE`);
    await pool.end();
  } else database.close();
}
