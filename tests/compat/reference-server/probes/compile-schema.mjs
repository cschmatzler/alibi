import { Database } from "bun:sqlite";

import { SQL } from "bun";
import { Kysely, PostgresDialect } from "kysely";

import { getMigrations } from "../node_modules/better-auth/dist/db/get-migration.mjs";
import { config } from "./schema-parity.mjs";
const kind = process.argv[2] ?? "sqlite";
if (!["sqlite", "postgres"].includes(kind)) throw new Error(`Unknown dialect ${kind}`);
const inspect = process.argv[3] === "inspect";
if (kind === "postgres" && !process.env.BETTER_AUTH_TEST_POSTGRES_URL)
  throw new Error("Set BETTER_AUTH_TEST_POSTGRES_URL to a disposable database");
const sql =
  kind === "postgres" ? new SQL(process.env.BETTER_AUTH_TEST_POSTGRES_URL, { max: 1 }) : null;
const schemaName = `alibi_schema_reference_${crypto.randomUUID().replaceAll("-", "")}`;
const pool = sql && {
  async connect() {
    return {
      async query(text, params) {
        const rows = await sql.unsafe(text, params);
        return { rows, rowCount: rows.count };
      },
      release() {},
    };
  },
  async end() {
    await sql.close();
  },
};
const database =
  kind === "sqlite"
    ? new Database(":memory:")
    : { type: "postgres", db: new Kysely({ dialect: new PostgresDialect({ pool }) }) };
try {
  if (sql) {
    await sql.unsafe(`CREATE SCHEMA "${schemaName}"`);
    await sql.unsafe(`SET search_path TO "${schemaName}"`);
  }
  const migration = await getMigrations({ ...config, database });
  if (inspect) {
    await migration.runMigrations();
    const query = await Bun.file(
      new URL(`../../../fixtures/schema/${kind}-inspect.sql`, import.meta.url),
    ).text();
    const result =
      kind === "sqlite"
        ? Object.values(database.query(query).get())[0]
        : Object.values((await sql.unsafe(query))[0])[0];
    console.log(JSON.stringify(typeof result === "string" ? JSON.parse(result) : result, null, 2));
  } else console.log(await migration.compileMigrations());
} finally {
  if (sql) {
    await sql.unsafe("SET search_path TO public");
    await sql.unsafe(`DROP SCHEMA "${schemaName}" CASCADE`);
    await sql.close();
  } else database.close();
}
