import { betterAuth, type BetterAuthOptions } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { SQL } from "bun";
import { PostgresDialect } from "kysely";
export async function postgresSchemaFixture(base: BetterAuthOptions) {
  const connectionURL = process.env.BETTER_AUTH_TEST_POSTGRES_URL;
  if (!connectionURL)
    return {
      async handle(_request: Request) {
        return null;
      },
    };
  const sql = new SQL(connectionURL);
  const namespace = `compat_schema_ts_${process.env.PORT}`;
  // Adapt the real Bun Postgres connection to Kysely's documented pg-pool interface.
  const pool = {
    async connect() {
      const connection = await sql.reserve();
      return {
        async query(text: string, parameters: unknown[]) {
          const rows = await connection.unsafe(text, parameters as any[]);
          return {
            rows: Array.from(rows),
            rowCount: rows.count,
            command: text.trim().split(/\s+/)[0].toUpperCase(),
          };
        },
        release() {
          connection.release();
        },
      };
    },
    async end() {
      await sql.close();
    },
  };
  const options: BetterAuthOptions = {
    ...base,
    database: {
      dialect: new PostgresDialect({ pool: pool as any }),
      type: "postgres",
      schemaName: namespace,
    },
    basePath: "/__test/profiles/postgres-schema/api/auth",
    plugins: [],
  };
  await (await getMigrations(options)).runMigrations();
  const auth = betterAuth(options);
  return {
    async handle(request: Request) {
      const url = new URL(request.url);
      if (url.pathname.startsWith("/__test/profiles/postgres-schema/api/auth/"))
        return auth.handler(request);
      if (url.pathname === "/__test/postgres-schema/state") {
        const schemas = await sql.unsafe(
          "SELECT schema_name FROM information_schema.schemata WHERE schema_name = $1",
          [namespace],
        );
        const users = await sql.unsafe(
          `SELECT id, name, email FROM "${namespace}"."user" ORDER BY email`,
        );
        const sessions = await sql.unsafe(`SELECT "userId" AS owner FROM "${namespace}"."session"`);
        const path = await sql.unsafe("SHOW search_path");
        return Response.json({
          schemaExists: schemas.length === 1,
          connectionUsesNamespace: path[0].search_path.includes(namespace),
          users: Array.from(users),
          sessions: Array.from(sessions),
        });
      }
      return null;
    },
  };
}
