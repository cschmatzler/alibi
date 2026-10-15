import { betterAuth, type BetterAuthOptions } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { PostgresDialect } from "kysely";
import { Pool } from "pg";

export async function postgresSchemaFixture(base: BetterAuthOptions) {
  const connectionURL = process.env.BETTER_AUTH_TEST_POSTGRES_URL;
  if (!connectionURL) {
    return {
      async handle(_request: Request) {
        return null;
      },
    };
  }
  const pool = new Pool({ connectionString: connectionURL, max: 1 });
  const namespace = `compat_schema_ts_${process.env.PORT}`;
  const options: BetterAuthOptions = {
    ...base,
    database: {
      dialect: new PostgresDialect({ pool }),
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
      if (url.pathname.startsWith("/__test/profiles/postgres-schema/api/auth/")) {
        return auth.handler(request);
      }
      if (url.pathname === "/__test/postgres-schema/state") {
        const schemas = (
          await pool.query(
            "SELECT schema_name FROM information_schema.schemata WHERE schema_name = $1",
            [namespace],
          )
        ).rows;
        const users = (
          await pool.query(`SELECT id, name, email FROM "${namespace}"."user" ORDER BY email`)
        ).rows;
        const sessions = (
          await pool.query(`SELECT "userId" AS owner FROM "${namespace}"."session"`)
        ).rows;
        const path = (await pool.query("SHOW search_path")).rows;
        return Response.json({
          schemaExists: schemas.length === 1,
          connectionUsesNamespace: path[0].search_path.includes(namespace),
          users,
          sessions,
        });
      }
      return null;
    },
  };
}
