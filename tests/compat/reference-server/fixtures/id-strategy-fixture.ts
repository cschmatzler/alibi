import { Database } from "bun:sqlite";

import { betterAuth, type BetterAuthOptions } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
export async function idStrategyFixture(base: BetterAuthOptions) {
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  const databases = new Map<string, Database>();
  const events = new Map<string, unknown[]>();
  for (const mode of ["uuid", "serial", "custom", "false", "throw"]) {
    const db = new Database(":memory:");
    databases.set(mode, db);
    const receipts: unknown[] = [];
    events.set(mode, receipts);
    let sequence = 0;
    const options: BetterAuthOptions = {
      ...base,
      database: db,
      basePath: `/__test/profiles/id-strategy-${mode}/api/auth`,
      advanced: {
        ...base.advanced,
        database: {
          ...base.advanced?.database,
          generateId:
            mode === "uuid" || mode === "serial"
              ? mode
              : ({ model, size }: any) => {
                  receipts.push({ model, ...(size === undefined ? {} : { size }) });
                  if (mode === "throw") throw new Error("Application ID generation failed");
                  return mode === "false" ? false : `${model}_application_${++sequence}`;
                },
        },
      },
    };
    await (await getMigrations(options)).runMigrations();
    profiles.set(mode, betterAuth(options));
  }
  return {
    async handle(request: Request) {
      const path = new URL(request.url).pathname;
      for (const [mode, auth] of profiles) {
        if (path.startsWith(`/__test/profiles/id-strategy-${mode}/api/auth/`)) {
          return auth.handler(request);
        }
        if (path === `/__test/id-strategy/${mode}/state`) {
          const db = databases.get(mode)!;
          // Compare identifier values across application-selected integer/text schemas.
          return Response.json({
            users: db.query("SELECT CAST(id AS TEXT) AS id FROM user").all(),
            accounts: db
              .query(
                'SELECT CAST(id AS TEXT) AS id, CAST("userId" AS TEXT) AS "userId" FROM account',
              )
              .all(),
            sessions: db
              .query(
                'SELECT CAST(id AS TEXT) AS id, CAST("userId" AS TEXT) AS "userId" FROM session',
              )
              .all(),
            verification: db.query("SELECT CAST(id AS TEXT) AS id FROM verification").all(),
            events: events.get(mode),
          });
        }
      }
      return null;
    },
  };
}
