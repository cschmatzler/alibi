/** Installed Source policies exercised through actual authentication mutations. */
import { Database } from "bun:sqlite";

import { type BetterAuthOptions, betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";

export async function createRateLimitFixture(base: BetterAuthOptions) {
  const profiles = new Map(
    ["ordered", "default", "database-first", "database-second"].map((name) => {
      const profile = `rate-limit-${name}`;
      return [
        profile,
        betterAuth({
          ...base,
          plugins: (base.plugins ?? []).filter((plugin) => plugin.id === "email-otp"),
          basePath: `/__test/profiles/${profile}/api/auth`,
          rateLimit: {
            enabled: true,
            storage: name.startsWith("database-") ? "database" : "memory",
            window: 60,
            max: name === "ordered" ? 1 : 10000,
            ...(name.startsWith("database-")
              ? { customRules: { "/get-session": { window: 1, max: 2 } } }
              : {}),
            ...(name === "ordered"
              ? {
                  customRules: {
                    "/sign-up/*": { window: 60, max: 2 },
                    "/sign-up/email": { window: 60, max: 4 },
                    "/get-session": async (request, inherited) =>
                      request.headers.get("x-rate-bypass") === "yes"
                        ? false
                        : {
                            ...inherited,
                            max: 1,
                            window:
                              request.headers.get("x-rate-zero") === "yes" ? 0 : inherited.window,
                          },
                    "/list-sessions": false,
                  },
                }
              : {}),
          },
        }),
      ] as const;
    }),
  );
  const databaseAuth = profiles.get("rate-limit-database-first")!;
  const context = await databaseAuth.$context;
  await (await getMigrations(context.options)).runMigrations();
  return {
    async handle(request: Request) {
      const url = new URL(request.url);
      if (url.pathname === "/__test/rate-database-control" && request.method === "POST") {
        const { action } = await request.json();
        if (!(base.database instanceof Database))
          throw new Error("Fixture requires SQLite database");
        base.database.run(
          action === "disable"
            ? 'ALTER TABLE "rateLimit" RENAME TO "fixtureRateLimitHeld"'
            : 'ALTER TABLE "fixtureRateLimitHeld" RENAME TO "rateLimit"',
        );
        return Response.json({ status: true });
      }
      if (url.pathname === "/__test/rate-database-state") {
        // Quota records use different native primary-key layouts. Observe the
        // actual shared quota contract, independently of adapter bookkeeping.
        const rows = await context.adapter.findMany({
          model: "rateLimit",
          sortBy: { field: "key", direction: "asc" },
        });
        return Response.json(
          rows.map((row: any) => ({
            key: row.key,
            count: row.count,
            lastRequest: Number(row.lastRequest),
          })),
        );
      }
      for (const [profile, auth] of profiles) {
        if (url.pathname.startsWith(`/__test/profiles/${profile}/api/auth/`)) {
          return auth.handler(request);
        }
      }
      return null;
    },
  };
}
