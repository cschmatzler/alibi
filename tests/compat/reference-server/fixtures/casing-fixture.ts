import { Database } from "bun:sqlite";

import { createKyselyAdapter } from "@better-auth/kysely-adapter";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { openAPI } from "better-auth/plugins";

export async function casingFixture(base: BetterAuthOptions) {
  const db = base.database as Database;
  const { kysely } = await createKyselyAdapter(base);
  const auth = betterAuth({
    ...base,
    database: { db: kysely!, type: "sqlite", casing: "snake" },
    basePath: "/__test/profiles/snake-casing/api/auth",
    plugins: [
      ...(base.plugins ?? []).filter((plugin) =>
        ["admin", "organization", "two-factor", "username"].includes(plugin.id),
      ),
      openAPI(),
    ],
  });
  return {
    async handle(request: Request) {
      const url = new URL(request.url);
      if (url.pathname.startsWith("/__test/profiles/snake-casing/api/auth/")) {
        return auth.handler(request);
      }
      if (url.pathname === "/__test/casing/state") {
        // The pinned adapter accepts casing but leaves its physical camel-case schema unchanged.
        const columns = db.query('PRAGMA table_info("user")').all() as { name: string }[];
        if (!columns.some((c) => c.name === "emailVerified")) {
          throw new Error("Pinned casing behavior changed");
        }
        return Response.json({
          users: db
            .query('SELECT id, name, email, "emailVerified" AS verified FROM user WHERE id = ?')
            .all(url.searchParams.get("userId")),
          sessions: db
            .query('SELECT "userId" AS owner FROM session WHERE "userId" = ?')
            .all(url.searchParams.get("userId")),
        });
      }
      return null;
    },
  };
}
