import { type BetterAuthOptions, betterAuth } from "better-auth";
import { multiSession } from "better-auth/plugins";

/** Configured token generation makes SQLite's result order observable. */
export function createMultipleSessionFixture(base: BetterAuthOptions) {
  let counter = 0;
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();

  const limits: Record<string, number> = {
    "multi-session": 5,
    "multi-session-limited": 2,
    "multi-session-zero": 0,
    "multi-session-fractional": 1.5,
    "multi-session-negative": -1,
    "multi-session-nan": Number.NaN,
    "multi-session-infinite": Number.POSITIVE_INFINITY,
    "multi-session-negative-infinite": Number.NEGATIVE_INFINITY,
    "multi-session-cookie-alias": 5,
    "multi-session-cookie-prefix": 5,
  };
  for (const [name, maximumSessions] of Object.entries(limits)) {
    const path = `/__test/profiles/${name}/api/auth`;
    profiles.set(
      path,
      betterAuth({
        ...base,
        basePath: path,
        ...(name.startsWith("multi-session-cookie-")
          ? {
              advanced: {
                ...base.advanced,
                cookiePrefix: "device-proof",
                defaultCookieAttributes: { path, httpOnly: false, sameSite: "strict", maxAge: 71 },
                ...(name.endsWith("alias")
                  ? {
                      cookies: {
                        session_token: {
                          name: "configured-device-token",
                          attributes: { httpOnly: true, sameSite: "lax", maxAge: 123 },
                        },
                      },
                    }
                  : {}),
              },
            }
          : {}),
        databaseHooks: {
          session: {
            create: {
              async before(session) {
                const count = ++counter;
                const rank = count % 3 === 1 ? 3 : count % 3 === 2 ? 1 : 2;
                return {
                  data: {
                    ...session,
                    token: `${String(rank).padStart(4, "0")}${String(count).padStart(28, "0")}`,
                  },
                };
              },
            },
          },
        },
        plugins: [multiSession({ maximumSessions })],
      }),
    );
  }

  const statelessPath = "/__test/profiles/multi-session-stateless/api/auth";
  profiles.set(
    statelessPath,
    betterAuth({
      ...base,
      database: undefined,
      basePath: statelessPath,
      session: { cookieCache: { enabled: true, strategy: "jwe", maxAge: 300 } },
      plugins: [multiSession()],
    }),
  );

  return {
    profiles,
    reset() {
      counter = 0;
    },
  };
}
