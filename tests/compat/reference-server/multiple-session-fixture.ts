import { type BetterAuthOptions, betterAuth } from "better-auth";
import { multiSession } from "better-auth/plugins";

/** Configured token generation makes SQLite's result order observable. */
export function createMultipleSessionFixture(base: BetterAuthOptions) {
  let counter = 0;
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  for (const name of ["multi-session", "multi-session-limited"]) {
    const path = `/__test/profiles/${name}/api/auth`;
    profiles.set(
      path,
      betterAuth({
        ...base,
        basePath: path,
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
        plugins: [multiSession({ maximumSessions: name === "multi-session-limited" ? 2 : 5 })],
      }),
    );
  }
  return {
    profiles,
    reset() {
      counter = 0;
    },
  };
}
