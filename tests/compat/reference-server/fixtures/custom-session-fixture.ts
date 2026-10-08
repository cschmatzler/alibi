import { type BetterAuthOptions, betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import { customSession, jwt, multiSession } from "better-auth/plugins";

export function createCustomSessionFixture(base: BetterAuthOptions) {
  let counter = 0;
  const calls = new Map<string, number>();
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();

  for (const name of [
    "custom-session-list-default",
    "custom-session-list-false",
    "custom-session",
    "custom-session-jwt",
    "custom-session-deferred",
    "custom-session-core-error",
  ]) {
    const path = `/__test/profiles/${name}/api/auth`;
    profiles.set(
      path,
      betterAuth({
        ...base,
        basePath: path,
        session: {
          ...base.session,
          deferSessionRefresh: name.endsWith("-deferred"),
          additionalFields: {
            label: {
              type: "string",
              defaultValue: "custom-public-label",
              ...(name.endsWith("-core-error")
                ? {
                    transform: {
                      async output() {
                        throw new Error("Configured session projection failed");
                      },
                    },
                  }
                : {}),
            },
            hidden: { type: "string", defaultValue: "custom-server-secret", returned: false },
          },
        },
        databaseHooks: {
          session: {
            create: {
              async before(session) {
                return {
                  data: { ...session, token: `custom${String(++counter).padStart(27, "0")}` },
                };
              },
            },
          },
        },
        plugins: [
          customSession(
            async (session, ctx) => {
              const count = (calls.get(name) ?? 0) + 1;
              calls.set(name, count);
              const mode = ctx.headers?.get("x-custom-session");

              if (mode === "error") {
                throw new APIError("FORBIDDEN", {
                  code: "CUSTOM_SESSION_DENIED",
                  message: "Application session denied",
                });
              }

              if (mode === "ordinary") {
                throw new Error("Application session failed");
              }

              if (mode === "null") {
                return null;
              }

              if (mode === "filtered") {
                return { userId: session.user.id, label: session.user.name };
              }

              const stored = await ctx.context.internalAdapter.findUserById(session.user.id);

              if (!stored) {
                throw new Error("Authenticated user is missing");
              }

              return {
                ...session,
                application: {
                  userId: stored.id,
                  label: stored.name,
                  path: ctx.path,
                  ...(name.startsWith("custom-session-list-") ? { calls: count } : {}),
                },
              };
            },
            undefined,
            name === "custom-session-list-default"
              ? undefined
              : { shouldMutateListDeviceSessionsEndpoint: name !== "custom-session-list-false" },
          ),
          multiSession(),
          ...(name.endsWith("-jwt") || name.endsWith("-deferred") ? [jwt()] : []),
        ],
      }),
    );
  }

  return {
    profiles,
    reset() {
      counter = 0;
      calls.clear();
    },
  };
}
