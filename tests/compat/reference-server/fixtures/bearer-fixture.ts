import { apiKey } from "@better-auth/api-key";
import { type BetterAuthOptions, betterAuth } from "better-auth";
import { createAuthMiddleware } from "better-auth/api";
import { bearer, multiSession } from "better-auth/plugins";

/** Genuine configured tokens let both runtimes compare complete signed headers. */
export function createBearerFixture(base: BetterAuthOptions) {
  let counter = 0;
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();

  for (const name of [
    "bearer-default",
    "bearer-signed",
    "bearer-composition",
    "bearer-renamed-cookie",
    "bearer-secure-cookie",
  ]) {
    const path = `/__test/profiles/${name}/api/auth`;
    profiles.set(
      path,
      betterAuth({
        ...base,
        basePath: path,
        ...(name === "bearer-renamed-cookie"
          ? {
              advanced: {
                ...base.advanced,
                cookies: { session_token: { name: "configured-bearer-token" } },
              },
            }
          : {}),
        ...(name === "bearer-secure-cookie"
          ? { advanced: { ...base.advanced, useSecureCookies: true, cookiePrefix: "bearer-app" } }
          : {}),
        databaseHooks: {
          session: {
            create: {
              async before(session) {
                return {
                  data: { ...session, token: `bearer${String(++counter).padStart(26, "0")}` },
                };
              },
            },
          },
        },
        plugins: [
          ...(name === "bearer-signed"
            ? [
                {
                  id: "application-exposure",
                  hooks: {
                    after: [
                      {
                        matcher: () => true,
                        handler: createAuthMiddleware(async (ctx) => {
                          ctx.setHeader(
                            "access-control-expose-headers",
                            "X-First, X-First, X-Second",
                          );
                        }),
                      },
                    ],
                  },
                },
              ]
            : []),
          bearer({ requireSignature: name === "bearer-signed" }),
          ...(name === "bearer-composition"
            ? [multiSession(), apiKey({ enableSessionForAPIKeys: true })]
            : []),
        ],
      }),
    );
  }

  return {
    profiles,
    async control(request: Request) {
      const input = (await request.json()) as any;
      const profile = input.profile ?? "bearer-default";
      const path = `/__test/profiles/${profile}/api/auth`;
      const auth = profiles.get(path);
      if (!auth) {
        return new Response(null, { status: 404 });
      }
      const options = {
        ...(Object.hasOwn(input, "body") ? { body: input.body } : {}),
        ...(Object.hasOwn(input, "headers") ? { headers: new Headers(input.headers) } : {}),
        ...(Object.hasOwn(input, "requestHeaders")
          ? {
              request: new Request(
                `${typeof base.baseURL === "string" ? base.baseURL : "http://localhost:3000"}${path}/get-session`,
                { headers: input.requestHeaders },
              ),
            }
          : {}),
        asResponse: true,
      };
      const api = auth.api as any;
      const operation =
        (
          { "sign-up": "signUpEmail", list: "listDeviceSessions", "sign-out": "signOut" } as Record<
            string,
            string
          >
        )[input.action] ?? "getSession";
      return api[operation](options);
    },
    reset() {
      counter = 0;
    },
  };
}
