import { type BetterAuthOptions, betterAuth } from "better-auth";
import { createAuthEndpoint, createAuthMiddleware } from "better-auth/api";

/** Actual router security policy with application hook observations. */
export function createDispatchFixture(base: BetterAuthOptions) {
  const events: { path: string; method: string }[] = [];
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  for (const mode of [
    "default",
    "csrf-off",
    "origin-off",
    "origin-off-explicit-csrf",
    "origin-path",
    "trailing",
    "disabled-email",
    "disabled-template",
    "disabled-literal",
  ] as const) {
    const name = `dispatch-${mode}`;
    profiles.set(
      `/__test/profiles/${name}/api/auth`,
      betterAuth({
        ...base,
        basePath: `/__test/profiles/${name}/api/auth`,
        advanced: {
          ...(mode === "csrf-off" ? { disableCSRFCheck: true } : {}),
          ...(mode === "origin-off" || mode === "origin-off-explicit-csrf"
            ? { disableOriginCheck: true }
            : {}),
          ...(mode === "origin-off-explicit-csrf" ? { disableCSRFCheck: false } : {}),
          ...(mode === "origin-path" ? { disableOriginCheck: ["/sign-in/"] } : {}),
          skipTrailingSlashes: mode === "trailing",
        },
        disabledPaths:
          mode === "disabled-email"
            ? ["/sign-in/email"]
            : mode === "disabled-template"
              ? ["/owned/:id"]
              : mode === "disabled-literal"
                ? ["/owned/item"]
                : [],
        plugins: [
          {
            id: "dispatch-application",
            hooks: {
              before: [
                {
                  matcher: () => true,
                  handler: createAuthMiddleware(async (ctx) => {
                    events.push({
                      path: new URL(ctx.request!.url).pathname.slice(
                        `/__test/profiles/${name}/api/auth`.length,
                      ),
                      method: ctx.method ?? "GET",
                    });
                  }),
                },
              ],
            },
            endpoints: {
              owned: createAuthEndpoint("/owned/:id", { method: "GET" }, async (ctx) =>
                ctx.json({ id: ctx.params.id }),
              ),
              child: createAuthEndpoint(
                "/sign-in/child",
                { method: "POST", metadata: { allowedMediaTypes: [" Application/JSON "] } },
                async (ctx) => ctx.json({ payload: ctx.body }),
              ),
              peer: createAuthEndpoint(
                "/sign-in-peer",
                { method: "POST", metadata: { allowedMediaTypes: [" Application/JSON "] } },
                async (ctx) => ctx.json({ payload: ctx.body }),
              ),
            },
          },
        ],
      }),
    );
  }
  return {
    profiles,
    handle(request: Request) {
      if (new URL(request.url).pathname !== "/__test/dispatch-events") return null;
      return Response.json(events.splice(0));
    },
  };
}
