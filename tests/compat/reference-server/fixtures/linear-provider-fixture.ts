import { betterAuth, type BetterAuthOptions } from "better-auth";

/** Actual published factory with only its two fixed HTTP destinations redirected. */
export function linearProviderFixture(base: BetterAuthOptions) {
  let control: Record<string, unknown> = {};
  const receipts: unknown[] = [];
  const mapperReceipts: unknown[] = [];
  const transport = Bun.serve({
    port: 0,
    async fetch(request) {
      const path = new URL(request.url).pathname;
      const text = await request.text();
      receipts.push({
        path,
        method: request.method,
        authorization: request.headers.get("authorization"),
        contentType: request.headers.get("content-type"),
        body:
          path === "/token"
            ? Object.fromEntries(new URLSearchParams(text))
            : path === "/userinfo"
              ? JSON.parse(text)
              : text,
      });
      if (path === "/token") {
        return Response.json(
          control.tokenResponse ?? {
            access_token: "fixture-linear-access",
            refresh_token: "fixture-linear-refresh",
            scope: "read",
            expires_in: 3600,
          },
          { status: typeof control.tokenStatus === "number" ? control.tokenStatus : 200 },
        );
      }
      if (path === "/userinfo") {
        return Response.json(
          control.envelope ?? {
            data: {
              viewer: control.profile ?? {
                id: "fixture-linear-subject",
                name: "Linear User",
                email: "linear@example.invalid",
                avatarUrl: "https://images.example.invalid/linear.png",
                active: true,
                createdAt: "2020-01-01T00:00:00.000Z",
                updatedAt: "2020-01-02T00:00:00.000Z",
              },
            },
          },
          { status: typeof control.userInfoStatus === "number" ? control.userInfoStatus : 200 },
        );
      }
      return new Response("Unknown application-owned Linear destination", { status: 404 });
    },
  });
  const previousFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = (async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    const route =
      url.origin === "https://api.linear.app" && url.pathname === "/oauth/token"
        ? "token"
        : url.origin === "https://api.linear.app" && url.pathname === "/graphql"
          ? "userinfo"
          : null;
    return route
      ? previousFetch(new Request(`${transport.url}${route}`, request))
      : previousFetch(input, init);
  }) as typeof fetch;
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  for (const mode of [
    "default",
    "public",
    "configured",
    "disabled-scope",
    "disabled-configured",
    "mapped",
    "implicit-disabled",
    "signup-disabled",
    "configured-endpoint",
    "empty-clients",
    "client-key",
  ] as const) {
    const path = `/__test/profiles/social-linear-${mode}/api/auth`;
    profiles.set(
      path,
      betterAuth({
        ...base,
        basePath: path,
        plugins: [],
        socialProviders: {
          linear: {
            clientId: mode === "empty-clients" ? "" : "fixture-social-client",
            ...(mode !== "public" ? { clientSecret: "fixture-social-secret" } : {}),
            ...(["configured", "disabled-configured"].includes(mode)
              ? { scope: ["configured-scope", "read", "punctuation !~*'()"] }
              : {}),
            ...(["disabled-scope", "disabled-configured"].includes(mode)
              ? { disableDefaultScope: true }
              : {}),
            ...(mode === "configured-endpoint"
              ? {
                  authorizationEndpoint:
                    "https://alternate-linear.example.invalid/authorize?state=stale&state=duplicate&client_id=stale&retained=value",
                  redirectURI: "https://client.example.invalid/linear-return",
                }
              : {}),
            ...(mode === "mapped"
              ? {
                  mapProfileToUser: (profile: Record<string, unknown>) => {
                    mapperReceipts.push(profile);
                    return {
                      linearPublic: { source: profile.id ?? null, scopes: ["read"] },
                      id: "cannot-replace-raw-account",
                      name: "Mapped Linear User",
                      email: "mapped-linear@example.invalid",
                      emailVerified: true,
                      image: "https://images.example.invalid/mapped-linear.png",
                    };
                  },
                }
              : {}),
            ...(mode === "client-key" ? { clientKey: "fixture-linear-client-key" } : {}),
            disableImplicitSignUp: mode === "implicit-disabled",
            disableSignUp: mode === "signup-disabled",
          },
        },
      }),
    );
  }
  return {
    profiles,
    reset() {
      control = {};
      receipts.length = 0;
      mapperReceipts.length = 0;
    },
    async handle(request: Request) {
      const path = new URL(request.url).pathname;
      if (path === "/__test/linear/control" && request.method === "POST") {
        control = await request.json();
        return Response.json({ status: true });
      }
      if (path === "/__test/linear/receipts") return Response.json(receipts);
      if (path === "/__test/linear/mapper-receipts") return Response.json(mapperReceipts);
      return null;
    },
  };
}
