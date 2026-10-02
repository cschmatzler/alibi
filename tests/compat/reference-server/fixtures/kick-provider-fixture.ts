import { type BetterAuthOptions, betterAuth } from "better-auth";

/** Actual published factory with only its two fixed HTTP destinations redirected. */
export function kickProviderFixture(base: BetterAuthOptions) {
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
        body: path === "/token" ? Object.fromEntries(new URLSearchParams(text)) : text,
      });

      if (path === "/token") {
        return Response.json(
          control.tokenResponse ?? {
            access_token: "fixture-kick-access",
            refresh_token: "fixture-kick-refresh",
            scope: "user:read",
            expires_in: 3600,
          },
          { status: typeof control.tokenStatus === "number" ? control.tokenStatus : 200 },
        );
      }

      if (path === "/userinfo") {
        return Response.json(
          control.envelope ?? {
            data: [
              control.profile ?? {
                user_id: "fixture-kick-subject",
                name: "Kick User",
                email: "kick@example.invalid",
                profile_picture: "https://images.example.invalid/kick.png",
              },
              {
                user_id: "unselected-kick-subject",
                name: "Unselected Kick User",
                email: "unselected-kick@example.invalid",
                profile_picture: "https://images.example.invalid/unselected-kick.png",
              },
            ],
          },
          { status: typeof control.userInfoStatus === "number" ? control.userInfoStatus : 200 },
        );
      }

      return new Response("Unknown application-owned Kick destination", { status: 404 });
    },
  });
  const previousFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = (async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    const route =
      url.origin === "https://id.kick.com" && url.pathname === "/oauth/token"
        ? "token"
        : url.origin === "https://api.kick.com" && url.pathname === "/public/v1/users"
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
    const path = `/__test/profiles/social-kick-${mode}/api/auth`;
    profiles.set(
      path,
      betterAuth({
        ...base,
        basePath: path,
        plugins: [],
        socialProviders: {
          kick: {
            clientId: mode === "empty-clients" ? "" : "fixture-social-client",
            ...(mode !== "public" ? { clientSecret: "fixture-social-secret" } : {}),
            ...(["configured", "disabled-configured"].includes(mode)
              ? { scope: ["channel:read", "user:read", "punctuation !~*'()"] }
              : {}),
            ...(["disabled-scope", "disabled-configured"].includes(mode)
              ? { disableDefaultScope: true }
              : {}),
            ...(mode === "configured-endpoint"
              ? {
                  authorizationEndpoint:
                    "https://alternate-kick.example.invalid/authorize?state=stale&state=duplicate&client_id=stale&retained=value",
                  redirectURI: "https://client.example.invalid/kick-return",
                }
              : {}),
            ...(mode === "mapped"
              ? {
                  mapProfileToUser: (profile: Record<string, unknown>) => {
                    mapperReceipts.push(profile);
                    return {
                      id: "cannot-replace-raw-account",
                      name: "Mapped Kick User",
                      email: "mapped-kick@example.invalid",
                      emailVerified: true,
                      image: "https://images.example.invalid/mapped-kick.png",
                    };
                  },
                }
              : {}),
            ...(mode === "client-key" ? { clientKey: "fixture-kick-client-key" } : {}),
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

      if (path === "/__test/kick/control" && request.method === "POST") {
        control = await request.json();
        return Response.json({ status: true });
      }

      if (path === "/__test/kick/receipts") {
        return Response.json(receipts);
      }

      if (path === "/__test/kick/mapper-receipts") {
        return Response.json(mapperReceipts);
      }

      return null;
    },
  };
}
