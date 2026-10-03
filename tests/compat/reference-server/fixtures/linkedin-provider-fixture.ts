import { betterAuth, type BetterAuthOptions } from "better-auth";

/** Actual published factory with only its two fixed HTTP destinations redirected. */
export function linkedinProviderFixture(base: BetterAuthOptions) {
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
            access_token: "fixture-linkedin-access",
            refresh_token: "fixture-linkedin-refresh",
            scope: "profile",
            expires_in: 3600,
          },
          { status: typeof control.tokenStatus === "number" ? control.tokenStatus : 200 },
        );
      }
      if (path === "/userinfo") {
        return Response.json(
          control.envelope ??
            control.profile ?? {
              sub: "fixture-linkedin-subject",
              name: "LinkedIn User",
              email: "linkedin@example.invalid",
              picture: "https://images.example.invalid/linkedin.png",
              email_verified: false,
              locale: { country: "US", language: "en" },
            },
          { status: typeof control.userInfoStatus === "number" ? control.userInfoStatus : 200 },
        );
      }
      return new Response("Unknown application-owned LinkedIn destination", { status: 404 });
    },
  });
  const previousFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = (async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    const route =
      url.origin === "https://www.linkedin.com" && url.pathname === "/oauth/v2/accessToken"
        ? "token"
        : url.origin === "https://api.linkedin.com" && url.pathname === "/v2/userinfo"
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
    const path = `/__test/profiles/social-linkedin-${mode}/api/auth`;
    profiles.set(
      path,
      betterAuth({
        ...base,
        basePath: path,
        plugins: [],
        socialProviders: {
          linkedin: {
            clientId: mode === "empty-clients" ? "" : "fixture-social-client",
            ...(mode !== "public" ? { clientSecret: "fixture-social-secret" } : {}),
            ...(["configured", "disabled-configured"].includes(mode)
              ? { scope: ["configured-scope", "profile", "punctuation !~*'()"] }
              : {}),
            ...(["disabled-scope", "disabled-configured"].includes(mode)
              ? { disableDefaultScope: true }
              : {}),
            ...(mode === "configured-endpoint"
              ? {
                  authorizationEndpoint:
                    "https://alternate-linkedin.example.invalid/authorize?state=stale&state=duplicate&client_id=stale&retained=value",
                  redirectURI: "https://client.example.invalid/linkedin-return",
                }
              : {}),
            ...(mode === "mapped"
              ? {
                  mapProfileToUser: (profile: Record<string, unknown>) => {
                    mapperReceipts.push(profile);
                    return {
                      providerExtra: { retained: true },
                      id: "cannot-replace-raw-account",
                      name: "Mapped LinkedIn User",
                      email: "mapped-linkedin@example.invalid",
                      emailVerified: true,
                      image: "https://images.example.invalid/mapped-linkedin.png",
                    };
                  },
                }
              : {}),
            ...(mode === "client-key" ? { clientKey: "fixture-linkedin-client-key" } : {}),
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
      if (path === "/__test/linkedin/control" && request.method === "POST") {
        control = await request.json();
        return Response.json({ status: true });
      }
      if (path === "/__test/linkedin/receipts") return Response.json(receipts);
      if (path === "/__test/linkedin/mapper-receipts") return Response.json(mapperReceipts);
      return null;
    },
  };
}
