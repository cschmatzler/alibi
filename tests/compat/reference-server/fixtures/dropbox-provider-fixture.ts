import { type BetterAuthOptions, betterAuth } from "better-auth";

/** Actual published factory with only its two fixed HTTP destinations redirected. */
export function dropboxProviderFixture(base: BetterAuthOptions) {
  let control: Record<string, unknown> = {};
  const receipts: unknown[] = [],
    mapperReceipts: unknown[] = [];
  const transport = Bun.serve({
    port: 0,
    async fetch(request) {
      const path = new URL(request.url).pathname,
        text = await request.text();
      receipts.push({
        path,
        method: request.method,
        authorization: request.headers.get("authorization"),
        contentType: request.headers.get("content-type"),
        body: path === "/token" ? Object.fromEntries(new URLSearchParams(text)) : text,
      });
      if (path === "/token")
        return Response.json(
          control.tokenResponse ?? {
            access_token: "fixture-dropbox-access",
            refresh_token: "fixture-dropbox-refresh",
            scope: "account_info.read",
            expires_in: 3600,
          },
          { status: typeof control.tokenStatus === "number" ? control.tokenStatus : 200 },
        );
      if (path === "/userinfo")
        return Response.json(
          control.profile ?? {
            account_id: "fixture-dropbox-subject",
            name: { display_name: "Dropbox User", given_name: "Dropbox", surname: "User" },
            email: "dropbox@example.invalid",
            email_verified: true,
            profile_photo_url: "https://images.example.invalid/dropbox.png",
          },
          { status: typeof control.userInfoStatus === "number" ? control.userInfoStatus : 200 },
        );
      return new Response("Unknown application-owned Dropbox destination", { status: 404 });
    },
  });
  const previousFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = (async (input, init) => {
    const request = new Request(input, init),
      url = new URL(request.url);
    const route =
      url.origin === "https://api.dropboxapi.com" && url.pathname === "/oauth2/token"
        ? "token"
        : url.origin === "https://api.dropboxapi.com" &&
            url.pathname === "/2/users/get_current_account"
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
    "offline",
    "online",
    "legacy",
    "mapped",
    "implicit-disabled",
    "signup-disabled",
    "configured-endpoint",
    "empty-clients",
    "client-key",
  ] as const) {
    const path = `/__test/profiles/social-dropbox-${mode}/api/auth`;
    profiles.set(
      path,
      betterAuth({
        ...base,
        basePath: path,
        plugins: [],
        socialProviders: {
          dropbox: {
            clientId: mode === "empty-clients" ? "" : "fixture-social-client",
            ...(mode !== "public" ? { clientSecret: "fixture-social-secret" } : {}),
            ...(["configured", "disabled-configured"].includes(mode)
              ? { scope: ["files.metadata.read", "account_info.read", "punctuation !~*'()"] }
              : {}),
            ...(["disabled-scope", "disabled-configured"].includes(mode)
              ? { disableDefaultScope: true }
              : {}),
            ...(["offline", "online", "legacy"].includes(mode)
              ? { accessType: mode as "offline" | "online" | "legacy" }
              : {}),
            ...(mode === "configured-endpoint"
              ? {
                  authorizationEndpoint:
                    "https://alternate-dropbox.example.invalid/authorize?state=stale&state=duplicate&client_id=stale&retained=value",
                  redirectURI: "https://client.example.invalid/dropbox-return",
                }
              : {}),
            ...(mode === "mapped"
              ? {
                  mapProfileToUser: (profile: Record<string, unknown>) => {
                    mapperReceipts.push(profile);
                    return {
                      id: "cannot-replace-raw-account",
                      name: "Mapped Dropbox User",
                      email: "mapped-dropbox@example.invalid",
                      emailVerified: false,
                      image: "https://images.example.invalid/mapped-dropbox.png",
                    };
                  },
                }
              : {}),
            ...(mode === "client-key" ? { clientKey: "fixture-dropbox-client-key" } : {}),
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
      if (path === "/__test/dropbox/control" && request.method === "POST") {
        control = await request.json();
        return Response.json({ status: true });
      }
      if (path === "/__test/dropbox/receipts") return Response.json(receipts);
      if (path === "/__test/dropbox/mapper-receipts") return Response.json(mapperReceipts);
      return null;
    },
  };
}
