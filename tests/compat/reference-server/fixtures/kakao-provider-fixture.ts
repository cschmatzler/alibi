import { type BetterAuthOptions, betterAuth } from "better-auth";

/** Actual published factory with only its two fixed HTTP destinations redirected. */
export function kakaoProviderFixture(base: BetterAuthOptions) {
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
            access_token: "fixture-kakao-access",
            refresh_token: "fixture-kakao-refresh",
            scope: "account_email profile_image profile_nickname",
            expires_in: 3600,
          },
          { status: typeof control.tokenStatus === "number" ? control.tokenStatus : 200 },
        );
      }

      if (path === "/userinfo") {
        return Response.json(
          control.profile ?? {
            id: 4242,
            kakao_account: {
              name: "Kakao Account",
              email: "kakao@example.invalid",
              is_email_valid: true,
              is_email_verified: true,
              profile: {
                nickname: "Kakao User",
                profile_image_url: "https://images.example.invalid/kakao.png",
                thumbnail_image_url: "https://images.example.invalid/kakao-thumb.png",
              },
            },
          },
          { status: typeof control.userInfoStatus === "number" ? control.userInfoStatus : 200 },
        );
      }

      return new Response("Unknown application-owned Kakao destination", { status: 404 });
    },
  });
  const previousFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = (async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    const route =
      url.origin === "https://kauth.kakao.com" && url.pathname === "/oauth/token"
        ? "token"
        : url.origin === "https://kapi.kakao.com" && url.pathname === "/v2/user/me"
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
    const path = `/__test/profiles/social-kakao-${mode}/api/auth`;
    profiles.set(
      path,
      betterAuth({
        ...base,
        basePath: path,
        plugins: [],
        socialProviders: {
          kakao: {
            clientId: mode === "empty-clients" ? "" : "fixture-social-client",
            ...(mode !== "public" ? { clientSecret: "fixture-social-secret" } : {}),
            ...(["configured", "disabled-configured"].includes(mode)
              ? { scope: ["friends", "account_email", "punctuation !~*'()"] }
              : {}),
            ...(["disabled-scope", "disabled-configured"].includes(mode)
              ? { disableDefaultScope: true }
              : {}),
            ...(mode === "configured-endpoint"
              ? {
                  authorizationEndpoint:
                    "https://alternate-kakao.example.invalid/authorize?state=stale&state=duplicate&client_id=stale&retained=value",
                  redirectURI: "https://client.example.invalid/kakao-return",
                }
              : {}),
            ...(mode === "mapped"
              ? {
                  mapProfileToUser: (profile: Record<string, unknown>) => {
                    mapperReceipts.push(profile);
                    return {
                      id: "cannot-replace-raw-account",
                      name: "Mapped Kakao User",
                      email: "mapped-kakao@example.invalid",
                      emailVerified: false,
                      image: "https://images.example.invalid/mapped-kakao.png",
                    };
                  },
                }
              : {}),
            ...(mode === "client-key" ? { clientKey: "fixture-kakao-client-key" } : {}),
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

      if (path === "/__test/kakao/control" && request.method === "POST") {
        control = await request.json();
        return Response.json({ status: true });
      }

      if (path === "/__test/kakao/receipts") {
        return Response.json(receipts);
      }

      if (path === "/__test/kakao/mapper-receipts") {
        return Response.json(mapperReceipts);
      }

      return null;
    },
  };
}
