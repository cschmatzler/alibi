import { type BetterAuthOptions, betterAuth } from "better-auth";

/** Actual published factory with only its two fixed HTTP destinations redirected. */
export function huggingfaceProviderFixture(base: BetterAuthOptions) {
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
            access_token: "fixture-huggingface-access",
            refresh_token: "fixture-huggingface-refresh",
            scope: "openid profile email",
            expires_in: 3600,
          },
          { status: typeof control.tokenStatus === "number" ? control.tokenStatus : 200 },
        );
      }

      if (path === "/userinfo") {
        return Response.json(
          control.profile ?? {
            sub: "fixture-huggingface-subject",
            name: "Hugging Face User",
            preferred_username: "hf-user",
            email: "huggingface@example.invalid",
            email_verified: true,
            picture: "https://images.example.invalid/huggingface.png",
          },
          { status: typeof control.userInfoStatus === "number" ? control.userInfoStatus : 200 },
        );
      }

      return new Response("Unknown application-owned HuggingFace destination", { status: 404 });
    },
  });
  const previousFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = (async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    const route =
      url.origin === "https://huggingface.co" && url.pathname === "/oauth/token"
        ? "token"
        : url.origin === "https://huggingface.co" && url.pathname === "/oauth/userinfo"
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
    const path = `/__test/profiles/social-huggingface-${mode}/api/auth`;
    profiles.set(
      path,
      betterAuth({
        ...base,
        basePath: path,
        plugins: [],
        socialProviders: {
          huggingface: {
            clientId: mode === "empty-clients" ? "" : "fixture-social-client",
            ...(mode !== "public" ? { clientSecret: "fixture-social-secret" } : {}),
            ...(["configured", "disabled-configured"].includes(mode)
              ? { scope: ["read-repos", "email", "punctuation !~*'()"] }
              : {}),
            ...(["disabled-scope", "disabled-configured"].includes(mode)
              ? { disableDefaultScope: true }
              : {}),
            ...(mode === "configured-endpoint"
              ? {
                  authorizationEndpoint:
                    "https://alternate-huggingface.example.invalid/authorize?state=stale&state=duplicate&client_id=stale&retained=value",
                  redirectURI: "https://client.example.invalid/huggingface-return",
                }
              : {}),
            ...(mode === "mapped"
              ? {
                  mapProfileToUser: (profile: Record<string, unknown>) => {
                    mapperReceipts.push(profile);
                    return {
                      id: "cannot-replace-raw-account",
                      name: "Mapped HuggingFace User",
                      email: "mapped-huggingface@example.invalid",
                      emailVerified: false,
                      image: "https://images.example.invalid/mapped-huggingface.png",
                    };
                  },
                }
              : {}),
            ...(mode === "client-key" ? { clientKey: "fixture-huggingface-client-key" } : {}),
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

      if (path === "/__test/huggingface/control" && request.method === "POST") {
        control = await request.json();
        return Response.json({ status: true });
      }

      if (path === "/__test/huggingface/receipts") {
        return Response.json(receipts);
      }

      if (path === "/__test/huggingface/mapper-receipts") {
        return Response.json(mapperReceipts);
      }

      return null;
    },
  };
}
