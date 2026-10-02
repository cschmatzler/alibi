import { readFileSync } from "node:fs";

import { type BetterAuthOptions, betterAuth } from "better-auth";

/** Actual published Facebook factory; only fixed trusted HTTP authorities redirect. */
export function facebookProviderFixture(base: BetterAuthOptions) {
  let control: Record<string, unknown> = {};
  const receipts: unknown[] = [];
  const mapperReceipts: unknown[] = [];
  const defaultKeys = JSON.parse(
    readFileSync(new URL("../../../fixtures/one-tap/jwks.json", import.meta.url), "utf8"),
  );
  const transport = Bun.serve({
    port: 0,
    async fetch(request) {
      const url = new URL(request.url);
      const path = url.pathname;
      const body =
        request.method === "POST"
          ? Object.fromEntries(new URLSearchParams(await request.text()))
          : null;
      receipts.push({
        path,
        method: request.method,
        authorization: request.headers.get("authorization"),
        contentType: request.headers.get("content-type"),
        query: Object.fromEntries(url.searchParams),
        body,
      });

      if (path === "/keys") {
        return Response.json(control.keys ?? defaultKeys);
      }

      if (path === "/token") {
        return Response.json(
          control.tokenResponse ?? {
            access_token: "fixture-facebook-access",
            refresh_token: "fixture-facebook-refresh",
            token_type: "Bearer",
            expires_in: 3600,
            ...(control.idToken ? { id_token: control.idToken } : {}),
          },
          { status: typeof control.tokenStatus === "number" ? control.tokenStatus : 200 },
        );
      }

      if (path === "/debug") {
        return Response.json(
          control.inspection ?? {
            data: {
              is_valid: true,
              app_id: "fixture-social-client",
              user_id:
                (control.profile as Record<string, unknown> | undefined)?.id ??
                "fixture-facebook-subject",
            },
          },
          { status: typeof control.inspectionStatus === "number" ? control.inspectionStatus : 200 },
        );
      }

      if (path === "/userinfo") {
        return Response.json(
          control.profile ?? {
            id: "fixture-facebook-subject",
            name: "Facebook User",
            email: "facebook@example.invalid",
            email_verified: true,
            picture: {
              data: {
                url: "https://images.example.invalid/facebook.png",
                height: 50,
                width: 50,
                is_silhouette: false,
              },
            },
          },
          { status: typeof control.userInfoStatus === "number" ? control.userInfoStatus : 200 },
        );
      }

      return new Response("Unknown trusted Facebook destination", { status: 404 });
    },
  });
  const previousFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = (async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    const route =
      url.origin === "https://graph.facebook.com"
        ? url.pathname === "/v24.0/oauth/access_token"
          ? "token"
          : url.pathname === "/debug_token"
            ? "debug"
            : url.pathname === "/me"
              ? "userinfo"
              : null
        : url.origin === "https://limited.facebook.com" &&
            url.pathname === "/.well-known/oauth/openid/jwks/"
          ? "keys"
          : null;
    return route
      ? previousFetch(new Request(`${transport.url}${route}${url.search}`, request))
      : previousFetch(input, init);
  }) as typeof fetch;
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  const modes = [
    "default",
    "configured",
    "disabled-scope",
    "disabled-configured",
    "mapped",
    "client-array",
    "missing-secret",
    "empty-clients",
    "configured-endpoint",
    "client-key",
    "disabled-idtoken",
    "implicit-disabled",
    "signup-disabled",
    "fields",
    ...[
      "no-iat",
      "old",
      "future",
      "raw-positive-iat",
      "raw-negative-iat",
      "issuer",
      "audience",
      "expired",
      "not-before",
      "iat-type",
      "nonce",
      "hashed-nonce",
      "signature",
      "unknown-kid",
      "missing-subject",
      "null-subject",
      "blank-subject",
      "missing-email",
      "null-email",
      "empty-email",
      "numeric-name",
      "null-name",
      "empty-image",
    ].map((name) => `jwt-${name}`),
    ...[
      "removed",
      "algorithm",
      "use",
      "operations",
      "private",
      "duplicate",
      "invalid-ext",
      "duplicate-import",
      "weak-modulus",
    ].map((name) => `keys-${name}`),
  ];

  for (const mode of modes) {
    const path = `/__test/profiles/social-facebook-${mode}/api/auth`;
    profiles.set(
      path,
      betterAuth({
        ...base,
        basePath: path,
        plugins: [],
        socialProviders: {
          facebook: {
            clientId:
              mode === "empty-clients"
                ? []
                : mode === "client-array"
                  ? ["fixture-social-client", "fixture-facebook-secondary"]
                  : "fixture-social-client",
            ...(mode !== "missing-secret" ? { clientSecret: "fixture-social-secret" } : {}),
            ...(["configured", "disabled-configured"].includes(mode)
              ? {
                  scope: ["configured-scope", "email", "punctuation !~*'()"],
                  configId: "ConfiguredFacebook",
                }
              : {}),
            ...(["disabled-scope", "disabled-configured"].includes(mode)
              ? { disableDefaultScope: true }
              : {}),
            ...(mode === "fields" ? { fields: ["email", "birthday", "locale"] } : {}),
            ...(mode === "configured-endpoint"
              ? {
                  authorizationEndpoint:
                    "https://alternate-facebook.example.invalid/authorize?state=stale&state=duplicate&client_id=stale&retained=value",
                  redirectURI: "https://client.example.invalid/facebook-return",
                }
              : {}),
            ...(mode === "client-key" ? { clientKey: "fixture-facebook-client-key" } : {}),
            ...(mode === "mapped"
              ? {
                  mapProfileToUser: (profile: Record<string, unknown>) => {
                    mapperReceipts.push(profile);
                    return {
                      id: "cannot-replace-raw-account",
                      name: "Mapped Facebook User",
                      email: "mapped-facebook@example.invalid",
                      emailVerified: false,
                      image: "https://images.example.invalid/mapped-facebook.png",
                    };
                  },
                }
              : {}),
            disableIdTokenSignIn: mode === "disabled-idtoken",
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

      if (path === "/__test/facebook/control" && request.method === "POST") {
        control = await request.json();
        return Response.json({ status: true });
      }

      if (path === "/__test/facebook/receipts") {
        return Response.json(receipts);
      }

      if (path === "/__test/facebook/mapper-receipts") {
        return Response.json(mapperReceipts);
      }

      return null;
    },
  };
}
