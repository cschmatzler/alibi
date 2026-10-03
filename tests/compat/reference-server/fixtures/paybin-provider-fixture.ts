import { type BetterAuthOptions, betterAuth } from "better-auth";

/** Run the published factory; redirect only its fixed provider HTTP destinations. */
export function paybinProviderFixture(base: BetterAuthOptions) {
  let control: Record<string, unknown> = {};
  const receipts: unknown[] = [];
  const mapperReceipts: unknown[] = [];
  const transport = Bun.serve({
    port: 0,
    async fetch(request) {
      const path = new URL(request.url).pathname;
      const body =
        request.method === "POST"
          ? Object.fromEntries(new URLSearchParams(await request.text()))
          : null;
      receipts.push({
        path,
        method: request.method,
        authorization: request.headers.get("authorization"),
        contentType: request.headers.get("content-type"),
        body,
      });

      if (path.endsWith("/oauth2/token") || path === "/leak") {
        return Response.json(
          control.tokenResponse ?? {
            ...(control.idToken ? { id_token: control.idToken } : {}),
            access_token: "fixture-paybin-access",
            refresh_token: "fixture-paybin-refresh",
            token_type: "Bearer",
            expires_in: 3600,
            scope: "user-details.read",
          },
          {
            status: Number(path === "/leak" ? 200 : (control.tokenStatus ?? 200)),
            ...(control.tokenRedirect && path.endsWith("/oauth2/token")
              ? { headers: { location: `${transport.url}leak` } }
              : {}),
          },
        );
      }

      return new Response("Unknown trusted Paybin destination", { status: 404 });
    },
  });
  const previousFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = (async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);

    if (
      [
        "https://idp.paybin.io/oauth2/token",
        "https://issuer.example.invalid/root//oauth2/token",
      ].includes(url.href)
    ) {
      return previousFetch(new Request(`${transport.url}${url.pathname.slice(1)}`, request));
    }

    return previousFetch(input, init);
  }) as typeof fetch;
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();

  for (const mode of [
    "default",
    "configured",
    "disabled-scope",
    "disabled-configured",
    "public",
    "empty-clients",
    "issuer",
    "empty-issuer",
    "prompt",
    "encoded",
    "mapped",
    "implicit-disabled",
    "signup-disabled",
    "required",
    "configured-endpoint",
    "client-key",
  ]) {
    const path = `/__test/profiles/social-paybin-${mode}/api/auth`;
    const credentials =
      mode === "public"
        ? { clientId: "fixture-social-client" }
        : {
            clientId:
              mode === "empty-clients"
                ? ""
                : mode === "encoded"
                  ? "client :+!*'()"
                  : "fixture-social-client",
            clientSecret: mode === "encoded" ? "secret :+!*'()" : "fixture-social-secret",
          };
    profiles.set(
      path,
      betterAuth({
        ...base,
        basePath: path,
        plugins: [],
        socialProviders: {
          paybin: {
            ...credentials,
            ...(mode === "issuer" ? { issuer: "https://issuer.example.invalid/root/" } : {}),
            ...(mode === "empty-issuer" ? { issuer: "" } : {}),
            ...(mode === "prompt" ? { prompt: "consent" as const } : {}),
            ...(["configured", "disabled-configured"].includes(mode)
              ? { scope: ["configured-scope", "shared-scope", "configured-scope"] }
              : {}),
            ...(mode === "client-key" ? { clientKey: "fixture-client-key" } : {}),
            ...(mode.startsWith("disabled-") ? { disableDefaultScope: true } : {}),
            ...(mode === "mapped"
              ? {
                  mapProfileToUser: (profile: Record<string, unknown>) => {
                    mapperReceipts.push(profile);
                    return {
                      id: "cannot-replace-account-subject",
                      name: `Mapped ${profile.name}`,
                      email: "mapped-paybin@example.invalid",
                      emailVerified: true,
                      image: "https://images.example.invalid/mapped-paybin.png",
                    };
                  },
                }
              : {}),
            ...(mode === "implicit-disabled" ? { disableImplicitSignUp: true } : {}),
            ...(mode === "signup-disabled" ? { disableSignUp: true } : {}),
            ...(mode === "required" ? { requireEmailVerification: true } : {}),
            ...(mode === "configured-endpoint"
              ? {
                  authorizationEndpoint: "https://configured.example.invalid/authorize",
                  redirectURI: "https://configured.example.invalid/callback",
                  responseMode: "form_post" as const,
                }
              : {}),
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

      if (path === "/__test/paybin/control" && request.method === "POST") {
        control = await request.json();
        return Response.json({ status: true });
      }

      if (path === "/__test/paybin/receipts") {
        return Response.json(receipts);
      }

      if (path === "/__test/paybin/mapper-receipts") {
        return Response.json(mapperReceipts);
      }

      return null;
    },
  };
}
