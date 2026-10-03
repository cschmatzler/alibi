import { type BetterAuthOptions, betterAuth } from "better-auth";

/** Run the published factory; redirect only its fixed provider HTTP destinations. */
export function paypalProviderFixture(base: BetterAuthOptions) {
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
        accept: request.headers.get("accept"),
        query: Object.fromEntries(new URL(request.url).searchParams),
        body,
      });

      if (path === "/token" || path === "/leak") {
        return Response.json(
          control.tokenResponse ?? {
            access_token: "fixture-paypal-access",
            refresh_token: "fixture-paypal-refresh",
            token_type: "Bearer",
            expires_in: 3600,
            scope: "user-details.read",
          },
          {
            status: Number(path === "/leak" ? 200 : (control.tokenStatus ?? 200)),
            ...(control.tokenRedirect && path === "/token"
              ? { headers: { location: `${transport.url}leak` } }
              : {}),
          },
        );
      }

      if (path === "/user") {
        return Response.json(
          Object.hasOwn(control, "profile")
            ? control.profile
            : {
                user_id: "fixture-paypal-subject",
                name: "PayPal Name",
                email: "paypal@example.invalid",
                email_verified: true,
              },
          { status: Number(control.profileStatus ?? 200) },
        );
      }

      return new Response("Unknown trusted PayPal destination", { status: 404 });
    },
  });
  const previousFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = (async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);

    if (
      ["api-m.sandbox.paypal.com", "api-m.paypal.com"].includes(url.hostname) &&
      ["/v1/oauth2/token", "/v1/identity/oauth2/userinfo"].includes(url.pathname)
    ) {
      return previousFetch(
        new Request(
          `${transport.url}${url.pathname.endsWith("token") ? "token" : "user"}${url.search}`,
          request,
        ),
      );
    }

    return previousFetch(input, init);
  }) as typeof fetch;
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();

  for (const mode of [
    "default",
    "live",
    "configured",
    "disabled-scope",
    "disabled-configured",
    "public",
    "empty-client",
    "encoded",
    "mapped",
    "implicit-disabled",
    "signup-disabled",
    "required",
    "configured-endpoint",
    "client-key",
    "shipping",
    "prompt",
    "empty-prompt",
  ]) {
    const path = `/__test/profiles/social-paypal-${mode}/api/auth`;
    const credentials =
      mode === "public"
        ? { clientId: "fixture-social-client", clientSecret: "" }
        : {
            clientId:
              mode === "empty-client"
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
          paypal: {
            ...credentials,
            ...(mode === "live" ? { environment: "live" as const } : {}),
            ...(mode === "shipping" ? { requestShippingAddress: true } : {}),
            ...(["prompt", "empty-prompt"].includes(mode)
              ? { prompt: mode === "prompt" ? ("consent" as const) : ("" as "consent") }
              : {}),
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
                      email: "mapped-paypal@example.invalid",
                      emailVerified: true,
                      image: "https://images.example.invalid/mapped-paypal.png",
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

      if (path === "/__test/paypal/control" && request.method === "POST") {
        control = await request.json();
        return Response.json({ status: true });
      }

      if (path === "/__test/paypal/receipts") {
        return Response.json(receipts);
      }

      if (path === "/__test/paypal/mapper-receipts") {
        return Response.json(mapperReceipts);
      }

      return null;
    },
  };
}
