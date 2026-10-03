import { type BetterAuthOptions, betterAuth } from "better-auth";

/** Run the published factory; redirect only its fixed provider HTTP destinations. */
export function polarProviderFixture(base: BetterAuthOptions) {
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

      if (path === "/token" || path === "/leak") {
        return Response.json(
          control.tokenResponse ?? {
            access_token: "fixture-polar-access",
            refresh_token: "fixture-polar-refresh",
            token_type: "Bearer",
            expires_in: 3600,
            scope: "openid profile email",
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
                id: "fixture-polar-subject",
                public_name: "Polar Name",
                username: "polar-user",
                email: "polar@example.invalid",
              },
          { status: Number(control.profileStatus ?? 200) },
        );
      }

      return new Response("Unknown trusted Polar destination", { status: 404 });
    },
  });
  const previousFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = (async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);

    if (
      url.href === "https://api.polar.sh/v1/oauth2/token" ||
      url.href === "https://api.polar.sh/v1/oauth2/userinfo"
    ) {
      return previousFetch(
        new Request(
          `${transport.url}${url.pathname.endsWith("token") ? "token" : "user"}`,
          request,
        ),
      );
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
    "encoded",
    "mapped",
    "implicit-disabled",
    "signup-disabled",
    "required",
    "configured-endpoint",
    "prompt",
    "empty-endpoint",
    "client-key",
  ]) {
    const path = `/__test/profiles/social-polar-${mode}/api/auth`;
    const credentials =
      mode === "public"
        ? { clientId: "fixture-social-client" }
        : {
            clientId: mode === "encoded" ? "client :+!*'()" : "fixture-social-client",
            clientSecret: mode === "encoded" ? "secret :+!*'()" : "fixture-social-secret",
          };
    profiles.set(
      path,
      betterAuth({
        ...base,
        basePath: path,
        plugins: [],
        socialProviders: {
          polar: {
            ...credentials,
            ...(["configured", "disabled-configured"].includes(mode)
              ? { scope: ["configured-scope", "shared-scope", "configured-scope"] }
              : {}),
            ...(mode === "prompt" ? { prompt: "consent" as const } : {}),
            ...(mode === "empty-endpoint" ? { authorizationEndpoint: "", redirectURI: "" } : {}),
            ...(mode === "client-key" ? { clientKey: "fixture-client-key" } : {}),
            ...(mode.startsWith("disabled-") ? { disableDefaultScope: true } : {}),
            ...(mode === "mapped"
              ? {
                  mapProfileToUser: (profile: Record<string, unknown>) => {
                    mapperReceipts.push(profile);
                    return {
                      id: "cannot-replace-account-subject",
                      name: `Mapped ${profile.public_name}`,
                      email: "mapped-polar@example.invalid",
                      emailVerified: true,
                      image: "https://images.example.invalid/mapped-polar.png",
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

      if (path === "/__test/polar/control" && request.method === "POST") {
        control = await request.json();
        return Response.json({ status: true });
      }

      if (path === "/__test/polar/receipts") {
        return Response.json(receipts);
      }

      if (path === "/__test/polar/mapper-receipts") {
        return Response.json(mapperReceipts);
      }

      return null;
    },
  };
}
