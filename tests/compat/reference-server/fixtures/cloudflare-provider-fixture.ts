import { type BetterAuthOptions, betterAuth } from "better-auth";

/** Run the published factory; redirect only its fixed provider HTTP destinations. */
export function cloudflareProviderFixture(base: BetterAuthOptions) {
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
            access_token: "fixture-cloudflare-access",
            refresh_token: "fixture-cloudflare-refresh",
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
          control.envelope ?? {
            success: true,
            result: control.profile ?? {
              id: "fixture-cloudflare-subject",
              first_name: "Cloudflare",
              last_name: "Name",
              email: "cloudflare@example.invalid",
            },
          },
          { status: Number(control.profileStatus ?? 200) },
        );
      }

      return new Response("Unknown trusted Cloudflare destination", { status: 404 });
    },
  });
  const previousFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = (async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);

    if (
      url.href === "https://dash.cloudflare.com/oauth2/token" ||
      url.href === "https://api.cloudflare.com/client/v4/user"
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
    "post",
    "encoded",
    "mapped",
    "implicit-disabled",
    "signup-disabled",
    "required",
    "configured-endpoint",
  ]) {
    const path = `/__test/profiles/social-cloudflare-${mode}/api/auth`;
    const credentials =
      mode === "public"
        ? { clientId: "fixture-social-client" }
        : {
            clientId: mode === "encoded" ? "client :+!*'()" : "fixture-social-client",
            clientSecret: mode === "encoded" ? "secret :+!*'()" : "fixture-social-secret",
            ...(mode === "post" ? { tokenEndpointAuthMethod: "client_secret_post" as const } : {}),
          };
    profiles.set(
      path,
      betterAuth({
        ...base,
        basePath: path,
        plugins: [],
        socialProviders: {
          cloudflare: {
            ...credentials,
            ...(["configured", "disabled-configured"].includes(mode)
              ? { scope: ["configured-scope", "user-details.read", "configured-scope"] }
              : {}),
            ...(mode.startsWith("disabled-") ? { disableDefaultScope: true } : {}),
            ...(mode === "mapped"
              ? {
                  mapProfileToUser: (profile: Record<string, unknown>) => {
                    mapperReceipts.push(profile);
                    return {
                      id: "cannot-replace-account-subject",
                      name: `Mapped ${profile.first_name}`,
                      email: "mapped-cloudflare@example.invalid",
                      emailVerified: true,
                      image: "https://images.example.invalid/mapped-cloudflare.png",
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

      if (path === "/__test/cloudflare/control" && request.method === "POST") {
        control = await request.json();
        return Response.json({ status: true });
      }

      if (path === "/__test/cloudflare/receipts") {
        return Response.json(receipts);
      }

      if (path === "/__test/cloudflare/mapper-receipts") {
        return Response.json(mapperReceipts);
      }

      return null;
    },
  };
}
