import { type BetterAuthOptions, betterAuth } from "better-auth";

/** Run the published factory; redirect only its fixed provider HTTP destinations. */
export function notionProviderFixture(base: BetterAuthOptions) {
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
        notionVersion: request.headers.get("notion-version"),
        body,
      });

      if (path === "/token" || path === "/leak") {
        return Response.json(
          control.tokenResponse ?? {
            access_token: "fixture-notion-access",
            refresh_token: "fixture-notion-refresh",
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
            bot: {
              owner: {
                user: control.profile ?? {
                  id: "fixture-notion-subject",
                  name: "Notion Name",
                  person: { email: "notion@example.invalid" },
                },
              },
            },
          },
          { status: Number(control.profileStatus ?? 200) },
        );
      }

      return new Response("Unknown trusted Notion destination", { status: 404 });
    },
  });
  const previousFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = (async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);

    if (
      url.href === "https://api.notion.com/v1/oauth/token" ||
      url.href === "https://api.notion.com/v1/users/me"
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
    "client-key",
  ]) {
    const path = `/__test/profiles/social-notion-${mode}/api/auth`;
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
          notion: {
            ...credentials,
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
                      email: "mapped-notion@example.invalid",
                      emailVerified: true,
                      image: "https://images.example.invalid/mapped-notion.png",
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

      if (path === "/__test/notion/control" && request.method === "POST") {
        control = await request.json();
        return Response.json({ status: true });
      }

      if (path === "/__test/notion/receipts") {
        return Response.json(receipts);
      }

      if (path === "/__test/notion/mapper-receipts") {
        return Response.json(mapperReceipts);
      }

      return null;
    },
  };
}
