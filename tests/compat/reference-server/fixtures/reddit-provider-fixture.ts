import { appendFileSync } from "node:fs";
import { type BetterAuthOptions, betterAuth } from "better-auth";

/** Run the published factory; redirect only its fixed provider HTTP destinations. */
export function redditProviderFixture(base: BetterAuthOptions) {
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
      if (process.env.REDDIT_WIRE_LOG) appendFileSync(process.env.REDDIT_WIRE_LOG, JSON.stringify({path, method: request.method, headers: Object.fromEntries(request.headers), body}) + "\n");
      const declaredHeader = (name: string) => { const value = request.headers.get(`x-fixture-reddit-${name}`); return value === "__absent__" ? null : value; };
      receipts.push({
        path,
        method: request.method,
        authorization: request.headers.get("authorization"),
        accept: request.headers.get("accept"),
        userAgent: declaredHeader("user-agent"),
        contentType: request.headers.get("content-type"),
        body,
      });

      if (path === "/token" || path === "/leak") {
        return Response.json(
          control.tokenResponse ?? {
            access_token: "fixture-reddit-access",
            refresh_token: "fixture-reddit-refresh",
            token_type: "Bearer",
            expires_in: 3600,
            scope: "identity",
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
                id: "fixture-reddit-subject",
                name: "Reddit Name",
                icon_img: "https://images.example.invalid/reddit.png?size=large",
                email: "reddit@example.invalid",
              },
          { status: Number(control.profileStatus ?? 200) },
        );
      }

      return new Response("Unknown trusted Reddit destination", { status: 404 });
    },
  });
  const previousFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = (async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);

    if (
      url.href === "https://www.reddit.com/api/v1/access_token" ||
      url.href === "https://oauth.reddit.com/api/v1/me"
    ) {
      // Preserve the exact factory headers independently of Bun ambient defaults.
      request.headers.set("x-fixture-reddit-accept", request.headers.get("accept") ?? "__absent__");
      request.headers.set("x-fixture-reddit-user-agent", request.headers.get("user-agent") ?? "__absent__");
      return previousFetch(
        new Request(
          `${transport.url}${url.hostname === "www.reddit.com" ? "token" : "user"}`,
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
    "permanent",
    "empty-duration",
    "mapped-empty-email",
  ]) {
    const path = `/__test/profiles/social-reddit-${mode}/api/auth`;
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
          reddit: {
            ...credentials,
            ...(["configured", "disabled-configured"].includes(mode)
              ? { scope: ["configured-scope", "shared-scope", "configured-scope"] }
              : {}),
            ...(mode === "permanent" ? { duration: "permanent" } : {}),
            ...(mode === "empty-duration" ? { duration: "" } : {}),
            ...(mode === "prompt" ? { prompt: "consent" as const } : {}),
            ...(mode === "empty-endpoint" ? { authorizationEndpoint: "", redirectURI: "" } : {}),
            ...(mode === "client-key" ? { clientKey: "fixture-client-key" } : {}),
            ...(mode.startsWith("disabled-") ? { disableDefaultScope: true } : {}),
            ...(["mapped", "mapped-empty-email"].includes(mode)
              ? {
                  mapProfileToUser: (profile: Record<string, unknown>) => {
                    mapperReceipts.push(profile);
                    return {
                      id: "cannot-replace-account-subject",
                      name: `Mapped ${profile.name}`,
                      email: mode === "mapped-empty-email" ? "" : "mapped-reddit@example.invalid",
                      emailVerified: true,
                      image: "https://images.example.invalid/mapped-reddit.png",
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

      if (path === "/__test/reddit/control" && request.method === "POST") {
        control = await request.json();
        return Response.json({ status: true });
      }

      if (path === "/__test/reddit/receipts") {
        return Response.json(receipts);
      }

      if (path === "/__test/reddit/mapper-receipts") {
        return Response.json(mapperReceipts);
      }

      return null;
    },
  };
}
