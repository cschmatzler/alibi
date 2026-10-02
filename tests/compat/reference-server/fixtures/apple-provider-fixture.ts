import { type BetterAuthOptions, betterAuth } from "better-auth";

/** Published Apple factory, with only fixed trusted HTTP destinations redirected. */
export function appleProviderFixture(base: BetterAuthOptions) {
  let control: Record<string, unknown> = {};
  const receipts: unknown[] = [];
  const defaultKeys = JSON.parse(
    require("node:fs").readFileSync(
      new URL("../../../fixtures/one-tap/jwks.json", import.meta.url),
      "utf8",
    ),
  );
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
      if (path === "/keys") return Response.json(control.keys ?? defaultKeys);
      if (path === "/token")
        return Response.json(
          control.tokenResponse ?? {
            access_token: "fixture-apple-access",
            refresh_token: "fixture-apple-refresh",
            id_token: control.idToken,
            token_type: "Bearer",
            expires_in: 3600,
          },
        );
      return new Response("Unknown trusted Apple destination", { status: 404 });
    },
  });
  const previousFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = (async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    if (
      url.origin === "https://appleid.apple.com" &&
      ["/auth/keys", "/auth/token"].includes(url.pathname)
    ) {
      return previousFetch(
        new Request(`${transport.url}${url.pathname.endsWith("keys") ? "keys" : "token"}`, request),
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
    "bundle",
    "audience",
    "client-array",
    "disabled-idtoken",
    "signup-disabled",
    "implicit-disabled",
    "encrypted",
    "mapped",
    "empty-clients",
  ]) {
    const path = `/__test/profiles/social-apple-${mode}/api/auth`;
    profiles.set(
      path,
      betterAuth({
        ...base,
        basePath: path,
        plugins: [],
        ...(mode === "encrypted" ? { account: { ...base.account, encryptOAuthTokens: true } } : {}),
        socialProviders: {
          apple: {
            clientId:
              mode === "empty-clients"
                ? []
                : mode === "client-array"
                  ? ["fixture-social-client", "fixture-apple-secondary"]
                  : ["bundle", "audience"].includes(mode)
                    ? ["fixture-builder-client"]
                    : "fixture-social-client",
            clientSecret: "fixture-social-secret",
            ...(mode === "mapped"
              ? {
                  mapProfileToUser: (profile: Record<string, unknown>) => ({
                    name: `Mapped ${profile.name}`,
                    email: "mapped-apple@example.invalid",
                    emailVerified: false,
                    image: "https://images.example.invalid/mapped-apple.png",
                  }),
                }
              : {}),
            ...(["configured", "disabled-configured"].includes(mode)
              ? { scope: ["configured-scope"] }
              : {}),
            ...(mode.startsWith("disabled-") && mode !== "disabled-idtoken"
              ? { disableDefaultScope: true }
              : {}),
            ...(mode === "bundle" ? { appBundleIdentifier: "fixture-apple-bundle" } : {}),
            ...(mode === "audience"
              ? { audience: ["fixture-apple-audience"], appBundleIdentifier: "ignored-bundle" }
              : {}),
            ...(mode === "disabled-idtoken" ? { disableIdTokenSignIn: true } : {}),
            ...(mode === "signup-disabled" ? { disableSignUp: true } : {}),
            ...(mode === "implicit-disabled" ? { disableImplicitSignUp: true } : {}),
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
    },
    async handle(request: Request) {
      const path = new URL(request.url).pathname;
      if (path === "/__test/apple/control" && request.method === "POST") {
        control = await request.json();
        return Response.json({ status: true });
      }
      if (path === "/__test/apple/receipts") return Response.json(receipts);
      return null;
    },
  };
}
