import { microsoft } from "@better-auth/core/social-providers";
import { betterAuth, type BetterAuthOptions } from "better-auth";
/** Unchanged published factory; network receipts come from actual fixed trusted destinations. */
export function microsoftProviderFixture(base: BetterAuthOptions) {
  let control: Record<string, unknown> = {};
  const receipts: unknown[] = [];
  const mapperReceipts: unknown[] = [];
  const assertionReceipts: unknown[] = [];
  const defaultKeys = JSON.parse(
    require("node:fs").readFileSync(
      new URL("../../../fixtures/one-tap/jwks.json", import.meta.url),
      "utf8",
    ),
  );
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  let constructorError: string | null = null;
  try {
    microsoft({
      clientId: "fixture-social-client",
      clientSecret: "fixture-social-secret",
      clientAssertion: () => Promise.resolve("fixture-assertion"),
    });
  } catch (error) {
    constructorError = (error as Error).message;
  }
  const authority = String(base.baseURL);
  const tenants = ["common", "organizations", "consumers", "fixture-tenant"];
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
      if (path.endsWith("/keys")) return Response.json(control.keys ?? defaultKeys);
      if (path.endsWith("/token")) {
        if (control.tokenRedirect) {
          return new Response(null, {
            status: 302,
            headers: { location: String(control.tokenRedirect) },
          });
        }
        return Response.json(
          control.tokenResponse ?? {
            access_token: "fixture-microsoft-access",
            refresh_token: "fixture-microsoft-refresh",
            token_type: "Bearer",
            expires_in: 3600,
            ...(control.idToken ? { id_token: control.idToken } : {}),
          },
          { status: Number(control.tokenStatus ?? 200) },
        );
      }
      if (path.startsWith("/photo/")) {
        return new Response(new Uint8Array([0xff, 0xd8, 0, 65, 0xff, 0xd9]), {
          status: Number(control.photoStatus ?? 200),
          headers: { "content-type": "image/jpeg" },
        });
      }
      return new Response("Unknown trusted Microsoft destination", { status: 404 });
    },
  });
  const previousFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = (async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    if (
      (url.origin === authority || url.origin === "https://login.microsoftonline.com") &&
      tenants.some((tenant) =>
        ["/" + tenant + "/oauth2/v2.0/token", "/" + tenant + "/discovery/v2.0/keys"].includes(
          url.pathname,
        ),
      )
    ) {
      return previousFetch(new Request(new URL(url.pathname, transport.url), request));
    }
    if (
      url.origin === "https://graph.microsoft.com" &&
      /^\/v1.0\/me\/photos\/(48x48|64x64)\/\$value$/.test(decodeURIComponent(url.pathname))
    ) {
      return previousFetch(
        new Request(new URL("/photo/" + url.pathname.split("/")[4], transport.url), request),
      );
    }
    return previousFetch(input, init);
  }) as typeof fetch;
  for (const mode of [
    "default",
    "configured",
    "disabled-scope",
    "disabled-configured",
    "public",
    "client-array",
    "empty-clients",
    "mapped",
    "client-key",
    "assertion",
    "organizations",
    "consumers",
    "fixed-tenant",
    "authority-slashes",
    "photo64",
    "no-photo",
    "implicit-disabled",
    "signup-disabled",
    "disabled-idtoken",
  ] as const) {
    const path = `/__test/profiles/social-microsoft-${mode}/api/auth`;
    const tenant = ["organizations", "consumers"].includes(mode)
      ? mode
      : mode === "fixed-tenant"
        ? "fixture-tenant"
        : "common";
    profiles.set(
      path,
      betterAuth({
        ...base,
        basePath: path,
        plugins: [],
        socialProviders: {
          microsoft: {
            clientId:
              mode === "empty-clients"
                ? []
                : mode === "client-array"
                  ? ["fixture-social-client", "fixture-microsoft-secondary"]
                  : "fixture-social-client",
            ...(!["public", "assertion"].includes(mode)
              ? { clientSecret: "fixture-social-secret" }
              : {}),
            authority:
              mode === "default"
                ? "https://login.microsoftonline.com"
                : authority + (mode === "authority-slashes" ? "///" : ""),
            tenantId: tenant,
            ...(["configured", "disabled-configured"].includes(mode)
              ? { scope: ["configured-scope", "openid", "punctuation-!~*'()"], prompt: "login" }
              : {}),
            disableDefaultScope: mode.startsWith("disabled-"),
            ...(mode === "client-key" ? { clientKey: "fixture-microsoft-client-key" } : {}),
            ...(mode === "assertion"
              ? {
                  clientAssertion: async (context) => {
                    await new Promise((resolve) => setTimeout(resolve, 10));
                    assertionReceipts.push(context);
                    return "fixture-assertion-" + context.grantType;
                  },
                }
              : {}),
            ...(mode === "photo64" ? { profilePhotoSize: 64 as const } : {}),
            disableProfilePhoto: mode === "no-photo",
            ...(mode === "mapped"
              ? {
                  mapProfileToUser: (profile: Record<string, unknown>) => {
                    mapperReceipts.push(profile);
                    return {
                      id: "cannot-replace-raw-oid",
                      microsoftMapped: { oid: profile.oid },
                      name: `Mapped ${profile.name ?? ""}`,
                      email: "mapped-microsoft@example.invalid",
                      emailVerified: false,
                      image: "https://images.example.invalid/mapped-microsoft.png",
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
      assertionReceipts.length = 0;
    },
    async handle(request: Request) {
      const path = new URL(request.url).pathname;
      if (path === "/__test/microsoft/control" && request.method === "POST") {
        control = await request.json();
        return Response.json({ status: true });
      }
      if (path === "/__test/microsoft/constructor") {
        return Response.json({ error: constructorError });
      }
      if (path === "/__test/microsoft/receipts") return Response.json(receipts);
      if (path === "/__test/microsoft/mapper-receipts") return Response.json(mapperReceipts);
      if (path === "/__test/microsoft/assertion-receipts") return Response.json(assertionReceipts);
      return null;
    },
  };
}
