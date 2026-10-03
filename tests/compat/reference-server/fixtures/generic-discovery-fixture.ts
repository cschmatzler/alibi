import { readFileSync } from "node:fs";

import { betterAuth, type BetterAuthOptions } from "better-auth";
import { genericOAuth } from "better-auth/plugins";
export function genericDiscoveryFixture(base: BetterAuthOptions) {
  let control: Record<string, any> = {};
  const receipts: unknown[] = [];
  const transport = Bun.serve({
    port: 0,
    async fetch(request): Promise<Response> {
      const url = new URL(request.url);
      const path = url.pathname;
      if (path === "/metadata/keys") {
        return Response.json(
          JSON.parse(readFileSync("../../../tests/fixtures/one-tap/jwks.json", "utf8")),
        );
      }
      if (path.startsWith("/metadata/")) {
        const mode = path.split("/").at(-1)!;
        receipts.push({ path: "/metadata", mode, header: request.headers.get("x-discovery") });
        if (["failed", "fallback", "required"].includes(mode)) {
          return Response.json({ error: "metadata failed" }, { status: 503 });
        }
        return Response.json({
          authorization_endpoint: "https://discovered.example.invalid/authorize",
          token_endpoint: `${transport.url}token/discovered`,
          userinfo_endpoint: `${transport.url}user/discovered`,
          end_session_endpoint: "https://discovered.example.invalid/logout",
          ...(mode === "invalid-issuer" ? { issuer: "not a url" } : {}),
          ...(mode === "invalid-jwks"
            ? { issuer: "https://issuer.example.invalid", jwks_uri: "http://[bad" }
            : {}),
          ...(mode === "oidc"
            ? {
                issuer: "https://issuer.example.invalid",
                jwks_uri: "keys",
                id_token_signing_alg_values_supported: ["RS256"],
              }
            : {}),
        });
      }
      if (path.startsWith("/token/")) {
        const raw = await request.text();
        receipts.push({
          path,
          authorization: request.headers.get("authorization"),
          grantHeader: request.headers.get("x-grant"),
          body: [...new URLSearchParams(raw)],
          raw,
        });
        return Response.json(
          control.tokenResponse ?? {
            access_token: "discovery-access",
            refresh_token: "discovery-refresh",
            token_type: "Bearer",
            expires_in: 3600,
            scope: "profile",
          },
          { status: control.tokenStatus ?? 200 },
        );
      }
      receipts.push({ path, authorization: request.headers.get("authorization") });
      return Response.json(
        control.profile ?? {
          id: "discovery-subject",
          sub: "oidc-subject",
          email: "discovery@example.invalid",
          email_verified: true,
          name: "Discovery Name",
        },
        { status: control.userStatus ?? 200 },
      );
    },
  });
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  for (const mode of [
    "success",
    "override",
    "failed",
    "fallback",
    "invalid-issuer",
    "invalid-jwks",
    "required",
    "oidc",
    "mapped",
    "logout",
    "logout-configured",
    "logout-disabled",
    "logout-invalid",
    "logout-no-return",
  ]) {
    const path = `/__test/profiles/generic-discovery-${mode}/api/auth`;
    profiles.set(
      path,
      betterAuth<BetterAuthOptions>({
        ...base,
        basePath: path,
        socialProviders: {},
        plugins: [
          genericOAuth({
            config: [
              {
                providerId: "discovery",
                clientId: "discovery-client",
                clientSecret: "discovery-secret",
                discoveryUrl: `${transport.url}metadata/${mode}`,
                discoveryHeaders: { "x-discovery": "configured-header" },
                ...(["override", "fallback", "invalid-issuer"].includes(mode)
                  ? {
                      authorizationUrl: "https://configured.example.invalid/authorize",
                      tokenUrl: `${transport.url}token/configured`,
                      userInfoUrl: `${transport.url}user/configured`,
                    }
                  : {}),
                disableProviderLogout: !mode.startsWith("logout") || mode === "logout-disabled",
                ...(mode.startsWith("logout") && mode !== "logout-no-return"
                  ? { postLogoutRedirectURI: "/signed-out" }
                  : {}),
                ...(mode === "logout-configured"
                  ? {
                      endSessionEndpoint:
                        "https://configured.example.invalid/logout?keep=1&id_token_hint=old&id_token_hint=duplicate",
                    }
                  : {}),
                ...(mode === "logout-invalid" ? { endSessionEndpoint: "http://[bad" } : {}),
                requireIdTokenVerification: mode === "required",
                scopes: ["profile"],
                tokenUrlParams: { resource: "discovery-resource" },
                refreshTokenParams: { resource: "refresh-resource" },
                authorizationHeaders: { "x-grant": "configured-grant" },
                ...(mode === "oidc"
                  ? {
                      getUserInfo: async () => {
                        receipts.push({ path: "/custom" });
                        return control.profile;
                      },
                    }
                  : {}),
                ...(mode === "mapped"
                  ? {
                      // Deliberately supply a forbidden mapped ID to prove original account authority.
                      mapProfileToUser: async () =>
                        ({ id: "mapped-id", name: "Mapped Name" }) as { name: string },
                    }
                  : {}),
              },
              ...(mode === "logout"
                ? ["invalid", "backup"].map((providerId) => ({
                    providerId,
                    clientId: "discovery-client",
                    clientSecret: "discovery-secret",
                    authorizationUrl: "https://unused.example.invalid/authorize",
                    tokenUrl: `${transport.url}token/configured`,
                    endSessionEndpoint:
                      providerId === "invalid"
                        ? "http://[bad"
                        : "https://backup.example.invalid/logout",
                    postLogoutRedirectURI: "/signed-out",
                  }))
                : []),
            ],
          }),
        ],
      }),
    );
  }
  return {
    profiles,
    reset() {
      control = {};
      for (let i = receipts.length - 1; i >= 0; i--) {
        if ((receipts[i] as any).path !== "/metadata") receipts.splice(i, 1);
      }
    },
    async handle(request: Request) {
      const p = new URL(request.url).pathname;
      if (p === "/__test/generic-discovery/control" && request.method === "POST") {
        control = await request.json();
        return Response.json({ status: true });
      }
      if (p === "/__test/generic-discovery/receipts") return Response.json(receipts);
      return null;
    },
  };
}
