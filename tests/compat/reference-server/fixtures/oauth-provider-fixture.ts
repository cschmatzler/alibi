import { oauthProvider } from "@better-auth/oauth-provider";
import { betterAuth } from "better-auth";
import { jwt } from "better-auth/plugins";
export function oauthProviderDiscovery(baseURL: string) {
  const instances = new Map(
    ["default", "oauth", "disabled", "configured"].map(
      (mode) =>
        [
          mode,
          betterAuth({
            secret: "local-oauth-provider-reference-secret-with-32-chars",
            baseURL,
            plugins: [
              jwt(
                mode === "configured"
                  ? {
                      jwt: { issuer: "http://issuer.fixture.test/tenant?discard=1#discard" },
                      jwks: {
                        jwksPath: "/keys",
                        remoteUrl: "https://keys.fixture.test/jwks",
                        keyPairConfig: { alg: "EdDSA" },
                      },
                    }
                  : {},
              ),
              oauthProvider({
                loginPage: "/login",
                consentPage: "/consent",
                ...(mode === "oauth" ? { scopes: ["read"] } : {}),
                ...(mode === "disabled" ? { disableJwtPlugin: true } : {}),
                ...(mode === "configured"
                  ? {
                      scopes: ["read"],
                      advertisedMetadata: { scopes_supported: ["read"] },
                      grantTypes: ["client_credentials"],
                      allowDynamicClientRegistration: true,
                      allowUnauthenticatedClientRegistration: true,
                    }
                  : {}),
              }),
            ],
          }),
        ] as const,
    ),
  );
  return async (mode: string) =>
    instances.get(mode)!.api.getOAuthServerConfig({ asResponse: true });
}
