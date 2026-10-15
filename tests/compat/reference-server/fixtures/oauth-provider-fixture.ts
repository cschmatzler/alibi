import { oauthProvider } from "@better-auth/oauth-provider";
import { betterAuth } from "better-auth";
import { jwt } from "better-auth/plugins";
export function oauthProviderDiscovery(baseURL: string) {
  const instances = new Map(
    ["default", "oauth", "disabled", "configured", "registry", "registry-oauth", "registry-empty"].map(
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
                ...(mode.startsWith("registry") ? {extensions:[{clientDiscovery:["first","second"].map(id=>({
                  id:`metadata-${id}`,matches:()=>false,resolve:async()=>null,
                  ...(mode==="registry-empty"?{}:{discoveryMetadata:id==="first"?{
                    client_id_metadata_document_supported:true,registry_order:"first",registry_first_only:17,
                    issuer:"https://untrusted.fixture.test",token_endpoint_auth_methods_supported:["wrong"],scopes_supported:["wrong"],claims_supported:["wrong"],jwks_uri:"https://untrusted.fixture.test/keys"
                  }:{registry_order:"second",registry_second_only:{enabled:true},issuer:"https://also-untrusted.fixture.test"}})
                }))}]} : {}),
                ...(mode==="registry-oauth"?{scopes:["read"]}:{}),
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
  return async (mode: string, operation = "getOAuthServerConfig") =>
    operation === "getOpenIdConfig"
      ? instances.get(mode)!.api.getOpenIdConfig({ asResponse: true })
      : instances.get(mode)!.api.getOAuthServerConfig({ asResponse: true });
}
