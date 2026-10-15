import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
for (const mode of ["registry", "registry-oauth", "registry-empty"]) {
  compatScenario(
    `Client discovery ${mode} advertises public clients and merges metadata before provider policy`,
    async (ctx) => {
      const results = [];
      for (const operation of ["getOAuthServerConfig", "getOpenIdConfig"]) {
        const response = await ctx
          .actor()
          .fetch(
            `${ctx.baseURL}/__test/server-api/oauth-provider-metadata?mode=${mode}&operation=${operation}`,
          );
        if (mode === "registry-oauth" && operation === "getOpenIdConfig") {
          expect(response.status).toBe(404);
          expect(await response.text()).toBe("");
          results.push({ operation, status: response.status });
          continue;
        }
        expect(response.status).toBe(200);
        const document = await response.json();
        expect(document.token_endpoint_auth_methods_supported).toEqual([
          "none",
          "client_secret_basic",
          "client_secret_post",
          "private_key_jwt",
        ]);
        expect(document.introspection_endpoint_auth_methods_supported).toEqual([
          "client_secret_basic",
          "client_secret_post",
          "private_key_jwt",
        ]);
        expect(document.revocation_endpoint_auth_methods_supported).toEqual([
          "client_secret_basic",
          "client_secret_post",
          "private_key_jwt",
        ]);
        expect(document.issuer).toBe(`${ctx.baseURL}/api/auth`);
        expect(document.jwks_uri).toBe(`${ctx.baseURL}/api/auth/jwks`);
        expect(document.scopes_supported).toEqual(
          mode === "registry-oauth" ? ["read"] : ["openid", "profile", "email", "offline_access"],
        );
        if (mode === "registry-empty") {
          expect(document).not.toHaveProperty("client_id_metadata_document_supported");
          expect(document).not.toHaveProperty("registry_order");
        } else {
          expect(document.client_id_metadata_document_supported).toBe(true);
          expect(document.registry_order).toBe("second");
          expect(document.registry_first_only).toBe(17);
          expect(document.registry_second_only).toEqual({ enabled: true });
          if (mode === "registry-oauth") expect(document.claims_supported).toEqual(["wrong"]);
          else {
            expect(document.claims_supported).toContain("sub");
            expect(document.claims_supported).not.toContain("wrong");
          }
        }
        results.push({ operation, status: response.status, document });
      }
      return ctx.snapshot({ results });
    },
  );
}
