import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
for (const mode of ["default", "oauth", "disabled", "configured"] as const) {
  compatScenario(
    `OAuth Provider ${mode} direct discovery describes issuer and configured policy`,
    async (ctx) => {
      const response = await ctx
        .actor()
        .fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-metadata?mode=${mode}`);
      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toBe("application/json");
      const document = (await response.json()) as Record<string, any>;
      expect(document.authorization_endpoint).toBe(`${ctx.baseURL}/api/auth/oauth2/authorize`);
      expect(document.token_endpoint).toBe(`${ctx.baseURL}/api/auth/oauth2/token`);
      expect(document.code_challenge_methods_supported).toEqual(["S256"]);
      if (mode === "configured") {
        expect(document.issuer).toBe("https://issuer.fixture.test/tenant");
        expect(document.jwks_uri).toBe("https://keys.fixture.test/jwks");
        expect(document.registration_endpoint).toBe(`${ctx.baseURL}/api/auth/oauth2/register`);
        expect(document.response_types_supported).toEqual([]);
        expect(document.grant_types_supported).toEqual(["client_credentials"]);
        expect(document.token_endpoint_auth_methods_supported).toEqual([
          "none",
          "client_secret_basic",
          "client_secret_post",
          "private_key_jwt",
        ]);
      } else {
        expect(document.issuer).toBe(`${ctx.baseURL}/api/auth`);
        expect(document).not.toHaveProperty("registration_endpoint");
      }
      if (mode === "oauth" || mode === "configured") {
        expect(document.scopes_supported).toEqual(["read"]);
        expect(document).not.toHaveProperty("userinfo_endpoint");
      } else {
        expect(document.scopes_supported).toEqual(["openid", "profile", "email", "offline_access"]);
        expect(document.userinfo_endpoint).toBe(`${ctx.baseURL}/api/auth/oauth2/userinfo`);
      }
      if (mode === "disabled") {
        expect(document).not.toHaveProperty("jwks_uri");
        expect(document.id_token_signing_alg_values_supported).toEqual(["HS256"]);
        expect(document.backchannel_logout_supported).toBe(false);
      }
      return ctx.snapshot(document);
    },
  );
}

for (const mode of ["default", "oauth", "disabled", "configured"] as const) {
  compatScenario(
    `OAuth Provider ${mode} direct OpenID discovery admits only openid scope`,
    async (ctx) => {
      const response = await ctx
        .actor()
        .fetch(
          `${ctx.baseURL}/__test/server-api/oauth-provider-metadata?mode=${mode}&operation=getOpenIdConfig`,
        );
      expect(response.headers.get("content-type")).toBe("application/json");
      if (mode === "oauth" || mode === "configured") {
        expect(response.status).toBe(404);
        expect(await response.text()).toBe("");
        return { status: response.status };
      }
      expect(response.status).toBe(200);
      const document = (await response.json()) as Record<string, any>;
      expect(document.issuer).toBe(`${ctx.baseURL}/api/auth`);
      expect(document.userinfo_endpoint).toBe(`${ctx.baseURL}/api/auth/oauth2/userinfo`);
      expect(document.claims_parameter_supported).toBe(true);
      expect(document.subject_types_supported).toEqual(["public"]);
      expect(document.id_token_signing_alg_values_supported).toEqual([
        mode === "disabled" ? "HS256" : "EdDSA",
      ]);
      for (const claim of ["sub", "sid", "name", "email_verified"]) {
        expect(document.claims_supported).toContain(claim);
      }
      return ctx.snapshot(document);
    },
  );
}

for (const mode of ["extensions", "extensions-oauth", "extensions-mutation"]) {
  compatScenario(
    `OAuth extension metadata keeps base-document isolation and first-wins ownership ${mode}`,
    async (ctx) => {
      const response = await ctx
        .actor()
        .fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-metadata?mode=${mode}`);
      expect(response.status).toBe(200);
      const document = (await response.json()) as Record<string, any>;
      expect(document.extension_stage).toBe("first");
      expect(document.extension_first_base_clean).toBe(true);
      expect(document.extension_second_base_clean).toBe(true);
      expect(document.extension_first_type).toBe(
        mode !== "extensions-oauth" ? "openid-configuration" : "oauth-authorization-server",
      );
      expect(document.extension_second_type).toBe(document.extension_first_type);
      expect(document.extension_first_scope_count).toBe(mode !== "extensions-oauth" ? 4 : 1);
      expect(document.extension_second_scope_count).toBe(document.extension_first_scope_count);
      expect(document.issuer).toBe(`${ctx.baseURL}/api/auth`);
      expect(document.grant_types_supported).toEqual([
        "authorization_code",
        "client_credentials",
        "refresh_token",
      ]);
      expect(Object.hasOwn(document, "constructor")).toBe(false);
      expect(Object.hasOwn(document, "toString")).toBe(false);
      expect(document.custom_nullable).toBeNull();
      expect(document.extension_context_header).toBeNull();
      if (mode === "extensions-mutation") {
        expect(document.extension_first_saw_mutation).toBe(false);
        expect(document.extension_second_saw_mutation).toBe(true);
        expect(document).not.toHaveProperty("shared_mutation");
      }

      if (mode !== "extensions-oauth") {
        expect(document.claims_supported).toContain("sub");
        expect(document.claims_supported).not.toContain("custom-extension-claim");
      } else {
        expect(document.claims_supported).toEqual(["custom-extension-claim"]);
      }
      return ctx.snapshot(document);
    },
  );
}
