import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SSO provider lists isolate real owners and redact every stored credential",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const signup = async (name: string) => {
      const result = await control({
        action: "signup",
        body: { email: ctx.uniqueEmail(name), name: "Native owner", password: "password123" },
      });
      expect(result.status).toBe(200);
      return result.headers
        .getSetCookie()
        .filter((raw) => Boolean(Cookie.parse(raw)?.value))
        .map((raw) => raw.split(";")[0])
        .join("; ");
    };
    const owner = await signup("sso-list-owner");
    const foreign = await signup("sso-list-foreign");
    const empty = await signup("sso-list-empty");
    for (const [cookie, providerId, clientId] of [
      [foreign, "foreign-provider", "foreign-client"],
      [owner, "owned-alpha", "alpha-client"],
      [owner, "owned-beta", "beta-client"],
    ]) {
      const created = await control({
        headers: { cookie },
        body: {
          providerId,
          issuer: "https://idp.example.com",
          domain: "company.com",
          oidcConfig: {
            clientId,
            clientSecret: "stored-secret",
            skipDiscovery: true,
            pkce: true,
            scopes: ["openid", "email"],
          },
        },
      });
      expect(created.status).toBe(200);
    }
    const results = [];
    for (const [cookie, ids] of [
      [owner, ["owned-alpha", "owned-beta"]],
      [foreign, ["foreign-provider"]],
      [empty, []],
    ] as const) {
      const result = await control({ action: "list", headers: { cookie } });
      expect(result.status).toBe(200);
      const data = (await result.json()) as any;
      expect(data.providers.map((provider: any) => provider.providerId)).toEqual(ids);
      for (const provider of data.providers) {
        expect(provider.type).toBe("oidc");
        expect(provider.domainVerified).toBe(false);
        expect(provider.organizationId).toBe(null);
        expect(provider.oidcConfig.clientIdLastFour).toBe("****ient");
        expect(provider.oidcConfig.clientId).toBeUndefined();
        expect(provider.oidcConfig.clientSecret).toBeUndefined();
        expect(provider.userId).toBeUndefined();
        expect(provider.spMetadataUrl).toBe(
          `${ctx.baseURL}/api/auth/sso/saml2/sp/metadata?providerId=${provider.providerId}`,
        );
      }
      results.push({
        providers: data.providers.map((provider: any) => ({
          ...provider,
          spMetadataUrl:
            new URL(provider.spMetadataUrl).pathname + new URL(provider.spMetadataUrl).search,
        })),
      });
    }
    const anonymous = await control({ action: "list", headers: {} });
    expect(anonymous.status).toBe(401);
    return { results, anonymous: anonymous.status };
  },
);
