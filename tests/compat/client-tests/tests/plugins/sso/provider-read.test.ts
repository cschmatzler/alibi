import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SSO provider reads authorize the owner and redact real stored OIDC credentials",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const cookies = (response: Response) =>
      response.headers
        .getSetCookie()
        .filter((raw) => Boolean(Cookie.parse(raw)?.value))
        .map((raw) => raw.split(";")[0])
        .join("; ");
    const owner = await control({
      action: "signup",
      body: { email: ctx.uniqueEmail("sso-reader"), name: "Native owner", password: "password123" },
    });
    expect(owner.status).toBe(200);
    const foreign = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("sso-foreign"),
        name: "Native owner",
        password: "password123",
      },
    });
    expect(foreign.status).toBe(200);
    const headers = { cookie: cookies(owner) };
    const created = await control({
      headers,
      body: {
        providerId: "read-provider",
        issuer: "https://idp.example.com",
        domain: "company.com",
        oidcConfig: {
          clientId: "enterprise-client",
          clientSecret: "stored-secret",
          skipDiscovery: true,
          authorizationEndpoint: "https://idp.example.com/authorize",
          tokenEndpoint: "https://idp.example.com/token",
          jwksEndpoint: "https://idp.example.com/jwks",
          pkce: true,
          scopes: ["openid", "email"],
        },
      },
    });
    expect(created.status).toBe(200);
    const result = await control({
      action: "get",
      query: { providerId: "read-provider" },
      headers,
    });
    expect(result.status).toBe(200);
    const provider = (await result.json()) as any;
    expect(provider).toEqual({
      providerId: "read-provider",
      type: "oidc",
      issuer: "https://idp.example.com",
      domain: "company.com",
      organizationId: null,
      domainVerified: false,
      oidcConfig: {
        discoveryEndpoint: "https://idp.example.com/.well-known/openid-configuration",
        clientIdLastFour: "****ient",
        pkce: true,
        authorizationEndpoint: "https://idp.example.com/authorize",
        tokenEndpoint: "https://idp.example.com/token",
        jwksEndpoint: "https://idp.example.com/jwks",
        scopes: ["openid", "email"],
        tokenEndpointAuthentication: "client_secret_basic",
      },
      spMetadataUrl: `${ctx.baseURL}/api/auth/sso/saml2/sp/metadata?providerId=read-provider`,
    });
    const denied = await control({
      action: "get",
      query: { providerId: "read-provider" },
      headers: { cookie: cookies(foreign) },
    });
    expect(denied.status).toBe(403);
    expect(await denied.json()).toEqual({ message: "You don't have access to this provider" });
    const missing = await control({
      action: "get",
      query: { providerId: "missing-provider" },
      headers,
    });
    expect(missing.status).toBe(404);
    expect(await missing.json()).toEqual({ message: "Provider not found" });
    const anonymous = await control({
      action: "get",
      query: { providerId: "read-provider" },
      headers: {},
    });
    expect(anonymous.status).toBe(401);
    const row = (await (
      await control({ action: "row", providerId: "read-provider" })
    ).json()) as any;
    expect(JSON.parse(row.oidcConfig).clientSecret).toBe("stored-secret");
    return {
      provider: {
        ...provider,
        spMetadataUrl:
          new URL(provider.spMetadataUrl).pathname + new URL(provider.spMetadataUrl).search,
      },
      denied: denied.status,
      missing: missing.status,
      anonymous: anonymous.status,
    };
  },
);
