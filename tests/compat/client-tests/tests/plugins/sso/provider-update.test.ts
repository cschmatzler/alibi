import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Partial SSO updates preserve omitted credentials and block linked identity changes",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const signup = async (name: string) => {
      const response = await control({
        action: "signup",
        body: { email: ctx.uniqueEmail(name), name: "Native owner", password: "password123" },
      });
      expect(response.status).toBe(200);
      return {
        user: ((await response.json()) as any).user,
        cookie: response.headers
          .getSetCookie()
          .filter((raw) => Boolean(Cookie.parse(raw)?.value))
          .map((raw) => raw.split(";")[0])
          .join("; "),
      };
    };
    const owner = await signup("sso-update-owner");
    const foreign = await signup("sso-update-foreign");
    const headers = { cookie: owner.cookie };
    const created = await control({
      headers,
      body: {
        providerId: "update-provider",
        issuer: "https://idp.example.com",
        domain: "original.com",
        oidcConfig: {
          clientId: "enterprise-client",
          clientSecret: "original-secret",
          skipDiscovery: true,
          pkce: true,
          scopes: ["openid", "email"],
          authorizationEndpoint: "https://idp.example.com/authorize",
          tokenEndpoint: "https://idp.example.com/token",
          jwksEndpoint: "https://idp.example.com/jwks",
        },
      },
    });
    expect(created.status).toBe(200);
    expect(
      (
        await control({
          action: "create-account",
          body: {
            userId: owner.user.id,
            providerId: "update-provider",
            accountId: "linked-subject",
          },
        })
      ).status,
    ).toBe(200);
    const input = {
      providerId: "update-provider",
      domain: "updated.com",
      oidcConfig: { clientSecret: "rotated-secret", scopes: ["openid"], pkce: false },
    };
    const updated = await control({ action: "update", body: input, headers });
    expect(updated.status).toBe(200);
    const data = (await updated.json()) as any;
    expect(data.domain).toBe("updated.com");
    expect(data.domainVerified).toBe(false);
    expect(data.oidcConfig.scopes).toEqual(["openid"]);
    expect(data.oidcConfig.pkce).toBe(false);
    expect(data.oidcConfig.clientIdLastFour).toBe("****ient");
    expect(data.oidcConfig.clientSecret).toBeUndefined();
    const row = (await (
      await control({ action: "row", providerId: "update-provider" })
    ).json()) as any;
    const config = JSON.parse(row.oidcConfig);
    expect(config.clientSecret).toBe("rotated-secret");
    expect(config.clientId).toBe("enterprise-client");
    expect(config.tokenEndpoint).toBe("https://idp.example.com/token");
    expect(config.tokenEndpointAuthentication).toBe("client_secret_basic");
    for (const field of [
      "authorizationEndpoint",
      "tokenEndpoint",
      "userInfoEndpoint",
      "jwksEndpoint",
      "discoveryEndpoint",
    ]) {
      for (const [value, detail] of [
        ["not-a-url", "must be valid"],
        ["ftp://idp.example.com/endpoint", "must use the http or https supported protocols"],
      ]) {
        const response = await control({
          action: "update",
          headers,
          body: { providerId: "update-provider", oidcConfig: { [field]: value } },
        });
        expect(response.status).toBe(400);
        expect(await response.json()).toEqual(
          value === "not-a-url"
            ? { code: "VALIDATION_ERROR", message: `[body.oidcConfig.${field}] Invalid URL` }
            : {
                code: "discovery_invalid_url",
                message: `Invalid OIDC endpoint URL: The url "${field}" ${detail}: ${value}`,
              },
        );
        expect(
          await (await control({ action: "row", providerId: "update-provider" })).json(),
        ).toEqual(row);
      }
    }
    const rejected = [];
    for (const body of [
      { providerId: "update-provider", issuer: "https://other-idp.example.com" },
      { providerId: "update-provider", oidcConfig: { clientId: "different-client" } },
    ]) {
      const response = await control({ action: "update", body, headers });
      expect(response.status).toBe(409);
      const error = await response.json();
      expect(error).toEqual({
        message: "Cannot change SSO provider identity fields while linked accounts exist",
      });
      expect(
        await (await control({ action: "row", providerId: "update-provider" })).json(),
      ).toEqual(row);
      rejected.push(error);
    }
    const empty = await control({
      action: "update",
      body: { providerId: "missing-provider" },
      headers,
    });
    expect(empty.status).toBe(400);
    expect(await empty.json()).toEqual({ message: "No fields provided for update" });
    const denied = await control({
      action: "update",
      body: input,
      headers: { cookie: foreign.cookie },
    });
    expect(denied.status).toBe(403);
    const anonymous = await control({ action: "update", body: input, headers: {} });
    expect(anonymous.status).toBe(401);
    expect(data.spMetadataUrl).toBe(
      `${ctx.baseURL}/api/auth/sso/saml2/sp/metadata?providerId=update-provider`,
    );
    return {
      data: {
        ...data,
        spMetadataUrl: new URL(data.spMetadataUrl).pathname + new URL(data.spMetadataUrl).search,
      },
      row: { ...row, oidcConfig: config },
      rejected,
      empty: empty.status,
      denied: denied.status,
      anonymous: anonymous.status,
    };
  },
);
