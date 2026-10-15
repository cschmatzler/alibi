import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
import { privateEndpointURLs, privateEndpointError } from "./private-endpoint-input";
compatScenario(
  "SSO registration persists owned OIDC configuration and rejects duplicate and reserved providers",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const signup = await control({
      action: "signup",
      body: { email: ctx.uniqueEmail("sso-owner"), name: "Native owner", password: "password123" },
    });
    expect(signup.status).toBe(200);
    const owner = (await signup.json()) as any;
    const cookie = signup.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const body = {
      providerId: "enterprise-oidc",
      issuer: "https://idp.example.com",
      domain: "company.com,subsidiary.com",
      oidcConfig: {
        clientId: "enterprise-client",
        clientSecret: "enterprise-secret",
        skipDiscovery: true,
        authorizationEndpoint: "https://idp.example.com/authorize",
        tokenEndpoint: "https://idp.example.com/token",
        jwksEndpoint: "https://idp.example.com/jwks",
        scopes: ["openid", "email"],
        pkce: true,
      },
    };
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
        const providerId = `invalid-${field}-${value === "not-a-url" ? "syntax" : "protocol"}`;
        const rejected = await control({
          headers: { cookie },
          body: { ...body, providerId, oidcConfig: { ...body.oidcConfig, [field]: value } },
        });
        expect(rejected.status).toBe(400);
        expect(await rejected.json()).toEqual(
          value === "not-a-url"
            ? { code: "VALIDATION_ERROR", message: `[body.oidcConfig.${field}] Invalid URL` }
            : {
                code: "discovery_invalid_url",
                message: `Invalid OIDC endpoint URL: The url "${field}" ${detail}: ${value}`,
              },
        );
        expect(await (await control({ action: "row", providerId })).json()).toBe(null);
      }
    }
    for (const field of [
      "authorizationEndpoint",
      "tokenEndpoint",
      "userInfoEndpoint",
      "jwksEndpoint",
      "discoveryEndpoint",
    ]) {
      for (const [index, value] of privateEndpointURLs.entries()) {
        const providerId = `private-${field}-${index}`;
        const response = await control({
          headers: { cookie },
          body: { ...body, providerId, oidcConfig: { ...body.oidcConfig, [field]: value } },
        });
        expect(response.status).toBe(400);
        expect(await response.json()).toEqual(privateEndpointError(field, value));
        expect(await (await control({ action: "row", providerId })).json()).toBe(null);
      }
    }
    const trustedId = "trusted-private-endpoints";
    const trustedEndpoints = Object.fromEntries(
      [
        "authorizationEndpoint",
        "tokenEndpoint",
        "userInfoEndpoint",
        "jwksEndpoint",
        "discoveryEndpoint",
      ].map((field) => [field, `${ctx.baseURL}/${field}`]),
    );
    const trusted = await control({
      headers: { cookie },
      body: {
        ...body,
        providerId: trustedId,
        oidcConfig: { ...body.oidcConfig, ...trustedEndpoints },
      },
    });
    expect(trusted.status).toBe(200);
    const changedEndpoints = Object.fromEntries(
      Object.keys(trustedEndpoints).map((field) => [field, `${ctx.baseURL}/changed/${field}`]),
    );
    const changed = await control({
      action: "update",
      headers: { cookie },
      body: { providerId: trustedId, oidcConfig: changedEndpoints },
    });
    expect(changed.status).toBe(200);
    const trustedRow = (await (
      await control({ action: "row", providerId: trustedId })
    ).json()) as any;
    expect(JSON.parse(trustedRow.oidcConfig)).toMatchObject(changedEndpoints);
    const publicId = "public-ip-endpoints";
    const publicEndpoints = Object.fromEntries(
      Object.keys(trustedEndpoints).map((field) => [field, `https://[64:ff9b:2::1]/${field}`]),
    );
    const publicProvider = await control({
      headers: { cookie },
      body: {
        ...body,
        providerId: publicId,
        oidcConfig: { ...body.oidcConfig, ...publicEndpoints },
      },
    });
    expect(publicProvider.status).toBe(200);
    const publicRow = (await (
      await control({ action: "row", providerId: publicId })
    ).json()) as any;
    expect(JSON.parse(publicRow.oidcConfig)).toMatchObject(publicEndpoints);
    const created = await control({ body, headers: { cookie } });
    expect(created.status).toBe(200);
    const provider = (await created.json()) as any;
    expect(provider.providerId).toBe("enterprise-oidc");
    expect(provider.userId).toBe(owner.user.id);
    expect(provider.domain).toBe(body.domain);
    expect(provider.oidcConfig).toEqual({
      issuer: body.issuer,
      clientId: "enterprise-client",
      clientSecret: "enterprise-secret",
      authorizationEndpoint: body.oidcConfig.authorizationEndpoint,
      tokenEndpoint: body.oidcConfig.tokenEndpoint,
      jwksEndpoint: body.oidcConfig.jwksEndpoint,
      tokenEndpointAuthentication: "client_secret_basic",
      discoveryEndpoint: `${body.issuer}/.well-known/openid-configuration`,
      scopes: ["openid", "email"],
      pkce: true,
      overrideUserInfo: false,
    });
    expect(provider.samlConfig).toBe(null);
    expect(provider.domainVerified).toBeUndefined();
    expect(provider.redirectURI).toBe(`${ctx.baseURL}/api/auth/sso/callback/enterprise-oidc`);
    expect((await control({ action: "restart" })).status).toBe(200);
    const persisted = (await (
      await control({ action: "row", providerId: body.providerId })
    ).json()) as any;
    expect(persisted.id).toBe(provider.id);
    expect(persisted.userId).toBe(owner.user.id);
    expect(JSON.parse(persisted.oidcConfig)).toEqual(provider.oidcConfig);
    const duplicate = await control({ body, headers: { cookie } });
    expect(duplicate.status).toBe(422);
    expect(await duplicate.json()).toEqual({
      message: "SSO provider with this providerId already exists",
    });
    const reserved = await control({
      body: { ...body, providerId: "credential" },
      headers: { cookie },
    });
    expect(reserved.status).toBe(422);
    expect(await reserved.json()).toEqual({
      message: "This providerId is reserved and cannot be used for an SSO provider",
    });
    const anonymous = await control({ body, headers: {} });
    expect(anonymous.status).toBe(401);
    return {
      provider: { ...provider, redirectURI: new URL(provider.redirectURI).pathname },
      persisted: { ...persisted, oidcConfig: JSON.parse(persisted.oidcConfig) },
      duplicate: duplicate.status,
      reserved: reserved.status,
      anonymous: anonymous.status,
    };
  },
);
