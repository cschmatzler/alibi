import { expect } from "bun:test";
import { createHash, createHmac } from "node:crypto";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SSO authorization uses the registered provider and persists PKCE-bound state",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const owner = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("sso-signin-owner"),
        name: "Native owner",
        password: "password123",
      },
    });
    expect(owner.status).toBe(200);
    const cookie = owner.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const registration = {
      providerId: "signin-provider",
      issuer: "https://idp.example.com",
      domain: "company.com,subsidiary.com",
      oidcConfig: {
        clientId: "enterprise-client",
        clientSecret: "stored-secret",
        skipDiscovery: true,
        pkce: true,
        scopes: ["openid", "email"],
        authorizationEndpoint: "https://idp.example.com/authorize",
        tokenEndpoint: "https://idp.example.com/token",
        jwksEndpoint: "https://idp.example.com/jwks",
      },
    };
    const created = await control({ headers: { cookie }, body: registration });
    expect(created.status).toBe(200);
    const provider = (await created.json()) as any;
    const input = {
      providerId: "signin-provider",
      callbackURL: `${ctx.baseURL}/complete`,
      errorCallbackURL: `${ctx.baseURL}/failed`,
      loginHint: "employee@company.com",
      scopes: ["openid", "profile"],
    };
    const response = await control({ action: "sign-in", body: input });
    expect(response.status).toBe(200);
    const data = (await response.json()) as any;
    expect(data.redirect).toBe(true);
    const url = new URL(data.url);
    expect(url.origin).toBe("https://idp.example.com");
    expect(url.pathname).toBe("/authorize");
    expect(url.searchParams.get("client_id")).toBe("enterprise-client");
    expect(url.searchParams.get("redirect_uri")).toBe(
      `${ctx.baseURL}/api/auth/sso/callback/signin-provider`,
    );
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("scope")).toBe("openid profile");
    expect(url.searchParams.get("login_hint")).toBe("employee@company.com");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    const state = url.searchParams.get("state")!;
    const proof = (await (
      await control({ action: "proof", identifier: `auth-state:${state}` })
    ).json()) as any;
    expect(proof).not.toBe(null);
    const payload = JSON.parse(proof.value);
    expect(payload.callbackURL).toBe(input.callbackURL);
    expect(payload.errorURL).toBe(input.errorCallbackURL);
    expect(payload.oauthState).toBe(state);
    expect(payload.codeVerifier).toHaveLength(128);
    expect(url.searchParams.get("code_challenge")).toBe(
      createHash("sha256").update(payload.codeVerifier).digest("base64url"),
    );
    expect(payload.serverContext.ssoProviderReference.providerId).toBe("signin-provider");
    expect(payload.serverContext.ssoProviderReference.source).toEqual({
      type: "persisted",
      recordId: provider.id,
    });
    const canonical = (value: any): string =>
      value === null || typeof value !== "object"
        ? JSON.stringify(value)
        : Array.isArray(value)
          ? `[${value.map(canonical).join(",")}]`
          : `{${Object.keys(value)
              .sort()
              .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
              .join(",")}}`;
    const expectedConfiguration = {
      domain: "company.com,subsidiary.com",
      issuer: "https://idp.example.com",
      organizationId: null,
      oidcConfig: {
        issuer: "https://idp.example.com",
        clientId: "enterprise-client",
        authorizationEndpoint: "https://idp.example.com/authorize",
        tokenEndpoint: "https://idp.example.com/token",
        jwksEndpoint: "https://idp.example.com/jwks",
        pkce: true,
        scopes: ["openid", "email"],
        tokenEndpointAuthentication: "client_secret_basic",
        discoveryEndpoint: "https://idp.example.com/.well-known/openid-configuration",
        overrideUserInfo: false,
      },
    };
    expect(payload.serverContext.ssoProviderReference.authenticationConfigurationFingerprint).toBe(
      createHash("sha256").update(canonical(expectedConfiguration)).digest("base64url"),
    );
    expect(Date.parse(proof.expiresAt)).toBeGreaterThan(Date.now() + 9 * 60000);
    expect(Date.parse(proof.expiresAt)).toBeLessThanOrEqual(Date.now() + 10 * 60000);
    const stateCookie = response.headers
      .getSetCookie()
      .find((value) => value.startsWith("better-auth.state="));
    expect(stateCookie).toBeDefined();
    expect(stateCookie).toContain("Max-Age=300");
    const signed = decodeURIComponent(
      stateCookie!.split(";")[0]!.slice("better-auth.state=".length),
    );
    const signature = createHmac(
      "sha256",
      ["compat", "test", "only", "key", "not", "real", "minimum", "32chars"].join("-"),
    )
      .update(state)
      .digest("base64");
    expect(signed).toBe(`${state}.${signature}`);
    for (const selector of [
      { domain: " engineering.COMPANY.com " },
      { email: "employee@engineering.subsidiary.com" },
      { domain: "COMPANY.COM" },
    ]) {
      const selected = await control({
        action: "sign-in",
        body: { ...selector, callbackURL: input.callbackURL },
      });
      expect(selected.status).toBe(200);
      const selectedURL = new URL(((await selected.json()) as any).url);
      expect(selectedURL.origin).toBe("https://idp.example.com");
      expect(selectedURL.searchParams.get("redirect_uri")).toBe(
        `${ctx.baseURL}/api/auth/sso/callback/signin-provider`,
      );
    }
    for (const domain of ["notcompany.com", "company.com.attacker.test", "unrelated.test"]) {
      const denied = await control({
        action: "sign-in",
        body: { domain, callbackURL: input.callbackURL },
      });
      expect(denied.status).toBe(404);
    }
    for (const [index, domainList, search, admitted] of [
      [
        0,
        "https://NORMALIZED.example:443/path,, subsidiary.example/path",
        "team.normalized.example",
        true,
      ],
      [1, "normalize-port.example:99999", "normalize-port.example", true],
      [2, "trailing-dot.example.", "trailing-dot.example", true],
      [3, "invalid-list.example,not a domain", "team.invalid-list.example", false],
      [4, "leading-hyphen.example,-bad.example", "team.leading-hyphen.example", false],
    ] as const) {
      const id = `normalized-provider-${index}`;
      const registered = await control({
        headers: { cookie },
        body: {
          ...registration,
          providerId: id,
          domain: domainList,
        },
      });
      expect(registered.status).toBe(200);
      const selected = await control({
        action: "sign-in",
        body: {
          domain: search,
          callbackURL: input.callbackURL,
        },
      });
      expect(selected.status).toBe(admitted ? 200 : 404);
      if (admitted) {
        const selectedURL = new URL(((await selected.json()) as any).url);
        expect(selectedURL.searchParams.get("redirect_uri")).toBe(
          `${ctx.baseURL}/api/auth/sso/callback/${id}`,
        );
      }
    }
    const missing = await control({
      action: "sign-in",
      body: { providerId: "missing-provider", callbackURL: input.callbackURL },
    });
    expect(missing.status).toBe(404);
    expect(await missing.json()).toEqual({ message: "No provider found for the issuer" });
    return {
      redirect: data.redirect,
      params: Object.fromEntries(
        [...url.searchParams].filter(
          ([key]) => !["state", "code_challenge", "redirect_uri"].includes(key),
        ),
      ),
      callbackPath: new URL(url.searchParams.get("redirect_uri")!).pathname,
      providerReference: {
        ...payload.serverContext.ssoProviderReference,
        source: { type: payload.serverContext.ssoProviderReference.source.type },
      },
      missing: missing.status,
    };
  },
);
