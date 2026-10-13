import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SSO callback redeems a real PKCE code and creates a usable session",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
        redirect: "manual",
      });
    const pairs = (response: Response) =>
      response.headers
        .getSetCookie()
        .filter((raw) => Boolean(Cookie.parse(raw)?.value))
        .map((raw) => raw.split(";")[0])
        .join("; ");
    const email = ctx.uniqueEmail("sso-employee");
    const idp = (await (await control({ action: "idp", email })).json()) as any;
    const owner = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("sso-callback-owner"),
        name: "Native owner",
        password: "password123",
      },
    });
    expect(owner.status).toBe(200);
    const created = await control({
      headers: { cookie: pairs(owner) },
      body: {
        providerId: "callback-provider",
        issuer: idp.base,
        domain: "example.test",
        oidcConfig: {
          clientId: "enterprise-client",
          clientSecret: "stored-secret",
          skipDiscovery: true,
          pkce: true,
          scopes: ["openid", "email"],
          authorizationEndpoint: `${idp.base}/authorize`,
          tokenEndpoint: `${idp.base}/token`,
          userInfoEndpoint: `${idp.base}/userinfo`,
          jwksEndpoint: `${idp.base}/jwks`,
        },
      },
    });
    expect(created.status).toBe(200);
    const started = await control({
      action: "sign-in",
      body: {
        providerId: "callback-provider",
        callbackURL: `${ctx.baseURL}/complete`,
        errorCallbackURL: `${ctx.baseURL}/failed`,
      },
    });
    expect(started.status, await started.clone().text()).toBe(200);
    const authorization = ((await started.json()) as any).url;
    // The independent IdP mints a unique code; compare Alibi and Better Auth, not IdP randomness.
    const granted = await fetch(authorization, { redirect: "manual" });
    expect(granted.status).toBe(302);
    const callback = new URL(granted.headers.get("location")!);
    const query = Object.fromEntries(callback.searchParams);
    const state = query.state;
    const proof = (await (
      await control({ action: "proof", identifier: `auth-state:${state}` })
    ).json()) as any;
    const payload = JSON.parse(proof.value);
    const input = {
      action: "callback",
      params: { providerId: "callback-provider" },
      query,
      headers: { cookie: pairs(started) },
    };
    const unbound = await control({ ...input, headers: {} });
    expect(unbound.status).toBe(302);
    expect(unbound.headers.get("location")).toBe(`${ctx.baseURL}/failed?error=state_mismatch`);
    expect(
      await (await control({ action: "proof", identifier: `auth-state:${state}` })).json(),
    ).not.toBe(null);
    expect(await (await control({ action: "idp-exchanges" })).json()).toHaveLength(0);
    const completed = await control(input);
    expect(completed.status).toBe(302);
    expect(completed.headers.get("location")).toBe(`${ctx.baseURL}/complete`);
    const session = await control({ action: "session", headers: { cookie: pairs(completed) } });
    expect(session.status).toBe(200);
    const authenticated = (await session.json()) as any;
    expect(authenticated.user.email).toBe(email);
    expect(authenticated.user.name).toBe("SSO employee");
    expect(authenticated.user.emailVerified).toBe(false);
    expect(
      await (await control({ action: "proof", identifier: `auth-state:${state}` })).json(),
    ).toBe(null);
    const account = (await (
      await control({
        action: "account-row",
        providerId: "callback-provider",
        accountId: "employee-subject",
      })
    ).json()) as any;
    expect(account).not.toBe(null);
    expect(account.userId).toBe(authenticated.user.id);
    const exchanges = (await (await control({ action: "idp-exchanges" })).json()) as any[];
    expect(exchanges).toHaveLength(1);
    expect(exchanges[0].form.code_verifier).toBe(payload.codeVerifier);
    expect(exchanges[0].form.redirect_uri).toBe(
      `${ctx.baseURL}/api/auth/sso/callback/callback-provider`,
    );
    expect(exchanges[0].authorization).toBe("Basic ZW50ZXJwcmlzZS1jbGllbnQ6c3RvcmVkLXNlY3JldA==");
    const replay = await control(input);
    expect(replay.status).toBe(302);
    expect(replay.headers.get("location")).toContain("error=state_mismatch");
    expect(await (await control({ action: "idp-exchanges" })).json()).toHaveLength(1);
    return { authenticated, account, completed: completed.status, replay: replay.status };
  },
);
