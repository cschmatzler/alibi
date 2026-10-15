import { createHash } from "node:crypto";

import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Sign-out retires session-bound access tokens while offline refresh authority survives",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: unknown) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const signup = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("retirement-owner"),
        name: "Native owner",
        password: "password123",
      },
    });
    expect(signup.status).toBe(200);
    const cookie = signup.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const created = await control({
      action: "admin-create",
      headers: { cookie },
      body: {
        client_name: "Token client",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "openid email offline_access",
        token_endpoint_auth_method: "client_secret_post",
        skip_consent: true,
        grant_types: ["authorization_code", "refresh_token"],
      },
    });
    expect(created.status).toBe(201);
    const client = (await created.json()) as any;
    const id = client.client_id;
    expect(typeof client.client_secret).toBe("string");
    const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const grant = await control({
      action: "authorize",
      headers: { cookie, accept: "application/json" },
      query: {
        client_id: id,
        response_type: "code",
        redirect_uri: "https://app.fixture.test/callback",
        scope: "openid email offline_access",
        state: "token-state",
        nonce: "oidc-nonce",
        code_challenge: challenge,
        code_challenge_method: "S256",
      },
    });
    expect(grant.status).toBe(200);
    const callback = new URL(((await grant.json()) as any).url);
    expect(callback.pathname).toBe("/callback");
    expect(callback.searchParams.get("state")).toBe("token-state");
    const code = callback.searchParams.get("code");
    expect(code).toBeTruthy();
    const input = {
      grant_type: "authorization_code",
      client_id: id,
      client_secret: client.client_secret,
      code,
      code_verifier: verifier,
      redirect_uri: "https://app.fixture.test/callback",
    };
    const response = await control({ action: "token", body: input });
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("pragma")).toBe("no-cache");
    const token = (await response.json()) as any;
    expect(token.scope).toBe("openid email offline_access");
    expect(token.token_type).toBe("Bearer");
    expect(token.expires_in).toBe(3600);
    expect(token.access_token).toMatch(/^[A-Za-z]{32}$/);
    expect(token.refresh_token).toMatch(/^[A-Za-z]{32}$/);

    const sessionResponse = await control({ action: "session", headers: { cookie } });
    expect(sessionResponse.status).toBe(200);
    const session = (await sessionResponse.json()) as any;
    const otherSignup = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("retirement-other"),
        name: "Native owner",
        password: "password123",
      },
    });
    expect(otherSignup.status).toBe(200);
    const otherCookie = otherSignup.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const otherSessionResponse = await control({
      action: "session",
      headers: { cookie: otherCookie },
    });
    expect(otherSessionResponse.status).toBe(200);
    const otherSession = (await otherSessionResponse.json()) as any;
    const otherGrant = await control({
      action: "authorize",
      headers: { cookie: otherCookie, accept: "application/json" },
      query: {
        client_id: id,
        response_type: "code",
        redirect_uri: "https://app.fixture.test/callback",
        scope: "openid email offline_access",
        state: "token-state",
        nonce: "oidc-nonce",
        code_challenge: challenge,
        code_challenge_method: "S256",
      },
    });
    expect(otherGrant.status).toBe(200);
    const otherCode = new URL(((await otherGrant.json()) as any).url).searchParams.get("code");
    const issuedOther = await control({ action: "token", body: { ...input, code: otherCode } });
    expect(issuedOther.status).toBe(200);
    const otherToken = (await issuedOther.json()) as any;
    expect(otherToken.access_token).not.toBe(token.access_token);
    const before = await control({
      action: "token-row",
      kind: "access",
      token: token.access_token,
    });
    expect(before.status).toBe(200);
    const original = (await before.json()) as any;
    expect(original.revoked).toBeNull();
    const started = Date.now();
    const ended = await control({
      action: "signout",
      headers: { cookie, origin: ctx.baseURL },
      foreignKeys: true,
    });
    const finished = Date.now();
    expect(ended.status).toBe(200);
    const afterResponse = await control({
      action: "token-row",
      kind: "access",
      token: token.access_token,
    });
    expect(afterResponse.status).toBe(200);
    const after = (await afterResponse.json()) as any;
    expect(after.id).toBe(original.id);
    expect(after.sessionId).toBeNull();
    expect(Date.parse(after.revoked)).toBeGreaterThanOrEqual(started);
    expect(Date.parse(after.revoked)).toBeLessThanOrEqual(finished);
    const denied = await control({
      action: "userinfo",
      headers: { authorization: `Bearer ${token.access_token}` },
    });
    expect(denied.status).toBe(401);
    expect(await denied.json()).toEqual({
      error: "invalid_token",
      error_description: "Invalid access token",
    });
    const results = [];
    for (const [value, hint, active] of [
      [token.access_token, "access_token", false],
      [token.refresh_token, "refresh_token", true],
    ] as const) {
      const observed = await control({
        action: "introspect",
        body: {
          client_id: id,
          client_secret: client.client_secret,
          token: value,
          token_type_hint: hint,
        },
      });
      expect(observed.status).toBe(200);
      const body = (await observed.json()) as any;
      expect(body.active).toBe(active);
      results.push({ hint, active: body.active });
    }
    const refreshed = await control({
      action: "token-row",
      kind: "refresh",
      token: token.refresh_token,
    });
    expect(refreshed.status).toBe(200);
    expect(((await refreshed.json()) as any).revoked).toBeNull();
    const unaffected = await control({
      action: "userinfo",
      headers: { authorization: `Bearer ${otherToken.access_token}` },
    });
    expect(unaffected.status).toBe(200);
    const info = (await unaffected.json()) as any;
    expect(info.sub).toBe(otherSession.user.id);
    return ctx.snapshot({
      authorizationSession: session,
      otherAuthorizationSession: otherSession,
      unaffected: unaffected.status,
      ended: ended.status,
      denied: denied.status,
      results,
    });
  },
);
