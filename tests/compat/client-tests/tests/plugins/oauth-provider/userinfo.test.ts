import { createHash } from "node:crypto";

import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "UserInfo resolves scoped claims from real access authority with strict token transport and liveness",
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
        email: ctx.uniqueEmail("userinfo-owner"),
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
        scope: "openid email profile",
        token_endpoint_auth_method: "none",
        skip_consent: true,
      },
    });
    expect(created.status).toBe(201);
    const id = ((await created.json()) as any).client_id;
    const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const grant = await control({
      action: "authorize",
      headers: { cookie, accept: "application/json" },
      query: {
        client_id: id,
        response_type: "code",
        redirect_uri: "https://app.fixture.test/callback",
        scope: "openid email profile",
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
      code,
      code_verifier: verifier,
      redirect_uri: "https://app.fixture.test/callback",
    };
    const response = await control({ action: "token", body: input });
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("pragma")).toBe("no-cache");
    const token = (await response.json()) as any;
    expect(token.scope).toBe("openid email profile");
    expect(token.token_type).toBe("Bearer");
    expect(token.expires_in).toBe(3600);
    expect(token.access_token).toMatch(/^[A-Za-z]{32}$/);
    expect(token.refresh_token).toBeUndefined();

    const sessionResponse = await control({ action: "session", headers: { cookie } });
    expect(sessionResponse.status).toBe(200);
    const session = (await sessionResponse.json()) as any;
    const claims = {
      sub: session.user.id,
      name: "Native owner",
      given_name: "Native",
      family_name: "owner",
      email: session.user.email,
      email_verified: false,
    };
    const successes = [];
    for (const [headers, body, method, attachRequest] of [
      [{ authorization: `Bearer ${token.access_token}` }, undefined, "GET", true],
      [{ authorization: `bearer   ${token.access_token}  ` }, undefined, "GET", true],
      [{ authorization: token.access_token }, undefined, "GET", true],
      [{ authorization: `Bearer ${token.access_token}` }, undefined, "GET", false],
      [{}, { access_token: token.access_token }, "POST", true],
    ] as const) {
      const r = await control({ action: "userinfo", headers, body, method, attachRequest });
      expect(r.status).toBe(200);
      expect(r.headers.get("cache-control")).toBe("no-store");
      expect(r.headers.get("pragma")).toBe("no-cache");
      const info = await r.json();
      expect(info).toEqual(claims);
      const { sub, ...fields } = info as any;
      successes.push({ userId: sub, ...fields });
    }
    const failures = [];
    for (const [headers, body, method, attachRequest, status, error, description] of [
      [{}, undefined, "GET", true, 401, "invalid_request", "access token not found"],
      [
        {},
        { access_token: token.access_token },
        "GET",
        true,
        401,
        "invalid_request",
        "access token not found",
      ],
      [
        {},
        { access_token: token.access_token },
        "POST",
        false,
        401,
        "invalid_request",
        "access token not found",
      ],
      [
        { authorization: `Bearer ${token.access_token}` },
        { access_token: token.access_token },
        "POST",
        true,
        400,
        "invalid_request",
        "Multiple access token transport methods are not allowed",
      ],
      [
        { authorization: "Bearer missing-token" },
        undefined,
        "GET",
        true,
        401,
        "invalid_token",
        "Invalid access token",
      ],
      [
        { authorization: `DPoP ${token.access_token}` },
        undefined,
        "GET",
        true,
        401,
        "invalid_token",
        "DPoP authorization requires a DPoP-bound access token",
      ],
    ] as const) {
      const r = await control({ action: "userinfo", headers, body, method, attachRequest });
      expect(r.status).toBe(status);
      const errorBody = await r.json();
      expect(errorBody).toEqual({ error, error_description: description });
      if (description === "Invalid access token") {
        expect(r.headers.get("www-authenticate")).toBe(
          'Bearer error="invalid_token", error_description="Invalid access token"',
        );
      }
      failures.push({ status, body: errorBody });
    }

    const scoped = [];
    for (const scope of ["openid", "email"]) {
      const grant = await control({
        action: "authorize",
        headers: { cookie, accept: "application/json" },
        query: {
          client_id: id,
          response_type: "code",
          redirect_uri: "https://app.fixture.test/callback",
          scope,
          state: "token-state",
          code_challenge: challenge,
          code_challenge_method: "S256",
          ...(scope === "openid" ? { nonce: "oidc-nonce" } : {}),
        },
      });
      expect(grant.status).toBe(200);
      const code = new URL(((await grant.json()) as any).url).searchParams.get("code");
      expect(code).toBeTruthy();
      const issued = await control({ action: "token", body: { ...input, code } });
      expect(issued.status).toBe(200);
      const scopedToken = ((await issued.json()) as any).access_token;
      const r = await control({
        action: "userinfo",
        headers: { authorization: `Bearer ${scopedToken}` },
      });
      if (scope === "openid") {
        expect(r.status).toBe(200);
        expect(await r.json()).toEqual({ sub: session.user.id });
        const retired = await control({
          action: "revoke",
          body: { client_id: id, token: scopedToken, token_type_hint: "access_token" },
        });
        expect(retired.status).toBe(200);
        const denied = await control({
          action: "userinfo",
          headers: { authorization: `Bearer ${scopedToken}` },
        });
        expect(denied.status).toBe(401);
        expect(await denied.json()).toEqual({
          error: "invalid_token",
          error_description: "Invalid access token",
        });
        scoped.push({ scope, status: r.status, retired: denied.status });
      } else {
        expect(r.status).toBe(400);
        expect(await r.json()).toEqual({
          error: "invalid_scope",
          error_description: "Missing required scope",
        });
        scoped.push({ scope, status: r.status });
      }
    }
    const expired = await control({ action: "expire-session", token: session.session.token });
    expect(expired.status).toBe(200);
    expect(await expired.json()).toEqual({ expired: true });
    const denied = await control({
      action: "userinfo",
      headers: { authorization: `Bearer ${token.access_token}` },
    });
    expect(denied.status).toBe(401);
    expect(await denied.json()).toEqual({
      error: "invalid_token",
      error_description: "Invalid access token",
    });
    expect(denied.headers.get("www-authenticate")).toBe(
      'Bearer error="invalid_token", error_description="Invalid access token"',
    );
    return ctx.snapshot({
      authorizationSession: session,
      successes,
      failures,
      scoped,
      expired: denied.status,
    });
  },
);
