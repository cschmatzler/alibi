import { expect } from "bun:test";
import { createHash } from "node:crypto";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "OAuth HTTP form endpoints deliver real grants, claims, introspection and revocation",
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
        email: ctx.uniqueEmail("form-owner"),
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
        token_endpoint_auth_method: "client_secret_post",
        skip_consent: true,
      },
    });
    expect(created.status).toBe(201);
    const client = (await created.json()) as any;
    const id = client.client_id;
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
      client_secret: client.client_secret,
      code,
      code_verifier: verifier,
      redirect_uri: "https://app.fixture.test/callback",
    };
    const response = await control({
      action: "protocol-http",
      path: "/oauth2/token",
      method: "POST",
      body: input,
    });
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
    const get = await control({
      action: "protocol-http",
      path: "/oauth2/userinfo",
      method: "GET",
      headers: { authorization: `Bearer ${token.access_token}` },
    });
    expect(get.status).toBe(200);
    expect(await get.json()).toEqual(claims);
    const post = await control({
      action: "protocol-http",
      path: "/oauth2/userinfo",
      method: "POST",
      body: { access_token: token.access_token },
    });
    expect(post.status).toBe(200);
    expect(await post.json()).toEqual(claims);
    const introspection = {
      client_id: id,
      client_secret: client.client_secret,
      token: token.access_token,
      token_type_hint: "access_token",
    };
    const observed = await control({
      action: "protocol-http",
      path: "/oauth2/introspect",
      method: "POST",
      body: introspection,
    });
    expect(observed.status).toBe(200);
    expect(((await observed.json()) as any).active).toBe(true);
    const rejections = [];
    for (const [path, body] of [
      ["/oauth2/token", input],
      ["/oauth2/introspect", introspection],
      ["/oauth2/revoke", introspection],
      ["/oauth2/userinfo", { access_token: token.access_token }],
    ] as const) {
      const denied = await control({
        action: "protocol-http",
        path,
        method: "POST",
        body,
        contentType: "application/json",
      });
      expect(denied.status).toBe(415);
      const error = await denied.json();
      expect(error).toEqual({
        code: "UNSUPPORTED_MEDIA_TYPE",
        message:
          'Content-Type "application/json" is not allowed. Allowed types: application/x-www-form-urlencoded',
      });
      rejections.push(error);
    }
    const retired = await control({
      action: "protocol-http",
      path: "/oauth2/revoke",
      method: "POST",
      body: introspection,
    });
    expect(retired.status).toBe(200);
    expect(await retired.text()).toBe("");
    const inactive = await control({
      action: "protocol-http",
      path: "/oauth2/introspect",
      method: "POST",
      body: introspection,
    });
    expect(inactive.status).toBe(200);
    expect(await inactive.json()).toEqual({ active: false });
    const denied = await control({
      action: "protocol-http",
      path: "/oauth2/userinfo",
      method: "POST",
      body: { access_token: token.access_token },
    });
    expect(denied.status).toBe(401);
    expect(await denied.json()).toEqual({
      error: "invalid_token",
      error_description: "Invalid access token",
    });
    return ctx.snapshot({
      authorizationSession: session,
      rejections,
      retired: retired.status,
      inactive: inactive.status,
      denied: denied.status,
    });
  },
);
