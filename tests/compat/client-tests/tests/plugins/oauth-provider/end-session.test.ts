import { createHash } from "node:crypto";

import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "End-session verifies actual ID-token hints and deletes only the issuing session",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: unknown) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        redirect: "manual",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const signup = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("logout-owner"),
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
        enable_end_session: true,
        post_logout_redirect_uris: ["https://app.fixture.test/logout"],
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
    const hintPayload = JSON.parse(
      Buffer.from(token.id_token.split(".")[1], "base64url").toString(),
    );
    expect(hintPayload.sid).toBe(session.session.id);
    expect(hintPayload.sub).toBe(session.user.id);
    const failures = [];
    for (const [query, status, error, error_description] of [
      [{}, 400, "invalid_request", "No active session is available for logout"],
      [{ client_id: "missing" }, 400, "invalid_client", "The logout client does not exist"],
      [
        { client_id: id, id_token_hint: "tampered" },
        401,
        "invalid_token",
        "The id_token_hint is invalid",
      ],
    ] as const) {
      const r = await control({ action: "end-session", query });
      expect(r.status).toBe(status);
      const body = await r.json();
      expect(body).toEqual({ error, error_description });
      failures.push({ status, body });
    }
    const confirmation = await control({
      action: "end-session",
      query: { client_id: id },
      headers: { cookie },
    });
    expect(confirmation.status).toBe(400);
    expect(await confirmation.json()).toEqual({
      error: "invalid_request",
      error_description: "User confirmation is required to complete logout",
    });
    const unrelated = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("logout-other"),
        name: "Native owner",
        password: "password123",
      },
    });
    expect(unrelated.status).toBe(200);
    const otherCookie = unrelated.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const ended = await control({
      action: "end-session",
      query: {
        id_token_hint: token.id_token,
        post_logout_redirect_uri: "https://app.fixture.test/logout",
        state: "logout-state",
      },
    });
    expect(ended.status).toBe(302);
    expect(ended.headers.get("content-type")).toBe("application/json");
    expect(ended.headers.get("location")).toBe(
      "https://app.fixture.test/logout?state=logout-state",
    );
    const current = await control({ action: "session", headers: { cookie } });
    expect(current.status).toBe(200);
    expect(await current.json()).toBeNull();
    const other = await control({ action: "session", headers: { cookie: otherCookie } });
    expect(other.status).toBe(200);
    const otherSession = (await other.json()) as any;
    expect(otherSession.user.email).toContain("logout-other");
    const repeated = await control({
      action: "end-session",
      query: {
        id_token_hint: token.id_token,
        post_logout_redirect_uri: "https://evil.fixture.test/logout",
      },
    });
    expect(repeated.status).toBe(200);
    expect(await repeated.json()).toBeNull();
    return ctx.snapshot({
      authorizationSession: session,
      otherAuthorizationSession: otherSession,
      failures,
      ended: ended.status,
      deleted: current.status,
      unrelated: other.status,
      repeated: repeated.status,
    });
  },
);
