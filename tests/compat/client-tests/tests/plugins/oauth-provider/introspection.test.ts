import { createHash } from "node:crypto";

import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Introspection reports genuine issued tokens and respects access versus refresh session liveness",
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
        email: ctx.uniqueEmail("introspection-owner"),
        name: "Owner",
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
        scope: "email offline_access",
        token_endpoint_auth_method: "client_secret_post",
        skip_consent: true,
        grant_types: ["authorization_code", "refresh_token"],
      },
    });
    expect(created.status).toBe(201);
    const client = (await created.json()) as any;
    const id = client.client_id;
    const secret = client.client_secret;
    const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const grant = await control({
      action: "authorize",
      headers: { cookie, accept: "application/json" },
      query: {
        client_id: id,
        response_type: "code",
        redirect_uri: "https://app.fixture.test/callback",
        scope: "email offline_access",
        state: "token-state",
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
      client_secret: secret,
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
    expect(token.scope).toBe("email offline_access");
    expect(token.token_type).toBe("Bearer");
    expect(token.expires_in).toBe(3600);
    expect(token.access_token).toMatch(/^[A-Za-z]{32}$/);
    expect(token.refresh_token).toMatch(/^[A-Za-z]{32}$/);
    expect(token.id_token).toBeUndefined();

    const sessionResponse = await control({ action: "session", headers: { cookie } });
    expect(sessionResponse.status).toBe(200);
    const session = (await sessionResponse.json()) as any;
    const active = [];
    for (const [issued, kind, lifetime] of [
      [token.access_token, "access_token", 3600],
      [token.refresh_token, "refresh_token", 2_592_000],
    ] as const) {
      for (const hint of [kind, undefined, "unknown_hint"]) {
        const response = await control({
          action: "introspect",
          body: {
            client_id: id,
            client_secret: secret,
            token: issued,
            ...(hint ? { token_type_hint: hint } : {}),
          },
        });
        expect(response.status).toBe(200);
        expect(response.headers.get("cache-control")).toBe("no-store");
        expect(response.headers.get("pragma")).toBe("no-cache");
        const payload = (await response.json()) as any;
        expect(payload.active).toBe(true);
        expect(payload.client_id).toBe(id);
        expect(payload.sub).toBe(session.user.id);
        expect(payload.sid).toBe(session.session.id);
        expect(payload.iss).toBe(`${ctx.baseURL}/api/auth`);
        expect(payload.scope).toBe("email offline_access");
        expect(payload.token_type).toBe("Bearer");
        expect(payload.exp - payload.iat).toBe(lifetime);
        expect(payload.aud).toBeUndefined();
        if (kind === "access_token") expect(payload.azp).toBe(id);
        else expect(payload.azp).toBeUndefined();
        active.push({ kind, hint: hint ?? null, lifetime: payload.exp - payload.iat });
      }
    }
    const failures = [];
    for (const [body, status, error, description] of [
      [{ token: token.access_token }, 401, "invalid_client", "missing required credentials"],
      [
        { client_id: id, client_secret: "wrong", token: token.access_token },
        400,
        "invalid_client",
        "invalid client_secret",
      ],
      [
        { client_id: id, client_secret: secret, token: "" },
        400,
        "invalid_request",
        "missing a required token for introspection",
      ],
    ] as const) {
      const r = await control({ action: "introspect", body });
      expect(r.status).toBe(status);
      const errorBody = await r.json();
      expect(errorBody).toEqual({ error, error_description: description });
      failures.push({ status, body: errorBody });
    }
    const inactive = [];
    for (const [issued, hint] of [
      ["unknown-token", "access_token"],
      ["unknown-token", "refresh_token"],
      [token.access_token, "refresh_token"],
      [token.refresh_token, "access_token"],
    ]) {
      const r = await control({
        action: "introspect",
        body: { client_id: id, client_secret: secret, token: issued, token_type_hint: hint },
      });
      expect(r.status).toBe(200);
      expect(await r.json()).toEqual({ active: false });
      inactive.push({ hint, active: false });
    }
    const expired = await control({ action: "expire-session", token: session.session.token });
    expect(expired.status).toBe(200);
    expect(await expired.json()).toEqual({ expired: true });
    const liveness = [];
    for (const [issued, hint, active] of [
      [token.access_token, "access_token", false],
      [token.refresh_token, "refresh_token", true],
    ] as const) {
      const r = await control({
        action: "introspect",
        body: { client_id: id, client_secret: secret, token: issued, token_type_hint: hint },
      });
      expect(r.status).toBe(200);
      const payload = (await r.json()) as any;
      expect(payload.active).toBe(active);
      expect(payload.sid).toBeUndefined();
      if (active) {
        expect(payload.sub).toBe(session.user.id);
        expect(payload.scope).toBe("email offline_access");
        expect(payload.client_id).toBe(id);
        expect(payload.iss).toBe(`${ctx.baseURL}/api/auth`);
        expect(payload.exp - payload.iat).toBe(2_592_000);
      } else {
        expect(payload).toEqual({ active: false });
      }
      liveness.push({
        hint,
        active: payload.active,
        scope: payload.scope ?? null,
        lifetime: payload.active ? payload.exp - payload.iat : null,
        sessionAbsent: payload.sid === undefined,
      });
    }
    return ctx.snapshot({ authorizationSession: session, active, failures, inactive, liveness });
  },
);
