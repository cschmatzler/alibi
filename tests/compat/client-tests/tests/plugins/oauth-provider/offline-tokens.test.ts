import { createHash } from "node:crypto";

import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Offline access issues protected linked refresh and access tokens with replay cleanup",
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
      body: { email: ctx.uniqueEmail("offline-owner"), name: "Owner", password: "password123" },
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
        token_endpoint_auth_method: "none",
        skip_consent: true,
        grant_types: ["authorization_code", "refresh_token"],
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

    const accessResponse = await control({ action: "token-row", token: token.access_token });
    const refreshResponse = await control({
      action: "token-row",
      kind: "refresh",
      token: token.refresh_token,
    });
    expect(accessResponse.status).toBe(200);
    expect(refreshResponse.status).toBe(200);
    const access = (await accessResponse.json()) as any;
    const refresh = (await refreshResponse.json()) as any;
    expect(refresh.clientId).toBe(id);
    expect(refresh.userId).toBe(access.userId);
    expect(refresh.sessionId).toBe(access.sessionId);
    expect(refresh.scopes).toEqual(["email", "offline_access"]);
    expect(refresh.resources).toBeNull();
    expect(refresh.token).toBe(
      createHash("sha256").update(token.refresh_token).digest("base64url"),
    );
    expect(refresh.authorizationCodeId).toBe(
      createHash("sha256").update(code!).digest("base64url"),
    );
    expect(Date.parse(refresh.expiresAt) - Date.parse(refresh.createdAt)).toBe(2_592_000_000);
    expect(access.refreshId).toBe(refresh.id);
    expect(refresh.authTime).toBeTruthy();
    const sessionResponse = await control({ action: "session", headers: { cookie } });
    const session = (await sessionResponse.json()) as any;
    expect(refresh.userId).toBe(session.user.id);
    expect(refresh.sessionId).toBe(session.session.id);
    expect(Date.parse(refresh.authTime)).toBe(Date.parse(session.session.createdAt));
    const replay = await control({ action: "token", body: input });
    expect(replay.status).toBe(400);
    expect(await replay.json()).toEqual({
      error: "invalid_grant",
      error_description: "invalid code",
    });
    for (const [kind, issuedToken] of [
      ["access", token.access_token],
      ["refresh", token.refresh_token],
    ]) {
      const receipt = await control({ action: "token-row", kind, token: issuedToken });
      expect(await receipt.json()).toBeNull();
    }
    return ctx.snapshot({
      authorizationSession: session,
      scopes: refresh.scopes,
      refreshLifetime: (Date.parse(refresh.expiresAt) - Date.parse(refresh.createdAt)) / 1000,
      linked: Boolean(access.refreshId),
      replay: replay.status,
    });
  },
);
