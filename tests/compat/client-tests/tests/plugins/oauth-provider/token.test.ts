import { expect } from "bun:test";
import { createHash } from "node:crypto";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "PKCE code exchange persists a protected token and replay removes the issued token",
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
      body: { email: ctx.uniqueEmail("token-owner"), name: "Owner", password: "password123" },
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
        scope: "email",
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
        scope: "email",
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
    expect(token.scope).toBe("email");
    expect(token.token_type).toBe("Bearer");
    expect(token.expires_in).toBe(3600);
    expect(token.access_token).toMatch(/^[A-Za-z]{32}$/);
    expect(token.refresh_token).toBeUndefined();
    expect(token.id_token).toBeUndefined();
    const receipt = await control({ action: "token-row", token: token.access_token });
    expect(receipt.status).toBe(200);
    const stored = (await receipt.json()) as any;
    expect(stored.clientId).toBe(id);
    expect(stored.scopes).toEqual(["email"]);
    expect(stored.token).toBe(createHash("sha256").update(token.access_token).digest("base64url"));
    expect(stored.authorizationCodeId).toBe(createHash("sha256").update(code!).digest("base64url"));
    expect(Date.parse(stored.expiresAt) - Date.parse(stored.createdAt)).toBe(3600_000);
    expect(Date.parse(stored.expiresAt) / 1000).toBe(token.expires_at);
    const replay = await control({ action: "token", body: input });
    expect(replay.status).toBe(400);
    expect(await replay.json()).toEqual({
      error: "invalid_grant",
      error_description: "invalid code",
    });
    const removed = await control({ action: "token-row", token: token.access_token });
    expect(await removed.json()).toBeNull();

    const denials = [];
    for (const [field, wrong, status, description] of [
      ["code_verifier", "wrong-verifier", 401, "code verification failed"],
      ["redirect_uri", "https://app.fixture.test/other", 400, "redirect_uri mismatch"],
    ] as const) {
      const produced = await control({
        action: "authorize",
        headers: { cookie, accept: "application/json" },
        query: {
          client_id: id,
          response_type: "code",
          redirect_uri: "https://app.fixture.test/callback",
          scope: "email",
          state: "token-state",
          code_challenge: challenge,
          code_challenge_method: "S256",
        },
      });
      expect(produced.status).toBe(200);
      const callback = new URL(((await produced.json()) as any).url);
      const grantCode = callback.searchParams.get("code");
      expect(grantCode).toBeTruthy();
      const input = {
        grant_type: "authorization_code",
        client_id: id,
        code: grantCode,
        code_verifier: verifier,
        redirect_uri: "https://app.fixture.test/callback",
        [field]: wrong,
      };
      const rejected = await control({ action: "token", body: input });
      expect(rejected.status).toBe(status);
      expect(await rejected.json()).toEqual({
        error: status === 401 ? "invalid_request" : "invalid_grant",
        error_description: description,
      });
      const retry = await control({
        action: "token",
        body: {
          ...input,
          [field]: field === "code_verifier" ? verifier : "https://app.fixture.test/callback",
        },
      });
      expect(retry.status).toBe(400);
      expect(await retry.json()).toEqual({
        error: "invalid_grant",
        error_description: "invalid code",
      });
      denials.push({ status, description, retry: retry.status });
    }
    return {
      denials,
      scope: token.scope,
      type: token.token_type,
      lifetime: token.expires_in,
      persistedScopes: stored.scopes,
      replay: replay.status,
      removed: true,
    };
  },
);
