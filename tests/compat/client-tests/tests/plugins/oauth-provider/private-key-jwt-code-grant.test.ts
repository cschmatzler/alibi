import { createHash, randomUUID } from "node:crypto";
import { readFile as readFixtureFile } from "node:fs/promises";

import { importJWK, SignJWT } from "jose";
import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "Signed client assertions redeem code without secrets and assertion replay preserves issued authority",
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
        email: ctx.uniqueEmail("private-jwt-code-owner"),
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
    const fixture = JSON.parse(
      await readFixtureFile(
        new URL("../../../../../fixtures/oauth/client-assertion-keys.json", import.meta.url),
        "utf8",
      ),
    );
    const key = fixture.keys.find((key: any) => key.family === "RSA");
    const signingKey = await importJWK(key.privateJwk, "RS256");
    const created = await control({
      action: "admin-create",
      headers: { cookie },
      body: {
        client_name: "Signed code client",
        redirect_uris: ["https://app.fixture.test/callback"],
        token_endpoint_auth_method: "private_key_jwt",
        scope: "email",
        skip_consent: true,
        require_pkce: false,
        jwks: { keys: [{ ...key.publicJwk, alg: "RS256", kid: "application-key" }] },
      },
    });
    expect(created.status).toBe(201);
    const client = (await created.json()) as any;
    expect(client.client_secret).toBeUndefined();
    const id = client.client_id;
    const proof = (endpoint: string) => {
      const now = Math.floor(Date.now() / 1000);
      return new SignJWT({
        iss: id,
        sub: id,
        aud: `${ctx.baseURL}/api/auth/oauth2/${endpoint}`,
        iat: now,
        exp: now + 90,
        jti: randomUUID(),
      })
        .setProtectedHeader({ alg: "RS256", kid: "application-key" })
        .sign(signingKey);
    };
    const grant = await control({
      action: "authorize",
      headers: { cookie, accept: "application/json" },
      query: {
        client_id: id,
        response_type: "code",
        redirect_uri: "https://app.fixture.test/callback",
        scope: "email",
        state: "signed-state",
      },
    });
    expect(grant.status).toBe(200);
    const callback = new URL(((await grant.json()) as any).url);
    expect(callback.pathname).toBe("/callback");
    expect(callback.searchParams.get("state")).toBe("signed-state");
    const code = callback.searchParams.get("code");
    expect(code).toBeTruthy();
    // The assertion identifies its client; no body client_id, secret or PKCE verifier is supplied.
    const input = {
      grant_type: "authorization_code",
      code,
      redirect_uri: "https://app.fixture.test/callback",
      client_assertion: await proof("token"),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    };
    const rejected = await control({
      action: "token",
      body: { ...input, client_assertion: await proof("introspect") },
    });
    expect(rejected.status).toBe(401);
    expect(rejected.headers.get("cache-control")).toBe("no-store");
    expect(rejected.headers.get("pragma")).toBe("no-cache");

    const rejectedBody = await rejected.json();
    expect(rejectedBody).toEqual({
      error: "invalid_client",
      error_description: "client assertion signature verification failed",
    });
    const response = await control({ action: "token", body: input });
    expect(response.status).toBe(200);
    const token = (await response.json()) as any;
    expect(token.scope).toBe("email");
    expect(token.token_type).toBe("Bearer");
    expect(token.access_token).toMatch(/^[A-Za-z]{32}$/);
    const receipt = await control({ action: "token-row", token: token.access_token });
    const stored = (await receipt.json()) as any;
    expect(stored.authorizationCodeId).toBe(createHash("sha256").update(code!).digest("base64url"));
    expect(stored.clientId).toBe(id);
    expect(stored.scopes).toEqual(["email"]);
    expect(stored.token).toBe(createHash("sha256").update(token.access_token).digest("base64url"));
    const replay = await control({ action: "token", body: input });
    expect(replay.status).toBe(400);
    expect(replay.headers.get("cache-control")).toBe("no-store");
    expect(replay.headers.get("pragma")).toBe("no-cache");

    const replayBody = await replay.json();
    expect(replayBody).toEqual({
      error: "invalid_client",
      error_description: "client assertion jti has already been used",
    });
    const inspection = await control({
      action: "introspect",
      body: {
        token: token.access_token,
        client_assertion: await proof("introspect"),
        client_assertion_type: input.client_assertion_type,
      },
    });
    expect(inspection.status).toBe(200);
    const active = (await inspection.json()) as any;
    expect(active.active).toBe(true);
    expect(active.client_id).toBe(id);
    expect(active.azp).toBe(id);
    expect(active.iss).toBe(`${ctx.baseURL}/api/auth`);
    expect(active.sub).toBe(stored.userId);
    expect(active.sid).toBe(stored.sessionId);
    expect(active.exp).toBe(Date.parse(stored.expiresAt) / 1000);
    expect(active.iat).toBe(Date.parse(stored.createdAt) / 1000);
    expect(active.scope).toBe("email");
    expect(active.token_type).toBe("Bearer");

    const codeReplay = await control({
      action: "token",
      body: { ...input, client_assertion: await proof("token") },
    });
    expect(codeReplay.status).toBe(400);
    const codeReplayBody = await codeReplay.json();
    expect(codeReplayBody).toEqual({ error: "invalid_grant", error_description: "invalid code" });
    const removed = await control({ action: "token-row", token: token.access_token });
    expect(await removed.json()).toBeNull();
    return ctx.snapshot({
      client,
      rejected: { status: rejected.status, body: rejectedBody },
      token,
      stored: { clientId: stored.clientId, scopes: stored.scopes },
      replay: { status: replay.status, body: replayBody },
      active: {
        active: active.active,
        client_id: active.client_id,
        scope: active.scope,
        token_type: active.token_type,
        lifetime: active.exp - active.iat,
      },
      codeReplay: { status: codeReplay.status, body: codeReplayBody },
    });
  },
);
