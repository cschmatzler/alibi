import { createHash } from "node:crypto";

import { jwtVerify, createLocalJWKSet } from "jose";
import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compareValues } from "../../../support/compare";
import { compatScenario } from "../../../support/scenario";
compatScenario(
  "OpenID code exchange issues a signed ID token bound to the actual client, session and access token",
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
      body: { email: ctx.uniqueEmail("oidc-owner"), name: "Owner", password: "password123" },
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

    expect(token.id_token).toBeTypeOf("string");
    const sessionResponse = await control({ action: "session", headers: { cookie } });
    expect(sessionResponse.status).toBe(200);
    const session = (await sessionResponse.json()) as any;
    const keysResponse = await control({ action: "jwks" });
    expect(keysResponse.status).toBe(200);
    const keys = (await keysResponse.json()) as any;
    const jwksVerifier = createLocalJWKSet(keys);
    const verified = await jwtVerify(token.id_token, jwksVerifier, {
      issuer: `${ctx.baseURL}/api/auth`,
      audience: id,
    });
    const payload = verified.payload;
    expect(verified.protectedHeader.alg).toBe("EdDSA");
    expect(payload.iss).toBe(`${ctx.baseURL}/api/auth`);
    expect(payload.aud).toBe(id);
    expect(payload.sub).toBe(session.user.id);
    expect(payload.nonce).toBe("oidc-nonce");
    expect(payload.acr).toBe("0");
    expect(payload.auth_time).toBe(Math.floor(Date.parse(session.session.createdAt) / 1000));
    expect(payload.exp! - payload.iat!).toBe(36_000);
    expect(payload.at_hash).toBe(
      createHash("sha512")
        .update(token.access_token)
        .digest()
        .subarray(0, 32)
        .toString("base64url"),
    );
    for (const field of ["email", "email_verified", "name", "picture", "sid"]) {
      expect(payload[field]).toBeUndefined();
    }
    const parts = token.id_token.split(".");
    const signature = Buffer.from(parts[2], "base64url");
    signature[0] = signature[0]! ^ 1;
    const tampered = `${parts[0]}.${parts[1]}.${signature.toString("base64url")}`;
    await expect(
      jwtVerify(tampered, jwksVerifier, { issuer: `${ctx.baseURL}/api/auth`, audience: id }),
    ).rejects.toThrow();
    await expect(
      jwtVerify(token.id_token, jwksVerifier, {
        issuer: `${ctx.baseURL}/api/auth`,
        audience: "foreign-client",
      }),
    ).rejects.toThrow();
    const original = {
      observation: { authorizationSession: session, clientId: id, issued: token },
    };
    for (const [field, value, reason] of [
      ["at_hash", "unbound-hash", "OIDC access hash"],
      ["aud", "foreign-client", "OIDC audience"],
      ["auth_time", 0, "OIDC authentication time"],
    ] as const) {
      const wrongPayload = { ...payload, [field]: value };
      const wrongToken = `${parts[0]}.${Buffer.from(JSON.stringify(wrongPayload)).toString("base64url")}.${parts[2]}`;
      const incorrect = {
        observation: {
          authorizationSession: session,
          clientId: id,
          issued: { ...token, id_token: wrongToken },
        },
      };
      const now = Date.now();
      expect(
        compareValues(original, incorrect, {
          leftBaseURL: ctx.baseURL,
          rightBaseURL: ctx.baseURL,
          leftStartedAt: now,
          rightStartedAt: now,
        }).some((difference) => difference.reason.includes(reason)),
      ).toBe(true);
    }
    const expired = {
      observation: { ...original.observation, issued: { ...token, expires_at: 0 } },
    };
    expect(
      compareValues(original, expired, {
        leftBaseURL: ctx.baseURL,
        rightBaseURL: ctx.baseURL,
        leftStartedAt: (token.expires_at - token.expires_in) * 1000,
        rightStartedAt: (token.expires_at - token.expires_in) * 1000,
        leftFinishedAt: Date.now(),
        rightFinishedAt: Date.now(),
      }).filter((difference) => difference.reason.includes("access-token expiration")),
    ).toHaveLength(1);
    return ctx.snapshot({ authorizationSession: session, clientId: id, issued: token });
  },
);
