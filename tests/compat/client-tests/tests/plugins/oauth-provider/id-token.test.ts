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
    const control = (input: object) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "claims", ...input }),
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
        metadata: { tenant: "application" },
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
    const idState = async (input: object = {}) => {
      const response = await control({ action: "id-claims-state", ...input });
      expect(response.status).toBe(200);
      return (await response.json()) as any;
    };
    await idState({ value: "code", error: "", reset: true });
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
    expect(payload.name).toBe("ID operator code");
    expect(payload.email).toBe("id-code@example.test");
    expect(payload.email_verified).toBe(true);
    expect(payload.extension_owner).toBe("id-operator-code");
    expect(payload.per_request).toBe("id-operator-code");
    expect(payload.sid).toBeUndefined();
    // cnf is deliberately not part of the pinned ID-token reserved set.
    expect(payload.cnf).toEqual({ operator: "code" });
    for (const field of ["picture", "nbf", "jti", "amr", "azp", "c_hash", "s_hash"]) {
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
    const params = {
      scopes: ["openid", "email", "profile"],
      sessionId: session.session.id,
      authTime: session.session.createdAt,
      nonce: "api-nonce",
      idTokenClaims: {
        name: "Request name",
        email: "request@example.test",
        extension_owner: "request",
        per_request: "request",
        request_only: "retained",
      },
    };
    const issue = (extra: object = {}) =>
      control({
        action: "issue-tokens",
        ...extra,
        body: {
          claimsProfile: true,
          idClaimsProfile: true,
          clientId: id,
          userId: session.user.id,
          grantType: "urn:fixture:id-claims",
          params,
        },
      });
    await idState({ value: "api" });
    const extraResponse = await issue();
    expect(extraResponse.status).toBe(200);
    const extra = (await extraResponse.json()) as any;
    const extraPayload = (
      await jwtVerify(extra.id_token, jwksVerifier, {
        issuer: `${ctx.baseURL}/api/auth`,
        audience: id,
      })
    ).payload;
    expect(extraPayload).toMatchObject({
      name: "ID operator api",
      email: "id-api@example.test",
      extension_owner: "id-operator-api",
      per_request: "id-operator-api",
      request_only: "retained",
      nonce: "api-nonce",
      sub: session.user.id,
    });
    expect(extraPayload.sid).toBeUndefined();
    expect(extraPayload.auth_time).toBe(Math.floor(Date.parse(session.session.createdAt) / 1000));
    expect(extraPayload.exp! - extraPayload.iat!).toBe(36_000);
    expect(extraPayload.at_hash).toBe(
      createHash("sha512")
        .update(extra.access_token)
        .digest()
        .subarray(0, 32)
        .toString("base64url"),
    );
    const counts = async () => {
      const response = await control({ action: "authority-counts", sessionId: session.session.id });
      expect(response.status).toBe(200);
      return (await response.json()) as any;
    };
    const failures = [];
    for (const error of ["api", "ordinary"]) {
      await idState({ error });
      const before = await counts();
      const rejected = await issue({ captureError: true });
      expect(rejected.status).toBe(200);
      const receipt = await rejected.json();
      expect(receipt).toEqual(
        error === "api"
          ? {
              apiError: { status: 400, code: "ID_CLAIM_REJECTED", message: "ID callback rejected" },
            }
          : { ordinaryError: "ID callback failed" },
      );
      const after = await counts();
      expect(after).toEqual({ ...before, access: before.access + 1 });
      failures.push({ error, receipt });
    }
    const calls = (await idState()).calls;
    expect(calls).toEqual(
      Array.from({ length: 4 }, () => ({
        userId: session.user.id,
        userName: "Owner",
        userEmail: session.user.email,
        scopes: ["openid", "email", "profile"],
        metadata: { tenant: "application" },
      })),
    );
    params.scopes = ["email"];
    const noId = await issue();
    expect(noId.status).toBe(200);
    expect(await noId.json()).not.toHaveProperty("id_token");
    expect((await idState()).calls).toEqual(calls);
    await idState({ value: null, error: "", reset: true });
    return ctx.snapshot({
      authorizationSession: session,
      clientId: id,
      issued: token,
      // Core bindings are verified against this issuance above; keep the
      // operator/per-request values as the differential receipt. The original
      // bound JWT remains in the harness's canonical `issued` observation.
      extraClaims: {
        name: extraPayload.name,
        email: extraPayload.email,
        email_verified: extraPayload.email_verified,
        extension_owner: extraPayload.extension_owner,
        per_request: extraPayload.per_request,
        request_only: extraPayload.request_only,
        cnf: extraPayload.cnf,
        nonce: extraPayload.nonce,
      },
      failures,
      calls,
    });
  },
);
