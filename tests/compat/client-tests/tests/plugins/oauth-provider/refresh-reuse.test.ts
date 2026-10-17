import { createHash } from "node:crypto";

import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { createLocalJWKSet, jwtVerify } from "jose";
import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Refresh reuse intervals replay encrypted authority and preserve the family after mismatched retries",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: unknown) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "reuse", ...(input as Record<string, unknown>) }),
      });
    const generatorState = async (input: object = {}) => {
      const response = await control({ action: "credential-generator-state", ...input });
      expect(response.status).toBe(200);
      return (await response.json()) as any;
    };
    await generatorState({ accessMode: "", refreshMode: "", reset: true });
    const signup = await control({
      action: "signup",
      body: { email: ctx.uniqueEmail("reuse-owner"), name: "Owner", password: "password123" },
    });
    expect(signup.status).toBe(200);
    const owner = (await signup.json()) as any;
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
        scope: "openid email offline_access",
        nonce: "generator-nonce",
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
    expect(token.scope).toBe("openid email offline_access");
    expect(token.token_type).toBe("Bearer");
    expect(token.expires_in).toBe(3600);
    expect(token.access_token).toBe("application-access-1");
    expect(token.refresh_token).toBe("application-refresh-1");
    expect(token.id_token).toBeTypeOf("string");
    expect((await generatorState()).calls).toEqual(["refresh", "access"]);

    const refreshInput = {
      grant_type: "refresh_token",
      client_id: id,
      refresh_token: token.refresh_token,
    };
    const issuedResponse = await control({ action: "token", body: refreshInput });
    expect(issuedResponse.status).toBe(200);
    const issued = (await issuedResponse.json()) as any;
    expect(issued.access_token).toBe("application-access-2");
    expect(issued.refresh_token).toBe("application-refresh-2");
    const expectedCalls = ["refresh", "access", "refresh", "access"];
    expect((await generatorState()).calls).toEqual(expectedCalls);
    for (const access of [token.access_token, issued.access_token]) {
      const row = await control({ action: "token-row", token: access });
      expect(row.status).toBe(200);
      const stored = (await row.json()) as any;
      expect(stored.token).toBe(createHash("sha256").update(access).digest("base64url"));
      expect(stored.token).not.toBe(access);
      const info = await control({
        action: "userinfo",
        headers: { authorization: `Bearer ${access}` },
      });
      expect(info.status).toBe(200);
      expect(((await info.json()) as any).sub).toBe(owner.user.id);
    }
    const revoked = await control({
      action: "revoke",
      body: { client_id: id, token: token.access_token, token_type_hint: "access_token" },
    });
    expect(revoked.status).toBe(200);
    expect(
      await (await control({ action: "token-row", token: token.access_token })).json(),
    ).toBeNull();
    const rowResponse = await control({
      action: "token-row",
      kind: "refresh",
      token: token.refresh_token,
    });
    expect(rowResponse.status).toBe(200);
    const row = (await rowResponse.json()) as any;
    expect(typeof row.rotationReplayResponse).toBe("string");
    expect(row.rotationReplayResponse).not.toContain(issued.access_token);
    const bytes = Buffer.from(row.rotationReplayResponse, "hex");
    const key = createHash("sha256")
      .update("compat-test-only-key-not-real-minimum-32chars")
      .digest();
    const replay = JSON.parse(
      Buffer.from(
        xchacha20poly1305(key, bytes.subarray(0, 24)).decrypt(bytes.subarray(24)),
      ).toString(),
    );
    expect(replay.response).toEqual(issued);
    expect(replay.request.effectiveScopes).toEqual(["email", "offline_access", "openid"]);
    expect(Date.parse(row.rotationReplayExpiresAt) - Date.parse(row.rotatedAt)).toBe(60_000);
    const repeatedResponse = await control({ action: "token", body: refreshInput });
    expect(repeatedResponse.status).toBe(200);
    const repeated = (await repeatedResponse.json()) as any;
    for (const key of ["access_token", "refresh_token", "expires_at", "scope", "token_type"]) {
      expect(repeated[key]).toBe(issued[key]);
    }
    expect(repeated.expires_in).toBeLessThanOrEqual(3600);
    expect(repeated.expires_in).toBeGreaterThanOrEqual(0);
    for (const scope of ["offline_access email openid", "openid email offline_access email"]) {
      const response = await control({ action: "token", body: { ...refreshInput, scope } });
      expect(response.status).toBe(200);
      const replayed = (await response.json()) as any;
      for (const key of ["access_token", "refresh_token", "expires_at", "scope", "token_type"]) {
        expect(replayed[key]).toBe(issued[key]);
      }
      const unchanged = await control({
        action: "token-row",
        kind: "refresh",
        token: token.refresh_token,
      });
      expect(unchanged.status).toBe(200);
      const stored = (await unchanged.json()) as any;
      expect(stored.rotationReplayResponse).toBe(row.rotationReplayResponse);
      expect(stored.rotationReplayExpiresAt).toBe(row.rotationReplayExpiresAt);
    }
    const denied = await control({ action: "token", body: { ...refreshInput, scope: "email" } });
    expect(denied.status).toBe(400);
    expect(await denied.json()).toEqual({
      error: "invalid_grant",
      error_description: "invalid refresh token",
    });
    for (const [kind, value] of [
      ["access", issued.access_token],
      ["refresh", issued.refresh_token],
    ]) {
      const retained = await control({ action: "token-row", kind, token: value });
      expect(retained.status).toBe(200);
      expect(await retained.json()).not.toBeNull();
    }
    const recovered = await control({ action: "token", body: refreshInput });
    expect(recovered.status).toBe(200);
    expect(((await recovered.json()) as any).access_token).toBe(issued.access_token);
    for (const field of ["access_token", "token_type", "refresh_token"]) {
      const malformed = structuredClone(replay);
      if (field === "access_token") {
        delete malformed.response[field];
      } else {
        malformed.response[field] = 17;
      }
      const nonce = crypto.getRandomValues(new Uint8Array(24));
      const changed = Buffer.concat([
        nonce,
        xchacha20poly1305(key, nonce).encrypt(Buffer.from(JSON.stringify(malformed))),
      ]).toString("hex");
      const written = await control({
        action: "replace-refresh-replay",
        token: token.refresh_token,
        ciphertext: changed,
      });
      expect(written.status).toBe(200);
      expect(((await written.json()) as any).id).toBe(row.id);
      const denied = await control({ action: "token", body: refreshInput });
      expect(denied.status).toBe(400);
      expect(await denied.json()).toEqual({
        error: "invalid_grant",
        error_description: "invalid refresh token",
      });
      const retained = await control({
        action: "token-row",
        kind: "refresh",
        token: issued.refresh_token,
      });
      expect(retained.status).toBe(200);
      expect(await retained.json()).not.toBeNull();
    }
    const restored = await control({
      action: "replace-refresh-replay",
      token: token.refresh_token,
      ciphertext: row.rotationReplayResponse,
    });
    expect(restored.status).toBe(200);
    const valid = await control({ action: "token", body: refreshInput });
    expect(valid.status).toBe(200);
    expect(((await valid.json()) as any).access_token).toBe(issued.access_token);
    const expired = await control({ action: "expire-refresh-replay", token: token.refresh_token });
    expect(expired.status).toBe(200);
    const stored = (await expired.json()) as any;
    expect(stored.id).toBe(row.id);
    expect(Date.parse(stored.rotationReplayExpiresAt)).toBeLessThan(Date.now());
    const refused = await control({ action: "token", body: refreshInput });
    expect(refused.status).toBe(400);
    expect(await refused.json()).toEqual({
      error: "invalid_grant",
      error_description: "invalid refresh token",
    });
    for (const [kind, value] of [
      ["access", token.access_token],
      ["access", issued.access_token],
      ["refresh", token.refresh_token],
      ["refresh", issued.refresh_token],
    ]) {
      const removed = await control({ action: "token-row", kind, token: value });
      expect(removed.status).toBe(200);
      expect(await removed.json()).toBeNull();
    }
    expect((await generatorState()).calls).toEqual(expectedCalls);
    const session = (await (
      await control({ action: "session", headers: { cookie } })
    ).json()) as any;
    const params = { scopes: ["email", "offline_access"], sessionId: session.session.id };
    const issue = (extra: object = {}, resources?: string[]) =>
      control({
        action: "issue-tokens",
        ...extra,
        body: {
          credentialGenerators: true,
          clientId: id,
          userId: owner.user.id,
          grantType: "urn:fixture:generators",
          params: { ...params, ...(resources ? { resources } : {}) },
        },
      });
    const counts = async () => {
      const response = await control({ action: "authority-counts", sessionId: session.session.id });
      expect(response.status).toBe(200);
      return (await response.json()) as any;
    };
    const failures = [];
    for (const kind of ["refresh", "access"]) {
      await generatorState({
        refreshMode: kind === "refresh" ? "error" : "",
        accessMode: kind === "access" ? "error" : "",
      });
      const before = await counts();
      const response = await issue({ captureError: true });
      expect(response.status).toBe(200);
      const receipt = await response.json();
      expect(receipt).toEqual({ ordinaryError: `${kind} generator failed` });
      expect(await counts()).toEqual({
        ...before,
        refresh: before.refresh + Number(kind === "access"),
      });
      failures.push(receipt);
    }
    await generatorState({ accessMode: "fixed", refreshMode: "fixed" });
    const fixedResponse = await issue();
    expect(fixedResponse.status).toBe(200);
    const fixed = (await fixedResponse.json()) as any;
    expect(fixed.access_token).toBe("application-access-fixed");
    expect(fixed.refresh_token).toBe("application-refresh-fixed");
    const beforeCollision = await counts();
    const beforeRefreshCollision = await generatorState();
    const refreshCollision = await issue({ captureError: "failure" });
    expect(refreshCollision.status).toBe(200);
    expect(await refreshCollision.json()).toEqual({ failed: true });
    expect(await counts()).toEqual(beforeCollision);
    expect((await generatorState()).calls.length).toBe(beforeRefreshCollision.calls.length + 1);
    await generatorState({ refreshMode: "" });
    const beforeAccessCollision = await generatorState();
    const accessCollision = await issue({ captureError: "failure" });
    expect(accessCollision.status).toBe(200);
    expect(await accessCollision.json()).toEqual({ failed: true });
    expect(await counts()).toEqual({ ...beforeCollision, refresh: beforeCollision.refresh + 1 });
    expect((await generatorState()).calls.length).toBe(beforeAccessCollision.calls.length + 2);
    await generatorState({ accessMode: "empty", refreshMode: "empty" });
    const emptyResponse = await issue();
    expect(emptyResponse.status).toBe(200);
    const empty = (await emptyResponse.json()) as any;
    expect(empty.access_token).toBe("");
    expect(empty.refresh_token).toBe("");
    for (const kind of ["access", "refresh"]) {
      const row = await control({ action: "token-row", kind, token: "" });
      expect(row.status).toBe(200);
      expect(((await row.json()) as any).token).toBe(
        createHash("sha256").update("").digest("base64url"),
      );
    }
    await generatorState({ accessMode: "", refreshMode: "" });
    const accessCount = (await generatorState()).accessCount;
    const resource = `${ctx.baseURL}/api/auth/oauth2/userinfo`;
    const signedResponse = await issue({}, [resource]);
    expect(signedResponse.status).toBe(200);
    const signed = (await signedResponse.json()) as any;
    const keys = createLocalJWKSet((await (await control({ action: "jwks" })).json()) as any);
    await jwtVerify(signed.access_token, keys, {
      issuer: `${ctx.baseURL}/api/auth`,
      audience: resource,
    });
    expect((await generatorState()).accessCount).toBe(accessCount);
    return ctx.snapshot({
      authorizationSession: session,
      scope: issued.scope,
      denied: denied.status,
      repeated: repeatedResponse.status,
      recovered: recovered.status,
      expired: refused.status,
      generatorCalls: (await generatorState()).calls,
      failures,
    });
  },
);
