import { createHash, createDecipheriv } from "node:crypto";

import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { createLocalJWKSet, jwtVerify } from "jose";
import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Refresh reuse intervals replay encrypted authority and preserve the family after mismatched retries",
  async (ctx) => {
    const actor = ctx.actor();
    let clientSecret: string | undefined;
    const openRefresh = (token: string) => {
      const bytes = Buffer.from(token.slice(2), "base64url");
      const decipher = createDecipheriv(
        "aes-256-gcm",
        Buffer.from("application-refresh-key-32-bytes"),
        bytes.subarray(0, 12),
      );
      decipher.setAuthTag(bytes.subarray(-16));
      return JSON.parse(
        Buffer.concat([decipher.update(bytes.subarray(12, -16)), decipher.final()]).toString(),
      );
    };
    const plain = (token: string) =>
      token.startsWith("A.x.")
        ? token.slice(4)
        : token.startsWith("R_") && !token.startsWith("R_application-")
          ? openRefresh(token).token
          : token.startsWith("A_") || token.startsWith("R_")
            ? token.slice(2)
            : token;
    const control = (input: unknown) => {
      const value = { ...(input as Record<string, any>) };
      if (clientSecret && ["token", "revoke", "introspect"].includes(value.action)) {
        value.body = { ...value.body, client_secret: clientSecret };
      }
      // Store inspection/replay controls take a storage preimage, not a wire credential.
      if (
        ["token-row", "replace-refresh-replay", "expire-refresh-replay"].includes(value.action) &&
        typeof value.token === "string"
      ) {
        value.token = plain(value.token);
      }
      return actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "reuse", ...value }),
      });
    };
    const generatorState = async (input: object = {}) => {
      const response = await control({ action: "credential-generator-state", ...input });
      expect(response.status).toBe(200);
      return (await response.json()) as any;
    };
    const formatterState = async (input: object = {}) => {
      const response = await control({ action: "refresh-formatter-state", ...input });
      expect(response.status).toBe(200);
      return (await response.json()) as any;
    };
    await generatorState({ accessMode: "embedded", refreshMode: "embedded", reset: true });
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
        token_endpoint_auth_method: "client_secret_post",
        skip_consent: true,
        grant_types: ["authorization_code", "refresh_token"],
      },
    });
    expect(created.status).toBe(201);
    const client = (await created.json()) as any;
    const id = client.client_id;
    clientSecret = client.client_secret;
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
    expect(token.access_token).toBe("A_application-access-1-A_-R_");
    const decoded = openRefresh(token.refresh_token);
    expect(decoded.token).toBe("application-refresh-1-A_-R_");
    expect(decoded.sessionId).toBeTypeOf("string");
    expect((await formatterState()).calls).toEqual([
      { kind: "encrypt", token: "application-refresh-1-A_-R_", sessionId: decoded.sessionId },
    ]);
    expect(token.id_token).toBeTypeOf("string");
    expect((await generatorState()).calls).toEqual(["refresh", "access"]);
    const hashes = async () =>
      (await generatorState()).hashCalls as { token: string; kind: string }[];
    const prefixReceipts = [];
    const issuanceHashes = (await hashes()).filter((call) =>
      ["access_token", "refresh_token"].includes(call.kind),
    );
    expect(issuanceHashes).toEqual([
      { kind: "refresh_token", token: "application-refresh-1-A_-R_" },
      { kind: "access_token", token: "application-access-1-A_-R_" },
    ]);
    prefixReceipts.push({ phase: "issuance", calls: issuanceHashes });
    for (const invalid of [
      plain(token.refresh_token),
      `A_${plain(token.refresh_token)}`,
      `lead-${token.refresh_token}`,
    ]) {
      const start = (await hashes()).length;
      const response = await control({
        action: "token",
        body: { grant_type: "refresh_token", client_id: id, refresh_token: invalid },
      });
      expect(response.status).toBe(400);
      expect(await response.json()).toEqual({
        error: "invalid_token",
        error_description: "refresh token not found",
      });
      expect((await hashes()).slice(start)).toEqual([]);
    }

    const refreshInput = {
      grant_type: "refresh_token",
      client_id: id,
      refresh_token: token.refresh_token,
    };
    await formatterState({ decryptMode: "wrong-session" });
    const issuedResponse = await control({ action: "token", body: refreshInput });
    expect(issuedResponse.status).toBe(200);
    const issued = (await issuedResponse.json()) as any;
    expect(issued.access_token).toBe("A_application-access-2-A_-R_");
    expect(openRefresh(issued.refresh_token)).toEqual({
      token: "application-refresh-2-A_-R_",
      sessionId: decoded.sessionId,
    });
    const expectedCalls = ["refresh", "access", "refresh", "access"];
    await formatterState({ decryptMode: "no-session" });
    expect((await generatorState()).calls).toEqual(expectedCalls);
    for (const invalid of [
      plain(token.access_token),
      `R_${plain(token.access_token)}`,
      `lead-${token.access_token}`,
      `A_${token.access_token}`,
    ]) {
      const start = (await hashes()).length;
      const response = await control({
        action: "userinfo",
        headers: { authorization: `Bearer ${invalid}` },
      });
      expect(response.status).toBe(401);
      expect(await response.json()).toEqual({
        error: "invalid_token",
        error_description: "Invalid access token",
      });
      expect((await hashes()).slice(start)).toEqual(
        invalid.startsWith("A_") ? [{ kind: "access_token", token: token.access_token }] : [],
      );
    }
    let start = (await hashes()).length;
    const hashedWire = await control({
      mode: "default",
      action: "hash-token",
      token: token.access_token,
      kind: "access_token",
      prefix: { opaqueAccessToken: "A_", refreshToken: "R_" },
    });
    expect(hashedWire.status).toBe(200);
    expect(await hashedWire.json()).toEqual({
      hash: createHash("sha256").update(token.access_token).digest("base64url"),
    });
    expect((await hashes()).slice(start)).toEqual([
      { kind: "access_token", token: token.access_token },
    ]);
    prefixReceipts.push({ phase: "literal-hash", calls: (await hashes()).slice(start) });
    const rawValidation = await control({
      mode: "default",
      action: "validate-access",
      body: { token: plain(token.access_token), requireActive: true },
    });
    expect(rawValidation.status).toBe(200);
    expect(((await rawValidation.json()) as any).active).toBe(true);
    for (const [value, hint, kind] of [
      [issued.access_token, "access_token", "access_token"],
      [issued.refresh_token, "refresh_token", "refresh_token"],
      [issued.refresh_token, "", "refresh_token"],
    ]) {
      const start = (await hashes()).length;
      const response = await control({
        action: "introspect",
        body: { client_id: id, token: value, token_type_hint: hint },
      });
      expect(response.status).toBe(200);
      expect(((await response.json()) as any).active).toBe(true);
      expect((await hashes()).slice(start)).toEqual([{ kind, token: plain(value) }]);
      prefixReceipts.push({ phase: `introspect-${hint}`, calls: (await hashes()).slice(start) });
    }
    for (const [value, hint] of [
      [plain(issued.access_token), "access_token"],
      [plain(issued.refresh_token), "refresh_token"],
      [issued.refresh_token, "access_token"],
      [issued.access_token, "refresh_token"],
    ]) {
      const start = (await hashes()).length;
      const response = await control({
        action: "introspect",
        body: { client_id: id, token: value, token_type_hint: hint },
      });
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ active: false });
      expect((await hashes()).slice(start)).toEqual([]);
    }
    for (const access of [token.access_token, issued.access_token]) {
      const row = await control({ action: "token-row", token: access });
      expect(row.status).toBe(200);
      const stored = (await row.json()) as any;
      expect(stored.token).toBe(createHash("sha256").update(plain(access)).digest("base64url"));
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
    expect(session.session.id).toBe(decoded.sessionId);
    expect((await formatterState()).calls.filter((call: any) => call.kind === "encrypt")).toEqual([
      { kind: "encrypt", token: "application-refresh-1-A_-R_", sessionId: session.session.id },
      { kind: "encrypt", token: "application-refresh-2-A_-R_", sessionId: session.session.id },
    ]);
    await formatterState({ decryptMode: "" });
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
    const prefixedResponse = await control({
      action: "issue-tokens",
      body: {
        credentialGenerators: true,
        refreshFormatting: true,
        prefix: { opaqueAccessToken: "A.x.", refreshToken: "R_" },
        clientId: id,
        userId: owner.user.id,
        grantType: "urn:fixture:prefixes",
        params,
      },
    });
    expect(prefixedResponse.status).toBe(200);
    const prefixed = (await prefixedResponse.json()) as any;
    expect(prefixed.refresh_token.startsWith("R_")).toBe(true);
    expect(prefixed.access_token.startsWith("A.x.")).toBe(true);
    const dottedValidation = await control({
      mode: "default",
      action: "validate-access",
      body: {
        token: prefixed.access_token,
        requireActive: true,
        prefix: { opaqueAccessToken: "A.x.", refreshToken: "R_" },
      },
    });
    expect(dottedValidation.status).toBe(200);
    expect(((await dottedValidation.json()) as any).active).toBe(true);
    expect(
      await (await control({ action: "token-row", token: prefixed.access_token })).json(),
    ).not.toBeNull();
    start = (await hashes()).length;
    const wrongRevoke = await control({
      action: "revoke",
      body: {
        client_id: id,
        token: plain(prefixed.refresh_token),
        token_type_hint: "refresh_token",
      },
    });
    expect(wrongRevoke.status).toBe(400);
    expect(await wrongRevoke.json()).toEqual({
      error: "invalid_token",
      error_description: "refresh token not found",
    });
    expect((await hashes()).slice(start)).toEqual([]);
    const revokeRefresh = await control({
      action: "revoke",
      body: { client_id: id, token: prefixed.refresh_token, token_type_hint: "refresh_token" },
    });
    expect(revokeRefresh.status).toBe(200);
    expect((await hashes()).slice(start)).toEqual([
      { kind: "refresh_token", token: plain(prefixed.refresh_token) },
    ]);
    prefixReceipts.push({ phase: "refresh-revoke", calls: (await hashes()).slice(start) });
    expect(
      typeof (
        (await (
          await control({ action: "token-row", kind: "refresh", token: prefixed.refresh_token })
        ).json()) as any
      ).revoked,
    ).toBe("string");
    expect(
      await (await control({ action: "token-row", token: prefixed.access_token })).json(),
    ).toBeNull();
    const formattedIssue = (
      extra: object = {},
      values: object = {},
      originalRefreshToken?: string,
    ) =>
      control({
        action: "issue-tokens",
        ...extra,
        body: {
          credentialGenerators: true,
          refreshFormatting: true,
          prefix: { opaqueAccessToken: "A_", refreshToken: "R_" },
          clientId: id,
          userId: owner.user.id,
          grantType: "urn:fixture:format",
          params: { ...params, ...values },
          ...(originalRefreshToken ? { originalRefreshToken } : {}),
        },
      });
    const formatterReceipts = [];
    let before = await counts();
    let callCount = (await formatterState()).calls.length;
    await formatterState({ encryptMode: "error" });
    const formatFailed = await formattedIssue({ captureError: true });
    expect(formatFailed.status).toBe(200);
    expect(await formatFailed.json()).toEqual({ ordinaryError: "refresh encryption failed" });
    expect(await counts()).toEqual({ ...before, refresh: before.refresh + 1 });
    const errorCall = (await formatterState()).calls.slice(callCount);
    expect(errorCall).toEqual([
      {
        kind: "encrypt",
        token: `application-refresh-${(await generatorState()).refreshCount}`,
        sessionId: session.session.id,
      },
    ]);
    expect(
      await (
        await control({ action: "token-row", kind: "refresh", token: errorCall[0].token })
      ).json(),
    ).not.toBeNull();
    formatterReceipts.push({ phase: "persist-before-encrypt-error", calls: errorCall });
    await formatterState({ encryptMode: "" });
    const usableResponse = await formattedIssue();
    expect(usableResponse.status).toBe(200);
    const usable = (await usableResponse.json()) as any;
    const usableDecoded = openRefresh(usable.refresh_token);
    expect(usableDecoded).toEqual({
      token: `application-refresh-${(await generatorState()).refreshCount}`,
      sessionId: session.session.id,
    });
    for (const mode of ["wrong-session", "no-session", "sync", "empty"]) {
      await formatterState({ decryptMode: mode });
      const hashCount = (await hashes()).length;
      const response = await control({
        action: "introspect",
        body: { client_id: id, token: usable.refresh_token, token_type_hint: "refresh_token" },
      });
      if (mode === "empty") {
        expect(response.status).toBe(200);
        const body = (await response.json()) as any;
        expect(body.active).toBe(true); // The earlier empty generator issued real authority for this preimage.
        expect(body.sid).toBe(session.session.id);
        expect((await hashes()).slice(hashCount)).toEqual([{ token: "", kind: "refresh_token" }]);
      } else {
        expect(response.status).toBe(200);
        const body = (await response.json()) as any;
        expect(body.active).toBe(true);
        expect(body.sid).toBe(session.session.id);
      }
      formatterReceipts.push({ phase: `decode-${mode}`, status: response.status });
    }
    for (const [mode, status, body] of [
      ["error", 500, ""],
      [
        "api-error",
        429,
        JSON.stringify({ code: "REFRESH_FORMAT_LIMIT", message: "Refresh formatter limited" }),
      ],
      ["forbidden", 403, JSON.stringify({ message: "Refresh formatter forbidden" })],
      [
        "upstream",
        503,
        JSON.stringify({
          code: "REFRESH_FORMAT_UNAVAILABLE",
          message: "Refresh formatter unavailable",
        }),
      ],
    ] as const) {
      await formatterState({ decryptMode: mode });
      for (const hint of ["", "refresh_token"]) {
        for (const action of ["introspect", "revoke"]) {
          for (const boundary of ["server-api", "http"]) {
            const input = {
              client_id: id,
              client_secret: clientSecret!,
              token: usable.refresh_token,
              token_type_hint: hint,
            };
            const response = await control(
              boundary === "http"
                ? {
                    action: "protocol-http",
                    path: `/oauth2/${action}`,
                    method: "POST",
                    body: input,
                  }
                : { action, body: input },
            );
            const raw = await response.text();
            const applicationHeaders = Object.fromEntries(
              ["content-type", "cache-control", "pragma", "www-authenticate", "x-retry-after"].map(
                (name) => [name, response.headers.get(name)],
              ),
            );
            const fallback = hint === "" && mode !== "error";
            expect(response.status).toBe(fallback ? (action === "introspect" ? 200 : 400) : status);
            const rawBody = raw === "" ? "" : JSON.parse(raw);
            expect(rawBody).toEqual(
              fallback
                ? action === "introspect"
                  ? { active: false }
                  : { error: "invalid_request", error_description: "token not found" }
                : body === ""
                  ? ""
                  : JSON.parse(body),
            );
            expect(applicationHeaders).toEqual({
              "content-type": "application/json",
              "cache-control": action === "introspect" ? "no-store" : null,
              pragma: action === "introspect" ? "no-cache" : null,
              "www-authenticate": null,
              "x-retry-after": null,
            });
            formatterReceipts.push({
              phase: "decode-error",
              mode,
              hint,
              action,
              boundary,
              status: response.status,
              rawBody,
              applicationHeaders,
            });
          }
        }
      }
    }
    before = await counts();
    await formatterState({ decryptMode: "error" });
    callCount = (await formatterState()).calls.length;
    const decryptFailed = await control({
      action: "token",
      captureError: true,
      body: { grant_type: "refresh_token", client_id: id, refresh_token: usable.refresh_token },
    });
    expect(decryptFailed.status).toBe(200);
    expect(await decryptFailed.json()).toEqual({ ordinaryError: "refresh decryption failed" });
    expect(await counts()).toEqual(before);
    expect((await formatterState()).calls.slice(callCount)).toEqual([
      { kind: "decrypt", token: usable.refresh_token.slice(2) },
    ]);
    const unchanged = (await (
      await control({ action: "token-row", kind: "refresh", token: usable.refresh_token })
    ).json()) as any;
    expect(unchanged.revoked ?? null).toBeNull();
    await formatterState({ decryptMode: "", encryptMode: "error" });
    before = await counts();
    const rotationFailed = await formattedIssue(
      { captureError: true },
      { sessionId: undefined },
      usableDecoded.token,
    );
    expect(await rotationFailed.json()).toEqual({ ordinaryError: "refresh encryption failed" });
    // The successor has no session, so inspect its raw preimage instead of session counts.
    expect(await counts()).toEqual(before);
    const retained = (await (
      await control({ action: "token-row", kind: "refresh", token: usable.refresh_token })
    ).json()) as any;
    expect(retained.revoked).toBeTypeOf("string");
    expect(retained.rotationReplayResponse ?? null).toBeNull();
    const lastCall = (await formatterState()).calls.at(-1);
    expect(lastCall).toEqual({
      kind: "encrypt",
      token: `application-refresh-${(await generatorState()).refreshCount}`,
      sessionId: null,
    });
    const successor = (await (
      await control({ action: "token-row", kind: "refresh", token: lastCall.token })
    ).json()) as any;
    expect(successor).not.toBeNull();
    expect(successor.sessionId ?? null).toBeNull();
    formatterReceipts.push({ phase: "rotation-before-encrypt-error", call: lastCall });
    callCount = (await formatterState()).calls.length;
    expect(
      await (
        await formattedIssue(
          { captureError: "failure" },
          { sessionId: undefined },
          usableDecoded.token,
        )
      ).json(),
    ).toEqual({ failed: true });
    expect((await formatterState()).calls.length).toBe(callCount);
    for (const [mode, expected] of [
      ["async", "R_[object Promise]"],
      ["empty", "R_"],
    ]) {
      await formatterState({ encryptMode: mode });
      const response = await formattedIssue({}, { sessionId: undefined });
      expect(response.status).toBe(200);
      const issued = (await response.json()) as any;
      expect(issued.refresh_token).toBe(expected);
      const lastCall = (await formatterState()).calls.at(-1);
      expect(lastCall).toEqual({
        kind: "encrypt",
        token: `application-refresh-${(await generatorState()).refreshCount}`,
        sessionId: null,
      });
      expect(
        await (
          await control({ action: "token-row", kind: "refresh", token: lastCall.token })
        ).json(),
      ).not.toBeNull();
      const introspected = await control({
        action: "introspect",
        body: { client_id: id, token: expected, token_type_hint: "refresh_token" },
      });
      expect(introspected.status).toBe(500);
      formatterReceipts.push({
        phase: `encode-${mode}`,
        wire: issued.refresh_token,
        call: lastCall,
      });
    }
    expect((await formatterState()).completed).toEqual([
      {
        token: `application-refresh-${(await generatorState()).refreshCount - 1}`,
        sessionId: null,
      },
    ]);
    return ctx.snapshot({
      authorizationSession: session,
      scope: issued.scope,
      denied: denied.status,
      repeated: repeatedResponse.status,
      recovered: recovered.status,
      expired: refused.status,
      generatorCalls: (await generatorState()).calls,
      failures,
      prefixReceipts,
      formatterReceipts,
    });
  },
);
