import { createHash } from "node:crypto";

import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Revocation retires access tokens and revokes the real refresh-token family",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: unknown) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const protocol = (path: string, body: Record<string, string>) =>
      control({
        action: "protocol-http",
        path: `/oauth2/${path}`,
        method: "POST",
        body,
      });
    const signup = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("revocation-owner"),
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

    const before = await Promise.all(
      (
        [
          ["access", token.access_token],
          ["refresh", token.refresh_token],
        ] as const
      ).map(async ([kind, token]) => {
        const response = await control({ action: "token-row", kind, token });
        expect(response.status).toBe(200);
        return response.json();
      }),
    );
    for (const path of ["introspect", "revoke"]) {
      const valid = { client_id: id, client_secret: secret, token: token.access_token };
      const cases: [string, Record<string, string>, string | undefined, number, string][] = [
        [
          "wrong-secret",
          { ...valid, client_secret: "wrong" },
          undefined,
          400,
          "invalid client_secret",
        ],
        [
          "mixed-method",
          valid,
          `Basic ${Buffer.from(`${id}:${secret}`).toString("base64")}`,
          400,
          "A request must use only one client authentication method",
        ],
        [
          "registered-method",
          { token: token.access_token },
          `Basic ${Buffer.from(`${id}:${secret}`).toString("base64")}`,
          401,
          "client registered for client_secret_post cannot use client_secret_basic",
        ],
      ];
      for (const [name, body, authorization, status, description] of cases) {
        const response = await control({
          action: "protocol-http",
          path: `/oauth2/${path}`,
          method: "POST",
          body,
          ...(authorization ? { headers: { authorization } } : {}),
        });
        expect(response.status, `${path}/${name}`).toBe(status);
        expect(((await response.json()) as any).error_description).toBe(description);
        expect(response.headers.get("cache-control")).toBe(
          path === "introspect" ? "no-store" : null,
        );
        expect(response.headers.get("pragma")).toBe(path === "introspect" ? "no-cache" : null);
      }
      for (const [field, value] of Object.entries({
        client_id: id,
        client_secret: secret,
        client_assertion: "assertion",
        client_assertion_type: "urn:assertion",
      })) {
        const entries = [...Object.entries(valid), [field, value]];
        if (field.startsWith("client_assertion")) entries.push([field, value]);
        const response = await control({
          action: "protocol-http",
          path: `/oauth2/${path}`,
          method: "POST",
          rawBody: new URLSearchParams(entries).toString(),
        });
        expect(response.status).toBe(400);
        expect(await response.json()).toEqual({
          error: "invalid_request",
          error_description: `${field} must not be repeated`,
        });
      }
    }
    for (const [index, [kind, issued]] of (
      [
        ["access", token.access_token],
        ["refresh", token.refresh_token],
      ] as const
    ).entries()) {
      const response = await control({ action: "token-row", kind, token: issued });
      expect(await response.json()).toEqual(before[index]);
    }

    const revocationBody = {
      client_id: id,
      client_secret: secret,
      token: token.access_token,
      token_type_hint: "access_token",
    };
    const revoked = await protocol("revoke", revocationBody);
    expect(revoked.status).toBe(200);
    expect(await revoked.text()).toBe("");
    const accessAfter = await control({ action: "token-row", token: token.access_token });
    expect(await accessAfter.json()).toBeNull();
    const refreshAfter = await control({
      action: "token-row",
      kind: "refresh",
      token: token.refresh_token,
    });
    expect((await refreshAfter.json()) as any).toBeTruthy();
    const repeatedAccess = await protocol("revoke", revocationBody);
    expect(repeatedAccess.status).toBe(400);
    expect(await repeatedAccess.json()).toEqual({
      error: "invalid_request",
      error_description: "Invalid access token",
    });
    const second = await control({
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
    expect(second.status).toBe(200);
    const secondCode = new URL(((await second.json()) as any).url).searchParams.get("code");
    expect(secondCode).toBeTruthy();
    const secondResponse = await control({ action: "token", body: { ...input, code: secondCode } });
    expect(secondResponse.status).toBe(200);
    const secondTokens = (await secondResponse.json()) as any;
    expect(secondTokens.access_token).toMatch(/^[A-Za-z]{32}$/);
    expect(secondTokens.refresh_token).toMatch(/^[A-Za-z]{32}$/);
    const refreshRevocationBody = {
      client_id: id,
      client_secret: secret,
      token: secondTokens.refresh_token,
      token_type_hint: "refresh_token",
    };
    const start = Date.now();
    const refreshRevoked = await control({
      action: "protocol-http",
      path: "/oauth2/revoke",
      method: "POST",
      rawBody: new URLSearchParams([
        ["client_id", ""],
        ["client_id", id],
        ["client_secret", ""],
        ["client_secret", secret],
        ["token", "unknown-token"],
        ["token", secondTokens.refresh_token],
        ["token_type_hint", "access_token"],
        ["token_type_hint", "refresh_token"],
      ]).toString(),
    });
    expect(refreshRevoked.status).toBe(200);
    expect(await refreshRevoked.text()).toBe("");
    const access = await control({ action: "token-row", token: secondTokens.access_token });
    expect(await access.json()).toBeNull();
    const refresh = await control({
      action: "token-row",
      kind: "refresh",
      token: secondTokens.refresh_token,
    });
    const row = (await refresh.json()) as any;
    expect(row).toBeTruthy();
    expect(Date.parse(row.revoked) % 1000).toBe(0);
    expect(Date.parse(row.revoked)).toBeGreaterThanOrEqual(Math.floor(start / 1000) * 1000);
    expect(Date.parse(row.revoked)).toBeLessThanOrEqual(Date.now());
    const older = await control({
      action: "token-row",
      kind: "refresh",
      token: token.refresh_token,
    });
    expect((await older.json()) as any).toBeTruthy();
    const inactive = await protocol("introspect", refreshRevocationBody);
    expect(inactive.status).toBe(200);
    expect(await inactive.json()).toEqual({ active: false });
    const repeated = await protocol("revoke", refreshRevocationBody);
    expect(repeated.status).toBe(400);
    expect(await repeated.json()).toEqual({
      error: "invalid_request",
      error_description: "refresh token revoked",
    });
    for (const issued of [token.refresh_token, secondTokens.refresh_token]) {
      const receipt = await control({ action: "token-row", kind: "refresh", token: issued });
      expect(await receipt.json()).toBeNull();
    }
    const raceGrant = await control({
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
    expect(raceGrant.status).toBe(200);
    const raceCode = new URL(((await raceGrant.json()) as any).url).searchParams.get("code");
    expect(raceCode).toBeTruthy();
    const raceResponse = await control({ action: "token", body: { ...input, code: raceCode } });
    expect(raceResponse.status).toBe(200);
    const raceTokens = (await raceResponse.json()) as any;
    expect(raceTokens.access_token).toMatch(/^[A-Za-z]{32}$/);
    expect(raceTokens.refresh_token).toMatch(/^[A-Za-z]{32}$/);

    const raced = await control({
      action: "revoke-concurrently",
      body: {
        client_id: id,
        client_secret: secret,
        token: raceTokens.refresh_token,
        token_type_hint: "refresh_token",
      },
    });
    expect(raced.status).toBe(200);
    const statuses = await raced.json();
    expect(statuses).toEqual([200, 400]);
    for (const [kind, issued] of [
      ["refresh", raceTokens.refresh_token],
      ["access", raceTokens.access_token],
    ]) {
      const receipt = await control({ action: "token-row", kind, token: issued });
      expect(await receipt.json()).toBeNull();
    }
    return {
      concurrent: statuses,
      accessRetired: accessAfter.status,
      refreshInactive: inactive.status,
      repeatedAccess: repeatedAccess.status,
      repeatedRefresh: repeated.status,
    };
  },
);
