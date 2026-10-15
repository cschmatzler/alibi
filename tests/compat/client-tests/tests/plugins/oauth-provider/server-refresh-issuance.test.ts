import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Trusted retained-refresh issuance claims row IDs without replaying endpoint admission",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: object) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const signup = await control({
      action: "signup",
      body: { email: ctx.uniqueEmail("trusted-refresh"), name: "Owner", password: "password123" },
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
        client_name: "Trusted refresh",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "email offline_access",
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
      },
    });
    expect(created.status).toBe(201);
    const client = (await created.json()) as any;
    const session = (await (
      await control({ action: "session", headers: { cookie } })
    ).json()) as any;
    const userinfo = `${ctx.baseURL}/api/auth/oauth2/userinfo`;
    const issue = (
      params: object,
      originalRefreshToken?: string,
      withUser = true,
      snapshotToken?: string,
    ) =>
      control({
        action: "issue-tokens",
        body: {
          clientId: client.client_id,
          grantType: "urn:fixture:server",
          ...(withUser ? { userId: owner.user.id } : {}),
          ...(originalRefreshToken ? { originalRefreshToken } : {}),
          ...(snapshotToken ? { snapshotToken } : {}),
          params,
        },
      });
    const row = async (token: string) =>
      (await (await control({ action: "token-row", kind: "refresh", token })).json()) as any;
    const seedResponse = await issue({
      scopes: ["email", "offline_access"],
      sessionId: session.session.id,
      referenceId: "seed-ref",
      authTime: session.session.createdAt,
      requestedUserInfoClaims: ["email"],
      resources: [userinfo],
    });
    expect(seedResponse.status).toBe(200);
    const seed = (await seedResponse.json()) as any;
    const original = await row(seed.refresh_token);
    const machineResponse = await issue({ scopes: ["email"] }, seed.refresh_token, false);
    expect(machineResponse.status).toBe(200);
    const machine = (await machineResponse.json()) as any;
    expect(machine.refresh_token).toBeUndefined();
    expect((await row(seed.refresh_token)).revoked).toBeNull();
    // The actual saved row is supplied, with a non-authoritative token field.
    // Reference rotation keys the atomic claim by row ID, not by that field.
    const response = await issue(
      { scopes: ["email"], referenceId: "next-ref" },
      seed.refresh_token,
      true,
      "snapshot-not-a-lookup-key",
    );
    expect(response.status).toBe(200);
    const next = (await response.json()) as any;
    expect(next.access_token).toMatch(/^[A-Za-z]{32}$/);
    expect(next.scope).toBe("email");
    expect(typeof next.refresh_token).toBe("string");
    const retained = await row(next.refresh_token);
    expect(retained.id).not.toBe(original.id);
    expect(retained.scopes).toEqual(["email"]);
    expect(retained.resources).toEqual([userinfo]);
    expect(retained.requestedUserInfoClaims).toEqual(["email"]);
    expect(retained.sessionId).toBeNull();
    expect(retained.authTime).toBeNull();
    expect(retained.referenceId).toBe("next-ref");
    const old = await row(seed.refresh_token);
    expect(typeof old.revoked).toBe("string");
    expect(old.rotatedAt).toBe(old.revoked);
    const replay = await issue({ scopes: ["email"] }, seed.refresh_token);
    expect(replay.status).toBe(400);
    expect(await replay.json()).toEqual({
      error: "invalid_grant",
      error_description: "invalid refresh token",
    });
    expect((await row(next.refresh_token)).id).toBe(retained.id);
    expect((await row(next.refresh_token)).revoked).toBeNull();
    const accessOnly = await issue({ scopes: ["email"] }, next.refresh_token);
    expect(accessOnly.status).toBe(200);
    expect(((await accessOnly.json()) as any).refresh_token).toBeUndefined();
    expect((await row(next.refresh_token)).revoked).toBeNull();
    // The trusted capability can re-authorize scopes; a refresh endpoint cannot.
    const reauthorized = await issue({ scopes: ["email", "offline_access"] }, next.refresh_token);
    expect(reauthorized.status).toBe(200);
    const active = (await reauthorized.json()) as any;
    expect((await row(active.refresh_token)).scopes).toEqual(["email", "offline_access"]);
    const boundSeedResponse = await issue({
      scopes: ["email", "offline_access"],
      confirmation: { jkt: "retained-key" },
    });
    expect(boundSeedResponse.status).toBe(200);
    const bound = (await boundSeedResponse.json()) as any;
    for (const params of [
      { scopes: ["email", "offline_access"] },
      { scopes: ["email", "offline_access"], confirmation: null },
    ]) {
      const downgrade = await issue(params, bound.refresh_token);
      expect(downgrade.status).toBe(400);
      expect(await downgrade.json()).toEqual({
        error: "invalid_dpop_proof",
        error_description: "DPoP proof header is required",
      });
      expect((await row(bound.refresh_token)).revoked).toBeNull();
    }
    const reboundResponse = await issue(
      { scopes: ["email", "offline_access"], confirmation: { jkt: "replacement-key" } },
      bound.refresh_token,
    );
    expect(reboundResponse.status).toBe(200);
    const rebound = (await reboundResponse.json()) as any;
    expect(rebound.token_type).toBe("DPoP");
    expect((await row(rebound.refresh_token)).confirmation).toEqual({ jkt: "replacement-key" });
    return ctx.snapshot({
      owner: owner.user,
      rotated: true,
      scope: next.scope,
      reauthorized: active.scope,
    });
  },
);
