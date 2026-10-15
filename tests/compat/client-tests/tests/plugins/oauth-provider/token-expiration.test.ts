import { createLocalJWKSet, jwtVerify } from "jose";
import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Configured issuance lifetimes distinguish machine, user, ID and rotating refresh authority",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: object) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "issuance-expiry", ...input }),
      });
    const signup = await control({
      action: "signup",
      body: { email: ctx.uniqueEmail("expiry"), name: "Owner", password: "password123" },
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
        client_name: "Expiry client",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "openid email offline_access",
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
      },
    });
    expect(created.status).toBe(201);
    const client = (await created.json()) as any;
    const issuer = `${ctx.baseURL}/api/auth`;
    const receipts = [];
    for (const name of ["machine", "user", "jwt"]) {
      const withUser = name !== "machine";
      const params = {
        scopes: withUser ? ["openid", "email", "offline_access"] : ["email"],
        ...(name === "jwt" ? { resources: [`${issuer}/oauth2/userinfo`] } : {}),
      };
      const response = await control({
        action: "issue-tokens",
        body: {
          expiryProfile: true,
          grantType: "urn:fixture:server",
          clientId: client.client_id,
          ...(withUser ? { userId: owner.user.id } : {}),
          params,
        },
      });
      expect(response.status).toBe(200);
      const result = (await response.json()) as any;
      const expected = withUser ? 120 : 30;
      expect(result.expires_in).toBe(expected);
      let accessTtl;
      const keys = createLocalJWKSet((await (await control({ action: "jwks" })).json()) as any);
      if (name === "jwt") {
        const { payload } = await jwtVerify(result.access_token, keys, { issuer });
        accessTtl = Number(payload.exp) - Number(payload.iat);
      } else {
        const row = (await (
          await control({ action: "token-row", token: result.access_token })
        ).json()) as any;
        accessTtl = (Date.parse(row.expiresAt) - Date.parse(row.createdAt)) / 1000;
      }
      expect(accessTtl).toBe(expected);
      if (withUser) {
        const { payload } = await jwtVerify(result.id_token, keys, {
          issuer,
          audience: client.client_id,
        });
        expect(Number(payload.exp) - Number(payload.iat)).toBe(600);
        const refresh = (await (
          await control({ action: "token-row", kind: "refresh", token: result.refresh_token })
        ).json()) as any;
        expect((Date.parse(refresh.expiresAt) - Date.parse(refresh.createdAt)) / 1000).toBe(900);
        const rotated = await control({
          action: "token",
          body: {
            grant_type: "refresh_token",
            client_id: client.client_id,
            refresh_token: result.refresh_token,
          },
        });
        expect(rotated.status).toBe(200);
        const next = (await rotated.json()) as any;
        expect(next.expires_in).toBe(120);
        const retained = (await (
          await control({ action: "token-row", kind: "refresh", token: next.refresh_token })
        ).json()) as any;
        expect((Date.parse(retained.expiresAt) - Date.parse(retained.createdAt)) / 1000).toBe(900);
        const id = await jwtVerify(next.id_token, keys, { issuer, audience: client.client_id });
        expect(Number(id.payload.exp) - Number(id.payload.iat)).toBe(600);
      } else {
        expect(result.refresh_token).toBeUndefined();
        expect(result.id_token).toBeUndefined();
      }
      receipts.push({ name, ttl: result.expires_in, storedOrSignedTtl: accessTtl });
    }
    return ctx.snapshot({ owner: owner.user, receipts });
  },
);
