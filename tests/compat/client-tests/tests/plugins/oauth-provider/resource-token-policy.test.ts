import { expect } from "bun:test";

import { createLocalJWKSet, jwtVerify } from "jose";
import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Resource policy owns token lifetime, ordered claims and provisioned signing selection",
  async (ctx) => {
    const actor = ctx.actor();
    const url = `${ctx.baseURL}/__test/server-api/oauth-provider-clients`;
    const control = (input: object) =>
      actor.fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "resource-keyring", ...input }),
      });
    const signup = await control({
      action: "signup",
      body: { email: ctx.uniqueEmail("resource-policy"), name: "Owner", password: "password123" },
    });
    expect(signup.status).toBe(200);
    const owner = (await signup.json()) as any;
    const cookie = signup.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const headers = { cookie };
    const created = await control({
      action: "admin-create",
      headers,
      body: {
        client_name: "Resource policy",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "openid email offline_access",
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
      },
    });
    expect(created.status).toBe(201);
    const client = (await created.json()) as any;
    const warm = await control({ action: "sign-access", body: { sub: owner.user.id } });
    expect(warm.status).toBe(200);
    const uri = (name: string) => `https://api.fixture.test/policy/${name}`;
    for (const [name, accessTokenTtl, refreshTokenTtl] of [
      ["a", 120, 1800],
      ["b", 60, 900],
    ] as const) {
      const resource = await control({
        action: "resource-create",
        headers,
        body: {
          identifier: uri(name),
          accessTokenTtl,
          refreshTokenTtl,
          signingAlgorithm: "ES256",
          customClaims: {
            role: `from-${name}`,
            [name]: true,
            sub: "injected",
            iss: "injected",
            scope: "injected",
            cnf: { jkt: "injected" },
            auth_time: 123,
          },
        },
      });
      expect(resource.status).toBe(200);
      const link = await control({
        action: "resource-link",
        headers,
        params: { identifier: uri(name), client_id: client.client_id },
      });
      expect(link.status).toBe(200);
    }
    const issuer = `${ctx.baseURL}/api/auth`;
    const receipts = [];
    for (const name of ["user", "machine", "reverse", "scope-cap", "key-pin"]) {
      const resources = name === "reverse" ? [uri("b"), uri("a")] : [uri("a"), uri("b")];
      const withUser = name !== "machine";
      const response = await control({
        action: "issue-tokens",
        body: {
          ...(name === "scope-cap" ? { scopePolicy: "relative" } : {}),
          clientId: client.client_id,
          ...(withUser ? { userId: owner.user.id } : {}),
          grantType: "urn:fixture:server",
          params: {
            scopes: withUser ? ["openid", "email", "offline_access"] : ["email"],
            resources,
            accessTokenClaims: { role: "per-request", requestOnly: true, cnf: { jkt: "injected" } },
          },
        },
      });
      expect(response.status).toBe(200);
      const issued = (await response.json()) as any;
      const ttl = name === "scope-cap" ? 45 : 60;
      expect(issued.expires_in).toBe(ttl);
      expect(issued.token_type).toBe("Bearer");
      const jwks = (await (await control({ action: "jwks" })).json()) as any;
      const keys = createLocalJWKSet(jwks);
      const { payload, protectedHeader } = await jwtVerify(issued.access_token, keys, { issuer });
      expect(protectedHeader.alg).toBe("ES256");
      expect(protectedHeader.typ).toBe("at+jwt");
      expect(Number(payload.exp) - Number(payload.iat)).toBe(ttl);
      expect(payload.sub).toBe(withUser ? owner.user.id : client.client_id);
      expect(payload.scope).toBe(withUser ? "openid email offline_access" : "email");
      expect(payload.aud).toEqual(
        withUser ? [...resources, `${issuer}/oauth2/userinfo`] : resources,
      );
      expect(payload.role).toBe(name === "reverse" ? "from-a" : "from-b");
      expect(payload.requestOnly).toBe(true);
      expect(payload.a).toBe(true);
      expect(payload.b).toBe(true);
      expect(payload.cnf).toBeUndefined();
      expect(payload.auth_time).toBeUndefined();
      if (withUser) {
        const row = (await (
          await control({ action: "token-row", kind: "refresh", token: issued.refresh_token })
        ).json()) as any;
        expect((Date.parse(row.expiresAt) - Date.parse(row.createdAt)) / 1000).toBe(900);
        const id = await jwtVerify(issued.id_token, keys, { issuer, audience: client.client_id });
        expect(Number(id.payload.exp) - Number(id.payload.iat)).toBe(36000);
        const nextResponse = await control({
          action: "token",
          body: {
            grant_type: "refresh_token",
            client_id: client.client_id,
            refresh_token: issued.refresh_token,
          },
        });
        expect(nextResponse.status).toBe(200);
        const next = (await nextResponse.json()) as any;
        expect(next.expires_in).toBe(60);
        const verified = await jwtVerify(
          next.access_token,
          createLocalJWKSet((await (await control({ action: "jwks" })).json()) as any),
          { issuer },
        );
        expect(verified.protectedHeader.alg).toBe("ES256");
        expect(verified.payload.role).toBe(payload.role);
        expect(verified.payload.requestOnly).toBeUndefined();
        const retained = (await (
          await control({ action: "token-row", kind: "refresh", token: next.refresh_token })
        ).json()) as any;
        expect((Date.parse(retained.expiresAt) - Date.parse(retained.createdAt)) / 1000).toBe(900);
      } else {
        expect(issued.refresh_token).toBeUndefined();
      }
      if (name === "scope-cap") {
        const kid = jwks.keys.find((key: any) => key.alg === "ES256").kid;
        // The pin is an observed, server-generated key ID. Check it per run rather
        // than comparing its opaque bytes across independent keyrings.
        for (const identifier of resources) {
          const update = await fetch(url, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              mode: "resource-keyring",
              action: "resource-update",
              headers,
              params: { identifier },
              body: { signingAlgorithm: null, signingKeyId: kid },
            }),
          });
          expect(update.status).toBe(200);
        }
      }
      receipts.push({ name, ttl, algorithm: protectedHeader.alg, role: payload.role });
    }
    return ctx.snapshot({ owner: owner.user, receipts });
  },
);
