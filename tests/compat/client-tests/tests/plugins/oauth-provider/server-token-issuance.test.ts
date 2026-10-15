import { expect } from "bun:test";
import { createHash } from "node:crypto";

import { createLocalJWKSet, jwtVerify } from "jose";
import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "Trusted issuance mints real machine, user, OpenID, resource and bound authority",
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
      body: { email: ctx.uniqueEmail("issuer"), name: "Owner", password: "password123" },
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
        client_name: "Trusted issuer",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "openid email offline_access",
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
      },
    });
    expect(created.status).toBe(201);
    const client = (await created.json()) as any;
    const session = (await (
      await control({ action: "session", headers: { cookie } })
    ).json()) as any;
    const issuer = `${ctx.baseURL}/api/auth`;
    const userinfo = `${issuer}/oauth2/userinfo`;
    const missing = await control({
      action: "issue-tokens",
      body: { clientId: client.client_id, params: { scopes: ["email"] } },
    });
    expect(missing.status).toBe(500);
    expect(await missing.json()).toEqual({
      error: "server_error",
      error_description:
        "issueTokens requires a grant type; pass it to getOAuthProviderApi(ctx, opts, grantType).",
    });
    const receipts = [];
    for (const name of ["machine", "user", "openid", "resource", "bound"]) {
      const withUser = ["user", "openid", "bound"].includes(name);
      const scopes =
        name === "openid"
          ? ["openid", "email"]
          : name === "resource"
            ? ["email"]
            : ["email", "offline_access"];
      const params = {
        scopes,
        tokenResponse: {
          access_token: "injected",
          scope: "injected",
          refresh_token: "injected",
          id_token: "injected",
          custom: "receipt",
        },
        ...(name === "user"
          ? {
              sessionId: session.session.id,
              referenceId: "reference-123",
              authTime: session.session.createdAt,
              requestedUserInfoClaims: ["email"],
            }
          : {}),
        ...(name === "openid"
          ? {
              nonce: "nonce-123",
              idTokenClaims: {
                sub: "injected",
                at_hash: "injected",
                email: "injected",
                s_hash: "injected",
                nickname: "Custom nickname",
                custom: "receipt",
              },
            }
          : {}),
        ...(name === "resource"
          ? {
              resources: [userinfo],
              accessTokenClaims: {
                sub: "injected",
                iss: "injected",
                cnf: { jkt: "injected" },
                auth_time: 123,
                acr: "injected",
                amr: ["injected"],
                custom: "receipt",
              },
            }
          : {}),
        ...(name === "bound" ? { confirmation: { jkt: "bound-key" } } : {}),
      };
      const response = await control({
        action: "issue-tokens",
        body: {
          clientId: client.client_id,
          grantType: "urn:fixture:server",
          ...(withUser ? { userId: owner.user.id } : {}),
          params,
        },
      });
      expect(response.status).toBe(200);
      const result = (await response.json()) as any;
      expect(result.scope).toBe(scopes.join(" "));
      expect(result.expires_in).toBe(3600);
      expect(result.custom).toBe("receipt");
      expect(result.token_type).toBe(name === "bound" ? "DPoP" : "Bearer");
      const keys = createLocalJWKSet((await (await control({ action: "jwks" })).json()) as any);
      if (name === "resource") {
        const { payload, protectedHeader } = await jwtVerify(result.access_token, keys, {
          issuer,
          audience: userinfo,
        });
        expect(protectedHeader.typ).toBe("at+jwt");
        expect(payload.sub).toBe(client.client_id);
        expect(payload.client_id).toBe(client.client_id);
        expect(payload.azp).toBe(client.client_id);
        expect(payload.custom).toBe("receipt");
        expect(payload.cnf).toBeUndefined();
        expect(payload.auth_time).toBeUndefined();
        expect(payload.acr).toBeUndefined();
        expect(payload.amr).toBeUndefined();
        expect(result.refresh_token).toBeUndefined();
      } else {
        expect(result.access_token).toMatch(/^[A-Za-z]{32}$/);
        const row = (await (
          await control({ action: "token-row", token: result.access_token })
        ).json()) as any;
        expect(row.clientId).toBe(client.client_id);
        expect(row.userId ?? null).toBe(withUser ? owner.user.id : null);
        expect(row.scopes).toEqual(scopes);
        expect(row.token).toBe(
          createHash("sha256").update(result.access_token).digest("base64url"),
        );
        expect(row.authorizationCodeId ?? null).toBeNull();
        if (name === "user") {
          expect(row.sessionId).toBe(session.session.id);
          expect(row.referenceId).toBe("reference-123");
          expect(row.requestedUserInfoClaims).toEqual(["email"]);
        }
        if (name === "bound") expect(row.confirmation).toEqual({ jkt: "bound-key" });
        if (withUser && name !== "openid") {
          expect(result.refresh_token).toMatch(/^[A-Za-z]{32}$/);
          const refresh = (await (
            await control({ action: "token-row", kind: "refresh", token: result.refresh_token })
          ).json()) as any;
          expect(row.refreshId).toBe(refresh.id);
          expect(refresh.userId).toBe(owner.user.id);
          expect(refresh.scopes).toEqual(scopes);
          if (name === "user") {
            expect(refresh.referenceId).toBe("reference-123");
            expect(refresh.requestedUserInfoClaims).toEqual(["email"]);
            expect(Date.parse(refresh.authTime)).toBe(Date.parse(session.session.createdAt));
          }
        } else expect(result.refresh_token).toBeUndefined();
      }
      if (name === "openid") {
        const { payload } = await jwtVerify(result.id_token, keys, {
          issuer,
          audience: client.client_id,
        });
        expect(payload.sub).toBe(owner.user.id);
        expect(payload.nonce).toBe("nonce-123");
        expect(payload.custom).toBe("receipt");
        expect(payload.email).toBeUndefined();
        expect(payload.s_hash).toBeUndefined();
        expect(payload.nickname).toBe("Custom nickname");
        expect(payload.at_hash).toBe(
          createHash("sha512")
            .update(result.access_token)
            .digest()
            .subarray(0, 32)
            .toString("base64url"),
        );
      } else expect(result.id_token).toBeUndefined();
      receipts.push({
        name,
        scope: result.scope,
        type: result.token_type,
        refresh: Boolean(result.refresh_token),
        id: Boolean(result.id_token),
      });
    }
    return ctx.snapshot({ owner: owner.user, receipts });
  },
);
