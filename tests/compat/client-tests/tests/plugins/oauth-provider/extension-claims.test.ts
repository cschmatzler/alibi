import { createLocalJWKSet, jwtVerify } from "jose";
import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "Extension claims enrich signed issuance and UserInfo with ordered ownership",
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
      body: {
        email: ctx.uniqueEmail("extension-claims"),
        name: "Claim Owner",
        password: "password123",
      },
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
        client_name: "Claim consumer",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "openid profile email offline_access",
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code", "refresh_token"],
        metadata: { tenant: "application" },
      },
    });
    expect(created.status).toBe(201);
    const client = (await created.json()) as any;
    const session = (await (
      await control({ action: "session", headers: { cookie } })
    ).json()) as any;
    const issuer = `${ctx.baseURL}/api/auth`;
    const resource = `${issuer}/oauth2/userinfo`;
    const receipts = [];
    for (const resources of [undefined, [resource]]) {
      const response = await control({
        action: "issue-tokens",
        headers: { "x-claims-caller": "trusted-caller" },
        body: {
          claimsProfile: true,
          clientId: client.client_id,
          userId: owner.user.id,
          grantType: "urn:fixture:claims",
          params: {
            scopes: ["openid", "profile", "email", "offline_access"],
            resources,
            sessionId: session.session.id,
            referenceId: "application-reference",
            accessTokenClaims: { per_request: "request" },
            idTokenClaims: { per_request: "request" },
          },
        },
      });
      expect(response.status).toBe(200);
      const tokens = (await response.json()) as any;
      const keys = createLocalJWKSet((await (await control({ action: "jwks" })).json()) as any);
      const id = (await jwtVerify(tokens.id_token, keys, { issuer, audience: client.client_id }))
        .payload;
      expect(id.sub).toBe(owner.user.id);
      expect(id.extension_owner).toBe("first");
      expect(id.per_request).toBe("request");
      expect(id).not.toHaveProperty("email");
      expect(id).not.toHaveProperty("constructor");
      expect(id.nullable_claim).toBeNull();
      for (const name of ["first", "second"]) {
        expect(id[`extension_${name}`]).toEqual({
          grant: "urn:fixture:claims",
          scopes: ["openid", "profile", "email", "offline_access"],
          userId: owner.user.id,
          clientId: client.client_id,
          referenceId: "application-reference",
          sessionId: session.session.id,
          metadata: { tenant: "application" },
          caller: "trusted-caller",
        });
      }
      if (resources) {
        const access = (await jwtVerify(tokens.access_token, keys, { issuer, audience: resource }))
          .payload;
        expect(access.sub).toBe(owner.user.id);
        expect(access.scope).toBe("openid profile email offline_access");
        expect(access.extension_owner).toBe("first");
        expect(access.per_request).toBe("request");
        expect(access.extension_first).toEqual(id.extension_first);
        expect(access.extension_second).toEqual(id.extension_second);
        expect(access).not.toHaveProperty("constructor");
      }
      const userInfo = await control({
        action: "userinfo",
        headers: {
          authorization: `Bearer ${tokens.access_token}`,
          "x-claims-caller": "userinfo-caller",
        },
      });
      expect(userInfo.status).toBe(200);
      const claims = (await userInfo.json()) as any;
      expect(claims.sub).toBe(owner.user.id);
      expect(claims.name).toBe("Claim Owner");
      expect(claims.email_verified).toBe(false);
      expect(claims.extension_owner).toBe("first");
      expect(claims.nullable_claim).toBeNull();
      expect(claims).not.toHaveProperty("constructor");
      for (const name of ["first", "second"]) {
        expect(claims[`extension_${name}`]).toEqual({
          scopes: ["openid", "profile", "email", "offline_access"],
          userId: owner.user.id,
          clientId: client.client_id,
          requestedClaims: [],
          payloadSub: owner.user.id,
          caller: "userinfo-caller",
        });
      }
      const refresh = await control({
        action: "token",
        headers: { "x-claims-caller": "refresh-caller" },
        body: {
          grant_type: "refresh_token",
          client_id: client.client_id,
          client_secret: client.client_secret,
          refresh_token: tokens.refresh_token,
        },
      });
      expect(refresh.status).toBe(200);
      const renewed = (await refresh.json()) as any;
      const refreshedId = (
        await jwtVerify(renewed.id_token, keys, { issuer, audience: client.client_id })
      ).payload;
      expect(refreshedId.extension_owner).toBe("first");
      expect((refreshedId.extension_first as any).grant).toBe("refresh_token");
      expect((refreshedId.extension_first as any).caller).toBe("refresh-caller");
      expect(refreshedId.per_request).toBe("first");
      receipts.push({
        signedAccess: Boolean(resources),
        owner: claims.extension_owner,
        perRequest: id.per_request,
        refreshedGrant: (refreshedId.extension_first as any).grant,
      });
    }
    const beforeResponse = await control({
      action: "authority-counts",
      sessionId: session.session.id,
    });
    expect(beforeResponse.status).toBe(200);
    const before = await beforeResponse.json();
    for (const target of ["id", "access"]) {
      const rejected = await control({
        action: "issue-tokens",
        headers: { "x-claims-error": target },
        body: {
          claimsProfile: true,
          clientId: client.client_id,
          userId: owner.user.id,
          grantType: "urn:fixture:claims",
          params: {
            scopes: ["openid", "offline_access"],
            resources: [resource],
            sessionId: session.session.id,
          },
        },
      });
      expect(rejected.status).toBe(400);
      expect(await rejected.json()).toEqual({
        code: "CLAIM_REJECTED",
        message: `rejected ${target}`,
      });
      const after = await control({ action: "authority-counts", sessionId: session.session.id });
      expect(after.status).toBe(200);
      expect(await after.json()).toEqual(before);
    }
    const opaque = await control({
      action: "issue-tokens",
      headers: { "x-claims-error": "access" },
      body: {
        claimsProfile: true,
        clientId: client.client_id,
        userId: owner.user.id,
        grantType: "urn:fixture:claims",
        params: { scopes: ["email"] },
      },
    });
    expect(opaque.status).toBe(200);
    expect(((await opaque.json()) as any).access_token).toMatch(/^[A-Za-z]{32}$/);
    return ctx.snapshot({ user: owner.user, receipts, before });
  },
);
