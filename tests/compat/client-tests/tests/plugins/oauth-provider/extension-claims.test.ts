import { createLocalJWKSet, jwtVerify } from "jose";
import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "Opaque introspection re-derives live extension and resource claims",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: object) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "claims-opaque", ...input }),
      });
    const signup = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("opaque-claims"),
        name: "Live claim owner",
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
    const headers = { cookie };
    const created = await control({
      action: "admin-create",
      headers,
      body: {
        client_name: "Opaque claims",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "email profile",
        token_endpoint_auth_method: "client_secret_post",
        metadata: { tenant: "application" },
      },
    });
    expect(created.status).toBe(201);
    const client = (await created.json()) as any;
    const session = (await (await control({ action: "session", headers })).json()) as any;
    const resource = "https://api.fixture.test/live-claims";
    const resourceResponse = await control({
      action: "resource-create",
      headers,
      body: {
        identifier: resource,
        customClaims: { resource_wins: "resource-before", cnf: { jkt: "forged" } },
      },
    });
    expect(resourceResponse.status).toBe(200);
    expect(
      (
        await control({
          action: "resource-link",
          headers,
          params: {
            identifier: resource,
            client_id: client.client_id,
          },
        })
      ).status,
    ).toBe(200);
    const state = async (value?: string, extra: object = {}) => {
      const response = await control({ action: "claims-state", value, ...extra });
      expect(response.status).toBe(200);
      return (await response.json()) as any;
    };
    await state("before", { operator: true, mutateResource: resource, reset: true });
    const issue = (disableJwtPlugin: boolean) =>
      control({
        action: "issue-tokens",
        body: {
          disableJwtPlugin,
          claimsProfile: true,
          accessClaimsProfile: true,
          clientId: client.client_id,
          userId: owner.user.id,
          grantType: "urn:fixture:claims",
          params: {
            scopes: ["email", "profile"],
            resources: [resource],
            sessionId: session.session.id,
            referenceId: "live-reference",
            accessTokenClaims: { per_request: "issuance-only" },
          },
        },
      });
    const issued = await issue(true);
    expect(issued.status).toBe(200);
    const token = ((await issued.json()) as any).access_token;
    expect(token).toMatch(/^[A-Za-z]{32}$/);
    expect((await state()).calls).toEqual([]);
    expect((await state()).operatorCalls).toEqual([]);
    const signedResponse = await issue(false);
    expect(signedResponse.status).toBe(200);
    const signedToken = ((await signedResponse.json()) as any).access_token;
    const keys = createLocalJWKSet((await (await control({ action: "jwks" })).json()) as any);
    const signedClaims = (
      await jwtVerify(signedToken, keys, { issuer: `${ctx.baseURL}/api/auth`, audience: resource })
    ).payload;
    expect(signedClaims).toMatchObject({
      operator_value: "before",
      extension_owner: "operator-before",
      per_request: "operator-before",
      resource_wins: "resource-before",
      sub: owner.user.id,
      client_id: client.client_id,
      azp: client.client_id,
      sid: session.session.id,
      scope: "email profile",
    });
    expect(signedClaims.exp! - signedClaims.iat!).toBe(3600);
    expect(signedClaims.jti).toHaveLength(32);
    expect(signedClaims.jti).not.toBe("forged");
    for (const key of ["cnf", "auth_time", "acr", "amr"]) {
      expect(signedClaims).not.toHaveProperty(key);
    }
    const issuance = await state();
    expect(issuance.operatorCalls).toEqual([
      {
        userId: owner.user.id,
        scopes: ["email", "profile"],
        resources: [resource],
        referenceId: "live-reference",
        metadata: { tenant: "application" },
      },
    ]);
    expect(issuance.calls).toEqual(
      ["first", "second"].map((extension) => ({
        extension,
        grant: "urn:fixture:claims",
        sessionId: session.session.id,
        userId: owner.user.id,
        clientId: client.client_id,
        referenceId: "live-reference",
        scopes: ["email", "profile"],
        resources: [resource],
        metadata: { tenant: "application" },
      })),
    );
    await state(undefined, { reset: true });
    const introspect = async (
      accessToken = token,
      mode = "claims-opaque",
      introspector = client,
    ) => {
      const response = await control({
        action: "introspect",
        mode,
        body: {
          token: accessToken,
          token_type_hint: "access_token",
          client_id: introspector.client_id,
          client_secret: introspector.client_secret,
        },
      });
      expect(
        response.status,
        response.status === 200 ? undefined : await response.clone().text(),
      ).toBe(200);
      return (await response.json()) as any;
    };
    const peerResponse = await control({
      action: "admin-create",
      headers,
      body: {
        client_name: "Unlinked peer",
        redirect_uris: ["https://peer.fixture.test/callback"],
        scope: "email profile",
        token_endpoint_auth_method: "client_secret_post",
      },
    });
    expect(peerResponse.status).toBe(201);
    const peer = (await peerResponse.json()) as any;
    expect(await introspect(token, "claims-opaque", peer)).toEqual({ active: false });
    expect((await state()).calls).toEqual([]);
    expect((await state()).operatorCalls).toEqual([]);
    const receipts = [];
    for (const value of ["before", "after"]) {
      await state(value);
      expect(
        (
          await control({
            action: "resource-update",
            headers,
            params: { identifier: resource },
            body: {
              disabled: value === "after",
              ...(value === "after" ? { allowedScopes: ["openid"] } : {}),
              customClaims: {
                resource_wins: `resource-${value}`,
                cnf: { jkt: "forged" },
                jti: "forged",
                auth_time: 1,
              },
            },
          })
        ).status,
      ).toBe(200);
      const payload = await introspect();
      expect(payload.live_value).toBe(value);
      expect(payload.operator_value).toBe(value);
      expect(payload.extension_owner).toBe(`operator-${value}`);
      expect(payload.resource_wins).toBe(`resource-${value}`);
      expect(payload.per_request).toBe(`operator-${value}`);
      const rowResponse = await control({ action: "resource-row", identifier: resource });
      expect(rowResponse.status).toBe(200);
      expect(((await rowResponse.json()) as any).customClaims.resource_wins).toBe(
        `resource-during-${value}`,
      );
      expect(payload).toMatchObject({
        active: true,
        sub: owner.user.id,
        client_id: client.client_id,
        azp: client.client_id,
        sid: session.session.id,
        scope: "email profile",
        aud: resource,
        iss: `${ctx.baseURL}/api/auth`,
        token_type: "Bearer",
      });
      expect(payload.exp - payload.iat).toBe(3600);
      for (const key of ["cnf", "jti", "auth_time", "acr", "amr", "constructor"]) {
        expect(payload).not.toHaveProperty(key);
      }
      // The actual random client/session IDs are asserted above on each server;
      // retain the application-owned claim changes as the differential receipt.
      receipts.push({
        live: payload.live_value,
        operator: payload.operator_value,
        resource: payload.resource_wins,
        extension: payload.extension_owner,
        perRequest: payload.per_request,
        tokenType: payload.token_type,
      });
    }
    const calls = (await state()).calls;
    expect(calls).toEqual(
      ["first", "second", "first", "second"].map((extension) => ({
        extension,
        grant: null,
        sessionId: null,
        userId: owner.user.id,
        clientId: client.client_id,
        referenceId: "live-reference",
        scopes: ["email", "profile"],
        resources: [resource],
        metadata: { tenant: "application" },
      })),
    );
    const operatorCalls = (await state()).operatorCalls;
    expect(operatorCalls).toEqual(
      Array.from({ length: 2 }, () => ({
        userId: owner.user.id,
        scopes: ["email", "profile"],
        resources: [resource],
        referenceId: "live-reference",
        metadata: { tenant: "application" },
      })),
    );
    expect(
      (
        await jwtVerify(signedToken, keys, {
          issuer: `${ctx.baseURL}/api/auth`,
          audience: resource,
        })
      ).payload,
    ).toEqual(signedClaims);
    const signedValidation = await control({
      mode: "default",
      action: "validate-access",
      body: { token: signedToken, requireActive: true, accessClaimsProfile: true },
    });
    expect(signedValidation.status).toBe(200);
    const signedLive = (await signedValidation.json()) as any;
    expect(signedLive.operator_value).toBe("before");
    expect(signedLive.resource_wins).toBe("resource-before");
    expect((await state()).calls).toEqual(calls);
    expect((await state()).operatorCalls).toEqual(operatorCalls);
    expect(
      (
        await control({
          action: "revoke",
          body: {
            token,
            token_type_hint: "access_token",
            client_id: client.client_id,
            client_secret: client.client_secret,
          },
        })
      ).status,
    ).toBe(200);
    expect(await introspect()).toEqual({ active: false });
    expect((await state("must-not-leak")).calls).toEqual(calls);
    expect((await state()).operatorCalls).toEqual(operatorCalls);
    await state(undefined, { operator: false, mutateResource: null });
    return ctx.snapshot({
      owner: owner.user,
      authorizationSession: session,
      receipts,
      calls,
      operatorCalls,
      issuance: { calls: issuance.calls, operatorCalls: issuance.operatorCalls },
      signed: {
        operator: signedClaims.operator_value,
        resource: signedClaims.resource_wins,
        perRequest: signedClaims.per_request,
      },
    });
  },
);

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
    expect(
      (
        await control({
          action: "claims-state",
          operator: false,
          mutateResource: null,
          reset: true,
        })
      ).status,
    ).toBe(200);
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
    const accessTokens: string[] = [];
    const operatorState = async (input: object = {}) => {
      const response = await control({ action: "userinfo-claims-state", ...input });
      expect(response.status).toBe(200);
      return (await response.json()) as any;
    };
    for (const resources of [undefined, [resource]]) {
      await operatorState({ value: null, reset: true });
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
            requestedUserInfoClaims: ["email", "unsupported"],
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
      expect(claims.email).toBe(owner.user.email);
      expect(claims.email_verified).toBe(false);
      expect(claims.extension_owner).toBe("first");
      expect(claims.nullable_claim).toBeNull();
      expect(claims).not.toHaveProperty("constructor");
      for (const name of ["first", "second"]) {
        expect(claims[`extension_${name}`]).toEqual({
          scopes: ["openid", "profile", "email", "offline_access"],
          userId: owner.user.id,
          clientId: client.client_id,
          requestedClaims: resources ? [] : ["email", "unsupported"],
          payloadSub: owner.user.id,
          caller: "userinfo-caller",
        });
      }
      await operatorState({ value: "before", reset: true });
      const overrides = [];
      for (const value of ["before", "after"]) {
        if (value === "after") await operatorState({ value });
        const info = await control({
          action: "userinfo",
          headers: {
            authorization: `Bearer ${tokens.access_token}`,
            "x-claims-caller": "userinfo-caller",
          },
        });
        expect(info.status).toBe(200);
        const overridden = (await info.json()) as any;
        expect(overridden).toEqual({
          ...claims,
          name: `Operator ${value}`,
          email: `operator-${value}@example.test`,
          extension_owner: `operator-${value}`,
          toString: `operator-toString-${value}`,
          sub: owner.user.id,
        });
        expect(Object.hasOwn(overridden, "__proto__")).toBe(false);
        expect(Object.hasOwn(overridden, "operatorPrototype")).toBe(false);
        // Preserve every returned value using the harness's identity vocabulary.
        const { sub, extension_first, extension_second, ...profile } = overridden;
        const extensionReceipt = ({ payloadSub, ...fields }: any) => ({
          ...fields,
          payload: { userId: payloadSub },
        });
        overrides.push({
          userId: sub,
          ...profile,
          extension_first: extensionReceipt(extension_first),
          extension_second: extensionReceipt(extension_second),
        });
      }
      const operator = await operatorState();
      expect(operator.calls).toEqual(
        Array.from({ length: 2 }, () => ({
          userId: owner.user.id,
          userName: "Claim Owner",
          userEmail: owner.user.email,
          scopes: ["openid", "profile", "email", "offline_access"],
          requestedClaims: resources ? [] : ["email", "unsupported"],
          payloadSub: owner.user.id,
          payloadClientId: client.client_id,
          payloadScope: "openid profile email offline_access",
        })),
      );
      expect(operator.events).toEqual([
        "first",
        "second",
        "operator",
        "first",
        "second",
        "operator",
      ]);
      // A real issued ID token is signed but has the wrong access authority.
      for (const token of ["missing-token", tokens.id_token]) {
        const denied = await control({
          action: "userinfo",
          headers: { authorization: `Bearer ${token}` },
        });
        expect(denied.status).toBe(401);
        expect(await denied.json()).toEqual({
          error: "invalid_token",
          error_description: "Invalid access token",
        });
      }
      expect(await operatorState()).toEqual(operator);
      await operatorState({ value: null });
      expect(
        (await control({ action: "id-claims-state", value: "refresh", error: "", reset: true }))
          .status,
      ).toBe(200);
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
      // Keep the replacement authority, not an access row retired by refresh.
      accessTokens.push(renewed.access_token);
      const refreshedId = (
        await jwtVerify(renewed.id_token, keys, { issuer, audience: client.client_id })
      ).payload;
      expect(refreshedId.extension_owner).toBe("id-operator-refresh");
      expect(refreshedId.name).toBe("ID operator refresh");
      expect(refreshedId.email).toBe("id-refresh@example.test");
      expect(refreshedId.nonce).toBeUndefined();
      expect((refreshedId.extension_first as any).grant).toBe("refresh_token");
      expect((refreshedId.extension_first as any).caller).toBe("refresh-caller");
      expect(refreshedId.per_request).toBe("id-operator-refresh");
      const idCallbackResponse = await control({ action: "id-claims-state" });
      expect(idCallbackResponse.status).toBe(200);
      const idCallback = (await idCallbackResponse.json()) as any;
      expect(idCallback.calls).toEqual([
        {
          userId: owner.user.id,
          userName: "Claim Owner",
          userEmail: owner.user.email,
          scopes: ["openid", "profile", "email", "offline_access"],
          metadata: { tenant: "application" },
        },
      ]);
      expect(
        (await control({ action: "id-claims-state", value: null, error: "", reset: true })).status,
      ).toBe(200);
      receipts.push({
        signedAccess: Boolean(resources),
        owner: claims.extension_owner,
        perRequest: id.per_request,
        refreshedGrant: (refreshedId.extension_first as any).grant,
        idCallback,
        overrides,
        operator: {
          ...operator,
          calls: operator.calls.map(
            ({ payloadSub, payloadClientId, payloadScope, ...args }: any) => ({
              ...args,
              payload: { userId: payloadSub, clientId: payloadClientId, scope: payloadScope },
            }),
          ),
        },
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
    const emailOnly = ((await opaque.json()) as any).access_token;
    expect(emailOnly).toMatch(/^[A-Za-z]{32}$/);
    const beforeExpiry = await operatorState({ value: "must-not-leak" });
    const missingScope = await control({
      action: "userinfo",
      headers: { authorization: `Bearer ${emailOnly}` },
    });
    expect(missingScope.status).toBe(400);
    expect(await missingScope.json()).toEqual({
      error: "invalid_scope",
      error_description: "Missing required scope",
    });
    expect(await operatorState()).toEqual(beforeExpiry);
    const expired = await control({ action: "expire-session", token: session.session.token });
    expect(expired.status).toBe(200);
    expect(await expired.json()).toEqual({ expired: true });
    for (const token of accessTokens) {
      const denied = await control({
        action: "userinfo",
        headers: { authorization: `Bearer ${token}` },
      });
      expect(denied.status).toBe(401);
      expect(await denied.json()).toEqual({
        error: "invalid_token",
        error_description: "Invalid access token",
      });
    }
    expect(await operatorState()).toEqual(beforeExpiry);
    return ctx.snapshot({ user: owner.user, receipts, before });
  },
);
