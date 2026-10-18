import { createLocalJWKSet, jwtVerify } from "jose";
import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Opt-in resource cache preserves module-wide policy until successful admin CRUD",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (context: string, input: object) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "resource-seed", context, ...input }),
      });
    const identifier = "https://api.fixture.test/cache/policy";
    const live = `${identifier}/live`;
    const initialize = async (context: string, options: object = {}) => {
      const response = await control(context, {
        action: "resource-seed-init",
        resources: [],
        ...options,
      });
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ initialized: true });
    };
    await initialize("cached", {
      cachedResources: [identifier],
      enforcePerClientResources: true,
      resources: [
        { identifier, accessTokenTtl: 120, customClaims: { version: "old" } },
        { identifier: live, accessTokenTtl: 120 },
      ],
    });
    const signup = async (context: string) => {
      const response = await control(context, {
        action: "signup",
        body: {
          email: ctx.uniqueEmail(`cache-${context}`),
          name: "Owner",
          password: "password123",
        },
      });
      expect(response.status).toBe(200);
      return {
        cookie: response.headers
          .getSetCookie()
          .filter((raw) => Boolean(Cookie.parse(raw)?.value))
          .map((raw) => raw.split(";")[0])
          .join("; "),
      };
    };
    const headers = await signup("cached");
    const client = async (context: string, headers: object) => {
      const response = await control(context, {
        action: "admin-create",
        // Reuse the real configured application ID generator: protocol errors
        // embed the client ID literally, outside the comparator's identity graph.
        ...(context === "cached" ? { mode: "basic-special" } : {}),
        headers,
        body: {
          client_name: "Cache observer",
          redirect_uris: ["https://app.fixture.test/callback"],
          scope: "email",
          token_endpoint_auth_method: "none",
        },
      });
      expect(response.status).toBe(201);
      return (await response.json()) as any;
    };
    const createdClient = await client("cached", headers);
    const clientId = createdClient.client_id as string;
    const admin = (action: string, body?: object, extra: object = {}) =>
      control("cached", {
        action,
        headers,
        params: { identifier, client_id: clientId },
        ...(body ? { body } : {}),
        ...extra,
      });
    const external = async (context: string, action: string, body?: object, id = identifier) => {
      const response = await control(context, {
        action: `resource-external-${action}`,
        identifier: id,
        body,
      });
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual(
        action === "create" ? { created: true } : { updated: true },
      );
    };
    const receipts: object[] = [];
    let issuingContext = "cached";
    const issue = (context = issuingContext, id = identifier, issuingClient = clientId) =>
      control(context, {
        action: "issue-tokens",
        body: {
          clientId: issuingClient,
          grantType: "urn:fixture:server",
          params: { scopes: ["email"], resources: [id] },
        },
      });
    const accepted = async (
      ttl: number,
      version: string | undefined,
      context = issuingContext,
      issuingClient = clientId,
    ) => {
      const response = await issue(context, identifier, issuingClient);
      expect(response.status).toBe(200);
      const issued = (await response.json()) as any;
      expect(issued.expires_in).toBe(ttl);
      expect(issued.scope).toBe("email");
      const keys = createLocalJWKSet(
        (await (await control(context, { action: "jwks" })).json()) as any,
      );
      const { payload } = await jwtVerify(issued.access_token, keys, {
        issuer: `${ctx.baseURL}/api/auth`,
        audience: identifier,
      });
      expect(Number(payload.exp) - Number(payload.iat)).toBe(ttl);
      expect(payload.version).toBe(version);
      receipts.push({ context, ttl, version: version ?? null });
      return issued;
    };
    const denied = async (
      context = issuingContext,
      id = identifier,
      description = `requested resource ${id} is disabled`,
    ) => {
      const response = await issue(context, id);
      expect(response.status).toBe(400);
      expect(await response.json()).toEqual({
        error: "invalid_target",
        error_description: description,
      });
    };
    expect((await admin("resource-link")).status).toBe(200);
    expect(
      (
        await admin("resource-link", undefined, {
          params: { identifier: live, client_id: clientId },
        })
      ).status,
    ).toBe(200);
    await accepted(120, "old");
    await external("cached", "update", {
      disabled: true,
      accessTokenTtl: 33,
      customClaims: { version: "new" },
    });
    await external("cached", "update", { disabled: true }, live);
    await accepted(120, "old");
    await initialize("live");
    await denied("live");
    await denied("cached", live);
    const read = await admin("resource-get");
    expect(read.status).toBe(200);
    expect(((await read.json()) as any).disabled).toBe(true);
    expect((await admin("resource-list")).status).toBe(200);
    for (const [action, body, extra, status] of [
      ["resource-create", { identifier }, {}, 400],
      ["resource-update", { accessTokenTtl: -1 }, {}, 400],
      ["resource-update", { disabled: false }, { headers: {} }, 401],
      ["resource-link", undefined, { params: { identifier, client_id: "missing" } }, 404],
    ] as const) {
      expect((await admin(action, body, extra)).status).toBe(status);
      await accepted(120, "old");
    }
    expect((await admin("resource-unlink")).status).toBe(200);
    await denied(
      "cached",
      identifier,
      `client ${clientId} is not linked to resource(s) ${identifier}`,
    );
    for (let n = 0; n < 2; n++) {
      expect((await admin("resource-link")).status).toBe(200);
      await accepted(120, "old");
    }
    expect((await admin("resource-update", { name: "Invalidate" })).status).toBe(200);
    await denied();
    await external("cached", "update", { disabled: false });
    await denied();
    expect((await admin("resource-update", {})).status).toBe(200);
    await accepted(33, "new");
    await initialize("opaque", { cachedResources: [identifier], disableJwtPlugin: true });
    const opaqueResponse = await issue("opaque");
    expect(opaqueResponse.status).toBe(200);
    const opaque = (await opaqueResponse.json()) as any;
    expect(opaque.expires_in).toBe(33);
    await external("cached", "update", { customClaims: { version: "live-validation" } });
    const validation = await control("opaque", {
      action: "validate-access",
      body: { token: opaque.access_token, clientId },
    });
    expect(validation.status).toBe(200);
    const validated = (await validation.json()) as any;
    expect(validated).toEqual({
      active: true,
      version: "live-validation",
      client_id: clientId,
      azp: clientId,
      iss: `${ctx.baseURL}/api/auth`,
      aud: identifier,
      scope: "email",
      token_type: "Bearer",
      exp: expect.any(Number),
      iat: expect.any(Number),
    });
    expect(validated.exp - validated.iat).toBe(33);
    // Catalog lifecycle is independent of join-table deletion semantics.
    await initialize("catalog", { cachedResources: [identifier] });
    issuingContext = "catalog";
    await external("cached", "delete");
    for (const action of ["resource-update", "resource-delete"]) {
      expect((await admin(action, {})).status).toBe(404);
      await accepted(33, "new");
    }
    expect((await admin("resource-create", { identifier, accessTokenTtl: 60 })).status).toBe(200);
    await accepted(60, undefined);
    expect((await admin("resource-delete")).status).toBe(200);
    await denied("catalog", identifier, `requested resource ${identifier} is not configured`);
    await external("cached", "create", {
      name: identifier,
      disabled: false,
      accessTokenTtl: 90,
      refreshTokenTtl: null,
      signingAlgorithm: null,
      signingKeyId: null,
      allowedScopes: null,
      customClaims: { version: "a" },
      dpopBoundAccessTokensRequired: false,
      policyVersion: 1,
      metadata: null,
    });
    await accepted(90, "a");
    // A separate real database still consumes the module cache. Init and lazy seed
    // both write its own policy without evicting the first database's entry.
    await initialize("peer", {
      isolated: true,
      cachedResources: [identifier],
      resourceSeedMode: "overwrite",
      resources: [{ identifier, disabled: true, accessTokenTtl: 22 }],
    });
    await external("peer", "update", { disabled: false, accessTokenTtl: 44 });
    const peerHeaders = await signup("peer");
    const createdPeerClient = await client("peer", peerHeaders);
    const peerClient = createdPeerClient.client_id as string;
    await accepted(90, "a", "peer", peerClient);
    const peerRow = await control("peer", { action: "resource-seed-row", identifier });
    expect(peerRow.status).toBe(200);
    expect(await peerRow.json()).toMatchObject({ disabled: true, accessTokenTtl: 22 });
    const peerUpdate = await control("peer", {
      action: "resource-update",
      headers: peerHeaders,
      params: { identifier },
      body: { disabled: false },
    });
    expect(peerUpdate.status).toBe(200);
    await accepted(22, undefined, "peer", peerClient);
    await accepted(22, undefined);
    await accepted(90, "a", "live");
    const peerDelete = await control("peer", {
      action: "resource-delete",
      headers: peerHeaders,
      params: { identifier },
    });
    expect(peerDelete.status).toBe(200);
    await accepted(90, "a");
    return ctx.snapshot({
      client: createdClient,
      peerClient: createdPeerClient,
      receipts,
      validated,
    });
  },
);
compatScenario("Configured resources seed at init and once again at first lookup", async (ctx) => {
  const actor = ctx.actor();
  const control = (input: object) =>
    actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ mode: "resource-seed", ...input }),
    });
  const results = [];
  for (const resourceSeedMode of [undefined, "insertOnly", "merge", "overwrite"] as const) {
    const identifier = `https://api.fixture.test/seed/${resourceSeedMode ?? "default"}`;
    const duplicate = `${identifier}/duplicate`;
    const insertOnly = resourceSeedMode === undefined || resourceSeedMode === "insertOnly";
    const initialize = async (resources: unknown[]) => {
      const response = await control({ action: "resource-seed-init", resources, resourceSeedMode });
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ initialized: true });
    };
    const read = async (id = identifier) => {
      const response = await control({ action: "resource-seed-row", identifier: id });
      expect(response.status).toBe(200);
      return (await response.json()) as any;
    };
    const extra = [
      `urn:fixture:${resourceSeedMode ?? "default"}`,
      `http://api.fixture.test/${resourceSeedMode ?? "default"}`,
      `javascript:seed-${resourceSeedMode ?? "default"}`,
      `${identifier}/empty-fragment#`,
    ];
    await initialize([
      {
        identifier,
        name: "Configured",
        accessTokenTtl: 120,
        allowedScopes: ["email"],
        customClaims: { configured: true },
        signingAlgorithm: "HS256",
        unknown: "ignored",
      },
      {
        identifier: duplicate,
        name: "First",
        accessTokenTtl: 10,
        refreshTokenTtl: 20,
        signingAlgorithm: "RS256",
        signingKeyId: "configured-key",
        allowedScopes: ["profile"],
        customClaims: { first: true },
        dpopBoundAccessTokensRequired: true,
        disabled: true,
        metadata: { first: true },
        policyVersion: 99,
      },
      {
        identifier: duplicate,
        name: "Last",
        allowedScopes: [],
        customClaims: null,
        metadata: null,
      },
      ...extra,
      "relative",
      `${identifier}#fragment`,
    ]);
    const initial = await read();
    expect(initial).toMatchObject({
      identifier,
      name: "Configured",
      accessTokenTtl: 120,
      refreshTokenTtl: null,
      allowedScopes: ["email"],
      customClaims: { configured: true },
      signingAlgorithm: null,
      signingKeyId: null,
      disabled: false,
      dpopBoundAccessTokensRequired: false,
      policyVersion: 1,
      metadata: null,
    });
    expect(initial).not.toHaveProperty("unknown");
    const duplicateRow = await read(duplicate);
    expect(duplicateRow).toMatchObject({
      name: insertOnly ? "First" : "Last",
      accessTokenTtl: resourceSeedMode === "overwrite" ? null : 10,
      refreshTokenTtl: resourceSeedMode === "overwrite" ? null : 20,
      signingAlgorithm: resourceSeedMode === "overwrite" ? null : "RS256",
      signingKeyId: resourceSeedMode === "overwrite" ? null : "configured-key",
      allowedScopes: insertOnly ? ["profile"] : [],
      customClaims: insertOnly ? { first: true } : null,
      metadata: insertOnly ? { first: true } : null,
      disabled: resourceSeedMode !== "overwrite",
      dpopBoundAccessTokensRequired: resourceSeedMode !== "overwrite",
      policyVersion: 1,
    });
    for (const id of extra) {
      expect(await read(id)).toMatchObject({
        identifier: id,
        name: id,
        disabled: false,
        policyVersion: 1,
      });
    }
    expect(await read("relative")).toBeNull();
    expect(await read(`${identifier}#fragment`)).toBeNull();
    const signup = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail(`seed-${resourceSeedMode ?? "default"}`),
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
    const headers = { cookie };
    const patch = async (body: object) => {
      const response = await control({
        action: "resource-update",
        headers,
        params: { identifier },
        body,
      });
      expect(response.status).toBe(200);
      return (await response.json()) as any;
    };
    const admin = await patch({
      name: "Admin",
      accessTokenTtl: 45,
      refreshTokenTtl: 90,
      allowedScopes: ["profile"],
      customClaims: { admin: true },
      signingAlgorithm: "EdDSA",
      metadata: { admin: true },
    });
    const restart = {
      identifier,
      name: "Restart",
      accessTokenTtl: 120,
      allowedScopes: ["email"],
      customClaims: null,
      metadata: null,
      signingAlgorithm: "HS256",
      disabled: false,
    };
    await initialize([restart]);
    const restarted = await read();
    expect(await read(duplicate)).toEqual(duplicateRow);
    expect(restarted.id).toBe(initial.id);
    expect(restarted.createdAt).toBe(initial.createdAt);
    const expected = insertOnly
      ? admin
      : { ...admin, ...restart, signingAlgorithm: admin.signingAlgorithm };
    if (resourceSeedMode === "overwrite") {
      expected.refreshTokenTtl = null;
      expected.signingAlgorithm = null;
      expected.policyVersion = 1;
    }
    const policy = (row: any) => {
      const { id: _id, createdAt: _created, updatedAt: _updated, ...rest } = row;
      return rest;
    };
    expect(policy(restarted)).toEqual(policy(expected));
    await patch({ disabled: true, accessTokenTtl: 33 });
    const made = await control({
      action: "admin-create",
      headers,
      body: {
        client_name: "Seed policy",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "email profile",
        token_endpoint_auth_method: "none",
      },
    });
    expect(made.status).toBe(201);
    const client = (await made.json()) as any;
    const issue = () =>
      control({
        action: "issue-tokens",
        body: {
          clientId: client.client_id,
          grantType: "urn:fixture:server",
          params: { scopes: ["email", "profile"], resources: [identifier] },
        },
      });
    const first = await issue();
    expect(first.status).toBe(insertOnly ? 400 : 200);
    const firstBody = (await first.json()) as any;
    if (insertOnly) {
      expect(firstBody).toEqual({
        error: "invalid_target",
        error_description: `requested resource ${identifier} is disabled`,
      });
    } else {
      expect(firstBody.expires_in).toBe(120);
    }
    const lazy = await read();
    expect(lazy.disabled).toBe(insertOnly);
    expect(lazy.accessTokenTtl).toBe(insertOnly ? 33 : 120);
    await patch({ disabled: true });
    const denied = await issue();
    expect(denied.status).toBe(400);
    expect(await denied.json()).toEqual({
      error: "invalid_target",
      error_description: `requested resource ${identifier} is disabled`,
    });
    await patch({ disabled: false });
    const accepted = await issue();
    expect(accepted.status).toBe(200);
    const issued = (await accepted.json()) as any;
    expect(issued.scope).toBe(insertOnly ? "profile" : "email");
    expect(issued.expires_in).toBe(insertOnly ? 33 : 120);
    const keys = createLocalJWKSet((await (await control({ action: "jwks" })).json()) as any);
    const { payload } = await jwtVerify(issued.access_token, keys, {
      issuer: `${ctx.baseURL}/api/auth`,
      audience: identifier,
    });
    expect(payload.scope).toBe(issued.scope);
    expect(payload.admin).toBe(insertOnly ? true : undefined);
    expect(payload.configured).toBeUndefined();
    results.push({
      resourceSeedMode: resourceSeedMode ?? "default",
      initial: policy(initial),
      duplicate: policy(duplicateRow),
      restarted: policy(restarted),
      lazy: policy(lazy),
      scope: issued.scope,
      expires_in: issued.expires_in,
    });
  }
  const initializeCustom = async () => {
    const response = await control({
      action: "resource-seed-init",
      resources: ["local-resource"],
      customIdentifiers: true,
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ initialized: true });
  };
  await initializeCustom();
  const signup = await control({
    action: "signup",
    body: { email: ctx.uniqueEmail("seed-custom"), name: "Owner", password: "password123" },
  });
  expect(signup.status).toBe(200);
  const headers = {
    cookie: signup.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; "),
  };
  const created = await control({
    action: "admin-create",
    headers,
    body: {
      client_name: "Custom identifiers",
      redirect_uris: ["https://app.fixture.test/callback"],
      scope: "email",
      token_endpoint_auth_method: "none",
    },
  });
  expect(created.status).toBe(201);
  const client = (await created.json()) as any;
  const issue = () =>
    control({
      action: "issue-tokens",
      body: {
        clientId: client.client_id,
        grantType: "urn:fixture:server",
        params: { scopes: ["email"], resources: ["local-resource"] },
      },
    });
  const state = async (failNext = false) =>
    await (await control({ action: "resource-seed-validator", failNext })).json();
  expect(await state(true)).toEqual({ calls: 1 });
  const failed = await issue();
  expect(failed.status).toBe(403);
  expect(await failed.json()).toEqual({ message: "Resource validation denied" });
  const concurrent = await Promise.all([issue(), issue(), issue()]);
  for (const response of concurrent) {
    expect(response.status).toBe(200);
    expect(((await response.json()) as any).scope).toBe("email");
  }
  expect(await state()).toEqual({ calls: 3 });
  await initializeCustom();
  const peer = await issue();
  expect(peer.status).toBe(200);
  expect(((await peer.json()) as any).scope).toBe("email");
  expect(await state()).toEqual({ calls: 5 });
  return ctx.snapshot({ results, validator: await state() });
});
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
