import { createHash } from "node:crypto";

import { createLocalJWKSet, jwtVerify } from "jose";
import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "Trusted metadata-document persistence owns creation, replacement, and subsequent authorization",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: object) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        redirect: "manual",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "resource-seed", ...input }),
      });
    const a = "https://api.fixture.test/cimd/a";
    const b = "https://api.fixture.test/cimd/b";
    const disabled = "https://api.fixture.test/cimd/disabled";
    const clientId = "https://client.fixture.test/metadata.json";
    const clientDiscoveryId = "trusted-document-owner";
    const initialize = async (defaults: string[], scopes = ["email"], allowed = ["profile"]) => {
      const response = await control({
        action: "resource-seed-init",
        registrationResources: true,
        metadataDocuments: true,
        resources: [a, b, { identifier: disabled, disabled: true }],
        options: {
          clientRegistrationDefaultResources: defaults,
          clientRegistrationAllowedResources: [b],
          clientRegistrationDefaultScopes: scopes,
          clientRegistrationAllowedScopes: allowed,
        },
      });
      expect(response.status).toBe(200);
    };
    await initialize([a, a]);
    const metadata = {
      client_id: clientId,
      redirect_uris: ["https://app.fixture.test/callback"],
      client_name: "Remote",
      logo_uri: "https://client.fixture.test/logo",
      application_type: "web",
      scope: "email",
      require_pkce: true,
      grant_types: ["authorization_code", "future_grant"],
      jwks_uri: "https://client.fixture.test/jwks",
      client_secret: "ignored-secret",
      client_secret_expires_at: 99,
      user_id: "forged",
      reference_id: "forged",
      disabled: true,
      skip_consent: false,
      enable_end_session: true,
      resources: [b],
      unknown_root: "discarded",
      metadata: {
        custom: { version: 1 },
        client_discovery_id: "opaque-not-owner",
        clientId: "forged",
        resources: ["forged"],
        metadata: { nested: "reserved" },
      },
    };
    const register = (patch: object = {}, extra: object = {}) =>
      control({
        action: "cimd-register",
        clientId,
        clientDiscoveryId,
        metadata: { ...metadata, ...patch },
        ...extra,
      });
    const firstResponse = await register();
    const first = (await firstResponse.json()) as any;
    expect(firstResponse.status, `${ctx.baseURL}:${JSON.stringify(first)}`).toBe(200);
    expect(first.created).toBe(true);
    expect(first.clientSecret).toBeNull();
    expect(first.client.clientDiscoveryId).toBe(clientDiscoveryId);
    expect(first.client.clientId).toBe(clientId);
    expect(first.client.scopes).toEqual(["email", "profile"]);
    expect(first.resources).toEqual([a]);
    const row = async (id = clientId) =>
      (await (await control({ action: "row", clientId: id, raw: true })).json()) as any;
    const links = async () =>
      (await (await control({ action: "resource-links", clientId })).json()) as any[];
    const initial = await row();
    expect(initial.clientSecret).toBeNull();
    expect(initial.userId).toBeNull();
    expect(initial.referenceId).toBeNull();
    expect(initial.disabled).toBe(false);
    expect(initial.clientCredentialsScopes).toEqual([]);
    expect(initial.dpopBoundAccessTokens).toBe(false);
    expect(initial.metadata).toEqual({
      custom: { version: 1 },
      client_discovery_id: "opaque-not-owner",
    });
    expect(initial).not.toHaveProperty("unknown_root");
    expect(initial).not.toHaveProperty("resources");
    const initialLinks = await links();
    expect(initialLinks.map((link) => link.resourceId)).toEqual([a]);
    const rejections = [];
    for (const [patch, extra, error, description] of [
      [
        { backchannel_logout_uri: "https://logout.fixture.test/target" },
        {},
        "invalid_client_metadata",
        "Client ID Metadata Documents cannot register a back-channel logout target",
      ],
      [
        { backchannel_logout_session_required: false },
        {},
        "invalid_client_metadata",
        "Client ID Metadata Documents cannot register a back-channel logout target",
      ],
      [
        { token_endpoint_auth_method: "client_secret_basic" },
        {},
        "invalid_client_metadata",
        "Client ID Metadata Document clients cannot use a shared secret",
      ],
      [
        { require_pkce: false },
        {},
        "invalid_client_metadata",
        "pkce is required for registered clients.",
      ],
      [{ scope: "openid" }, {}, "invalid_scope", "cannot request scope openid"],
      [
        { grant_types: ["future_grant"] },
        {},
        "invalid_client_metadata",
        "no mutually supported grant_type among future_grant",
      ],
      [
        { grant_types: [] },
        {},
        "invalid_client_metadata",
        "grant_types must contain at least one grant type",
      ],
      [
        { application_type: "other" },
        {},
        "invalid_client_metadata",
        "application_type must be web or native",
      ],
      [
        { subject_type: "other" },
        {},
        "invalid_client_metadata",
        'subject_type must be "public" or "pairwise"',
      ],
      [
        { jwks: { keys: [] }, jwks_uri: undefined },
        {},
        "invalid_client_metadata",
        "jwks must be an RFC 7517 JWK Set object with a non-empty keys array",
      ],
      [
        { jwks_uri: "https://other.fixture.test/jwks" },
        {},
        "invalid_client_metadata",
        "jwks_uri must belong to a trusted origin or the Client ID Metadata Document origin",
      ],
      [
        {},
        { clientDiscoveryId: "different-owner" },
        "invalid_client",
        "client_id is already owned by a different registration source",
      ],
    ] as const) {
      const response = await register(patch, { existing: true, ...extra });
      const value = await response.json();
      expect(response.status).toBe(400);
      expect(value).toEqual({ error, error_description: description });
      expect(await row()).toEqual(initial);
      expect(await links()).toEqual(initialLinks);
      rejections.push(value);
    }
    // A stale-create collision goes through the real unique violation and one bounded retry.
    const collision = await register();
    const retried = (await collision.json()) as any;
    expect(collision.status).toBe(200);
    expect(retried.created).toBe(false);
    expect(retried.client.id).toBe(first.client.id);
    expect(await links()).toEqual(initialLinks);
    const privateKey = await register(
      { token_endpoint_auth_method: "private_key_jwt" },
      { existing: true },
    );
    expect(privateKey.status).toBe(200);
    expect(((await privateKey.json()) as any).clientSecret).toBeNull();
    expect((await row()).tokenEndpointAuthMethod).toBe("private_key_jwt");
    expect((await row()).clientSecret).toBeNull();
    const extensionUpdates = [];
    for (const [extension, expected] of [
      [
        { custom: { version: 2 }, other: false, client_secret: "forged" },
        { custom: { version: 2 }, other: false },
      ],
      [null, { custom: { version: 2 }, other: false }],
      [{}, { custom: { version: 2 }, other: false }],
      [
        { clientId: "forged", resources: [], metadata: {} },
        { custom: { version: 2 }, other: false },
      ],
      [{ final: [1, null, true] }, { final: [1, null, true] }],
    ] as const) {
      const response = await register({ metadata: extension }, { existing: true });
      expect(response.status).toBe(200);
      const stored = await row();
      expect(stored.metadata).toEqual(expected);
      expect(stored.clientDiscoveryId).toBe(clientDiscoveryId);
      expect(stored.clientSecret).toBeNull();
      extensionUpdates.push(stored.metadata);
    }
    await control({
      action: "cimd-operator",
      clientId,
      update: {
        disabled: true,
        skipConsent: true,
        enableEndSession: false,
        clientCredentialsScopes: ["operator-scope"],
      },
    });
    await initialize([b]);
    const replacement = {
      client_id: clientId,
      redirect_uris: ["http://127.0.0.1/callback"],
      grant_types: ["authorization_code", "future_grant"],
      disabled: false,
      skip_consent: false,
      enable_end_session: true,
    };
    const updatedResponse = await control({
      action: "cimd-register",
      clientId,
      clientDiscoveryId,
      existing: true,
      metadata: replacement,
    });
    const updated = (await updatedResponse.json()) as any;
    expect(updatedResponse.status).toBe(200);
    expect(updated.created).toBe(false);
    expect(updated.client.id).toBe(first.client.id);
    expect(updated.resources).toEqual([b]);
    const stored = await row();
    expect(stored.createdAt).toEqual(initial.createdAt);
    expect(stored.disabled).toBe(true);
    expect(stored.skipConsent).toBe(true);
    expect(stored.enableEndSession).toBe(false);
    expect(stored.clientCredentialsScopes).toEqual(["operator-scope"]);
    expect(stored.applicationType).toBeNull();
    // Adapter update filtering retains undefined metadata fields; do not assume deletion.
    expect(stored.name).toBe("Remote");
    expect(stored.icon).toBe(initial.icon);
    expect(stored.jwksUri).toBe(initial.jwksUri);
    expect(stored.requirePKCE).toBe(true);
    expect(stored.metadata).toEqual({ final: [1, null, true] });
    const additive = await links();
    expect(additive.map((link) => link.resourceId).sort()).toEqual([a, b]);
    expect(additive.find((link) => link.resourceId === a)).toEqual(initialLinks[0]);
    await initialize([], [], []);
    const emptyResponse = await control({
      action: "cimd-register",
      clientId,
      clientDiscoveryId,
      existing: true,
      metadata: replacement,
    });
    const empty = (await emptyResponse.json()) as any;
    expect(empty.resources).toEqual([]);
    expect(empty.client.scopes).toEqual([""]);
    expect(await links()).toEqual(additive);
    await initialize([disabled]);
    const invalidDefault = await control({
      action: "cimd-register",
      clientId,
      clientDiscoveryId,
      existing: true,
      metadata: replacement,
    });
    expect(invalidDefault.status).toBe(400);
    expect(await invalidDefault.json()).toEqual({
      error: "invalid_target",
      error_description: `requested resource ${disabled} is disabled`,
    });
    expect(await links()).toEqual(additive);
    // Restore capabilities, then use the persisted client through actual authorization and code redemption.
    await initialize([b]);
    await control({
      action: "cimd-operator",
      clientId,
      update: { disabled: false, skipConsent: false },
    });
    await control({
      action: "cimd-register",
      clientId,
      clientDiscoveryId,
      existing: true,
      metadata: { ...replacement, metadata: metadata.metadata },
    });
    expect((await row()).metadata).toEqual({
      custom: { version: 1 },
      client_discovery_id: "opaque-not-owner",
    });
    expect((await row()).clientDiscoveryId).toBe(clientDiscoveryId);
    expect(await (await control({ action: "consent-row", clientId })).json()).toEqual([]);
    const signup = await control({
      action: "signup",
      body: { email: ctx.uniqueEmail("cimd"), name: "Document user", password: "password123" },
    });
    expect(signup.status).toBe(200);
    const signedUp = (await signup.json()) as any;
    const cookie = signup.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const call = (input: object) => control({ headers: { cookie }, ...input });
    let managedId = "";
    const callbackReceipts = [];
    for (const source of ["managed-create", "managed-update", "document"]) {
      const extensions = {
        custom: { version: source === "managed-update" ? 2 : 1 },
        client_discovery_id: "opaque-not-owner",
      };
      if (source === "managed-create") {
        const response = await call({
          action: "admin-create",
          body: {
            redirect_uris: ["https://app.fixture.test/callback"],
            scope: "email profile",
            token_endpoint_auth_method: "none",
            metadata: { ...extensions, clientDiscoveryId: "forged", skip_consent: true },
          },
        });
        const created = (await response.json()) as any;
        expect(response.status, JSON.stringify(created)).toBe(201);
        expect(created.client_discovery_id).toBe("opaque-not-owner");
        managedId = created.client_id;
      } else if (source === "managed-update") {
        const response = await call({
          action: "admin-update",
          body: {
            client_id: managedId,
            update: {
              metadata: { ...extensions, clientDiscoveryId: "forged", skip_consent: true },
            },
          },
        });
        expect(response.status).toBe(200);
        expect(((await response.json()) as any).client_discovery_id).toBe("opaque-not-owner");
      }
      const grantClientId = source === "document" ? clientId : managedId;
      const redirectUri =
        source === "document" ? "http://127.0.0.1/callback" : "https://app.fixture.test/callback";
      const physical = await row(grantClientId);
      expect(physical.metadata).toEqual(extensions);
      expect(physical.clientDiscoveryId).toBe(source === "document" ? clientDiscoveryId : null);
      if (source !== "document") {
        const response = await call({ action: "get", query: { client_id: grantClientId } });
        expect(response.status).toBe(200);
        const read = (await response.json()) as any;
        expect(read.client_discovery_id).toBe("opaque-not-owner");
        expect(read.custom).toEqual(extensions.custom);
      }
      const verifier = "cimd-verifier-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP";
      const challenge = createHash("sha256").update(verifier).digest("base64url");
      const authorization = await call({
        action: "authorize",
        headers: { cookie, accept: "application/json" },
        query: {
          client_id: grantClientId,
          redirect_uri: redirectUri,
          response_type: "code",
          scope: "email",
          resource: b,
          prompt: "consent",
          code_challenge: challenge,
          code_challenge_method: "S256",
        },
      });
      expect(authorization.status).toBe(200);
      const target = new URL(((await authorization.json()) as any).url, ctx.baseURL);
      expect(target.pathname).toBe("/consent");
      const consent = await call({
        action: "consent",
        body: { accept: true, oauth_query: target.search.slice(1) },
      });
      expect(consent.status).toBe(200);
      const code = new URL(((await consent.json()) as any).url).searchParams.get("code");
      expect(code).toMatch(/^[a-zA-Z0-9]{32}$/);
      const tokenResponse = await call({
        action: "token",
        body: {
          client_id: grantClientId,
          grant_type: "authorization_code",
          redirect_uri: redirectUri,
          code,
          code_verifier: verifier,
        },
      });
      const token = (await tokenResponse.json()) as any;
      expect(tokenResponse.status, JSON.stringify(token)).toBe(200);
      const keys = createLocalJWKSet((await (await call({ action: "jwks" })).json()) as any);
      const { payload } = await jwtVerify(token.access_token, keys, { audience: b });
      expect(payload.document_metadata).toEqual(extensions);
      expect(payload.client_id).toBe(grantClientId);
      expect(payload.sub).toBe(signedUp.user.id);
      expect(payload.scope).toBe("email");
      expect(payload.aud).toBe(b);
      callbackReceipts.push({
        source,
        physical,
        metadata: payload.document_metadata,
        scope: token.scope,
        audience: payload.aud,
      });
    }
    const consents = (await (await call({ action: "consent-row", clientId })).json()) as any[];
    expect(consents).toHaveLength(1);
    expect(consents[0].clientId).toBe(clientId);
    return {
      first,
      initial,
      initialLinks,
      extensionUpdates,
      rejections,
      retried,
      updated,
      stored,
      additive,
      empty,
      callbackReceipts,
      consents,
    };
  },
);
