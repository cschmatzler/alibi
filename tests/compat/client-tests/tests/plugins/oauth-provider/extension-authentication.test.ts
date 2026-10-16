import { createHash, createHmac } from "node:crypto";

import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "Extension authentication dispatches aliases and preserves provider client admission",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: object) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "extension-auth", ...input }),
      });
    const proof = (clientId: string, audience: string, suppliedClientId?: string) => {
      const payload = Buffer.from(
        JSON.stringify({
          clientId,
          audience,
          suppliedClientId,
          confirmation: { "x5t#S256": "application-certificate" },
        }),
      ).toString("base64url");
      return `${payload}.${createHmac("sha256", "fixture-application-assertion-key").update(payload).digest("base64url")}`;
    };
    const validation = [];
    for (const [entries, message] of [
      [
        [{ method: " ", types: ["urn:fixture:proof"] }],
        "OAuth Provider extension token_endpoint_auth_method cannot be empty",
      ],
      [
        [{ method: "none", types: ["urn:fixture:proof"] }],
        "OAuth Provider extension token_endpoint_auth_method is reserved: none",
      ],
      [
        [{ method: "custom", types: [] }],
        "OAuth Provider extension client_assertion_type list cannot be empty for custom",
      ],
      [
        [{ method: "custom", types: null }],
        "OAuth Provider extension client_assertion_type must be an absolute URI: custom",
      ],
      [
        [{ method: "custom", types: [" "] }],
        "OAuth Provider extension client_assertion_type cannot be empty",
      ],
      [
        [{ method: "custom", types: ["urn:ietf:params:oauth:client-assertion-type:jwt-bearer"] }],
        "OAuth Provider extension client_assertion_type is reserved: urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      ],
      [
        [
          { method: "first", types: ["urn:fixture:proof"] },
          { method: "first", types: ["urn:fixture:other"] },
        ],
        'OAuth Provider extensions register token_endpoint_auth_method "first" more than once. Extension contributions must be disjoint.',
      ],
      [
        [
          { method: "first", types: ["urn:fixture:proof"] },
          { method: "second", types: ["urn:fixture:proof"] },
        ],
        'OAuth Provider extensions register client_assertion_type "urn:fixture:proof" more than once. Extension contributions must be disjoint.',
      ],
      [[{ method: "urn:fixture:default", types: null }], null],
    ] as const) {
      const checked = await control({ action: "extension-auth-validation", entries });
      expect(checked.status).toBe(200);
      const result = await checked.json();
      expect(result).toEqual(message ? { valid: false, message } : { valid: true });
      validation.push(result);
    }
    const signup = await control({
      action: "signup",
      body: { email: ctx.uniqueEmail("extension-auth"), name: "Owner", password: "password123" },
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
        client_name: "Extension client",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "email offline_access",
        grant_types: ["authorization_code", "refresh_token"],
        token_endpoint_auth_method: "application_assertion",
        skip_consent: true,
      },
    });
    expect(created.status).toBe(201);
    const client = (await created.json()) as any;
    expect(client).not.toHaveProperty("client_secret");
    const metadata = await control({ action: "grant-metadata" });
    expect(metadata.status).toBe(200);
    const document = (await metadata.json()) as any;
    for (const key of [
      "token_endpoint_auth_methods_supported",
      "introspection_endpoint_auth_methods_supported",
      "revocation_endpoint_auth_methods_supported",
    ]) {
      expect(document[key]).toContain("application_assertion");
    }
    const authenticate = (
      clientId: string,
      type: string,
      audience = `${ctx.baseURL}/api/auth/fixture/authenticate-client`,
      suppliedClientId?: string,
    ) =>
      control({
        action: "authenticate-client",
        body: {
          extensionAuth: true,
          client_assertion_type: type,
          client_assertion: proof(clientId, audience, suppliedClientId),
          ...(suppliedClientId ? { client_id: suppliedClientId } : {}),
          requestedScopes: ["email"],
          boundGrant: "authorization_code",
        },
      });
    const results = [];
    for (const alias of ["urn:fixture:client-assertion", "urn:fixture:client-alias"]) {
      const authenticated = await authenticate(client.client_id, alias);
      expect(authenticated.status).toBe(200);
      const result = (await authenticated.json()) as any;
      expect(result.method).toBe("application_assertion");
      expect(result.clientId).toBe(client.client_id);
      expect(result.confirmation).toEqual({ "x5t#S256": "application-certificate" });
      results.push(result);
    }
    const supplied = await authenticate(
      client.client_id,
      "urn:fixture:client-assertion",
      undefined,
      client.client_id,
    );
    expect(supplied.status).toBe(200);
    expect(((await supplied.json()) as any).clientId).toBe(client.client_id);
    const forged = await control({
      action: "authenticate-client",
      body: {
        extensionAuth: true,
        client_assertion_type: "urn:fixture:client-assertion",
        client_assertion: proof(
          client.client_id,
          `${ctx.baseURL}/api/auth/fixture/authenticate-client`,
        ).replace(/.$/, "!"),
      },
    });
    expect(forged.status).toBe(400);
    expect(await forged.json()).toEqual({
      error: "invalid_client",
      error_description: "application assertion rejected",
    });
    for (const [id, audience, error, description] of [
      [
        client.client_id,
        `${ctx.baseURL}/api/auth/wrong`,
        "invalid_client",
        "application assertion rejected",
      ],
      [
        "missing-client",
        `${ctx.baseURL}/api/auth/fixture/authenticate-client`,
        "invalid_client",
        "missing client",
      ],
    ]) {
      const denied = await authenticate(id, "urn:fixture:client-assertion", audience);
      expect(denied.status).toBe(400);
      expect(await denied.json()).toEqual({ error, error_description: description });
    }
    const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const grant = await control({
      action: "authorize",
      headers: { cookie, accept: "application/json" },
      query: {
        client_id: client.client_id,
        response_type: "code",
        redirect_uri: "https://app.fixture.test/callback",
        scope: "email offline_access",
        code_challenge: challenge,
        code_challenge_method: "S256",
      },
    });
    expect(grant.status).toBe(200);
    const code = new URL(((await grant.json()) as any).url).searchParams.get("code");
    const token = await control({
      action: "protocol-http",
      path: "/oauth2/token",
      method: "POST",
      body: {
        grant_type: "authorization_code",
        code,
        code_verifier: verifier,
        redirect_uri: "https://app.fixture.test/callback",
        client_assertion_type: "urn:fixture:client-alias",
        client_assertion: proof(client.client_id, `${ctx.baseURL}/api/auth/oauth2/token`),
      },
    });
    expect(token.status).toBe(200);
    const tokens = (await token.json()) as any;
    expect(tokens.access_token).toMatch(/^[A-Za-z]{32}$/);
    expect(tokens.refresh_token).toMatch(/^[A-Za-z]{32}$/);
    const inspected = await control({
      action: "introspect",
      body: {
        token: tokens.access_token,
        client_assertion_type: "urn:fixture:client-assertion",
        client_assertion: proof(client.client_id, `${ctx.baseURL}/api/auth/oauth2/introspect`),
      },
    });
    expect(inspected.status).toBe(200);
    expect(((await inspected.json()) as any).active).toBe(true);
    const refreshed = await control({
      action: "protocol-http",
      path: "/oauth2/token",
      method: "POST",
      body: {
        grant_type: "refresh_token",
        refresh_token: tokens.refresh_token,
        client_assertion_type: "urn:fixture:client-assertion",
        client_assertion: proof(client.client_id, `${ctx.baseURL}/api/auth/oauth2/token`),
      },
    });
    expect(refreshed.status).toBe(200);
    const fresh = (await refreshed.json()) as any;
    expect(fresh.access_token).toMatch(/^[A-Za-z]{32}$/);
    const revoked = await control({
      action: "revoke",
      body: {
        token: fresh.access_token,
        client_assertion_type: "urn:fixture:client-alias",
        client_assertion: proof(client.client_id, `${ctx.baseURL}/api/auth/oauth2/revoke`),
      },
    });
    expect(revoked.status).toBe(200);
    const inactive = await control({
      action: "introspect",
      body: {
        token: fresh.access_token,
        client_assertion_type: "urn:fixture:client-assertion",
        client_assertion: proof(client.client_id, `${ctx.baseURL}/api/auth/oauth2/introspect`),
      },
    });
    expect(inactive.status).toBe(200);
    expect(await inactive.json()).toEqual({ active: false });
    return ctx.snapshot({
      validation,
      results,
      methods: document.token_endpoint_auth_methods_supported,
    });
  },
);
