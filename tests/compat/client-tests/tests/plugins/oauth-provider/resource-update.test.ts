import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Partial resource updates preserve identity and immediately affect authorization policy",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: unknown) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "resources-open", ...(input as any) }),
      });
    const signup = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("resource-update-owner"),
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
    const other = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("resource-update-other"),
        name: "Other",
        password: "password123",
      },
    });
    expect(other.status).toBe(200);
    const otherCookie = other.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const identifier = "https://api.fixture.test/update";
    const created = await control({
      action: "resource-create",
      headers: { cookie },
      body: {
        identifier,
        name: "Original",
        allowedScopes: ["email"],
        accessTokenTtl: 120,
        refreshTokenTtl: 3600,
        signingAlgorithm: "EdDSA",
        customClaims: { original: true },
        metadata: { tenant: "old" },
      },
    });
    expect(created.status).toBe(200);
    const original = (await created.json()) as any;
    const patch = {
      name: "Updated",
      allowedScopes: ["profile"],
      accessTokenTtl: null,
      customClaims: null,
      metadata: { tenant: "new" },
      identifier: "urn:ignored:rename",
      policyVersion: 99,
    };
    const start = Date.now();
    const changed = await control({
      action: "resource-update",
      params: { identifier: encodeURIComponent(identifier) },
      headers: { cookie: otherCookie },
      body: patch,
    });
    expect(changed.status).toBe(200);
    const updated = (await changed.json()) as any;
    expect(updated.id).toBe(original.id);
    expect(updated.identifier).toBe(identifier);
    expect(updated.createdAt).toBe(original.createdAt);
    expect(updated.policyVersion).toBe(1);
    expect(updated.name).toBe("Updated");
    expect(updated.accessTokenTtl).toBeNull();
    expect(updated.customClaims).toBeNull();
    expect(updated.allowedScopes).toEqual(["profile"]);
    expect(updated.metadata).toEqual({ tenant: "new" });
    expect(updated.refreshTokenTtl).toBe(original.refreshTokenTtl);
    expect(updated.signingAlgorithm).toBe(original.signingAlgorithm);
    expect(new Date(updated.updatedAt).getTime()).toBeGreaterThanOrEqual(start);
    expect(new Date(updated.updatedAt).getTime()).toBeLessThanOrEqual(Date.now());
    const loaded = await control({
      action: "resource-get",
      params: { identifier },
      headers: { cookie },
    });
    expect(await loaded.json()).toEqual(updated);
    const failures = [];
    for (const [params, body, headers, status, error] of [
      [{ identifier: "urn:fixture:missing" }, { name: "Unknown" }, { cookie }, 404, "not_found"],
      [{ identifier }, { name: "Unauthorized" }, {}, 401, null],
      [{ identifier }, { allowedScopes: [true] }, { cookie }, 400, null],
      [{ identifier }, { accessTokenTtl: -1 }, { cookie }, 400, null],
    ] as const) {
      const r = await control({ action: "resource-update", params, headers, body });
      expect(r.status).toBe(status);
      const text = await r.text();
      const value = text ? JSON.parse(text) : null;
      if (error) {
        expect(value.error).toBe(error);
      } else if (status === 400) {
        expect(value.code).toBe("VALIDATION_ERROR");
      }
      failures.push({ status: r.status, body: value });
    }
    const unchanged = await control({
      action: "resource-get",
      params: { identifier },
      headers: { cookie },
    });
    expect(await unchanged.json()).toEqual(updated);
    const hidden = await control({
      action: "resource-http",
      operation: "update",
      identifier,
      headers: { cookie },
      body: patch,
    });
    expect(await hidden.json()).toEqual({ status: 404 });
    const clientResponse = await control({
      headers: { cookie },
      body: {
        client_name: "Policy observer",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "email profile",
        token_endpoint_auth_method: "none",
      },
    });
    expect(clientResponse.status).toBe(201);
    const client = (await clientResponse.json()) as any;
    const query = {
      client_id: client.client_id,
      response_type: "code",
      redirect_uri: "https://app.fixture.test/callback",
      scope: "profile",
      resource: identifier,
      code_challenge: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
      code_challenge_method: "S256",
    };
    const redirects = [];
    for (const [scope, path, error] of [
      ["email", "/callback", "invalid_scope"],
      ["profile", "/login", null],
    ] as const) {
      const r = await control({
        action: "authorize",
        query: { ...query, scope },
        headers: { accept: "application/json" },
      });
      expect(r.status).toBe(200);
      const result = (await r.json()) as any;
      const url = new URL(result.url, ctx.baseURL);
      expect(url.pathname).toBe(path);
      if (error) {
        expect(url.searchParams.get("error")).toBe(error);
      }
      redirects.push(result);
    }
    const disabledResponse = await control({
      action: "resource-update",
      params: { identifier },
      headers: { cookie },
      body: { disabled: true, metadata: null },
    });
    expect(disabledResponse.status).toBe(200);
    const disabled = (await disabledResponse.json()) as any;
    expect(disabled.disabled).toBe(true);
    expect(disabled.metadata).toBeNull();
    expect(disabled.name).toBe("Updated");
    const r = await control({
      action: "authorize",
      query,
      headers: { accept: "application/json" },
    });
    expect(r.status).toBe(200);
    const rejection = (await r.json()) as any;
    expect(new URL(rejection.url, ctx.baseURL).searchParams.get("error")).toBe("invalid_target");
    redirects.push(rejection);
    const project = ({ createdAt, updatedAt, ...row }: any) => row;
    return ctx.snapshot({
      updated: project(updated),
      disabled: project(disabled),
      failures,
      redirects,
    });
  },
);
