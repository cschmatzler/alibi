import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Resource creation durably stores policy and admits only enabled resources with allowed scopes",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: unknown) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const signup = await control({
      action: "signup",
      body: { email: ctx.uniqueEmail("resource-owner"), name: "Owner", password: "password123" },
    });
    expect(signup.status).toBe(200);
    const cookie = signup.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const input = {
      identifier: "https://api.fixture.test/metrics",
      name: "Metrics",
      allowedScopes: ["email"],
      accessTokenTtl: 120,
      refreshTokenTtl: 3600,
      signingAlgorithm: "EdDSA",
      metadata: { tenant: "fixture" },
      customClaims: { purpose: "metrics" },
    };
    const start = Date.now();
    const created = await control({ action: "resource-create", headers: { cookie }, body: input });
    expect(created.status).toBe(200);
    const value = (await created.json()) as any;
    expect(value.identifier).toBe(input.identifier);
    expect(value.name).toBe("Metrics");
    expect(value.policyVersion).toBe(1);
    expect(value.disabled).toBe(false);
    expect(value.dpopBoundAccessTokensRequired).toBe(false);
    expect(value.signingKeyId).toBeNull();
    expect(value.createdAt).toBe(value.updatedAt);
    expect(new Date(value.createdAt).getTime()).toBeGreaterThanOrEqual(start);
    expect(new Date(value.createdAt).getTime()).toBeLessThanOrEqual(Date.now());
    const row = await control({ action: "resource-row", identifier: input.identifier });
    expect(await row.json()).toEqual(value);
    const failures = [];
    for (const [body, headers, status, error] of [
      [{ identifier: input.identifier }, { cookie }, 400, "invalid_request"],
      [{ identifier: "/relative" }, { cookie }, 400, "invalid_target"],
      [{ identifier: "https://api.fixture.test/fragment#bad" }, { cookie }, 400, "invalid_target"],
      [{ identifier: "https://api.fixture.test/no-session" }, {}, 401, null],
      [{ identifier: "https://api.fixture.test/ttl", accessTokenTtl: 0 }, { cookie }, 400, null],
      [{ identifier: "https://api.fixture.test/ttl", accessTokenTtl: 1.5 }, { cookie }, 400, null],
      [
        { identifier: "https://api.fixture.test/algorithm", signingAlgorithm: "RS384" },
        { cookie },
        400,
        null,
      ],
    ] as const) {
      const r = await control({ action: "resource-create", headers, body });
      expect(r.status).toBe(status);
      const text = await r.text();
      const result = text ? JSON.parse(text) : null;
      if (error) {
        expect(result.error).toBe(error);
      } else if (status === 400) {
        expect(result.code).toBe("VALIDATION_ERROR");
      }
      failures.push({ status: r.status, body: result });
    }
    const hidden = await control({ action: "resource-http", headers: { cookie }, body: input });
    expect(await hidden.json()).toEqual({ status: 404 });
    const defaultsResponse = await control({
      action: "resource-create",
      headers: { cookie },
      body: { identifier: "urn:fixture:disabled", disabled: true },
    });
    expect(defaultsResponse.status).toBe(200);
    const defaults = (await defaultsResponse.json()) as any;
    expect(defaults.name).toBe("urn:fixture:disabled");
    expect(defaults.allowedScopes).toBeNull();
    expect(defaults.policyVersion).toBe(1);
    const clientResponse = await control({
      headers: { cookie },
      body: {
        client_name: "Resource caller",
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
      scope: "email",
      resource: input.identifier,
      code_challenge: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
      code_challenge_method: "S256",
    };
    const unlinked = await control({
      action: "authorize",
      query,
      headers: { accept: "application/json" },
    });
    expect(unlinked.status).toBe(200);
    const denied = (await unlinked.json()) as any;
    const deniedURL = new URL(denied.url, ctx.baseURL);
    expect(deniedURL.searchParams.get("error")).toBe("invalid_target");
    expect(deniedURL.searchParams.get("error_description")).toBe(
      `client ${client.client_id} is not linked to resource(s) ${input.identifier}`,
    );
    const redirects = [];
    for (const [resource, scope, path, error] of [
      [input.identifier, "email", "/login", null],
      ["urn:fixture:disabled", "email", "/callback", "invalid_target"],
      [input.identifier, "profile", "/callback", "invalid_scope"],
    ] as const) {
      const r = await control({
        action: "authorize",
        mode: "resources-open",
        query: { ...query, resource, scope },
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
    const project = ({ createdAt, updatedAt, ...row }: any) => row;
    return ctx.snapshot({
      created: project(value),
      defaults: project(defaults),
      failures,
      redirects,
    });
  },
);
