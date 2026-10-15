import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Deleting provider resource policy removes catalog lookup and authorization admission",
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
        email: ctx.uniqueEmail("resource-delete-owner"),
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
        email: ctx.uniqueEmail("resource-delete-other"),
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
    const identifier = "https://api.fixture.test/delete";
    const created = await control({
      action: "resource-create",
      headers: { cookie },
      body: { identifier, allowedScopes: ["email"] },
    });
    expect(created.status).toBe(200);
    const resource = await created.json();
    const clientResponse = await control({
      headers: { cookie },
      body: {
        client_name: "Deletion observer",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "email",
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
      resource: identifier,
      code_challenge: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
      code_challenge_method: "S256",
    };
    const admitted = await control({
      action: "authorize",
      query,
      headers: { accept: "application/json" },
    });
    expect(admitted.status).toBe(200);
    const beforeRedirect = (await admitted.json()) as any;
    expect(new URL(beforeRedirect.url, ctx.baseURL).pathname).toBe("/login");
    const failures = [];
    for (const [params, headers, status, error] of [
      [{ identifier: "urn:fixture:missing" }, { cookie }, 404, "not_found"],
      [{ identifier }, {}, 401, null],
    ] as const) {
      const r = await control({ action: "resource-delete", params, headers });
      expect(r.status).toBe(status);
      const text = await r.text();
      const value = text ? JSON.parse(text) : null;
      if (error) {
        expect(value.error).toBe(error);
      }
      failures.push({ status: r.status, body: value });
    }
    const unchanged = await control({
      action: "resource-get",
      params: { identifier },
      headers: { cookie },
    });
    expect(await unchanged.json()).toEqual(resource);
    const hidden = await control({
      action: "resource-http",
      operation: "delete",
      identifier,
      headers: { cookie },
    });
    expect(await hidden.json()).toEqual({ status: 404 });
    const removed = await control({
      action: "resource-delete",
      params: { identifier: encodeURIComponent(identifier) },
      headers: { cookie: otherCookie },
    });
    expect(removed.status).toBe(200);
    const result = await removed.json();
    expect(result).toEqual({ deleted: true });
    const missing = await control({
      action: "resource-get",
      params: { identifier },
      headers: { cookie },
    });
    expect(missing.status).toBe(404);
    expect(await missing.json()).toEqual({
      error: "not_found",
      error_description: `resource ${identifier} not found`,
    });
    const repeated = await control({
      action: "resource-delete",
      params: { identifier },
      headers: { cookie },
    });
    expect(repeated.status).toBe(404);
    const listed = await control({ action: "resource-list", headers: { cookie } });
    expect(await listed.json()).toEqual([]);
    const rejected = await control({
      action: "authorize",
      query,
      headers: { accept: "application/json" },
    });
    expect(rejected.status).toBe(200);
    const afterRedirect = (await rejected.json()) as any;
    const url = new URL(afterRedirect.url, ctx.baseURL);
    expect(url.pathname).toBe("/callback");
    expect(url.searchParams.get("error")).toBe("invalid_target");
    expect(url.searchParams.get("error_description")).toBe(
      `requested resource ${identifier} is not configured`,
    );
    return ctx.snapshot({ failures, result, beforeRedirect, afterRedirect });
  },
);
