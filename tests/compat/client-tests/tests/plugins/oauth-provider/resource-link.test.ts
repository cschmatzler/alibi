import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Linking a client durably admits its resource and repeated linkage is idempotent",
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
      body: {
        email: ctx.uniqueEmail("resource-link-owner"),
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
        email: ctx.uniqueEmail("resource-link-other"),
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
    const identifier = "https://api.fixture.test/link";
    const resource = await control({
      action: "resource-create",
      headers: { cookie },
      body: { identifier, allowedScopes: ["email"] },
    });
    expect(resource.status).toBe(200);
    const created = await control({
      headers: { cookie },
      body: {
        client_name: "Linked client",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "email",
        token_endpoint_auth_method: "none",
      },
    });
    expect(created.status).toBe(201);
    const client = (await created.json()) as any;
    const id = client.client_id;
    const query = {
      client_id: id,
      response_type: "code",
      redirect_uri: "https://app.fixture.test/callback",
      scope: "email",
      resource: identifier,
      code_challenge: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
      code_challenge_method: "S256",
    };
    const blocked = await control({
      action: "authorize",
      query,
      headers: { accept: "application/json" },
    });
    expect(blocked.status).toBe(200);
    const denied = (await blocked.json()) as any;
    const deniedURL = new URL(denied.url, ctx.baseURL);
    expect(deniedURL.searchParams.get("error")).toBe("invalid_target");
    expect(deniedURL.searchParams.get("error_description")).toBe(
      `client ${id} is not linked to resource(s) ${identifier}`,
    );
    const failures = [];
    for (const [params, headers, status, error] of [
      [{ identifier: "urn:fixture:missing", client_id: id }, { cookie }, 404, "not_found"],
      [{ identifier, client_id: "unknown-client" }, { cookie }, 404, "not_found"],
      [{ identifier, client_id: id }, {}, 401, null],
    ] as const) {
      const r = await control({ action: "resource-link", params, headers });
      expect(r.status).toBe(status);
      const text = await r.text();
      const value = text ? JSON.parse(text) : null;
      if (error) {
        expect(value.error).toBe(error);
      }
      failures.push({ status: r.status, body: value });
    }
    const empty = await control({ action: "resource-links", clientId: id });
    expect(await empty.json()).toEqual([]);
    const hidden = await control({
      action: "resource-http",
      operation: "link",
      identifier,
      clientId: id,
      headers: { cookie },
    });
    expect(await hidden.json()).toEqual({ status: 404 });
    const start = Date.now();
    const linked = await control({
      action: "resource-link",
      params: { identifier: encodeURIComponent(identifier), client_id: encodeURIComponent(id) },
      headers: { cookie: otherCookie },
    });
    expect(linked.status).toBe(200);
    const result = await linked.json();
    expect(result).toEqual({ linked: true });
    const rowsResponse = await control({ action: "resource-links", clientId: id });
    const rows = (await rowsResponse.json()) as any[];
    expect(rows).toHaveLength(1);
    expect(rows[0].clientId).toBe(id);
    expect(rows[0].resourceId).toBe(identifier);
    expect(rows[0].metadata).toBeNull();
    expect(new Date(rows[0].createdAt).getTime()).toBeGreaterThanOrEqual(start);
    expect(new Date(rows[0].createdAt).getTime()).toBeLessThanOrEqual(Date.now());
    const repeated = await control({
      action: "resource-link",
      params: { identifier, client_id: id },
      headers: { cookie },
    });
    expect(repeated.status).toBe(200);
    const duplicate = await repeated.json();
    expect(duplicate).toEqual({ linked: true, alreadyLinked: true });
    const unchanged = await control({ action: "resource-links", clientId: id });
    expect(await unchanged.json()).toEqual(rows);
    const allowed = await control({
      action: "authorize",
      query,
      headers: { accept: "application/json" },
    });
    expect(allowed.status).toBe(200);
    const redirect = (await allowed.json()) as any;
    expect(new URL(redirect.url, ctx.baseURL).pathname).toBe("/login");
    const removed = await control({
      action: "resource-delete",
      foreignKeys: true,
      params: { identifier },
      headers: { cookie },
    });
    expect(await removed.json()).toEqual({ deleted: true });
    const cascaded = await control({ action: "resource-links", clientId: id });
    expect(await cascaded.json()).toEqual([]);
    const stillExists = await control({
      action: "get",
      query: { client_id: id },
      headers: { cookie },
    });
    expect(stillExists.status).toBe(200);
    const { createdAt, ...link } = rows[0];
    return ctx.snapshot({ failures, result, duplicate, link, redirect });
  },
);
