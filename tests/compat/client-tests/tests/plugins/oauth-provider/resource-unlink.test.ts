import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Unlinking revokes only the selected membership and remains idempotent for absent pairs",
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
        email: ctx.uniqueEmail("resource-unlink-owner"),
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
        email: ctx.uniqueEmail("resource-unlink-other"),
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
    const identifier = "https://api.fixture.test/unlink";
    const secondary = "urn:fixture:still-linked";
    for (const resource of [identifier, secondary]) {
      const r = await control({
        action: "resource-create",
        headers: { cookie },
        body: { identifier: resource, allowedScopes: ["email"] },
      });
      expect(r.status).toBe(200);
    }
    const ids = [];
    for (const name of ["Unlinked client", "Other linked client"]) {
      const r = await control({
        headers: { cookie },
        body: {
          client_name: name,
          redirect_uris: ["https://app.fixture.test/callback"],
          scope: "email",
          token_endpoint_auth_method: "none",
        },
      });
      expect(r.status).toBe(201);
      ids.push(((await r.json()) as any).client_id);
    }
    const id = ids[0];
    const secondId = ids[1];
    for (const [resource, client] of [
      [identifier, id],
      [secondary, id],
      [identifier, secondId],
    ]) {
      const r = await control({
        action: "resource-link",
        params: { identifier: resource, client_id: client },
        headers: { cookie },
      });
      expect(r.status).toBe(200);
      expect(await r.json()).toEqual({ linked: true });
    }
    const initial = await control({ action: "resource-links", clientId: id });
    const rows = (await initial.json()) as any[];
    expect(rows).toHaveLength(2);
    const secondInitial = await control({ action: "resource-links", clientId: secondId });
    const secondRows = (await secondInitial.json()) as any[];
    const query = {
      client_id: id,
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
    const redirect = (await admitted.json()) as any;
    expect(new URL(redirect.url, ctx.baseURL).pathname).toBe("/login");
    const denied = await control({
      action: "resource-unlink",
      params: { identifier, client_id: id },
    });
    expect(denied.status).toBe(401);
    expect(await denied.text()).toBe("");
    const unchanged = await control({ action: "resource-links", clientId: id });
    expect(await unchanged.json()).toEqual(rows);
    const hidden = await control({
      action: "resource-http",
      operation: "unlink",
      identifier,
      clientId: id,
      headers: { cookie },
    });
    expect(await hidden.json()).toEqual({ status: 404 });
    const r = await control({
      action: "resource-unlink",
      params: { identifier: encodeURIComponent(identifier), client_id: encodeURIComponent(id) },
      headers: { cookie: otherCookie },
    });
    expect(r.status).toBe(200);
    const result = await r.json();
    expect(result).toEqual({ unlinked: true });
    const remainingResponse = await control({ action: "resource-links", clientId: id });
    const remaining = (await remainingResponse.json()) as any[];
    expect(remaining).toEqual(rows.filter((row) => row.resourceId === secondary));
    const otherRemaining = await control({ action: "resource-links", clientId: secondId });
    expect(await otherRemaining.json()).toEqual(secondRows);
    const repeated = [];
    for (const params of [
      { identifier, client_id: id },
      { identifier: "urn:fixture:missing", client_id: "missing-client" },
    ]) {
      const r = await control({ action: "resource-unlink", params, headers: { cookie } });
      expect(r.status).toBe(200);
      const value = await r.json();
      expect(value).toEqual({ unlinked: true });
      repeated.push(value);
    }
    const rejected = await control({
      action: "authorize",
      query,
      headers: { accept: "application/json" },
    });
    expect(rejected.status).toBe(200);
    const body = (await rejected.json()) as any;
    const url = new URL(body.url, ctx.baseURL);
    expect(url.searchParams.get("error")).toBe("invalid_target");
    expect(url.searchParams.get("error_description")).toBe(
      `client ${id} is not linked to resource(s) ${identifier}`,
    );
    const stable = await control({ action: "resource-links", clientId: id });
    expect(await stable.json()).toEqual(remaining);
    return ctx.snapshot({
      result,
      repeated,
      redirect,
      remaining: remaining.map(({ createdAt, ...row }) => row),
      other: secondRows.map(({ createdAt, ...row }) => row),
      denied: { error: url.searchParams.get("error") },
    });
  },
);
