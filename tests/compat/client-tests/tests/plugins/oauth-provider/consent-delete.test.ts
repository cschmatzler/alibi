import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Deleting owned consent requires consent again on subsequent authorization",
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
      body: { email: ctx.uniqueEmail("consent-owner"), name: "Owner", password: "password123" },
    });
    expect(signup.status).toBe(200);
    const owner = (await signup.json()) as any;
    const cookie = signup.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const created = await control({
      headers: { cookie },
      body: {
        client_name: "Consent client",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "email profile",
        token_endpoint_auth_method: "none",
      },
    });
    expect(created.status).toBe(201);
    const id = ((await created.json()) as any).client_id;
    const query = {
      client_id: id,
      response_type: "code",
      redirect_uri: "https://app.fixture.test/callback",
      scope: "email profile",
      state: "consent-state",
      code_challenge: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
      code_challenge_method: "S256",
    };
    const producer = await control({
      action: "authorize",
      query,
      headers: { accept: "application/json" },
    });
    expect(producer.status).toBe(200);
    const signed = new URL(((await producer.json()) as any).url, ctx.baseURL).search.slice(1);
    const accepted = await control({
      action: "consent",
      headers: { cookie },
      body: { accept: true, scope: "email", oauth_query: signed },
    });
    expect(accepted.status).toBe(200);
    const other = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("consent-list-other"),
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
    const listed = await control({ action: "consents", headers: { cookie } });
    expect(listed.status).toBe(200);
    const expected = ((await listed.json()) as any[])[0];
    expect(expected.userId).toBe(owner.user.id);
    const grantQuery = { ...query, scope: "email" };
    const remembered = await control({
      action: "authorize",
      query: grantQuery,
      headers: { cookie, accept: "application/json" },
    });
    expect(remembered.status).toBe(200);
    const beforeRedirect = (await remembered.json()) as any;
    const beforeURL = new URL(beforeRedirect.url);
    expect(beforeURL.host).toBe("app.fixture.test");
    expect(beforeURL.searchParams.get("code")).toMatch(/^[A-Za-z0-9]{32}$/);
    const failures = [];
    for (const [body, headers, status, error] of [
      [{ id: expected.id }, { cookie: otherCookie }, 401, null],
      [{ id: expected.id }, {}, 401, null],
      [{ id: "unknown-consent" }, { cookie }, 404, "not_found"],
      [{ id: "" }, { cookie }, 404, "not_found"],
      [{ id: 42 }, { cookie }, 400, null],
    ] as const) {
      const r = await control({ action: "consent-delete", headers, body });
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
    const unchanged = await control({ action: "consents", headers: { cookie } });
    expect(await unchanged.json()).toEqual([expected]);
    const removed = await control({
      action: "consent-delete",
      headers: { cookie },
      body: { id: expected.id },
    });
    expect(removed.status).toBe(200);
    expect(removed.headers.get("content-type")).toBe("application/json");
    expect(await removed.text()).toBe("");
    const missing = await control({
      action: "consent-get",
      query: { id: expected.id },
      headers: { cookie },
    });
    expect(missing.status).toBe(404);
    expect(await missing.json()).toEqual({ error: "not_found", error_description: "no consent" });
    const repeated = await control({
      action: "consent-delete",
      headers: { cookie },
      body: { id: expected.id },
    });
    expect(repeated.status).toBe(404);
    const after = await control({ action: "consents", headers: { cookie } });
    expect(await after.json()).toEqual([]);
    const reprompt = await control({
      action: "authorize",
      query: grantQuery,
      headers: { cookie, accept: "application/json" },
    });
    expect(reprompt.status).toBe(200);
    const afterRedirect = (await reprompt.json()) as any;
    const url = new URL(afterRedirect.url, ctx.baseURL);
    expect(url.pathname).toBe("/consent");
    expect(url.searchParams.has("code")).toBe(false);
    return ctx.snapshot({ failures, beforeRedirect, afterRedirect });
  },
);
