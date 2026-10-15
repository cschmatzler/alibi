import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Consent retrieval preserves the owned grant and rejects foreign ownership",
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
    const results = [];
    for (const [query, headers, status, error, description] of [
      [{ id: expected.id }, { cookie }, 200, null, null],
      [{ id: expected.id }, { cookie: otherCookie }, 401, null, null],
      [{ id: expected.id }, {}, 401, null, null],
      [{ id: "unknown-consent" }, { cookie }, 404, "not_found", "no consent"],
      [{ id: "" }, { cookie }, 404, "not_found", "missing id parameter"],
      [{ id: 42 }, { cookie }, 400, null, null],
    ] as const) {
      const r = await control({ action: "consent-get", query, headers });
      expect(r.status).toBe(status);
      const text = await r.text();
      const value = text ? JSON.parse(text) : null;
      if (status === 200) {
        expect(value).toEqual(expected);
        expect(value.clientId).toBe(id);
        expect(value.userId).toBe(owner.user.id);
        expect(value.scopes).toEqual(["email"]);
      }
      if (error) {
        expect(value).toEqual({ error, error_description: description });
      }
      if (status === 400) {
        expect(value.code).toBe("VALIDATION_ERROR");
      }
      if (status === 200) {
        const { createdAt, updatedAt, ...row } = value;
        results.push({ status: r.status, body: row });
      } else {
        results.push({ status: r.status, body: value });
      }
    }
    const after = await control({ action: "consents", headers: { cookie } });
    expect(await after.json()).toEqual([expected]);
    return ctx.snapshot({ results });
  },
);
