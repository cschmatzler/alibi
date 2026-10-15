import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Public OAuth client reads expose display fields to authenticated non-owners",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: unknown) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const signup = async (label: string) => {
      const r = await control({
        action: "signup",
        body: { email: ctx.uniqueEmail(label), name: label, password: "password123" },
      });
      expect(r.status).toBe(200);
      return r.headers
        .getSetCookie()
        .filter((raw) => Boolean(Cookie.parse(raw)?.value))
        .map((raw) => raw.split(";")[0])
        .join("; ");
    };
    const owner = await signup("oauth-display-owner");
    const other = await signup("oauth-display-other");
    const display = {
      client_name: "Display client",
      client_uri: "https://app.fixture.test",
      logo_uri: "https://app.fixture.test/logo.png",
      contacts: ["support@app.fixture.test"],
      tos_uri: "https://app.fixture.test/terms",
      policy_uri: "https://app.fixture.test/privacy",
    };
    const created = await control({
      headers: { cookie: owner },
      body: {
        ...display,
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "openid email",
      },
    });
    expect(created.status).toBe(201);
    const client = (await created.json()) as any;
    const results = [];
    for (const [id, cookie, status] of [
      [client.client_id, other, 200],
      [client.client_id, owner, 200],
      [client.client_id, "", 401],
      ["missing-client", other, 404],
    ] as const) {
      const r = await control({ action: "public", query: { client_id: id }, headers: { cookie } });
      expect(r.status).toBe(status);
      const text = await r.text();
      const value = text ? JSON.parse(text) : null;
      if (status === 200) {
        expect(value).toEqual({ ...display, client_id: client.client_id, redirect_uris: [] });
      }
      results.push({ status, body: value });
    }
    return { results: ctx.snapshot(results) };
  },
);
