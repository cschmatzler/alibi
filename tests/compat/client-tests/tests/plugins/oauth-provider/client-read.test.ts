import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "OAuth client reads redact the durable secret and enforce the real owner",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: unknown) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const signup = async (label: string) => {
      const response = await control({
        action: "signup",
        body: { email: ctx.uniqueEmail(label), name: label, password: "password123" },
      });
      expect(response.status).toBe(200);
      return {
        user: ((await response.json()) as any).user,
        cookie: response.headers
          .getSetCookie()
          .filter((raw) => Boolean(Cookie.parse(raw)?.value))
          .map((raw) => raw.split(";")[0])
          .join("; "),
      };
    };
    const owner = await signup("oauth-reader-owner");
    const other = await signup("oauth-reader-other");
    const creation = await control({
      body: {
        client_name: "Owned reader client",
        redirect_uris: ["https://app.fixture.test/callback"],
      },
      headers: { cookie: owner.cookie },
    });
    expect(creation.status).toBe(201);
    const created = (await creation.json()) as any;
    const { client_secret, ...expected } = created;
    expect(client_secret).toMatch(/^[a-zA-Z]{32}$/);
    const results = [];
    for (const [id, cookie, status] of [
      [created.client_id, owner.cookie, 200],
      [created.client_id, other.cookie, 401],
      [created.client_id, "", 401],
      ["missing-client", owner.cookie, 404],
      ["", owner.cookie, 404],
    ] as const) {
      const response = await control({
        action: "get",
        query: { client_id: id, user_id: owner.user.id },
        headers: { cookie },
      });
      expect(response.status).toBe(status);
      const text = await response.text();
      const value = text ? JSON.parse(text) : null;
      if (id === created.client_id && cookie === other.cookie) {
        expect(text).toBe("");
        expect(response.headers.get("content-type")).toBe("application/json");
      }
      if (status === 200) {
        expect(value).toEqual(expected);
        expect(value).not.toHaveProperty("client_secret");
      }
      results.push({ status, body: value });
    }
    return { results: ctx.snapshot(results) };
  },
);
