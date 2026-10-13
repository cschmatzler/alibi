import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "OAuth client lists isolate real owners and redact every stored secret",
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
    const owner = await signup("oauth-list-owner");
    const other = await signup("oauth-list-other");
    const empty = await control({ action: "list", headers: { cookie: owner } });
    expect(empty.status).toBe(200);
    expect(await empty.json()).toEqual([]);
    const expected: any[] = [];
    const foreign: any[] = [];
    for (const [name, cookie] of [
      ["Owner one", owner],
      ["Foreign", other],
      ["Owner two", owner],
    ] as const) {
      const r = await control({
        headers: { cookie },
        body: { client_name: name, redirect_uris: ["https://app.fixture.test/callback"] },
      });
      expect(r.status).toBe(201);
      const value = (await r.json()) as any;
      expect(value.client_secret).toMatch(/^[a-zA-Z]{32}$/);
      delete value.client_secret;
      (name === "Foreign" ? foreign : expected).push(value);
    }
    const results = [];
    for (const [cookie, clients] of [
      [owner, expected],
      [other, foreign],
    ] as const) {
      const r = await control({ action: "list", headers: { cookie } });
      expect(r.status).toBe(200);
      const value = await r.json();
      expect(value).toEqual(clients);
      results.push(value);
    }
    const guest = await control({ action: "list", headers: {} });
    expect(guest.status).toBe(401);
    return { lists: ctx.snapshot(results), guest: await guest.json() };
  },
);
