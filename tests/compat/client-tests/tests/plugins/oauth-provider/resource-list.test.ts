import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Resource listing includes global enabled and disabled policy for authenticated server callers",
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
        email: ctx.uniqueEmail("resource-list-owner"),
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
    const empty = await control({ action: "resource-list", headers: { cookie } });
    expect(empty.status).toBe(200);
    expect(await empty.json()).toEqual([]);
    const expected = [];
    for (const input of [
      { identifier: "https://api.fixture.test/list-a", name: "Enabled", allowedScopes: ["email"] },
      { identifier: "urn:fixture:list-b", disabled: true },
    ]) {
      const r = await control({ action: "resource-create", headers: { cookie }, body: input });
      expect(r.status).toBe(200);
      expected.push(await r.json());
    }
    const other = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("resource-list-other"),
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
    const lists = [];
    for (const headers of [{ cookie }, { cookie: otherCookie }]) {
      const r = await control({ action: "resource-list", headers });
      expect(r.status).toBe(200);
      const rows = (await r.json()) as any[];
      expect(rows).toEqual(expected);
      expect(rows[0].disabled).toBe(false);
      expect(rows[1].disabled).toBe(true);
      lists.push(rows.map(({ createdAt, updatedAt, ...row }) => row));
    }
    const denied = await control({ action: "resource-list" });
    expect(denied.status).toBe(401);
    expect(await denied.text()).toBe("");
    const http = await control({ action: "resource-http", operation: "list", headers: { cookie } });
    expect(await http.json()).toEqual({ status: 404 });
    return ctx.snapshot({ lists });
  },
);
