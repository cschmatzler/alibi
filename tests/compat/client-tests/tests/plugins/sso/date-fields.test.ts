import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SSO Date fields preserve SDK values, persisted instants and restart reads",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: unknown) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/sso-dates`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const owner = await control({
      action: "signup",
      body: { email: ctx.uniqueEmail("date-owner"), name: "Owner", password: "password123" },
    });
    expect(owner.status).toBe(200);
    const cookie = owner.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const headers = { cookie };
    const first = "2030-01-02T03:04:05.678Z";
    const body = {
      providerId: "date-provider",
      issuer: "https://idp.example.com",
      domain: "company.test",
      anniversary: first,
      oidcConfig: {
        clientId: "client",
        clientSecret: "secret",
        skipDiscovery: true,
        pkce: true,
        authorizationEndpoint: "https://idp.example.com/authorize",
        tokenEndpoint: "https://idp.example.com/token",
        jwksEndpoint: "https://idp.example.com/jwks",
      },
    };
    const created = await control({ body, headers, sdkDate: true });
    expect(created.status).toBe(200);
    expect(((await created.json()) as any).anniversary).toBe(first);
    for (const bad of [first, 3, null]) {
      const denied = await control({
        action: "update",
        body: { providerId: "date-provider", anniversary: bad },
        headers,
      });
      expect(denied.status).toBe(400);
      const read = await control({ action: "get", headers });
      expect(((await read.json()) as any).anniversary).toBe(first);
    }
    const next = "2031-06-07T08:09:10.123Z";
    const updated = await control({
      action: "update",
      body: { providerId: "date-provider", anniversary: next },
      headers,
      sdkDate: true,
    });
    expect(updated.status).toBe(200);
    expect(((await updated.json()) as any).anniversary).toBe(next);
    const physical = (await (await control({ action: "physical" })).json()) as any[];
    expect(new Date(physical[0].application_anniversary).toISOString()).toBe(next);
    await control({ action: "restart" });
    const read = await control({ action: "get", headers });
    expect(((await read.json()) as any).anniversary).toBe(next);
    const list = await control({ action: "list", headers });
    expect(((await list.json()) as any).providers[0].anniversary).toBe(next);
    return { created: first, updated: next, persisted: next };
  },
);
