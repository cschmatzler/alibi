import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario("Fractional provider fields survive registration and update", async (ctx) => {
  const actor = ctx.actor();
  const control = (input: Record<string, unknown>) =>
    actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ mode: "additional-fields", ...input }),
    });
  const owner = await control({
    action: "signup",
    body: { email: ctx.uniqueEmail("fraction-owner"), name: "Owner", password: "password123" },
  });
  expect(owner.status).toBe(200);
  const cookie = owner.headers
    .getSetCookie()
    .filter((raw) => Boolean(Cookie.parse(raw)?.value))
    .map((raw) => raw.split(";")[0])
    .join("; ");
  const headers = { cookie };
  const input = {
    providerId: "fraction-provider",
    issuer: "https://idp.example.com",
    domain: "company.test",
    label: "Fraction",
    tier: 4.5,
    oidcConfig: {
      clientId: "client",
      clientSecret: "secret",
      skipDiscovery: true,
      authorizationEndpoint: "https://idp.example.com/authorize",
      tokenEndpoint: "https://idp.example.com/token",
      jwksEndpoint: "https://idp.example.com/jwks",
    },
  };
  const created = await control({ headers, body: input });
  expect(created.status).toBe(200);
  expect(((await created.json()) as any).tier).toBe(4.5);
  const initial = (await (
    await control({ action: "row", providerId: input.providerId })
  ).json()) as any;
  expect(initial.tier).toBe(4.5);
  for (const value of [-1.25, 0, 9.75]) {
    const updated = await control({
      action: "update",
      headers,
      body: { providerId: input.providerId, tier: value },
    });
    expect(updated.status).toBe(200);
    expect(((await updated.json()) as any).tier).toBe(value);
    const row = (await (
      await control({ action: "row", providerId: input.providerId })
    ).json()) as any;
    expect(row.tier).toBe(value);
    const read = await control({ action: "get", headers, query: { providerId: input.providerId } });
    expect(read.status).toBe(200);
    expect(((await read.json()) as any).tier).toBe(value);
  }
  return { initial: initial.tier, final: 9.75 };
});
