import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario("SSO per-user provider limits resolve before durable registration", async (ctx) => {
  const actor = ctx.actor();
  const control = (input: Record<string, unknown>) =>
    actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ mode: "provider-limits", ...input }),
    });
  const signup = async (email: string) => {
    const response = await control({
      action: "signup",
      body: { email, name: "Limit owner", password: "password123" },
    });
    expect(response.status).toBe(200);
    const cookie = response.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    return { headers: { cookie }, user: ((await response.json()) as any).user };
  };
  const owner = await signup(ctx.uniqueEmail("limit-owner"));
  const body = {
    providerId: "limit-provider",
    issuer: "https://idp.example.com",
    domain: "company.test",
    oidcConfig: {
      clientId: "client",
      clientSecret: "secret",
      skipDiscovery: true,
      authorizationEndpoint: "https://idp.example.com/authorize",
      tokenEndpoint: "https://idp.example.com/token",
      jwksEndpoint: "https://idp.example.com/jwks",
    },
  };
  const cases: [number, number, string | null][] = [
    [0, 403, "SSO provider registration is disabled"],
    [1, 200, null],
    [1, 403, "You have reached the maximum number of SSO providers"],
    [2, 200, null],
    [1.5, 403, "You have reached the maximum number of SSO providers"],
    [3, 200, null],
    [-1, 403, "You have reached the maximum number of SSO providers"],
  ];
  const observations = [];
  for (const [index, [limit, status, message]] of cases.entries()) {
    await control({ action: "limit-policy", limit });
    const providerId = `limit-provider-${index}`;
    const response = await control({ headers: owner.headers, body: { ...body, providerId } });
    expect(response.status).toBe(status);
    if (message) expect(((await response.json()) as any).message).toBe(message);
    const row = await (await control({ action: "row", providerId })).json();
    expect(Boolean(row)).toBe(status === 200);
    const events = await (await control({ action: "limit-events" })).json();
    expect(events).toEqual([
      {
        userId: owner.user.id,
        email: owner.user.email,
        name: owner.user.name,
        emailVerified: owner.user.emailVerified,
      },
    ]);
    observations.push({ limit, status, message });
  }
  const other = await signup(ctx.uniqueEmail("limit-other"));
  await control({ action: "limit-policy", limit: 1 });
  const accepted = await control({ headers: other.headers, body });
  expect(accepted.status).toBe(200);
  const row = (await (await control({ action: "row", providerId: body.providerId })).json()) as any;
  expect(row.userId).toBe(other.user.id);
  expect(await (await control({ action: "limit-events" })).json()).toEqual([
    {
      userId: other.user.id,
      email: other.user.email,
      name: other.user.name,
      emailVerified: other.user.emailVerified,
    },
  ]);
  await control({ action: "limit-policy", limit: 1 });
  const denied = await control({ body });
  expect(denied.status).toBe(401);
  expect(await (await control({ action: "limit-events" })).json()).toEqual([]);
  return { observations, ownerIsolation: true, unauthenticatedCallback: false };
});
