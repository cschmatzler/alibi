import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario("Consent listing returns only the current users durable grants", async (ctx) => {
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
  const start = Date.now();
  const accepted = await control({
    action: "consent",
    headers: { cookie },
    body: { accept: true, scope: "email", oauth_query: signed },
  });
  expect(accepted.status).toBe(200);
  const other = await control({
    action: "signup",
    body: { email: ctx.uniqueEmail("consent-list-other"), name: "Other", password: "password123" },
  });
  expect(other.status).toBe(200);
  const otherCookie = other.headers
    .getSetCookie()
    .filter((raw) => Boolean(Cookie.parse(raw)?.value))
    .map((raw) => raw.split(";")[0])
    .join("; ");
  const results = [];
  for (const [headers, count, status] of [
    [{ cookie }, 1, 200],
    [{ cookie: otherCookie }, 0, 200],
    [{}, 0, 401],
  ] as const) {
    const response = await control({ action: "consents", headers });
    expect(response.status).toBe(status);
    if (status === 200) {
      const rows = (await response.json()) as any[];
      expect(rows).toHaveLength(count);
      if (count) {
        const row = rows[0];
        expect(row.clientId).toBe(id);
        expect(row.userId).toBe(owner.user.id);
        expect(row.scopes).toEqual(["email"]);
        expect(row.resources).toBeNull();
        expect(row.referenceId).toBeNull();
        expect(row.requestedUserInfoClaims).toEqual([]);
        expect(row.createdAt).toBe(row.updatedAt);
        expect(new Date(row.createdAt).getTime()).toBeGreaterThanOrEqual(
          Math.floor(start / 1000) * 1000,
        );
        expect(new Date(row.createdAt).getTime()).toBeLessThanOrEqual(Date.now());
        expect(Object.keys(row).sort()).toEqual(
          [
            "clientId",
            "createdAt",
            "id",
            "referenceId",
            "requestedUserInfoClaims",
            "resources",
            "scopes",
            "updatedAt",
            "userId",
          ].sort(),
        );
      }
      results.push(rows.map(({ createdAt, updatedAt, ...row }) => row));
    } else {
      results.push({ status: response.status, body: await response.json() });
    }
  }
  return ctx.snapshot({ results });
});
