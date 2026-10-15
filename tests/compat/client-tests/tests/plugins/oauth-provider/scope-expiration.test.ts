import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Scope expirations preserve absolute numeric values, ignored zero, dates and earliest relative bounds",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: object) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const signup = await control({
      action: "signup",
      body: { email: ctx.uniqueEmail("scope-expiry"), name: "Owner", password: "password123" },
    });
    expect(signup.status).toBe(200);
    const owner = (await signup.json()) as any;
    const cookie = signup.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const created = await control({
      action: "admin-create",
      headers: { cookie },
      body: {
        client_name: "Scope expiry",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "email profile offline_access",
        grant_types: ["authorization_code"],
        token_endpoint_auth_method: "none",
      },
    });
    expect(created.status).toBe(201);
    const client = (await created.json()) as any;
    // Absolute scope expirations produce execution-time-dependent negative TTLs.
    // Check those against genuine DB receipts, not a literal cross-run number.
    const mint = (input: object) =>
      fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const receipts = [];
    for (const policy of ["numeric", "zero", "relative", "date", "ceiling"]) {
      const mode = `scope-${policy}`;
      const response = await mint({
        mode,
        action: "issue-tokens",
        body: {
          scopePolicy: policy,
          grantType: "urn:fixture:server",
          clientId: client.client_id,
          userId: owner.user.id,
          params: { scopes: ["email", "profile", "offline_access"] },
        },
      });
      expect(response.status).toBe(200);
      const result = (await response.json()) as any;
      const row = (await (
        await control({ action: "token-row", token: result.access_token })
      ).json()) as any;
      const issued = Date.parse(row.createdAt) / 1000;
      const expected =
        policy === "numeric"
          ? 1
          : policy === "date"
            ? 0
            : issued + (policy === "relative" ? 45 : 3600);
      expect(result.expires_at).toBe(expected);
      expect(result.expires_in).toBe(expected - issued);
      expect(Date.parse(row.expiresAt) / 1000).toBe(expected);
      const refresh = (await (
        await control({ action: "token-row", kind: "refresh", token: result.refresh_token })
      ).json()) as any;
      expect((Date.parse(refresh.expiresAt) - Date.parse(refresh.createdAt)) / 1000).toBe(2592000);
      const rotated = await mint({
        mode,
        action: "token",
        body: {
          grant_type: "refresh_token",
          client_id: client.client_id,
          refresh_token: result.refresh_token,
        },
      });
      expect(rotated.status).toBe(200);
      const next = (await rotated.json()) as any;
      const nextRow = (await (
        await control({ action: "token-row", token: next.access_token })
      ).json()) as any;
      const nextIssued = Date.parse(nextRow.createdAt) / 1000;
      const nextExpected =
        policy === "numeric"
          ? 1
          : policy === "date"
            ? 0
            : nextIssued + (policy === "relative" ? 45 : 3600);
      expect(next.expires_at).toBe(nextExpected);
      expect(next.expires_in).toBe(nextExpected - nextIssued);
      expect(Date.parse(nextRow.expiresAt) / 1000).toBe(nextExpected);
      receipts.push({
        policy,
        absolute: policy === "numeric" || policy === "date",
        ttl: policy === "relative" ? 45 : policy === "zero" || policy === "ceiling" ? 3600 : null,
      });
    }
    return ctx.snapshot({ owner: owner.user, receipts });
  },
);
