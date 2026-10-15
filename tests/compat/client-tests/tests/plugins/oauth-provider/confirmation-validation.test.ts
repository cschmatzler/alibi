import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "Issued confirmation survives opaque validation and access/refresh introspection",
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
      body: { email: ctx.uniqueEmail("confirmation"), name: "Owner", password: "password123" },
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
        client_name: "Confirmation consumer",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "email offline_access",
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code"],
      },
    });
    expect(created.status).toBe(201);
    const client = (await created.json()) as any;
    const receipts = [];
    for (const confirmation of [
      { jkt: "bound-key" },
      { "x5t#S256": "certificate" },
      { jkt: "" },
      {},
      [],
      false,
      null,
    ]) {
      const expectedType =
        confirmation &&
        typeof confirmation === "object" &&
        !Array.isArray(confirmation) &&
        "jkt" in confirmation &&
        confirmation.jkt
          ? "DPoP"
          : "Bearer";
      const response = await control({
        action: "issue-tokens",
        body: {
          clientId: client.client_id,
          userId: owner.user.id,
          grantType: "urn:fixture:confirmation",
          params: { scopes: ["email", "offline_access"], confirmation },
        },
      });
      expect(response.status).toBe(200);
      const tokens = (await response.json()) as any;
      expect(tokens.token_type).toBe(expectedType);
      expect(typeof tokens.refresh_token).toBe("string");
      const validation = await control({
        action: "validate-access",
        body: { token: tokens.access_token, requireActive: false },
      });
      expect(validation.status).toBe(200);
      const payloads = [(await validation.json()) as any];
      for (const kind of ["access_token", "refresh_token"] as const) {
        const inspected = await control({
          action: "introspect",
          body: {
            client_id: client.client_id,
            client_secret: client.client_secret,
            token: tokens[kind],
            token_type_hint: kind,
          },
        });
        expect(inspected.status).toBe(200);
        payloads.push(await inspected.json());
      }
      for (const payload of payloads) {
        expect(payload.active).toBe(true);
        expect(payload.token_type).toBe(expectedType);
        if (confirmation) expect(payload.cnf).toEqual(confirmation);
        else expect(payload).not.toHaveProperty("cnf");
      }
      receipts.push({ confirmation, payloads });
    }
    return ctx.snapshot({ receipts });
  },
);
