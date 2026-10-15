import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Prelogin client lookup requires an enabled policy and a genuine unexpired signed authorization",
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
      body: { email: ctx.uniqueEmail("prelogin-owner"), name: "Owner", password: "password123" },
    });
    expect(signup.status).toBe(200);
    const cookie = signup.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const created = await control({
      headers: { cookie },
      body: {
        client_name: "Prelogin client",
        client_uri: "https://app.fixture.test",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "email",
        token_endpoint_auth_method: "none",
      },
    });
    expect(created.status).toBe(201);
    const id = ((await created.json()) as any).client_id;
    const query = {
      client_id: id,
      response_type: "code",
      redirect_uri: "https://app.fixture.test/callback",
      scope: "email",
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
    const responses = [];
    for (const [mode, body, status, error] of [
      ["prelogin", { client_id: id, oauth_query: signed }, 200, null],
      ["default", { client_id: id, oauth_query: signed }, 400, null],
      ["prelogin", { client_id: id }, 401, "invalid_signature"],
      [
        "prelogin",
        { client_id: id, oauth_query: signed.replace(/sig=[^&]*/, "sig=tampered") },
        400,
        "invalid_signature",
      ],
      [
        "prelogin",
        { client_id: id, oauth_query: signed + "&sig=duplicate" },
        400,
        "invalid_signature",
      ],
      ["prelogin", { client_id: "missing-client", oauth_query: signed }, 404, "not_found"],
    ] as const) {
      const response = await control({ action: "prelogin", mode, body });
      expect(response.status).toBe(status);
      const text = await response.text();
      const value = text ? JSON.parse(text) : null;
      if (status === 200) {
        expect(value).toEqual({
          client_id: id,
          client_name: "Prelogin client",
          client_uri: "https://app.fixture.test",
          redirect_uris: [],
        });
      }
      if (error) {
        expect(value.error).toBe(error);
      }
      if (status === 400 && !error) {
        expect(text).toBe("");
      }
      responses.push({ status: response.status, body: value });
    }
    const expiredProducer = await control({
      action: "authorize",
      mode: "expired",
      query,
      headers: { accept: "application/json" },
    });
    expect(expiredProducer.status).toBe(200);
    const expired = new URL(((await expiredProducer.json()) as any).url, ctx.baseURL).search.slice(
      1,
    );
    const rejected = await control({
      action: "prelogin",
      mode: "prelogin",
      body: { client_id: id, oauth_query: expired },
    });
    expect(rejected.status).toBe(400);
    expect(await rejected.json()).toEqual({ error: "invalid_signature" });
    return ctx.snapshot({ responses });
  },
);
