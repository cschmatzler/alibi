import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "Provider signed interaction admission rejects forged auth input before HTTP and private writes",
  async (ctx) => {
    const actor = ctx.actor("signed-interaction");
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "interaction", ...input }),
      });
    const email = ctx.uniqueEmail("signed-interaction-owner");
    const issued = await control({
      action: "signup",
      body: { email, name: "Interaction Owner", password: "password123" },
    });
    expect(issued.status).toBe(200);
    const owner = await issued.json();
    const cookie = issued.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const created = await control({
      headers: { cookie },
      body: {
        client_name: "Interaction client",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "email",
        token_endpoint_auth_method: "none",
      },
    });
    expect(created.status).toBe(201);
    const client = await created.json();
    const producer = await control({
      action: "authorize",
      query: {
        client_id: client.client_id,
        response_type: "code",
        redirect_uri: "https://app.fixture.test/callback",
        scope: "email",
        state: "signed-interaction",
        code_challenge: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
        code_challenge_method: "S256",
      },
      headers: { accept: "application/json" },
    });
    expect(producer.status).toBe(200);
    const login = await producer.json();
    const url = new URL(login.url, ctx.baseURL);
    expect(url.pathname).toBe("/login");
    const signed = url.search.slice(1);
    const before = await ctx.readUserState({ userId: owner.user.id });
    const results = [];
    for (const kind of ["signin", "signup"] as const) {
      for (const transport of ["http", "private"] as const) {
        for (const query of [
          signed + "&sig=duplicate",
          signed + "&scope=forged",
          true,
          {},
          ["not-a-pair"],
        ] as const) {
          const body = {
            email: kind === "signin" ? email : ctx.uniqueEmail("forged-interaction-signup"),
            name: "Forged signup",
            password: "password123",
            oauth_query: query,
          };
          const response = await control(
            transport === "http"
              ? {
                  action: "protocol-http",
                  method: "POST",
                  path: kind === "signin" ? "/sign-in/email" : "/sign-up/email",
                  contentType: "application/json",
                  body,
                }
              : { action: kind, body },
          );
          const status = Array.isArray(query) ? 500 : 400;
          expect(response.status, JSON.stringify({ kind, transport, query })).toBe(status);
          const text = await response.text();
          const value = text ? JSON.parse(text) : null;
          expect(value).toEqual(status === 400 ? { error: "invalid_signature" } : null);
          expect(response.headers.getSetCookie()).toEqual([]);
          expect(await ctx.readUserState({ userId: owner.user.id })).toEqual(before);
          results.push({ kind, transport, status, body: value });
        }
      }
    }
    const controls = [];
    for (const query of [signed, [...url.searchParams], "", false, null, 0]) {
      for (const transport of ["http", "private"] as const) {
        const body = { email, password: "wrong-password", oauth_query: query };
        const response = await control(
          transport === "http"
            ? {
                action: "protocol-http",
                method: "POST",
                path: "/sign-in/email",
                contentType: "application/json",
                body,
              }
            : { action: "signin", body },
        );
        expect(response.status).toBe(401);
        const value = await response.json();
        expect(value.code).toBe("INVALID_EMAIL_OR_PASSWORD");
        expect(response.headers.getSetCookie()).toEqual([]);
        controls.push({ transport, status: response.status, body: value });
      }
    }
    expect(await ctx.readUserState({ userId: owner.user.id })).toEqual(before);
    const ordinary = await control({ action: "signin", body: { email, password: "password123" } });
    expect(ordinary.status).toBe(200);
    const authenticated = await ordinary.json();
    expect(authenticated.user.id).toBe(owner.user.id);
    return ctx.snapshot({ owner, client, login, before, results, controls, authenticated });
  },
);
