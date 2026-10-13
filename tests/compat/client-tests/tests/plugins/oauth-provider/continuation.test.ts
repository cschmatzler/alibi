import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Continuation resumes genuine signed interactions and issues a code bound to the authenticated session",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: unknown) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "selection", ...(input as any) }),
      });
    const signup = await control({
      action: "signup",
      body: { email: ctx.uniqueEmail("continue-owner"), name: "Owner", password: "password123" },
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
        client_name: "Continuation client",
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
      scope: "email",
      state: "continue-state",
      prompt: "select_account",
      code_challenge: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
      code_challenge_method: "S256",
    };
    const producer = await control({
      action: "authorize",
      query,
      headers: { cookie, accept: "application/json" },
    });
    expect(producer.status).toBe(200);
    const url = new URL(((await producer.json()) as any).url, ctx.baseURL);
    expect(url.pathname).toBe("/select");
    const signed = url.search.slice(1);
    const failures = [];
    for (const [body, headers, attach, status, error, description] of [
      [{}, { cookie }, true, 400, "invalid_request", "Missing parameters"],
      [{ selected: true }, { cookie }, true, 400, "invalid_request", "missing oauth query"],
      [
        { selected: true, oauth_query: signed + "&sig=duplicate" },
        { cookie },
        true,
        400,
        "invalid_signature",
        null,
      ],
      [{ selected: true, oauth_query: signed }, {}, true, 401, null, null],
      [{ selected: 42, oauth_query: signed }, { cookie }, true, 400, null, null],
      [
        { selected: true, oauth_query: signed },
        { cookie },
        false,
        401,
        "invalid_request",
        "request not found",
      ],
    ] as const) {
      const r = await control({ action: "continue", body, headers, attachRequest: attach });
      expect(r.status).toBe(status);
      const text = await r.text();
      const value = text ? JSON.parse(text) : null;
      if (error) {
        expect(value.error).toBe(error);
        if (description) {
          expect(value.error_description).toBe(description);
        }
      } else if (status === 400) {
        expect(value.code).toBe("VALIDATION_ERROR");
      }
      failures.push({ status: r.status, body: value });
    }
    const selected = await control({
      action: "continue",
      body: { selected: true, oauth_query: signed },
      headers: { cookie },
    });
    expect(selected.status).toBe(200);
    const selection = (await selected.json()) as any;
    const target = new URL(selection.url, ctx.baseURL);
    expect(target.pathname).toBe("/consent");
    expect(target.searchParams.has("prompt")).toBe(false);
    const creationProducer = await control({
      action: "authorize",
      query: { ...query, prompt: "create" },
      headers: { cookie, accept: "application/json" },
    });
    expect(creationProducer.status).toBe(200);
    const creationURL = new URL(((await creationProducer.json()) as any).url, ctx.baseURL);
    const creationSigned = creationURL.search.slice(1);
    const redirects = [];
    for (const [body, path] of [
      [{ created: true, oauth_query: creationSigned }, "/consent"],
      [{ selected: true, created: true, oauth_query: creationSigned }, "/login"],
      [{ postLogin: true, oauth_query: signed }, "/consent"],
    ] as const) {
      const r = await control({ action: "continue", body, headers: { cookie } });
      expect(r.status).toBe(200);
      const value = (await r.json()) as any;
      expect(new URL(value.url, ctx.baseURL).pathname).toBe(path);
      redirects.push(value);
    }
    const accepted = await control({
      action: "consent",
      headers: { cookie },
      body: { accept: true, oauth_query: target.search.slice(1) },
    });
    expect(accepted.status).toBe(200);
    const sessionResponse = await control({ action: "session", headers: { cookie } });
    expect(sessionResponse.status).toBe(200);
    const session = (await sessionResponse.json()) as any;
    const resumed = await control({
      action: "continue",
      headers: { cookie },
      body: { selected: true, oauth_query: signed },
    });
    expect(resumed.status).toBe(200);
    const result = (await resumed.json()) as any;
    const callback = new URL(result.url);
    expect(callback.host).toBe("app.fixture.test");
    expect(callback.searchParams.get("state")).toBe("continue-state");
    const code = callback.searchParams.get("code");
    expect(code).toMatch(/^[A-Za-z0-9]{32}$/);
    const proofResponse = await control({ action: "grant-row", token: code });
    const proof = (await proofResponse.json()) as any;
    expect(proof.value.type).toBe("authorization_code");
    expect(proof.value.query.client_id).toBe(id);
    expect(proof.value.query.scope).toBe("email");
    expect(proof.value.query.state).toBe("continue-state");
    expect(proof.value.userId).toBe(session.user.id);
    expect(proof.value.sessionId).toBe(session.session.id);
    expect(proof.value.authTime).toBe(new Date(session.session.createdAt).getTime());
    return ctx.snapshot({ authorizationSession: session, failures, selection, redirects, result });
  },
);
