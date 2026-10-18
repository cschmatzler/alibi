import { Cookie } from "tough-cookie";
import { expect } from "vitest";

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
    const sessionResponse = await control({ action: "session", headers: { cookie } });
    expect(sessionResponse.status).toBe(200);
    const session = (await sessionResponse.json()) as any;
    const receipts = async () => {
      const response = await control({ action: "selection-policy-calls" });
      expect(response.status).toBe(200);
      return (await response.json()) as any[];
    };
    const automatic: any = { ...query, scope: "email  email profile" };
    delete automatic.prompt;
    const policyResults = [];
    for (const [decision, patch, authenticated, signup, postLogin, expected, stages] of [
      ["true", {}, true, true, true, "/select", ["selectAccount"]],
      ["true", { max_age: 3600 }, true, false, false, "/select", ["selectAccount"]],
      ["true", { prompt: "consent" }, true, true, true, "/select", ["selectAccount"]],
      ["ordinary-error", { prompt: "select_account" }, true, true, true, "/select", []],
      [
        "true",
        { prompt: "none" },
        true,
        true,
        true,
        "account_selection_required",
        ["selectAccount"],
      ],
      ["false", {}, true, true, true, "/signup", ["selectAccount", "signup"]],
      ["false", {}, true, false, true, "/post-login", ["selectAccount", "signup", "postLogin"]],
      ["false", {}, true, false, false, "/consent", ["selectAccount", "signup", "postLogin"]],
      ["ordinary-error", { scope: "forbidden" }, true, false, false, "invalid_scope", []],
      ["ordinary-error", { client_id: "missing" }, true, false, false, "invalid_client", []],
      [
        "ordinary-error",
        { redirect_uri: "https://evil.fixture.test/callback" },
        true,
        false,
        false,
        "invalid_redirect",
        [],
      ],
      ["ordinary-error", { code_challenge: "" }, true, false, false, "invalid_request", []],
      ["ordinary-error", { max_age: 0 }, true, false, false, "/login", []],
      ["ordinary-error", { prompt: "login" }, true, false, false, "/login", []],
      ["ordinary-error", { prompt: "create" }, true, false, false, "/signup", []],
      ["ordinary-error", { prompt: "none" }, false, false, false, "login_required", []],
      ["ordinary-error", {}, false, false, false, "/login", []],
      ["ordinary-error", {}, true, false, false, 500, ["selectAccount"]],
      ["native-error", {}, true, false, false, 403, ["selectAccount"]],
      ["api-error", {}, true, false, false, 403, ["selectAccount"]],
      ["upstream-error", {}, true, false, false, 503, ["selectAccount"]],
    ] as const) {
      const response = await control({
        action: "authorize",
        query: { ...automatic, ...patch },
        headers: {
          cookie: authenticated ? cookie : "",
          accept: "application/json",
          "x-selection-decision": "ordinary-error",
          "x-policy-caller": "logical",
        },
        requestHeaders: {
          "x-selection-decision": decision,
          "x-policy-caller": "physical",
          "x-signup-decision": String(signup),
          "x-postlogin-decision": String(postLogin),
        },
      });
      const text = await response.text();
      const value = text ? JSON.parse(text) : null;
      if (typeof expected === "number") {
        expect(response.status).toBe(expected);
        if (decision === "ordinary-error") expect(text).toBe("");
        if (decision === "native-error") expect(value).toEqual({ message: "Selection denied" });
        if (decision === "api-error") {
          expect(value).toEqual({ code: "SELECTION_DENIED", message: "Selection denied" });
        }
        if (decision === "upstream-error") {
          expect(value).toEqual({
            code: "SELECTION_UNAVAILABLE",
            message: "Selection unavailable",
          });
        }
      } else {
        expect(response.status).toBe(200);
        const target = new URL(value.url, ctx.baseURL);
        if (expected.startsWith("/")) {
          expect(target.pathname).toBe(expected);
          if (expected === "/select") {
            expect(target.searchParams.has("ba_pl")).toBe(false);
            expect(target.searchParams.has("max_age")).toBe(false);
          }
        } else {
          expect(target.searchParams.get("error")).toBe(expected);
          if (expected === "invalid_request") {
            expect(target.searchParams.get("error_description")).toBe(
              "pkce is required for public clients",
            );
          }
          if (expected === "account_selection_required") {
            expect(target.searchParams.get("error_description")).toBe(
              "End-User account selection is required",
            );
          }
        }
      }
      const calls = await receipts();
      expect(calls.map((c) => c.stage)).toEqual(stages);
      if (stages[0] === "selectAccount") {
        expect(calls[0]).toEqual({
          stage: "selectAccount",
          caller: "physical",
          decision,
          user: { id: session.user.id, email: session.user.email, name: session.user.name },
          session: {
            id: session.session.id,
            userId: session.session.userId,
            token: session.session.token,
          },
          scopes: ["email", "email", "profile"],
        });
      }
      policyResults.push({ status: response.status, value, calls });
    }
    const defaultScope = await control({
      action: "authorize",
      query: { ...automatic, scope: undefined },
      headers: { cookie, accept: "application/json" },
      requestHeaders: { "x-selection-decision": "true" },
    });
    expect(defaultScope.status).toBe(200);
    expect(new URL(((await defaultScope.json()) as any).url, ctx.baseURL).pathname).toBe("/select");
    expect((await receipts())[0].scopes).toEqual(["email", "profile"]);
    const automaticProducer = await control({
      action: "authorize",
      query: automatic,
      headers: { cookie, accept: "application/json" },
      requestHeaders: { "x-selection-decision": "true" },
    });
    expect(automaticProducer.status).toBe(200);
    const automaticValue = (await automaticProducer.json()) as any;
    const automaticURL = new URL(automaticValue.url, ctx.baseURL);
    expect(automaticURL.pathname).toBe("/select");
    await receipts();
    for (const flag of ["selected", "created", "postLogin"]) {
      const response = await control({
        action: "continue",
        body: { [flag]: true, oauth_query: automaticURL.search.slice(1) },
        headers: { cookie },
        requestHeaders: { "x-selection-decision": "ordinary-error" },
      });
      expect(response.status).toBe(200);
      expect(new URL(((await response.json()) as any).url, ctx.baseURL).pathname).toBe("/consent");
      expect((await receipts()).map((c) => c.stage)).toEqual(["signup", "postLogin"]);
    }
    const signin = await control({
      action: "signin",
      attachRequest: true,
      body: {
        email: session.user.email,
        password: "password123",
        oauth_query: automaticURL.search.slice(1),
      },
      requestHeaders: { "x-selection-decision": "ordinary-error" },
    });
    expect(signin.status).toBe(200);
    expect(new URL(((await signin.json()) as any).url, ctx.baseURL).pathname).toBe("/consent");
    expect((await receipts()).map((c) => c.stage)).toEqual(["signup", "postLogin"]);
    const fallbacks = [];
    for (const mode of ["selection-fallback", "selection-empty-page"]) {
      const response = await control({
        mode,
        action: "authorize",
        query: automatic,
        headers: { cookie, accept: "application/json" },
        requestHeaders: { "x-selection-decision": "true" },
      });
      expect(response.status).toBe(200);
      const value = (await response.json()) as any;
      expect(value.url.startsWith(mode === "selection-fallback" ? "/login?" : "?")).toBe(true);
      expect((await receipts()).map((c) => c.stage)).toEqual(["selectAccount"]);
      const explicit = await control({
        mode,
        action: "authorize",
        query,
        headers: { cookie, accept: "application/json" },
        requestHeaders: { "x-selection-decision": "ordinary-error" },
      });
      expect(explicit.status).toBe(200);
      const denied = (await explicit.json()) as any;
      expect(new URL(denied.url, ctx.baseURL).searchParams.get("error")).toBe(
        "unsupported_prompt_select_account",
      );
      expect(await receipts()).toEqual([]);
      fallbacks.push({ value, denied });
    }
    const producer = await control({
      action: "authorize",
      query: { ...query, prompt: undefined },
      headers: { cookie, accept: "application/json" },
      requestHeaders: { "x-selection-decision": "true" },
    });
    expect(producer.status).toBe(200);
    const url = new URL(((await producer.json()) as any).url, ctx.baseURL);
    expect(url.pathname).toBe("/select");
    expect((await receipts()).map((c) => c.stage)).toEqual(["selectAccount"]);
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
      [{ selected: true, created: true, oauth_query: creationSigned }, "/signup"],
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
    expect((await receipts()).every((c) => c.stage !== "selectAccount")).toBe(true);
    return ctx.snapshot({
      authorizationSession: session,
      failures,
      selection,
      redirects,
      result,
      policyResults,
      fallbacks,
    });
  },
);
