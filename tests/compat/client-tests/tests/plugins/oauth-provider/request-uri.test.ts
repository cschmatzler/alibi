import { createHash } from "node:crypto";

import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario("Request URI lookup replaces authorization input before validation", async (ctx) => {
  const actor = ctx.actor();
  const control = (input: Record<string, unknown>) =>
    actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
      method: "POST",
      redirect: "manual",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ mode: "request-uri", ...input }),
    });
  const signup = await control({
    action: "signup",
    body: {
      email: ctx.uniqueEmail("request-uri-owner"),
      name: "Owner",
      password: "password123",
    },
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
      client_name: "Request registry client",
      redirect_uris: ["https://app.fixture.test/callback"],
      scope: "email",
      token_endpoint_auth_method: "none",
    },
  });
  expect(created.status).toBe(201);
  const id = ((await created.json()) as any).client_id;
  const verifier = "request-uri-fixture-verifier-abcdefghijklmnopqrstuvwxyz";
  const parameters = {
    client_id: "malicious-client",
    response_type: "code",
    redirect_uri: " https://app.fixture.test/callback ",
    scope: "email",
    state: "resolved-state",
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    code_challenge_method: "S256",
    extension_scalar: 7,
  };
  expect((await control({ action: "request-uri-configure", parameters })).status).toBe(200);
  const query = { client_id: id, request_uri: "urn:fixture:valid" };
  const response = await control({
    action: "authorize",
    query,
    headers: { accept: "application/json", "x-request-uri": "physical" },
  });
  expect(response.status).toBe(200);
  const value = (await response.json()) as any;
  const login = new URL(value.url, ctx.baseURL);
  expect(login.pathname).toBe("/login");
  expect(login.searchParams.get("client_id")).toBe(id);
  expect(login.searchParams.get("state")).toBe("resolved-state");
  const calls = await (await control({ action: "request-uri-calls" })).json();
  expect(calls).toHaveLength(1);
  expect(calls[0].query).toEqual(query);
  expect(calls[0].requestHeader).toBe("physical");
  const redirects = await (await control({ action: "request-uri-redirects" })).json();
  expect(redirects).toEqual([
    {
      uri: "https://app.fixture.test/callback",
      registered: ["https://app.fixture.test/callback"],
      defaultResult: true,
    },
  ]);

  const signedIn = await control({
    action: "signin",
    attachRequest: true,
    body: {
      email: ctx.uniqueEmail("request-uri-owner"),
      password: "password123",
      oauth_query: login.search.slice(1),
    },
    headers: { accept: "application/json" },
  });
  expect(signedIn.status).toBe(200);
  const signedInValue = (await signedIn.json()) as any;
  const consent = new URL(signedInValue.url, ctx.baseURL);
  expect(consent.pathname).toBe("/consent");
  const loginCookie = signedIn.headers
    .getSetCookie()
    .filter((raw) => Boolean(Cookie.parse(raw)?.value))
    .map((raw) => raw.split(";")[0])
    .join("; ");
  const accepted = await control({
    action: "consent",
    headers: { cookie: loginCookie },
    body: { accept: true, oauth_query: consent.search.slice(1) },
  });
  expect(accepted.status).toBe(200);
  const acceptedValue = (await accepted.json()) as any;
  const callback = new URL(acceptedValue.url, ctx.baseURL);
  expect(callback.hostname).toBe("app.fixture.test");
  expect(callback.searchParams.get("state")).toBe("resolved-state");
  const code = callback.searchParams.get("code");
  expect(code).toMatch(/^[A-Za-z0-9]{32}$/);
  const stored = await (await control({ action: "grant-row", token: code })).json();
  const session = await (
    await control({ action: "session", headers: { cookie: loginCookie } })
  ).json();
  expect(stored.value.query.client_id).toBe(id);
  expect(stored.value.query.scope).toBe("email");
  expect(stored.value.query.state).toBe("resolved-state");
  expect(stored.value.query.redirect_uri).toBe("https://app.fixture.test/callback");
  expect(stored.value.userId).toBe(session.user.id);
  expect(stored.value.sessionId).toBe(session.session.id);
  expect(await (await control({ action: "request-uri-calls" })).json()).toEqual([]);
  const other = await control({
    headers: { cookie: loginCookie },
    body: {
      client_name: "Other registered client",
      redirect_uris: ["https://app.fixture.test/callback"],
      scope: "email",
      token_endpoint_auth_method: "none",
    },
  });
  expect(other.status).toBe(201);
  const otherId = ((await other.json()) as any).client_id;

  const failures = [];
  for (const [input, resolved, error, state, trusted, lookupCount] of [
    [
      {
        client_id: id,
        request_uri: "urn:fixture:expired",
        redirect_uri: "https://app.fixture.test/callback",
        state: "original",
        response_mode: "fragment",
      },
      parameters,
      "invalid_request_uri",
      "original",
      true,
      1,
    ],
    [{ client_id: id, request_uri: "" }, parameters, "invalid_request_uri", null, false, 1],
    [
      {
        client_id: id,
        request_uri: "urn:fixture:expired",
        redirect_uri: " https://app.fixture.test/callback ",
        state: "original",
      },
      parameters,
      "invalid_request_uri",
      null,
      false,
      1,
    ],
    [
      { client_id: id, request_uri: "urn:fixture:valid", request: "" },
      parameters,
      "invalid_request",
      null,
      false,
      0,
    ],
    [{ client_id: id, request: "" }, parameters, "request_not_supported", null, false, 0],
    [{ request_uri: "urn:fixture:valid" }, parameters, "invalid_request", null, false, 0],
    [
      { client_id: "", request_uri: "urn:fixture:valid" },
      parameters,
      "invalid_request",
      null,
      false,
      0,
    ],
    [
      { client_id: 42, request_uri: "urn:fixture:valid" },
      parameters,
      "invalid_request",
      null,
      false,
      0,
    ],
    [{ client_id: id, request_uri: ["one", "two"] }, parameters, "invalid_request", null, false, 0],
    [{ client_id: id, request_uri: 42 }, parameters, "invalid_request", null, false, 0],
    [{ client_id: id, request: 42 }, parameters, "invalid_request", null, false, 0],
    [
      query,
      { scope: 42, state: "resolved-error", redirect_uri: "https://app.fixture.test/callback" },
      "invalid_request",
      "resolved-error",
      true,
      1,
    ],
    [
      query,
      { scope: 42, state: "resolved-error", redirect_uri: " https://app.fixture.test/callback " },
      "invalid_request",
      null,
      false,
      1,
    ],
    [
      query,
      {
        max_age: "bad",
        state: "resolved-max-age",
        redirect_uri: "https://app.fixture.test/callback",
      },
      "invalid_request",
      "resolved-max-age",
      true,
      1,
    ],
    [
      { client_id: id, request_uri: "urn:fixture:invalid-max-age", max_age: 0 },
      { ...parameters, redirect_uri: "https://app.fixture.test/callback" },
      "invalid_request",
      "resolved-state",
      true,
      1,
    ],
  ] as const) {
    await control({ action: "request-uri-configure", parameters: resolved });
    const rejected = await control({
      action: "authorize",
      query: input,
      headers: { accept: "application/json", cookie: loginCookie },
    });
    expect(rejected.status).toBe(200);
    expect(rejected.headers.getSetCookie()).toEqual([]);
    const result = (await rejected.json()) as any;
    const target = new URL(result.url, ctx.baseURL);
    const fields = new URLSearchParams(target.hash ? target.hash.slice(1) : target.search);
    expect(target.hostname).toBe(trusted ? "app.fixture.test" : new URL(ctx.baseURL).hostname);
    expect(fields.get("error")).toBe(error);
    expect(fields.get("state")).toBe(state);
    const receipts = await (await control({ action: "request-uri-calls" })).json();
    expect(receipts).toHaveLength(lookupCount);
    failures.push({
      result,
      receipts,
      redirects: await (await control({ action: "request-uri-redirects" })).json(),
    });
  }
  await control({ action: "request-uri-configure", parameters });
  for (const [uri, status] of [
    ["urn:fixture:throw", 500],
    ["urn:fixture:api-error", 429],
  ] as const) {
    for (const http of [false, true]) {
      const rejected = await control({
        action: http ? "protocol-http" : "authorize",
        path: "/oauth2/authorize",
        method: "GET",
        query: {
          client_id: id,
          request_uri: uri,
          redirect_uri: "https://app.fixture.test/callback",
        },
        headers: { accept: "text/html", cookie: loginCookie },
      });
      expect(rejected.status).toBe(status);
      expect(rejected.headers.has("location")).toBe(false);
      expect(rejected.headers.getSetCookie()).toEqual([]);
      const text = await rejected.text();
      expect(text).toBe(
        status === 500
          ? ""
          : JSON.stringify({ code: "REQUEST_LOOKUP_LIMIT", message: "Request lookup limited" }),
      );
      failures.push({
        status,
        text,
        receipts: await (await control({ action: "request-uri-calls" })).json(),
        redirects: await (await control({ action: "request-uri-redirects" })).json(),
      });
    }
  }

  const replacements = [];
  for (const [extra, resolved, uri] of [
    [
      {
        scope: 42,
        state: "outer",
        redirect_uri: "https://evil.fixture.test",
        max_age: "bad",
        extension_scalar: 99,
        outer_only: true,
      },
      parameters,
      "urn:fixture:valid",
    ],
    [{ request: 42 }, parameters, "urn:fixture:valid"],
    [{}, { ...parameters, request: "", request_uri: "urn:fixture:throw" }, "urn:fixture:valid"],
    [{ extension_scalar: "outer" }, parameters, "urn:fixture:nonfinite"],
    [{}, { ...parameters, client_id: otherId }, "urn:fixture:valid"],
  ] as const) {
    await control({ action: "request-uri-configure", parameters: resolved });
    const replaced = await control({
      action: "authorize",
      query: { ...query, ...extra, request_uri: uri },
      headers: { accept: "application/json" },
    });
    expect(replaced.status).toBe(200);
    const result = (await replaced.json()) as any;
    const target = new URL(result.url, ctx.baseURL);
    expect(target.pathname).toBe("/login");
    expect(target.searchParams.get("client_id")).toBe(id);
    expect(target.searchParams.get("state")).toBe("resolved-state");
    expect(target.searchParams.get("extension_scalar")).toBe(
      uri === "urn:fixture:nonfinite" ? "Infinity" : "7",
    );
    if (uri === "urn:fixture:nonfinite") {
      expect(target.searchParams.getAll("extension_array")).toEqual(["-Infinity"]);
    }
    expect(target.searchParams.has("outer_only")).toBe(false);
    expect(target.searchParams.has("max_age")).toBe(false);
    const receipts = await (await control({ action: "request-uri-calls" })).json();
    expect(receipts).toHaveLength(1);
    replacements.push({ result, receipts });
  }
  await control({ action: "request-uri-configure", parameters });
  const rawAuthorization =
    JSON.stringify({ ...query, scope: 42, state: "outer", outer_only: true }).slice(0, -1) +
    ',"max_age":1e400,"extension_scalar":1e400}';
  const http = await control({
    action: "protocol-http",
    path: "/oauth2/authorize",
    method: "POST",
    contentType: "application/jsonapplication/x-www-form-urlencoded",
    rawBody: rawAuthorization,
    headers: { accept: "application/json" },
  });
  expect(http.status).toBe(200);
  const httpValue = (await http.json()) as any;
  const httpLogin = new URL(httpValue.url, ctx.baseURL);
  expect(httpLogin.pathname).toBe("/login");
  expect(httpLogin.searchParams.get("extension_scalar")).toBe("7");
  expect(httpLogin.searchParams.get("state")).toBe("resolved-state");
  expect(httpLogin.searchParams.has("outer_only")).toBe(false);
  expect(httpLogin.searchParams.has("max_age")).toBe(false);
  const httpCalls = await (await control({ action: "request-uri-calls" })).json();
  expect(httpCalls).toHaveLength(1);
  const unknown = await control({
    action: "authorize",
    query: { ...query, client_id: "resolver-unknown" },
    headers: { accept: "application/json", "x-request-uri": "physical" },
  });
  expect(unknown.status).toBe(200);
  const unknownValue = (await unknown.json()) as any;
  expect(new URL(unknownValue.url, ctx.baseURL).searchParams.get("error")).toBe("invalid_client");
  const discovery = await (await control({ action: "request-uri-calls" })).json();
  expect(discovery).toHaveLength(2);
  expect(discovery[1].stage).toBe("discovery");
  expect(discovery[1].query.client_id).toBe("resolver-unknown");
  expect(discovery[1].query.redirect_uri).toBe("https://app.fixture.test/callback");
  expect(discovery[1].query.state).toBe("resolved-state");
  expect(discovery[1].requestURL).toBe(`${ctx.baseURL}/api/auth/oauth2/authorize`);
  expect(discovery[1].requestHeader).toBe("physical");

  const unsupported = await control({
    mode: "interaction",
    action: "authorize",
    query: {
      ...query,
      redirect_uri: "https://app.fixture.test/callback",
      state: "unsupported-state",
    },
    headers: { accept: "application/json" },
  });
  expect(unsupported.status).toBe(200);
  const unsupportedValue = (await unsupported.json()) as any;
  expect(new URL(unsupportedValue.url).searchParams.get("error")).toBe("request_uri_not_supported");

  const token = await control({
    action: "token",
    body: {
      grant_type: "authorization_code",
      client_id: id,
      code,
      redirect_uri: "https://app.fixture.test/callback",
      code_verifier: verifier,
    },
  });
  expect(token.status).toBe(200);
  const tokenValue = (await token.json()) as any;
  expect(tokenValue.scope).toBe("email");
  expect(tokenValue.access_token).toEqual(expect.any(String));
  expect(await (await control({ action: "grant-row", token: code })).json()).toBeNull();
  return ctx.snapshot({
    value,
    calls,
    redirects,
    signedInValue,
    acceptedValue,
    stored,
    authorizationSession: session,
    failures,
    replacements,
    httpValue,
    httpCalls,
    unknownValue,
    discovery,
    unsupportedValue,
    token: {
      scope: tokenValue.scope,
      type: tokenValue.token_type,
      access_token: tokenValue.access_token,
    },
  });
});
