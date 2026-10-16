import { createHmac } from "node:crypto";

import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compareValues } from "../../../support/compare";
import { compatScenario } from "../../../support/scenario";
compatScenario(
  "OAuth authorization admits the real client and produces a signed login redirect",
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
      body: {
        email: ctx.uniqueEmail("oauth-authorization-owner"),
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
        client_name: "Authorization client",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "openid email",
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
      state: "caller-state",
      extension_zero: 0,
      extension_large: 1e21,
      extension_object: { label: "value" },
      extension_list: ["literal", false, null, { nested: 1 }, ["a", "b"]],
      extension_null: null,
      code_challenge: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
      code_challenge_method: "S256",
    };
    const start = Date.now();
    const r = await control({
      action: "authorize",
      query,
      headers: { accept: "application/json" },
    });
    expect(r.status).toBe(200);
    const value = (await r.json()) as any;
    expect(value.redirect).toBe(true);
    const url = new URL(value.url, ctx.baseURL);
    expect(url.pathname).toBe("/login");
    expect(url.searchParams.get("client_id")).toBe(id);
    expect(url.searchParams.get("redirect_uri")).toBe(query.redirect_uri);
    expect(url.searchParams.get("scope")).toBe("email");
    expect(url.searchParams.get("state")).toBe("caller-state");
    expect(url.searchParams.get("extension_zero")).toBe("0");
    expect(url.searchParams.get("extension_large")).toBe("1e+21");
    expect(url.searchParams.get("extension_object")).toBe("[object Object]");
    expect(url.searchParams.getAll("extension_list")).toEqual([
      "literal",
      "false",
      "null",
      "[object Object]",
      "a,b",
    ]);
    expect(url.searchParams.has("extension_null")).toBe(false);
    const iat = Number(url.searchParams.get("ba_iat"));
    expect(iat).toBeGreaterThanOrEqual(start);
    expect(iat).toBeLessThanOrEqual(Date.now());
    expect(Number(url.searchParams.get("exp"))).toBe(Math.floor(iat / 1000) + 600);
    const canonical = new URLSearchParams(
      [...url.searchParams]
        .filter(([name]) => name !== "sig")
        .sort(([a, av], [b, bv]) => (a < b ? -1 : a > b ? 1 : av < bv ? -1 : av > bv ? 1 : 0)),
    );
    expect(url.searchParams.get("sig")).toBe(
      createHmac("sha256", "compat-test-only-key-not-real-minimum-32chars")
        .update(canonical.toString())
        .digest("base64"),
    );
    const tampered = new URL(url);
    tampered.searchParams.set("sig", "tampered-signature");
    const finish = Date.now();
    expect(
      compareValues(
        { url: value.url },
        { url: tampered.href },
        {
          leftBaseURL: ctx.baseURL,
          rightBaseURL: ctx.baseURL,
          leftStartedAt: start,
          rightStartedAt: start,
          leftFinishedAt: finish,
          rightFinishedAt: finish,
          sessionCookieSecret: "compat-test-only-key-not-real-minimum-32chars",
        },
      ).length,
    ).toBeGreaterThan(0);
    const coercionFailure = await control({
      action: "authorize",
      headers: { accept: "application/json" },
      query: {
        ...query,
        extension_object: { toString: 42 },
      },
    });
    expect(coercionFailure.status).toBe(500);
    expect(await coercionFailure.text()).toBe("");
    expect(coercionFailure.headers.getSetCookie()).toEqual([]);
    const rejected = [];
    for (const [query, error] of [
      [
        {
          client_id: id,
          response_type: "code",
          redirect_uri: "https://app.fixture.test/callback",
          scope: 42,
          code_challenge: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
          code_challenge_method: "S256",
        },
        "invalid_request",
      ],
      [
        {
          client_id: id,
          response_type: "code",
          redirect_uri: "https://app.fixture.test/callback",
          scope: "email",
          resource: "https://unknown.fixture.test",
          code_challenge: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
          code_challenge_method: "S256",
        },
        "invalid_target",
      ],
      [
        {
          client_id: "missing-client",
          response_type: "code",
          redirect_uri: "https://app.fixture.test/callback",
        },
        "invalid_client",
      ],
      [
        {
          client_id: id,
          response_type: "code",
          redirect_uri: "https://evil.fixture.test/callback",
        },
        "invalid_redirect",
      ],
      [
        {
          client_id: id,
          response_type: "code",
          redirect_uri: "https://app.fixture.test/callback",
          scope: "forbidden",
          state: "caller-state",
        },
        "invalid_scope",
      ],
      [
        {
          client_id: id,
          response_type: "code",
          redirect_uri: "https://app.fixture.test/callback",
          scope: "email",
        },
        "invalid_request",
      ],
    ] as const) {
      const response = await control({
        action: "authorize",
        query,
        headers: { accept: "application/json" },
      });
      expect(response.status).toBe(200);
      const body = (await response.json()) as any;
      expect(new URL(body.url, ctx.baseURL).searchParams.get("error")).toBe(error);
      rejected.push(body);
    }
    const missing = await control({
      action: "authorize",
      query,
      headers: { accept: "application/json" },
      attachRequest: false,
    });
    expect(missing.status).toBe(401);
    const managedResponse = await control({
      action: "admin-create",
      headers: { cookie },
      body: {
        client_name: "Code client",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "email",
        skip_consent: true,
        require_pkce: false,
      },
    });
    expect(managedResponse.status).toBe(201);
    const managed = (await managedResponse.json()) as any;
    const actualSession = (await (
      await control({ action: "session", headers: { cookie } })
    ).json()) as any;
    const codeStart = Date.now();
    const codeResponse = await control({
      action: "authorize",
      headers: { accept: "application/json", cookie },
      query: {
        client_id: managed.client_id,
        response_type: "code",
        redirect_uri: "https://app.fixture.test/callback",
        scope: "email",
        state: "code-state",
      },
    });
    expect(codeResponse.status).toBe(200);
    const codeValue = (await codeResponse.json()) as any;
    const callback = new URL(codeValue.url, ctx.baseURL);
    expect(callback.hostname).toBe("app.fixture.test");
    const code = callback.searchParams.get("code");
    expect(code).toMatch(/^[a-zA-Z0-9]{32}$/);
    expect(callback.searchParams.get("state")).toBe("code-state");
    const proof = (await (await control({ action: "grant-row", token: code })).json()) as any;
    expect(proof).not.toBeNull();
    expect(proof.value.type).toBe("authorization_code");
    expect(proof.value.userId).toBe(actualSession.user.id);
    expect(proof.value.sessionId).toBe(actualSession.session.id);
    expect(proof.value.authTime).toBe(new Date(actualSession.session.createdAt).getTime());
    expect(proof.value.query.client_id).toBe(managed.client_id);
    expect(proof.value.query.state).toBe("code-state");
    expect(proof.value.resource).toEqual([]);
    expect(new Date(proof.createdAt).getTime()).toBeGreaterThanOrEqual(
      Math.floor(codeStart / 1000) * 1000,
    );
    expect(new Date(proof.createdAt).getTime()).toBeLessThanOrEqual(Date.now());
    expect(new Date(proof.expiresAt).getTime() - new Date(proof.createdAt).getTime()).toBe(600000);
    const publicQuery = {
      client_id: managed.client_id,
      response_type: "code",
      redirect_uri: "https://app.fixture.test/callback",
      scope: "email",
      state: "code-state",
    };
    const publicRejected = [];
    for (const [name, values] of [
      ["max_age", ["0", "86400"]],
      ["scope", ["email", "email"]],
      ["client_id", [managed.client_id, managed.client_id]],
      ["state", ["code-state", "code-state"]],
    ] as const) {
      const response = await control({
        action: "protocol-http",
        path: "/oauth2/authorize",
        headers: { accept: "application/json", cookie },
        query: { ...publicQuery, [name]: values },
      });
      expect(response.status).toBe(200);
      const result = await response.json();
      const target = new URL(result.url, ctx.baseURL);
      expect(target.searchParams.get("error"), `${ctx.baseURL}:repeated ${name}`).toBe(
        "invalid_request",
      );
      expect(target.searchParams.get("error_description")).toBe(
        name === "max_age" ? "max_age: Invalid input" : `${name} must not appear more than once`,
      );
      expect(target.searchParams.has("code")).toBe(false);
      expect(response.headers.getSetCookie()).toEqual([]);
      publicRejected.push({ name, result });
    }
    const publicLogin = await control({
      action: "protocol-http",
      path: "/oauth2/authorize",
      headers: { accept: "application/json" },
      query: { ...publicQuery, extension_hint: ["second", "first", "second"] },
    });
    expect(publicLogin.status).toBe(200);
    const publicLoginValue = await publicLogin.json();
    const publicLoginTarget = new URL(publicLoginValue.url, ctx.baseURL);
    expect(publicLoginTarget.pathname).toBe("/login");
    expect(publicLoginTarget.searchParams.getAll("extension_hint")).toEqual([
      "second",
      "first",
      "second",
    ]);
    const postAuthorizations = [];
    for (const [contentType, age] of [
      ["application/json", 86400],
      ["application/x-www-form-urlencoded", "86400"],
      ["application/jsonapplication/x-www-form-urlencoded", 86400],
    ] as const) {
      const body = { ...publicQuery, max_age: age };
      const response = await control({
        action: "protocol-http",
        path: "/oauth2/authorize",
        method: "POST",
        contentType,
        headers: { accept: "application/json", cookie },
        query: { client_id: "not-the-body-client", response_type: "token" },
        body,
        ...(contentType !== "application/x-www-form-urlencoded"
          ? { rawBody: JSON.stringify(body) }
          : {}),
      });
      if (contentType === "application/json") {
        expect(response.status).toBe(415);
        const result = await response.json();
        expect(result).toEqual({
          code: "UNSUPPORTED_MEDIA_TYPE",
          message:
            'Content-Type "application/json" is not allowed. Allowed types: application/x-www-form-urlencoded',
        });
        expect(response.headers.getSetCookie()).toEqual([]);
        postAuthorizations.push({ contentType, result });
        continue;
      }
      expect(response.status, `${ctx.baseURL}:${contentType}`).toBe(200);
      const result = await response.json();
      const callback = new URL(result.url, ctx.baseURL);
      expect(callback.hostname, `${ctx.baseURL}:${contentType}`).toBe("app.fixture.test");
      const code = callback.searchParams.get("code");
      expect(code).toMatch(/^[a-zA-Z0-9]{32}$/);
      const proof = await (await control({ action: "grant-row", token: code })).json();
      expect(proof.value.userId).toBe(actualSession.user.id);
      expect(proof.value.sessionId).toBe(actualSession.session.id);
      expect(proof.value.query.client_id).toBe(managed.client_id);
      expect(proof.value.query.response_type).toBe("code");
      expect(proof.value.query).not.toHaveProperty("max_age");
      postAuthorizations.push({ contentType, result, proof });
    }
    return {
      postAuthorizations: ctx.snapshot(postAuthorizations),
      publicRejected: ctx.snapshot(publicRejected),
      publicLogin: ctx.snapshot(publicLoginValue),
      authorizationSession: ctx.snapshot(actualSession),
      code: ctx.snapshot(codeValue),
      proof: ctx.snapshot(proof),
      redirect: ctx.snapshot(value),
      rejected: ctx.snapshot(rejected),
      missing: await missing.json(),
    };
  },
);
