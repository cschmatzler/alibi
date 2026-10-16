import { createHmac } from "node:crypto";

import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compareValues } from "../../../support/compare";
import { compatScenario } from "../../../support/scenario";
compatScenario(
  "OAuth authorization admits the real client and produces a signed login redirect",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        redirect: "manual",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "interaction", ...input }),
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
    const reservedCallback =
      "https://app.fixture.test/callback?code=stale&keep=first&code=duplicate&state=stale&iss=stale&keep=second";
    const managedResponse = await control({
      action: "admin-create",
      headers: { cookie },
      body: {
        client_name: "Code client",
        redirect_uris: ["https://app.fixture.test/callback", reservedCallback],
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
    const callbackQueries = [];
    for (const transport of ["private", "http"] as const) {
      const response = await control({
        ...(transport === "http"
          ? { action: "protocol-http", path: "/oauth2/authorize" }
          : { action: "authorize" }),
        headers: { accept: "application/json", cookie },
        query: { ...publicQuery, redirect_uri: reservedCallback },
      });
      expect(response.status).toBe(200);
      const result = await response.json();
      const target = new URL(result.url);
      expect(target.searchParams.getAll("code")).toHaveLength(1);
      const code = target.searchParams.get("code");
      expect(code).toMatch(/^[a-zA-Z0-9]{32}$/);
      expect(target.searchParams.getAll("state")).toEqual(["code-state"]);
      expect(target.searchParams.getAll("iss")).toEqual([`${ctx.baseURL}/api/auth`]);
      expect(target.searchParams.getAll("keep")).toEqual(["first", "second"]);
      const stored = await (await control({ action: "grant-row", token: code })).json();
      expect(stored.value.query.redirect_uri).toBe(reservedCallback);
      expect(stored.value.query.state).toBe("code-state");
      expect(stored.value.userId).toBe(actualSession.user.id);
      expect(stored.value.sessionId).toBe(actualSession.session.id);
      callbackQueries.push({ transport, result, stored });
    }
    const nativeClientResponse = await control({
      action: "admin-create",
      headers: { cookie },
      body: {
        client_name: "Loopback client",
        redirect_uris: [
          "http://localhost:1234/callback",
          "http://127.0.0.1:1234/callback",
          "http://[::1]:1234/callback",
        ],
        application_type: "native",
        scope: "email",
        skip_consent: true,
        require_pkce: false,
      },
    });
    expect(nativeClientResponse.status).toBe(201);
    const nativeClient = await nativeClientResponse.json();
    const loopbackRedirects = [];
    for (const transport of ["private", "http"] as const) {
      for (const [redirect_uri, allowed] of [
        ["http://localhost:5678/callback", true],
        ["http://127.0.0.1:5678/callback", true],
        ["http://[::1]:5678/callback", true],
        ["http://LOCALHOST:5678/callback", false],
        ["http://127.1:5678/callback", false],
        ["http://127.0.0.1:5678/other/../callback", false],
      ] as const) {
        const response = await control({
          ...(transport === "http"
            ? { action: "protocol-http", path: "/oauth2/authorize" }
            : { action: "authorize" }),
          headers: { accept: "application/json", cookie },
          query: { ...publicQuery, client_id: nativeClient.client_id, redirect_uri },
        });
        expect(response.status).toBe(200);
        expect(response.headers.getSetCookie()).toEqual([]);
        const result = await response.json();
        const target = new URL(result.url, ctx.baseURL);
        let stored = null;
        if (allowed) {
          expect(target.origin).toBe(new URL(redirect_uri).origin);
          expect(target.pathname).toBe("/callback");
          expect(target.searchParams.get("code")).toMatch(/^[a-zA-Z0-9]{32}$/);
          expect(target.searchParams.get("state")).toBe("code-state");
          stored = await (
            await control({ action: "grant-row", token: target.searchParams.get("code") })
          ).json();
          expect(stored.value.query.client_id).toBe(nativeClient.client_id);
          expect(stored.value.query.redirect_uri).toBe(redirect_uri);
          expect(stored.value.userId).toBe(actualSession.user.id);
          expect(stored.value.sessionId).toBe(actualSession.session.id);
        } else {
          expect(target.origin).toBe(new URL(ctx.baseURL).origin);
          expect(target.pathname).toBe("/api/auth/error");
          expect(target.searchParams.get("error")).toBe("invalid_redirect");
          expect(target.searchParams.has("code")).toBe(false);
          expect(target.searchParams.has("state")).toBe(false);
          expect(target.searchParams.has("iss")).toBe(false);
        }
        loopbackRedirects.push({ transport, redirect_uri, allowed, result, stored });
      }
    }
    const fetchRedirects = [];
    for (const transport of ["private", "http"] as const) {
      for (const [mode, destination, status] of [
        ["cors", undefined, 200],
        ["cors", "document", 200],
        ["same-origin", "empty", 302],
        ["navigate", "empty", 302],
      ] as const) {
        const response = await control({
          ...(transport === "http"
            ? { action: "protocol-http", path: "/oauth2/authorize" }
            : { action: "authorize" }),
          headers: {
            accept: "text/html",
            "sec-fetch-mode": mode,
            ...(destination ? { "sec-fetch-dest": destination } : {}),
          },
          query: publicQuery,
        });
        expect(response.status, `${ctx.baseURL}:${transport}:${mode}:${destination}`).toBe(status);
        expect(response.headers.get("content-type")).toBe("application/json");
        expect(response.headers.getSetCookie()).toEqual([]);
        const result = status === 200 ? await response.json() : await response.text();
        if (status === 200) expect(result.redirect).toBe(true);
        else expect(result).toBe("");
        const location = status === 200 ? result.url : response.headers.get("location");
        const target = new URL(location, ctx.baseURL);
        expect(target.pathname).toBe("/login");
        expect(target.searchParams.get("client_id")).toBe(managed.client_id);
        fetchRedirects.push({ transport, mode, destination, status, result, location });
      }
    }
    const errorChannels = [];
    for (const transport of ["private", "http"] as const) {
      for (const [query, fragment, error, description, trusted] of [
        [
          { response_type: "token" },
          true,
          "unsupported_response_type",
          "response_type must be one of: code",
          true,
        ],
        [
          { response_type: "token", response_mode: "query" },
          false,
          "unsupported_response_type",
          "response_type must be one of: code",
          true,
        ],
        [
          { response_type: "code id_token" },
          true,
          "unsupported_response_type",
          "response_type must be one of: code",
          true,
        ],
        [
          { response_type: "code_token" },
          false,
          "unsupported_response_type",
          "response_type must be one of: code",
          true,
        ],
        [
          { response_type: "étokené" },
          true,
          "unsupported_response_type",
          "response_type must be one of: code",
          true,
        ],
        [
          { response_mode: "fragment", prompt: "surprise" },
          true,
          "invalid_request",
          "prompt: unsupported prompt value: surprise",
          true,
        ],
        ...(
          [
            [{ request: ["first", "second"] }, "request must not appear more than once"],
            [{ request_uri: ["first", "second"] }, "request_uri must not appear more than once"],
            ...(transport === "private"
              ? ([
                  [{ request: null }, "request must be a string"],
                  [{ request_uri: 42 }, "request_uri must be a string"],
                  [{ request: null, request_uri: null }, "request must be a string"],
                ] as const)
              : []),
          ] as const
        ).map(
          ([query, description]) => [query, false, "invalid_request", description, true] as const,
        ),
        [
          { client_id: "", request_uri: "urn:fixture:request" },
          false,
          "invalid_request",
          "client_id is required",
          false,
        ],
        ...[
          { code_challenge_method: "" },
          { code_challenge_method: "plain" },
          { code_challenge_method: "plain", scope: "forbidden" },
          { code_challenge_method: "plain", prompt: "select_account" },
        ].map(
          (query) =>
            [
              { ...query, response_mode: "fragment" },
              true,
              "invalid_request",
              "code_challenge_method must be one of: S256",
              true,
            ] as const,
        ),
        [
          { response_mode: "fragment", scope: "forbidden" },
          false,
          "invalid_scope",
          "The following scopes are invalid: forbidden",
          true,
        ],
        [
          { response_type: "token", redirect_uri: "https://untrusted.fixture.test/callback" },
          false,
          "unsupported_response_type",
          "response_type must be one of: code",
          false,
        ],
      ] as const) {
        const response = await control({
          ...(transport === "http"
            ? { action: "protocol-http", path: "/oauth2/authorize" }
            : { action: "authorize" }),
          headers: { accept: "application/json", cookie },
          query: { ...publicQuery, ...query },
        });
        expect(response.status).toBe(200);
        expect(response.headers.getSetCookie()).toEqual([]);
        const result = await response.json();
        const target = new URL(result.url, ctx.baseURL);
        expect(target.hash.length > 0).toBe(fragment);
        expect(target.searchParams.has("error")).toBe(!fragment);
        const fields = fragment ? new URLSearchParams(target.hash.slice(1)) : target.searchParams;
        expect(fields.has("code")).toBe(false);
        expect(fields.get("error")).toBe(error);
        expect(fields.get("error_description")).toBe(description);
        if (trusted) {
          expect(target.hostname).toBe("app.fixture.test");
          expect(fields.get("state")).toBe(publicQuery.state);
          expect(fields.get("iss")).toBe(`${ctx.baseURL}/api/auth`);
        } else {
          expect(target.origin).toBe(new URL(ctx.baseURL).origin);
          expect(target.pathname).toBe("/api/auth/error");
          expect(fields.has("state")).toBe(false);
          expect(fields.has("iss")).toBe(false);
        }
        errorChannels.push({ transport, query, result });
      }
    }
    const confirmationHints = [];
    for (const transport of ["private", "http"] as const) {
      for (const [hint, prompt] of [
        ["", undefined],
        ["bad-value", undefined],
        ["A".repeat(42) + "+", undefined],
        ["A".repeat(43) + "\n", undefined],
        ["bad-value", "select_account"],
      ] as const) {
        const response = await control({
          ...(transport === "http"
            ? { action: "protocol-http", path: "/oauth2/authorize" }
            : { action: "authorize" }),
          headers: { accept: "application/json", cookie },
          query: { ...publicQuery, dpop_jkt: hint, ...(prompt ? { prompt } : {}) },
        });
        expect(response.status).toBe(200);
        expect(response.headers.getSetCookie()).toEqual([]);
        const result = await response.json();
        const target = new URL(result.url, ctx.baseURL);
        expect(target.searchParams.has("code")).toBe(false);
        expect(target.hostname).toBe("app.fixture.test");
        expect(target.searchParams.get("error")).toBe("invalid_request");
        expect(target.searchParams.get("error_description")).toBe(
          "dpop_jkt: dpop_jkt must be a base64url-encoded SHA-256 JWK thumbprint",
        );
        confirmationHints.push({ transport, hint, prompt, result });
      }
      const hint = "A".repeat(42) + "B";
      const response = await control({
        ...(transport === "http"
          ? { action: "protocol-http", path: "/oauth2/authorize" }
          : { action: "authorize" }),
        headers: { accept: "application/json", cookie },
        query: { ...publicQuery, dpop_jkt: hint },
      });
      expect(response.status).toBe(200);
      const result = await response.json();
      const target = new URL(result.url, ctx.baseURL);
      const token = target.searchParams.get("code");
      expect(token).toMatch(/^[a-zA-Z0-9]{32}$/);
      const proof = await (await control({ action: "grant-row", token })).json();
      expect(proof.value.query.dpop_jkt).toBe(hint);
      expect(proof.value.userId).toBe(actualSession.user.id);
      expect(proof.value.sessionId).toBe(actualSession.session.id);
      confirmationHints.push({ transport, hint, result, proof });
    }
    const promptAuthorizations = [];
    for (const transport of ["private", "http"] as const) {
      for (const [prompt, description] of [
        ["", "prompt must include at least one value"],
        ["surprise", "unsupported prompt value: surprise"],
        ["login\tconsent", "unsupported prompt value: login\tconsent"],
        ["none login", "prompt=none cannot be combined with other prompt values"],
        ["none select_account", "prompt=none cannot be combined with other prompt values"],
        ["none login surprise", "unsupported prompt value: surprise"],
        ["\uFEFFlogin\u00A0", null],
      ] as const) {
        const response = await control({
          ...(transport === "http"
            ? { action: "protocol-http", path: "/oauth2/authorize" }
            : { action: "authorize" }),
          headers: { accept: "application/json", cookie },
          query: { ...publicQuery, prompt },
        });
        expect(response.status).toBe(200);
        expect(response.headers.getSetCookie()).toEqual([]);
        const result = await response.json();
        const target = new URL(result.url, ctx.baseURL);
        expect(target.searchParams.has("code")).toBe(false);
        if (description === null) {
          expect(target.pathname).toBe("/login");
          expect(target.searchParams.get("prompt")).toBe(prompt);
        } else {
          expect(target.hostname, `${ctx.baseURL}:${transport}:${prompt}`).toBe("app.fixture.test");
          expect(target.searchParams.get("error")).toBe("invalid_request");
          expect(target.searchParams.get("error_description")).toBe(`prompt: ${description}`);
          expect(target.searchParams.get("state")).toBe(publicQuery.state);
        }
        promptAuthorizations.push({ transport, prompt, result });
      }
      const response = await control({
        ...(transport === "http"
          ? { action: "protocol-http", path: "/oauth2/authorize" }
          : { action: "authorize" }),
        headers: { accept: "application/json", cookie },
        query: { ...publicQuery, prompt: "none none" },
      });
      expect(response.status).toBe(200);
      const result = await response.json();
      const target = new URL(result.url, ctx.baseURL);
      const token = target.searchParams.get("code");
      expect(target.hostname).toBe("app.fixture.test");
      expect(token).toMatch(/^[a-zA-Z0-9]{32}$/);
      const proof = await (await control({ action: "grant-row", token })).json();
      expect(proof.value.userId).toBe(actualSession.user.id);
      expect(proof.value.sessionId).toBe(actualSession.session.id);
      expect(proof.value.query.prompt).toBe("none none");
      promptAuthorizations.push({ transport, prompt: "none none", result, proof });
    }
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
      callbackQueries: ctx.snapshot(callbackQueries),
      loopbackRedirects: ctx.snapshot(loopbackRedirects),
      fetchRedirects: ctx.snapshot(fetchRedirects),
      errorChannels: ctx.snapshot(errorChannels),
      confirmationHints: ctx.snapshot(confirmationHints),
      promptAuthorizations: ctx.snapshot(promptAuthorizations),
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
