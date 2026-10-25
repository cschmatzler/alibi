import { createHash } from "node:crypto";

import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
import { applicationHeaders } from "../../../support/trace";
compatScenario(
  "Configured response fields decorate real code and refresh grants before authority writes",
  async (ctx) => {
    const actor = ctx.actor();
    const publicActor = ctx.actor("public", "oauth-response-fields");
    const tokenEndpoint = `${ctx.baseURL}/__test/profiles/oauth-response-fields/api/auth/oauth2/token`;
    const control = (input: object) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "response-fields", ...input }),
      });
    // Success, callback failures and pre-callback denials all use the actual
    // public router; control routes only arrange and inspect genuine authority.
    const tokenRequest = (input: Record<string, string>) =>
      publicActor.fetch(tokenEndpoint, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams(input),
      });
    const state = async (value: string, reset = false) =>
      (await control({ action: "response-fields-state", value, reset })).json() as Promise<any>;
    await state("success", true);
    const email = ctx.uniqueEmail("response-owner");
    const signup = await control({
      action: "signup",
      body: { email, name: "Owner", password: "password123" },
    });
    expect(signup.status).toBe(200);
    const owner = (await signup.json()) as any;
    const cookie = signup.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const session = (await (
      await control({ action: "session", headers: { cookie } })
    ).json()) as any;
    const created = await control({
      action: "admin-create",
      headers: { cookie },
      body: {
        client_name: "Response fields",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "profile email offline_access",
        token_endpoint_auth_method: "none",
        skip_consent: true,
        metadata: { tenant: "application" },
      },
    });
    expect(created.status).toBe(201);
    const client = (await created.json()) as any;
    const resource = "https://api.fixture.test/response-fields";
    const registered = await control({
      action: "resource-create",
      headers: { cookie },
      body: { identifier: resource, allowedScopes: ["email", "offline_access"] },
    });
    expect(registered.status).toBe(200);
    const linked = await control({
      action: "resource-link",
      headers: { cookie },
      params: { identifier: resource, client_id: client.client_id },
    });
    expect(linked.status).toBe(200);
    const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const counts = async () =>
      (await control({ action: "authority-counts", sessionId: session.session.id })).json();
    let issued: any;
    const errors: {
      mode: string;
      status: number;
      headers: ReturnType<typeof applicationHeaders>;
      text: string;
    }[] = [];
    const recordFailure = async (response: Response, mode: string) => {
      expect(response.status).toBe(
        { ordinary: 500, api: 422, forbidden: 403, upstream: 409 }[mode],
      );
      const text = await response.text();
      if (mode === "ordinary") {
        expect(text).toBe("");
        for (const name of ["content-type", "cache-control", "pragma"]) {
          expect(response.headers.get(name)).toBeNull();
        }
      } else {
        expect(JSON.parse(text)).toEqual(
          {
            api: { code: "RESPONSE_REJECTED", message: "Operator response denied" },
            forbidden: { message: "Operator response forbidden" },
            upstream: { code: "RESPONSE_CONFLICT", message: "Operator response conflict" },
          }[mode],
        );
        expect(response.headers.get("content-type")).toBe("application/json");
        expect(response.headers.get("cache-control")).toBe("no-store");
        expect(response.headers.get("pragma")).toBe("no-cache");
      }
      errors.push({
        mode,
        status: response.status,
        headers: applicationHeaders(response.headers),
        text,
      });
    };
    for (const mode of ["ordinary", "api", "forbidden", "upstream", "success"]) {
      await state(mode);
      const grant = await control({
        action: "authorize",
        headers: { cookie, accept: "application/json" },
        query: {
          client_id: client.client_id,
          response_type: "code",
          redirect_uri: "https://app.fixture.test/callback",
          scope: "profile email offline_access",
          resource,
          state: "response-state",
          code_challenge: challenge,
          code_challenge_method: "S256",
        },
      });
      expect(grant.status).toBe(200);
      const code = new URL(((await grant.json()) as any).url).searchParams.get("code");
      expect(code).toBeTruthy();
      const input = {
        grant_type: "authorization_code",
        client_id: client.client_id,
        code: code!,
        code_verifier: verifier,
        redirect_uri: "https://app.fixture.test/callback",
      };
      const priorCalls = (await state(mode)).calls.length;
      if (mode === "ordinary") {
        const { code_verifier: _, ...invalid } = input;
        const denied = await tokenRequest(invalid);
        expect(denied.status).toBe(400);
        expect(await denied.json()).toEqual({
          error: "invalid_request",
          error_description: "Either code_verifier or client_secret is required",
        });
        expect((await state(mode)).calls).toHaveLength(priorCalls);
        expect(await counts()).toEqual({ access: 0, refresh: 0 });
      }
      const response = await tokenRequest(input);
      expect((await state(mode)).calls).toHaveLength(priorCalls + 1);
      if (mode === "success") {
        expect(response.status).toBe(200);
        issued = await response.json();
        expect(issued.application_metadata).toEqual({ service: "billing", plan: "pro" });
      } else {
        await recordFailure(response, mode);
        expect(await counts()).toEqual({ access: 0, refresh: 0 });
        const replay = await tokenRequest(input);
        expect(replay.status).toBe(400);
        expect(await replay.json()).toEqual({
          error: "invalid_grant",
          error_description: "invalid code",
        });
        expect((await state(mode)).calls).toHaveLength(priorCalls + 1);
      }
    }
    const receipt = {
      grant: "authorization_code",
      userId: owner.user.id,
      email,
      scopes: ["email", "offline_access"],
      metadata: { tenant: "application" },
      verification: {
        type: "authorization_code",
        userId: owner.user.id,
        sessionId: session.session.id,
        scope: "profile email offline_access",
        state: "response-state",
        clientId: client.client_id,
        challenge,
      },
    };
    expect((await state("success")).calls).toEqual(Array(5).fill(receipt));
    const original = issued.refresh_token;
    const originalRow = (await (
      await control({ action: "token-row", kind: "refresh", token: original })
    ).json()) as any;
    for (const mode of ["ordinary", "api", "forbidden", "upstream", "success"]) {
      await state(mode);
      const input = {
        grant_type: "refresh_token",
        client_id: client.client_id,
        refresh_token: original,
        scope: "email",
      };
      const priorCalls = (await state(mode)).calls.length;
      if (mode === "ordinary") {
        const denied = await tokenRequest({ ...input, scope: "profile" });
        expect(denied.status).toBe(400);
        expect(await denied.json()).toEqual({
          error: "invalid_scope",
          error_description: "unable to issue scope profile",
        });
        expect((await state(mode)).calls).toHaveLength(priorCalls);
      }
      const response = await tokenRequest(input);
      expect((await state(mode)).calls).toHaveLength(priorCalls + 1);
      if (mode === "success") {
        expect(response.status).toBe(200);
        issued = await response.json();
      } else {
        await recordFailure(response, mode);
        expect(await counts()).toEqual({ access: 1, refresh: 1 });
        const row = (await (
          await control({ action: "token-row", kind: "refresh", token: original })
        ).json()) as any;
        expect(row.revoked).toBeNull();
        expect(row).toEqual(originalRow);
      }
    }
    const refreshReceipt = {
      grant: "refresh_token",
      userId: owner.user.id,
      email,
      scopes: ["email"],
      metadata: { tenant: "application" },
      verification: null,
    };
    expect((await state("success")).calls.slice(5)).toEqual(Array(5).fill(refreshReceipt));
    expect(issued.application_metadata).toEqual({ service: "billing", plan: "pro" });
    expect(issued.per_request).toBe("global");
    expect(issued.toString).toBe("application-toString");
    expect(issued["__proto__"]).toEqual({ applicationPrototype: true });
    expect(issued.nullable).toBeNull();
    expect(issued.scope).toBe("email");
    expect(issued.token_type).toBe("Bearer");
    expect(issued.expires_in).toBe(3600);
    expect(issued.id_token).toBeUndefined();
    expect(issued.refresh_token).not.toBe(original);
    const rotated = (await (
      await control({ action: "token-row", kind: "refresh", token: original })
    ).json()) as any;
    expect(rotated.revoked).not.toBeNull();
    expect(rotated.rotatedAt).not.toBeNull();
    for (const [key, kind] of [
      ["access_token", "access"],
      ["refresh_token", "refresh"],
    ]) {
      expect(issued[key!]).toMatch(/^[A-Za-z]{32}$/);
      const row = (await (
        await control({ action: "token-row", kind, token: issued[key!] })
      ).json()) as any;
      expect(row.clientId).toBe(client.client_id);
      expect(row.userId).toBe(owner.user.id);
      expect(row.sessionId).toBe(session.session.id);
      expect(row.authorizationCodeId).toBe(originalRow.authorizationCodeId);
      expect(row.scopes).toEqual(["email"]);
      if (kind === "refresh") expect(row.resources).toEqual([resource]);
      if (kind === "access") expect(Date.parse(row.expiresAt) / 1000).toBe(issued.expires_at);
    }
    const response = await control({
      action: "issue-tokens",
      body: {
        responseFieldsProfile: true,
        clientId: client.client_id,
        grantType: "urn:native:response",
        params: {
          scopes: ["email"],
          tokenResponse: {
            per_request: "native",
            access_token: "injected",
            refresh_token: "injected",
            id_token: "injected",
          },
        },
      },
    });
    expect(response.status).toBe(200);
    const machine = (await response.json()) as any;
    expect(machine.per_request).toBe("native");
    expect(machine.application_metadata).toEqual({ service: "billing", plan: "pro" });
    expect(machine.scope).toBe("email");
    expect(machine.token_type).toBe("Bearer");
    expect(machine.id_token).toBeUndefined();
    expect(machine.refresh_token).toBeUndefined();
    const machineRow = (await (
      await control({ action: "token-row", token: machine.access_token })
    ).json()) as any;
    expect(machineRow.userId ?? null).toBeNull();
    const calls = (await state("success")).calls;
    expect(calls.at(-1)).toEqual({
      grant: "urn:native:response",
      userId: null,
      email: null,
      scopes: ["email"],
      metadata: { tenant: "application" },
      verification: null,
    });
    return ctx.snapshot({
      owner: owner.user,
      calls,
      errors,
      application: issued.application_metadata,
      perRequest: machine.per_request,
    });
  },
);
compatScenario(
  "PKCE code exchange persists a protected token and replay removes the issued token",
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
      body: { email: ctx.uniqueEmail("token-owner"), name: "Owner", password: "password123" },
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
        client_name: "Token client",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "email",
        token_endpoint_auth_method: "none",
        skip_consent: true,
      },
    });
    expect(created.status).toBe(201);
    const id = ((await created.json()) as any).client_id;
    const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const grant = await control({
      action: "authorize",
      headers: { cookie, accept: "application/json" },
      query: {
        client_id: id,
        response_type: "code",
        redirect_uri: "https://app.fixture.test/callback",
        scope: "email",
        state: "token-state",
        code_challenge: challenge,
        code_challenge_method: "S256",
      },
    });
    expect(grant.status).toBe(200);
    const callback = new URL(((await grant.json()) as any).url);
    expect(callback.pathname).toBe("/callback");
    expect(callback.searchParams.get("state")).toBe("token-state");
    const code = callback.searchParams.get("code");
    expect(code).toBeTruthy();
    const input = {
      grant_type: "authorization_code",
      client_id: id,
      code,
      code_verifier: verifier,
      redirect_uri: "https://app.fixture.test/callback",
    };
    const response = await control({ action: "token", body: input });
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("pragma")).toBe("no-cache");
    const token = (await response.json()) as any;
    expect(token.scope).toBe("email");
    expect(token.token_type).toBe("Bearer");
    expect(token.expires_in).toBe(3600);
    expect(token.access_token).toMatch(/^[A-Za-z]{32}$/);
    expect(token.refresh_token).toBeUndefined();
    expect(token.id_token).toBeUndefined();
    const receipt = await control({ action: "token-row", token: token.access_token });
    expect(receipt.status).toBe(200);
    const stored = (await receipt.json()) as any;
    expect(stored.clientId).toBe(id);
    expect(stored.scopes).toEqual(["email"]);
    expect(stored.token).toBe(createHash("sha256").update(token.access_token).digest("base64url"));
    expect(stored.authorizationCodeId).toBe(createHash("sha256").update(code!).digest("base64url"));
    expect(Date.parse(stored.expiresAt) - Date.parse(stored.createdAt)).toBe(3600_000);
    expect(Date.parse(stored.expiresAt) / 1000).toBe(token.expires_at);
    const replay = await control({ action: "token", body: input });
    expect(replay.status).toBe(400);
    expect(await replay.json()).toEqual({
      error: "invalid_grant",
      error_description: "invalid code",
    });
    const removed = await control({ action: "token-row", token: token.access_token });
    expect(await removed.json()).toBeNull();

    const denials = [];
    const session = (await (
      await control({ action: "session", headers: { cookie } })
    ).json()) as any;
    let tokenRequestNumber = 0;
    for (const [method, required] of [
      ["none", false],
      ["client_secret_post", undefined],
      ["client_secret_post", true],
      ["client_secret_post", false],
    ] as const) {
      const publicClient = method === "none";
      const created = await control({
        action: "admin-create",
        headers: { cookie },
        body: {
          client_name: "Precedence client",
          redirect_uris: ["https://app.fixture.test/callback"],
          scope: "email",
          token_endpoint_auth_method: method,
          require_pkce: required,
          skip_consent: true,
        },
      });
      expect(created.status).toBe(201);
      const client = (await created.json()) as any;
      const pkceRequired = publicClient || required !== false;
      for (const [name, bound] of [
        ["missing", true],
        ["empty", true],
        ["malformed", true],
        ["redirect", true],
        ["secret", true],
        ["code", true],
        ["success", true],
        ["missing", false],
        ["empty", false],
        ["malformed", false],
      ] as const) {
        if ((!bound && pkceRequired) || (name === "secret" && publicClient)) continue;
        const produced = await control({
          action: "authorize",
          headers: { cookie, accept: "application/json" },
          query: {
            client_id: client.client_id,
            response_type: "code",
            redirect_uri: "https://app.fixture.test/callback",
            scope: "email",
            state: "token-state",
            ...(bound ? { code_challenge: challenge, code_challenge_method: "S256" } : {}),
          },
        });
        expect(produced.status).toBe(200);
        const callback = new URL(((await produced.json()) as any).url);
        const grantCode = callback.searchParams.get("code");
        expect(grantCode).toBeTruthy();
        const valid: Record<string, string> = {
          grant_type: "authorization_code",
          client_id: client.client_id,
          code: grantCode!,
          ...(!publicClient ? { client_secret: client.client_secret } : {}),
          ...(bound ? { code_verifier: verifier } : {}),
          redirect_uri: "https://app.fixture.test/callback",
        };
        const input = { ...valid };
        delete input.code_verifier;
        if (name === "empty") input.code_verifier = "";
        if (name === "malformed") input.code_verifier = "!";
        if (name === "redirect") input.redirect_uri = "https://app.fixture.test/other";
        if (name === "secret") input.client_secret = "wrong-secret";
        if (name === "code") input.code = "unknown-code";
        if (name === "success") Object.assign(input, valid);
        const exchange = (body: Record<string, string>) =>
          control({
            action: "protocol-http",
            path: "/oauth2/token",
            method: "POST",
            body,
            headers: { "x-forwarded-for": `192.0.2.${++tokenRequestNumber}` },
          });
        const response = await exchange(input);
        const early = publicClient && ["missing", "empty", "redirect", "code"].includes(name);
        const success = name === "success" || (!bound && name !== "malformed");
        const [status, error, description] = success
          ? [200, "", ""]
          : early
            ? [400, "invalid_request", "Either code_verifier or client_secret is required"]
            : name === "redirect"
              ? [400, "invalid_grant", "redirect_uri mismatch"]
              : name === "code"
                ? [400, "invalid_grant", "invalid code"]
                : name === "secret"
                  ? [400, "invalid_client", "invalid client_secret"]
                  : name === "malformed"
                    ? bound
                      ? [400, "invalid_grant", "code verification failed"]
                      : [
                          400,
                          "invalid_request",
                          "code_verifier provided but PKCE was not used in authorization",
                        ]
                    : pkceRequired
                      ? [400, "invalid_request", "PKCE is required for this client"]
                      : [
                          400,
                          "invalid_request",
                          "code_verifier required because PKCE was used in authorization",
                        ];
        expect(response.status, `${method}/${required}/${name}/${bound}`).toBe(status);
        expect(response.headers.get("cache-control")).toBe("no-store");
        expect(response.headers.get("pragma")).toBe("no-cache");
        expect(response.headers.get("content-type")).toBe("application/json");
        const value = (await response.json()) as any;
        if (!success) expect(value).toEqual({ error, error_description: description });
        // Client authentication precedes the code lookup, so a rejected secret
        // leaves the one-time code unconsumed.
        const retained = early || name === "code" || name === "secret";
        let issued = success ? value : null;
        if (!success) {
          const retry = await exchange(valid);
          expect(retry.status).toBe(retained ? 200 : 400);
          if (retained) {
            issued = await retry.json();
          } else {
            expect(await retry.json()).toEqual({
              error: "invalid_grant",
              error_description: "invalid code",
            });
          }
        }
        if (issued) {
          const row = (await (
            await control({ action: "token-row", token: issued.access_token })
          ).json()) as any;
          expect(row.authorizationCodeId).toBe(
            createHash("sha256").update(grantCode!).digest("base64url"),
          );
          const replayInput = { ...valid };
          delete replayInput.code_verifier;
          const replay = await exchange(replayInput);
          expect(replay.status).toBe(400);
          expect(await replay.json()).toEqual(
            publicClient
              ? {
                  error: "invalid_request",
                  error_description: "Either code_verifier or client_secret is required",
                }
              : { error: "invalid_grant", error_description: "invalid code" },
          );
          const remaining = await (
            await control({ action: "token-row", token: issued.access_token })
          ).json();
          if (publicClient) expect(remaining).not.toBeNull();
          else expect(remaining).toBeNull();
          const final = await exchange(valid);
          expect(final.status).toBe(400);
          expect(await final.json()).toEqual({
            error: "invalid_grant",
            error_description: "invalid code",
          });
          expect(
            await (await control({ action: "token-row", token: issued.access_token })).json(),
          ).toBeNull();
        }
        expect(
          await (
            await control({ action: "authority-counts", sessionId: session.session.id })
          ).json(),
        ).toEqual({ access: 0, refresh: 0 });
        denials.push({
          method,
          required: required ?? null,
          name,
          bound,
          status,
          error,
          description,
          headers: applicationHeaders(response.headers),
          retained,
        });
      }
    }
    return ctx.snapshot({
      owner: owner.user,
      denials,
      scope: token.scope,
      type: token.token_type,
      lifetime: token.expires_in,
      persistedScopes: stored.scopes,
      replay: replay.status,
      removed: true,
    });
  },
);
compatScenario(
  "Unknown token-endpoint clients are invalid_client before code or refresh-token lookup",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: unknown) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const results = [];
    for (const [name, body, authorization, status, challenge] of [
      [
        "code-post",
        {
          grant_type: "authorization_code",
          client_id: "unknown-client",
          client_secret: "secret",
          code: "not-a-real-code",
          redirect_uri: "https://app.fixture.test/callback",
        },
        undefined,
        400,
        null,
      ],
      [
        "refresh-public",
        {
          grant_type: "refresh_token",
          client_id: "unknown-client",
          refresh_token: "not-a-real-refresh-token",
        },
        undefined,
        400,
        null,
      ],
      [
        "refresh-basic",
        { grant_type: "refresh_token", refresh_token: "not-a-real-refresh-token" },
        `Basic ${Buffer.from("unknown-client:secret").toString("base64")}`,
        401,
        "Basic",
      ],
    ] as const) {
      const response = await control({
        action: "protocol-http",
        path: "/oauth2/token",
        method: "POST",
        body,
        headers: authorization ? { authorization } : {},
      });
      expect(response.status, name).toBe(status);
      expect(response.headers.get("www-authenticate"), name).toBe(challenge);
      const value = await response.json();
      expect(value, name).toEqual({
        error: "invalid_client",
        error_description: "client not found",
      });
      results.push({ name, status: response.status, value });
    }
    return ctx.snapshot({ results });
  },
);
