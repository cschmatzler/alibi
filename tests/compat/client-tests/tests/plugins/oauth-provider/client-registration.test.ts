import { createHash } from "node:crypto";

import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "OAuth registration scope policy preserves capability unions without granting them",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: object) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        redirect: "manual",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const signup = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("registration-scopes"),
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
    const results = [];
    for (const [mode, expected] of [
      ["fallback", "openid profile email offline_access"],
      ["custom-provider", "email profile openid"],
      ["allowed-empty", "openid profile email offline_access"],
      ["empty", ""],
      ["both-empty", ""],
      ["allowed-only", "profile"],
      ["default-only", "email"],
      ["union", "email profile"],
      ["allowed-fallback", "openid profile email offline_access"],
    ] as const) {
      const call = (input: object) =>
        control({ mode: `registration-scopes-${mode}`, headers: { cookie }, ...input });
      for (const scope of [undefined, "", " ", "email", "profile", "openid", "forbidden"]) {
        const before = (await (await call({ action: "registration-state" })).json()) as any;
        const response = await call({
          action: "register",
          body: {
            redirect_uris: ["https://app.fixture.test/callback"],
            token_endpoint_auth_method: "none",
            ...(scope === undefined ? {} : { scope }),
          },
        });
        const value = (await response.json()) as any;
        if (scope?.trim() && !expected.split(" ").includes(scope)) {
          expect(response.status).toBe(400);
          expect(value).toEqual({
            error: "invalid_scope",
            error_description: `cannot request scope ${scope}`,
          });
          expect(
            ((await (await call({ action: "registration-state" })).json()) as any).counts,
          ).toEqual(before.counts);
          results.push({ mode, scope: scope ?? null, status: response.status, value });
          continue;
        }
        expect(response.status).toBe(201);
        expect(value.scope).toBe(expected);
        const persisted = (await (
          await call({ action: "get", query: { client_id: value.client_id } })
        ).json()) as any;
        expect(persisted.scope).toBe(expected);
        const grants = await (
          await call({ action: "consent-row", clientId: value.client_id })
        ).json();
        expect(grants).toEqual([]);
        const use = [];
        if (mode === "union" && scope === "email") {
          for (const requested of ["profile", "openid"]) {
            const response = await call({
              action: "authorize",
              headers: { cookie, accept: "application/json" },
              query: {
                client_id: value.client_id,
                response_type: "code",
                redirect_uri: "https://app.fixture.test/callback",
                scope: requested,
                code_challenge: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                code_challenge_method: "S256",
              },
            });
            expect(response.status).toBe(200);
            const output = (await response.json()) as any;
            const url = new URL(output.url, ctx.baseURL);
            expect(url.pathname).toBe(requested === "profile" ? "/consent" : "/callback");
            expect(url.searchParams.get("error")).toBe(
              requested === "profile" ? null : "invalid_scope",
            );
            use.push(output);
          }
        }
        results.push({
          mode,
          scope: scope ?? null,
          status: response.status,
          value: ctx.snapshot(value),
          persisted: ctx.snapshot(persisted),
          grants,
          use: ctx.snapshot(use),
        });
      }
      const created = await call({
        body: { redirect_uris: ["https://app.fixture.test/callback"], scope: "openid" },
      });
      expect(created.status).toBe(201);
      const managed = (await created.json()) as any;
      expect(managed.scope).toBe("openid");
      for (const update of [
        { client_name: "Scopes unchanged" },
        { scope: "" },
        { scope: "profile" },
      ]) {
        const response = await call({
          action: "update",
          body: { client_id: managed.client_id, update },
        });
        expect(response.status).toBe(200);
        const value = (await response.json()) as any;
        expect(value.scope).toBe("scope" in update ? update.scope : "openid");
        results.push({ mode, update, value: ctx.snapshot(value) });
      }
    }
    const configurations = [];
    for (const [options, invalid] of [
      [{ clientRegistrationDefaultScopes: ["unknown"] }, "unknown"],
      [{ clientRegistrationAllowedScopes: ["unknown"] }, "unknown"],
      [{ clientRegistrationDefaultScopes: [""] }, ""],
      [
        {
          clientRegistrationDefaultScopes: [" email"],
          clientRegistrationAllowedScopes: ["first-invalid"],
        },
        "first-invalid",
      ],
      [{ clientRegistrationDefaultScopes: [], clientRegistrationAllowedScopes: [] }, null],
    ] as const) {
      const value = await (
        await control({ action: "registration-scopes-validation", options })
      ).json();
      expect(value).toEqual(
        invalid === null
          ? { valid: true }
          : {
              valid: false,
              message: `clientRegistrationAllowedScope ${invalid} not found in scopes`,
            },
      );
      configurations.push(value);
    }
    return { results, configurations };
  },
);
compatScenario(
  "Dynamic OAuth registration gates admission and persists owned and anonymous clients",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: unknown) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        redirect: "manual",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const signup = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("oauth-registration-owner"),
        name: "Owner",
        password: "password123",
      },
    });
    expect(signup.status).toBe(200);
    const owner = (await signup.json()) as any;
    const cookie = signup.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const rejected = [];
    for (const [mode, body, headers, status] of [
      [
        "public",
        { redirect_uris: ["https://app.fixture.test/callback"], client_name: " \uFEFF " },
        {},
        400,
      ],
      ["default", { redirect_uris: ["https://app.fixture.test/callback"] }, {}, 403],
      ["dynamic", { redirect_uris: ["https://app.fixture.test/callback"] }, {}, 401],
      ["public", { grant_types: ["client_credentials"] }, {}, 400],
      [
        "public",
        { redirect_uris: ["https://app.fixture.test/callback"], scope: "forbidden" },
        {},
        400,
      ],
      [
        "public",
        { redirect_uris: ["https://app.fixture.test/callback"], skip_consent: true },
        {},
        400,
      ],
      [
        "public",
        { redirect_uris: ["https://app.fixture.test/callback"], subject_type: "pairwise" },
        {},
        400,
      ],
      ["public", { redirect_uris: ["https://app.fixture.test/callback"], resources: 42 }, {}, 400],
      ["dynamic", { client_name: 42 }, { cookie }, 400],
    ] as const) {
      const r = await control({ action: "register", mode, body, headers });
      expect(r.status).toBe(status);
      rejected.push({ status, body: await r.json() });
    }
    const bearerRejections = [];
    for (const transport of ["private", "http"] as const) {
      for (const mode of transport === "http"
        ? (["public"] as const)
        : (["public", "dynamic"] as const)) {
        for (const [authorization, status, error, description] of [
          ["bEaReR unconfigured", 401, "invalid_token", "Invalid initial access token"],
          ["Bearer", 400, "invalid_request", "Malformed initial access token Authorization header"],
          [
            "Bearer first second",
            400,
            "invalid_request",
            "Malformed initial access token Authorization header",
          ],
        ] as const) {
          const response = await control({
            ...(transport === "http"
              ? {
                  action: "protocol-http",
                  path: "/oauth2/register",
                  method: "POST",
                  contentType: "application/json",
                }
              : { action: "register" }),
            mode,
            headers: { authorization },
            body: {
              redirect_uris: ["https://app.fixture.test/callback"],
              token_endpoint_auth_method: "none",
            },
          });
          expect(response.status, `${ctx.baseURL}:${transport}:${mode}:${authorization}`).toBe(
            status,
          );
          expect(response.headers.get("www-authenticate")).toBe(`Bearer error="${error}"`);
          expect(response.headers.get("cache-control")).toBe("no-store");
          expect(response.headers.get("pragma")).toBe("no-cache");
          expect(response.headers.getSetCookie()).toEqual([]);
          const body = await response.json();
          expect(body).toEqual({ error, error_description: description });
          bearerRejections.push({ transport, mode, authorization, status, body });
        }
      }
    }
    const clients = [];
    const rows = [];
    for (const [mode, publicClient, headers] of [
      ["dynamic", false, { cookie }],
      ["public", true, {}],
    ] as const) {
      const start = Math.floor(Date.now() / 1000);
      const r = await control({
        action: "register",
        mode,
        headers: {
          ...headers,
          authorization: publicClient ? "Basic ignored" : "Bearer unconfigured",
        },
        body: {
          client_name: publicClient ? "\u0085" : "Owned dynamic client",
          redirect_uris: ["https://app.fixture.test/callback"],
          scope: "email",
          token_endpoint_auth_method: publicClient ? "none" : "client_secret_basic",
          user_id: "forged",
          client_id: "forged",
        },
      });
      expect(r.status).toBe(201);
      expect(r.headers.get("cache-control")).toBe("no-store");
      const value = (await r.json()) as any;
      expect(value.client_name).toBe(publicClient ? "\u0085" : "Owned dynamic client");
      expect(value.scope).toBe("openid profile email offline_access");
      expect(value.client_id_issued_at).toBeGreaterThanOrEqual(start);
      expect(value.client_id_issued_at).toBeLessThanOrEqual(Math.floor(Date.now() / 1000));
      expect(value.client_id).toMatch(/^[a-zA-Z]{32}$/);
      const row = (await (
        await control({ action: "row", clientId: value.client_id })
      ).json()) as any;
      expect(row.clientName).toBe(value.client_name);
      if (publicClient) {
        expect(value).not.toHaveProperty("user_id");
        expect(value).not.toHaveProperty("client_secret");
        expect(row.userId).toBeNull();
        expect(row.client_secret).toBeNull();
      } else {
        expect(value.user_id).toBe(owner.user.id);
        expect(row.userId).toBe(owner.user.id);
        expect(value.client_secret).toMatch(/^[a-zA-Z]{32}$/);
        expect(row.client_secret).toBe(
          createHash("sha256").update(value.client_secret).digest("base64url"),
        );
      }
      clients.push(value);
      rows.push(row);
    }
    const registrationState = async () =>
      (await (await control({ action: "registration-state" })).json()) as any;
    const tokenBody = {
      client_name: "Token client",
      redirect_uris: [" https://app.fixture.test/callback "],
      grant_types: [" client_credentials "],
      token_endpoint_auth_method: " client_secret_basic ",
      subject_type: "public",
      resources: [],
      user_id: "forged",
      reference_id: "forged",
      client_id: "forged",
    };
    const parsedMetadata = {
      client_name: "Token client",
      redirect_uris: ["https://app.fixture.test/callback"],
      grant_types: ["client_credentials"],
      token_endpoint_auth_method: "client_secret_basic",
      subject_type: "public",
      resources: [],
    };
    const tokenResults = [];
    for (const transport of ["private", "http"] as const) {
      const register = (mode: string, body: object, headers: object) =>
        control({
          ...(transport === "http"
            ? {
                action: "protocol-http",
                path: "/oauth2/register",
                method: "POST",
                contentType: "application/json",
              }
            : { action: "register" }),
          mode,
          body,
          headers,
        });
      const before = await registrationState();
      for (const mode of ["token-dynamic", "token-public"]) {
        for (const [authorization, status, expectedBody, invoked] of [
          [
            "Bearer rejected",
            401,
            { error: "invalid_token", error_description: "Invalid initial access token" },
            true,
          ],
          [
            "Bearer",
            400,
            {
              error: "invalid_request",
              error_description: "Malformed initial access token Authorization header",
            },
            false,
          ],
          [
            "Bearer first second",
            400,
            {
              error: "invalid_request",
              error_description: "Malformed initial access token Authorization header",
            },
            false,
          ],
          [
            "Bearer ordinary-error",
            500,
            { error: "server_error", error_description: "Initial access token validation failed" },
            true,
          ],
          [
            "Bearer api-error",
            429,
            { error: "slow_down", error_description: "Operator registration limit" },
            true,
          ],
          ["Bearer api-empty", 307, null, true],
          ["Bearer forbidden", 403, { message: "Operator forbids registration" }, true],
        ] as const) {
          const callsBefore = (await registrationState()).calls.length;
          const response = await register(mode, tokenBody, {
            authorization,
            "x-registration-caller": "fixture",
          });
          expect(response.status, `${ctx.baseURL}:${transport}:${mode}:${authorization}`).toBe(
            status,
          );
          expect(response.headers.get("cache-control")).toBe("no-store");
          expect(response.headers.get("pragma")).toBe("no-cache");
          expect(response.headers.getSetCookie()).toEqual([]);
          expect(response.headers.get("www-authenticate")).toBe(
            status === 400 || status === 401
              ? `Bearer error="${status === 400 ? "invalid_request" : "invalid_token"}"`
              : null,
          );
          if (status === 429) {
            expect(response.headers.get("retry-after")).toBe("17");
            expect(response.headers.get("x-registration-policy")).toBe("limited");
          }
          if (status === 307) {
            expect(response.headers.get("location")).toBe("https://operator.fixture.test/register");
            expect(response.headers.get("content-type")).toBe("application/json");
          }
          const text = await response.text();
          const responseBody = text ? JSON.parse(text) : null;
          expect(responseBody).toEqual(expectedBody);
          const state = await registrationState();
          expect(state.counts).toEqual(before.counts);
          expect(state.calls).toHaveLength(callsBefore + Number(invoked));
          if (invoked) {
            expect(state.calls.at(-1)).toEqual({
              token: authorization.slice("Bearer ".length),
              authorization,
              caller: "fixture",
              clientMetadata: parsedMetadata,
            });
          }
          tokenResults.push({
            transport,
            mode,
            authorization,
            status: response.status,
            body: responseBody,
          });
        }
      }
      for (const [body, headers, status] of [
        [{ client_name: 42 }, { authorization: "Bearer accepted" }, 400],
        [tokenBody, {}, 401],
        [tokenBody, { authorization: "Basic ignored" }, 401],
      ] as const) {
        const callsBefore = (await registrationState()).calls.length;
        const response = await register("token-dynamic", body, headers);
        expect(response.status).toBe(status);
        const state = await registrationState();
        expect(state.calls).toHaveLength(callsBefore);
        expect(state.counts).toEqual(before.counts);
      }
      for (const [mode, token, reference] of [
        ["token-dynamic", "accepted", null],
        ["token-public", "reference", "registration-reference"],
      ] as const) {
        const authorization = `bEaReR ${token}`;
        const callsBefore = (await registrationState()).calls.length;
        const response = await register(mode, tokenBody, {
          authorization,
          "x-registration-caller": "fixture",
        });
        expect(response.status).toBe(201);
        const value = (await response.json()) as any;
        expect(value).not.toHaveProperty("user_id");
        expect(value.reference_id ?? null).toBe(reference);
        expect(value.client_secret).toMatch(/^[a-zA-Z]{32}$/);
        const state = await registrationState();
        expect(state.calls).toHaveLength(callsBefore + 1);
        expect(state.calls.at(-1)).toEqual({
          token,
          authorization,
          caller: "fixture",
          clientMetadata: parsedMetadata,
        });
        const row = (await (
          await control({ action: "row", clientId: value.client_id })
        ).json()) as any;
        expect(row.userId).toBeNull();
        expect(row.referenceId).toBe(reference);
        expect(row.client_secret).toBe(
          createHash("sha256").update(value.client_secret).digest("base64url"),
        );
        const authenticated = await control({
          action: "authenticate-client",
          body: { client_id: value.client_id, boundGrant: "client_credentials" },
          headers: {
            authorization: `Basic ${Buffer.from(`${value.client_id}:${value.client_secret}`).toString("base64")}`,
          },
        });
        expect(authenticated.status).toBe(200);
        expect(((await authenticated.json()) as any).clientId).toBe(value.client_id);
        tokenResults.push({ transport, mode, value: ctx.snapshot(value), row: ctx.snapshot(row) });
      }
      for (const [mode, headers, userId] of [
        ["token-dynamic", { cookie, authorization: "Bearer ordinary-error" }, owner.user.id],
        ["token-public", { authorization: "Basic ignored" }, null],
      ] as const) {
        const callsBefore = (await registrationState()).calls.length;
        const response = await register(
          mode,
          {
            redirect_uris: ["https://app.fixture.test/callback"],
            token_endpoint_auth_method: "none",
          },
          headers,
        );
        expect(response.status).toBe(201);
        const value = (await response.json()) as any;
        expect(value.user_id ?? null).toBe(userId);
        expect(value).not.toHaveProperty("reference_id");
        expect((await registrationState()).calls).toHaveLength(callsBefore);
        tokenResults.push({ transport, mode, bypass: ctx.snapshot(value) });
      }
    }
    return {
      rejected,
      bearerRejections,
      clients: ctx.snapshot(clients),
      rows: ctx.snapshot(rows),
      tokenResults,
    };
  },
);
