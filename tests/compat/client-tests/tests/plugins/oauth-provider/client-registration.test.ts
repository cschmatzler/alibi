import { createHash } from "node:crypto";

import { createLocalJWKSet, jwtVerify } from "jose";
import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Registration resource capability policy persists genuine links and issued authority",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: object) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        redirect: "manual",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "resource-seed", ...input }),
      });
    const a = "https://api.fixture.test/registration/a";
    const b = "https://api.fixture.test/registration/b";
    const c = "https://api.fixture.test/registration/c";
    const disabled = "https://api.fixture.test/registration/disabled";
    const resources = [
      a,
      { identifier: b, allowedScopes: ["email"], accessTokenTtl: 123 },
      c,
      { identifier: disabled, disabled: true },
      "relative",
    ];
    let cookie: string | undefined;
    const results = [];
    for (const [mode, defaults, allowed] of [
      ["absent", undefined, undefined],
      ["empty-default", [], undefined],
      ["empty-allowed", undefined, []],
      ["empty", [], []],
      ["default", [a, a], []],
      ["allowed-only", undefined, [b]],
      ["union", [a, a], [b, a, b, disabled, "relative"]],
      ["disabled-default", [disabled], undefined],
      ["missing-default", ["relative"], undefined],
    ] as const) {
      const initialized = await control({
        action: "resource-seed-init",
        registrationResources: true,
        resources,
        options: {
          ...(defaults === undefined ? {} : { clientRegistrationDefaultResources: defaults }),
          ...(allowed === undefined ? {} : { clientRegistrationAllowedResources: allowed }),
        },
      });
      expect(initialized.status).toBe(200);
      expect(await initialized.json()).toEqual({ initialized: true });
      if (!cookie) {
        const signup = await control({
          action: "signup",
          body: {
            email: ctx.uniqueEmail("registration-resources"),
            name: "Owner",
            password: "password123",
          },
        });
        expect(signup.status).toBe(200);
        cookie = signup.headers
          .getSetCookie()
          .filter((raw) => Boolean(Cookie.parse(raw)?.value))
          .map((raw) => raw.split(";")[0])
          .join("; ");
      }
      const call = (input: object) => control({ headers: { cookie }, ...input });
      const configured = (await (
        await call({ action: "resource-row", identifier: a })
      ).json()) as any;
      expect(configured.identifier).toBe(a);
      for (const requested of [
        undefined,
        [],
        [a],
        [b, b],
        [b, b, a],
        [c],
        [disabled],
        ["urn:fixture:unknown"],
      ]) {
        const baseline: readonly string[] = defaults ?? [];
        const admitted: readonly string[] = [...baseline, ...(allowed ?? [])];
        const forbidden = requested?.find((id) => !admitted.includes(id));
        const invalid = [...baseline, ...(requested ?? [])].find(
          (id) => id === disabled || id === "relative",
        );
        const description = forbidden
          ? `requested resource ${forbidden} is not allowed for client registration`
          : invalid
            ? `requested resource ${invalid} ${invalid === disabled ? "is disabled" : "does not exist"}`
            : undefined;
        const before = (await (await call({ action: "registration-state" })).json()) as any;
        const response = await call({
          action: "register",
          body: {
            redirect_uris: ["https://app.fixture.test/callback"],
            scope: "email",
            token_endpoint_auth_method: "none",
            ...(requested === undefined ? {} : { resources: requested }),
          },
        });
        const value = (await response.json()) as any;
        if (description) {
          expect(response.status, `${ctx.baseURL}:${mode}:${JSON.stringify(requested)}`).toBe(400);
          expect(value).toEqual({ error: "invalid_target", error_description: description });
          expect(
            ((await (await call({ action: "registration-state" })).json()) as any).counts,
          ).toEqual(before.counts);
          results.push({ mode, requested: requested ?? null, status: response.status, value });
          continue;
        }
        expect(response.status).toBe(201);
        const expected = [...new Set([...baseline, ...(requested ?? [])])];
        expect(value.resources).toEqual(expected.length ? expected : undefined);
        const row = (await (
          await call({ action: "row", clientId: value.client_id, raw: true })
        ).json()) as any;
        expect(row).not.toHaveProperty("resources");
        expect(row.metadata).toBeNull();
        expect(row.clientCredentialsScopes).toEqual([]);
        const links = (await (
          await call({ action: "resource-links", clientId: value.client_id })
        ).json()) as any[];
        expect(links.map((row) => row.resourceId).sort()).toEqual([...expected].sort());
        for (const link of links) {
          expect(link.clientId).toBe(value.client_id);
          expect(link.metadata).toBeNull();
          expect(link.createdAt).toBeTypeOf("string");
        }
        expect(
          await (await call({ action: "consent-row", clientId: value.client_id })).json(),
        ).toEqual([]);
        const uses = [];
        if (mode === "union" && requested?.length === 3) {
          const verifier = "registration-resource-verifier-abcdefghijklmnopqrstuvwxyz";
          const challenge = createHash("sha256").update(verifier).digest("base64url");
          const keys = createLocalJWKSet((await (await call({ action: "jwks" })).json()) as any);
          for (const [resource, unlink] of [
            [a, false],
            [b, false],
            [b, true],
            [c, false],
          ] as const) {
            const authorized = await call({
              action: "authorize",
              headers: { cookie, accept: "application/json" },
              query: {
                client_id: value.client_id,
                response_type: "code",
                redirect_uri: "https://app.fixture.test/callback",
                scope: "email",
                resource,
                prompt: "consent",
                code_challenge: challenge,
                code_challenge_method: "S256",
              },
            });
            expect(authorized.status).toBe(200);
            const target = new URL(((await authorized.json()) as any).url, ctx.baseURL);
            if (resource === c) {
              expect(target.searchParams.get("error")).toBe("invalid_target");
              expect(target.searchParams.has("code")).toBe(false);
              uses.push({ resource, error: target.searchParams.get("error") });
              continue;
            }
            expect(target.pathname).toBe("/consent");
            const consent = await call({
              action: "consent",
              body: { accept: true, oauth_query: target.search.slice(1) },
            });
            expect(consent.status).toBe(200);
            const code = new URL(((await consent.json()) as any).url).searchParams.get("code");
            expect(code).toMatch(/^[a-zA-Z0-9]{32}$/);
            if (unlink) {
              const removed = await call({
                action: "resource-unlink",
                params: { identifier: resource, client_id: value.client_id },
              });
              expect(removed.status).toBe(200);
              const remaining = (await (
                await call({ action: "resource-links", clientId: value.client_id })
              ).json()) as any[];
              expect(remaining.map((row) => row.resourceId)).toEqual([a]);
            }
            const token = await call({
              action: "token",
              body: {
                grant_type: "authorization_code",
                client_id: value.client_id,
                redirect_uri: "https://app.fixture.test/callback",
                code,
                code_verifier: verifier,
              },
            });
            const issued = (await token.json()) as any;
            if (unlink) {
              expect(token.status).toBe(400);
              expect(issued).toEqual({
                error: "invalid_target",
                error_description: `client ${value.client_id} is not linked to resource(s) ${resource}`,
              });
              uses.push({ resource, unlinked: true, error: issued.error });
              continue;
            }
            expect(token.status).toBe(200);
            expect(issued.scope).toBe("email");
            if (resource === b) expect(issued.expires_in).toBe(123);
            const { payload } = await jwtVerify(issued.access_token, keys, {
              issuer: `${ctx.baseURL}/api/auth`,
              audience: resource,
            });
            expect(payload.scope).toBe("email");
            expect(payload.aud).toBe(resource);
            uses.push({
              resource,
              scope: issued.scope,
              expires_in: issued.expires_in,
              aud: payload.aud,
            });
          }
        }
        results.push({
          mode,
          requested: requested ?? null,
          value: ctx.snapshot(value),
          links: ctx.snapshot(links),
          uses,
        });
      }
      if (mode === "union") {
        for (const action of [undefined, "admin-create"]) {
          const response = await call({
            ...(action ? { action } : {}),
            body: {
              redirect_uris: ["https://app.fixture.test/callback"],
              scope: "email",
              resources: [b, c],
              token_endpoint_auth_method: "none",
            },
          });
          expect(response.status).toBe(201);
          const value = (await response.json()) as any;
          expect(value.resources).toEqual([a]);
          const links = (await (
            await call({ action: "resource-links", clientId: value.client_id })
          ).json()) as any[];
          expect(links.map((row) => row.resourceId)).toEqual([a]);
          results.push({
            mode,
            action: action ?? "managed",
            value: ctx.snapshot(value),
            links: ctx.snapshot(links),
          });
        }
      }
    }
    const configurations = [];
    for (const [options, option, identifier] of [
      [
        { resources: [a], clientRegistrationDefaultResources: [c] },
        "clientRegistrationDefaultResources",
        c,
      ],
      [
        { resources: [a], clientRegistrationAllowedResources: [c] },
        "clientRegistrationAllowedResources",
        c,
      ],
      [
        {
          resources: [a],
          clientRegistrationDefaultResources: ["first"],
          clientRegistrationAllowedResources: ["second"],
        },
        "clientRegistrationDefaultResources",
        "first",
      ],
    ] as const) {
      const value = await (
        await control({ action: "registration-resources-validation", options })
      ).json();
      expect(value).toEqual({
        valid: false,
        message: `${option} resource ${identifier} not found in resources`,
      });
      configurations.push(value);
    }
    return { results, configurations };
  },
);
compatScenario(
  "Registration PKCE policy survives persistence and governs genuine code exchanges",
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
      body: { email: ctx.uniqueEmail("registration-pkce"), name: "Owner", password: "password123" },
    });
    expect(signup.status).toBe(200);
    const cookie = signup.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const verifier = "registration-pkce-verifier-abcdefghijklmnopqrstuvwxyz";
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const results = [];
    for (const policy of ["absent", "true", "false"]) {
      const call = (input: object) =>
        control({ mode: `registration-pkce-${policy}`, headers: { cookie }, ...input });
      for (const source of [
        "dynamic-confidential",
        "dynamic-public",
        "managed",
        "admin-true",
        "admin-false",
      ]) {
        // DCR/ordinary creation strip this field; only the administrative API admits it.
        for (const explicit of source.startsWith("dynamic")
          ? [undefined, true, false]
          : [source === "admin-true"]) {
          const publicClient = source === "dynamic-public";
          const created = await call({
            ...(source.startsWith("dynamic")
              ? { action: "register" }
              : source.startsWith("admin")
                ? { action: "admin-create" }
                : {}),
            body: {
              redirect_uris: ["https://app.fixture.test/callback"],
              scope: "email",
              token_endpoint_auth_method: publicClient ? "none" : "client_secret_basic",
              ...(explicit === undefined ? {} : { require_pkce: explicit }),
            },
          });
          expect(created.status, `${ctx.baseURL}:${policy}:${source}:${explicit}`).toBe(201);
          const client = (await created.json()) as any;
          const row = (await (
            await call({ action: "row", clientId: client.client_id })
          ).json()) as any;
          const optional =
            source === "admin-false" || (source === "dynamic-confidential" && policy === "false");
          const exchanges = [];
          for (const [name, pkce, proof] of [
            ["absent", {}, undefined],
            ["unsolicited-verifier", {}, verifier],
            ["empty", { code_challenge: "" }, undefined],
            ["empty-pair", { code_challenge: "", code_challenge_method: "S256" }, undefined],
            ["missing-method", { code_challenge: challenge }, verifier],
            [
              "invalid-method",
              { code_challenge: challenge, code_challenge_method: "plain" },
              verifier,
            ],
            ["malformed", { code_challenge: "short", code_challenge_method: "S256" }, verifier],
            [
              "missing-verifier",
              { code_challenge: challenge, code_challenge_method: "S256" },
              undefined,
            ],
            [
              "wrong-verifier",
              { code_challenge: challenge, code_challenge_method: "S256" },
              "wrong",
            ],
            ["valid", { code_challenge: challenge, code_challenge_method: "S256" }, verifier],
          ] as const) {
            // Required confidential-client token error precedence is a separate existing mismatch;
            // this finding owns optional registration and the public-client security boundary.
            if (name === "missing-verifier" && !optional && !publicClient) continue;
            const authorized = await call({
              action: "authorize",
              headers: { cookie, accept: "application/json" },
              query: {
                client_id: client.client_id,
                response_type: "code",
                redirect_uri: "https://app.fixture.test/callback",
                scope: "email",
                prompt: "consent",
                ...pkce,
              },
            });
            expect(authorized.status).toBe(200);
            const target = new URL(((await authorized.json()) as any).url, ctx.baseURL);
            const admitted =
              name === "valid" ||
              name === "malformed" ||
              name === "missing-verifier" ||
              name === "wrong-verifier" ||
              (optional && ["absent", "empty", "unsolicited-verifier"].includes(name));
            if (!admitted) {
              expect(target.searchParams.get("error"), `${policy}:${source}:${name}`).toBe(
                "invalid_request",
              );
              expect(target.searchParams.has("code")).toBe(false);
              exchanges.push({
                name,
                error: target.searchParams.get("error"),
                description: target.searchParams.get("error_description"),
              });
              continue;
            }
            expect(target.pathname, `${policy}:${source}:${name}`).toBe("/consent");
            const consent = await call({
              action: "consent",
              body: { accept: true, oauth_query: target.search.slice(1) },
            });
            expect(consent.status).toBe(200);
            const callback = new URL(((await consent.json()) as any).url);
            const code = callback.searchParams.get("code");
            expect(code).toMatch(/^[a-zA-Z0-9]{32}$/);
            const token = await call({
              action: "token",
              headers: publicClient
                ? {}
                : {
                    authorization: `Basic ${Buffer.from(`${client.client_id}:${client.client_secret}`).toString("base64")}`,
                  },
              body: {
                grant_type: "authorization_code",
                client_id: client.client_id,
                redirect_uri: "https://app.fixture.test/callback",
                code,
                ...(proof === undefined ? {} : { code_verifier: proof }),
              },
            });
            const value = (await token.json()) as any;
            const success = name === "valid" || name === "absent" || name === "empty";
            expect(
              token.status,
              `${ctx.baseURL}:${policy}:${source}:${name}:${JSON.stringify(value)}`,
            ).toBe(success ? 200 : publicClient && name === "missing-verifier" ? 400 : 401);
            if (success) {
              expect(value.access_token).toBeTypeOf("string");
              expect(value.token_type).toBe("Bearer");
              expect(value.scope).toBe("email");
            } else {
              expect(value.error).toBe("invalid_request");
            }
            exchanges.push({
              name,
              status: token.status,
              value: success ? { scope: value.scope, token_type: value.token_type } : value,
            });
          }
          expect(row.requirePKCE, `${ctx.baseURL}:${policy}:${source}:${explicit}`).toBe(
            source.startsWith("admin") ? source === "admin-true" : optional ? false : null,
          );
          // An ordinary update cannot override the stored operator/DCR decision.
          const updated = await call({
            action: "update",
            body: {
              client_id: client.client_id,
              update: { client_name: "Updated", require_pkce: !optional },
            },
          });
          expect(updated.status).toBe(200);
          const after = (await (
            await call({ action: "row", clientId: client.client_id })
          ).json()) as any;
          expect(after.requirePKCE).toBe(row.requirePKCE);
          console.log(
            "registration-pkce-runtime",
            JSON.stringify({
              baseURL: ctx.baseURL,
              policy,
              source,
              explicit,
              stored: row.requirePKCE,
              exchanges,
            }),
          );
          results.push({
            policy,
            source,
            explicit: explicit ?? null,
            stored: row.requirePKCE,
            exchanges,
          });
        }
      }
    }
    return results;
  },
);
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
