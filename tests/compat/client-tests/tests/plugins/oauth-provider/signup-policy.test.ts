import { createHmac } from "node:crypto";

import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "OAuth signup policy precedes consent and codes with authenticated ordered input",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        redirect: "manual",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "signup-policy", ...input }),
      });
    const signup = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("signup-policy"),
        name: "Signup Owner",
        password: "password123",
      },
    });
    expect(signup.status).toBe(200);
    const owner = await signup.json();
    const cookie = signup.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const session = await (await control({ action: "session", headers: { cookie } })).json();
    const created = await control({
      action: "admin-create",
      headers: { cookie },
      body: {
        client_name: "Signup client",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "email profile",
        require_pkce: false,
        skip_consent: true,
      },
    });
    expect(created.status).toBe(201);
    const client = await created.json();
    const results = [];
    const baseQuery = {
      client_id: client.client_id,
      response_type: "code",
      redirect_uri: "https://app.fixture.test/callback",
      scope: "email  email",
      state: "signup-state",
      extension: "bound",
    };
    for (const mode of [
      "signup-policy",
      "signup-fallback",
      "signup-empty-page",
      "signup-page-only",
    ]) {
      const page =
        mode === "signup-fallback" ? "/login" : mode === "signup-empty-page" ? "" : "/signup";
      const cases: [string, Record<string, unknown>, boolean, string, boolean, "http"?][] =
        mode === "signup-page-only"
          ? [
              ["true", { prompt: "create" }, true, page, false],
              ["true", {}, true, "code", false],
            ]
          : mode !== "signup-policy"
            ? [
                ["true", {}, true, page, true],
                ["page", {}, true, "/registration/step", true],
                ["true", { prompt: "create" }, true, page, false],
              ]
            : [
                ["true", {}, true, page, true],
                ["page", {}, true, "/registration/step", true],
                ["false", { prompt: "none" }, true, "code", true],
                ["empty", {}, true, "code", true],
                ["true", { prompt: "none" }, true, "interaction_required", true],
                ["true", { prompt: "consent" }, true, page, true],
                ["true", {}, false, "/login", false],
                ["true", { prompt: "none" }, false, "login_required", false],
                ["true", { prompt: "login" }, true, "/login", false],
                ["true", { max_age: "0" }, true, "/login", false],
                ["true", { max_age: "3600" }, true, page, true],
                ["true", { prompt: "create" }, true, page, false],
                ["true", { prompt: "select_account" }, true, "/select", false],
                ["true", { scope: "forbidden" }, true, "invalid_scope", false],
                ["true", { code_challenge: "incomplete" }, true, "invalid_request", false],
                ["ordinary-error", {}, true, "ordinary-error", true],
                ["api-error", {}, true, "api-error", true],
                ["native-error", {}, true, "native-error", true],
                ["upstream-error", {}, true, "upstream-error", true],
              ];
      if (mode === "signup-policy") {
        cases.push(
          ["ordinary-error", {}, true, "ordinary-error", true, "http"],
          ["api-error", {}, true, "api-error", true, "http"],
          ["native-error", {}, true, "native-error", true, "http"],
          ["upstream-error", {}, true, "upstream-error", true, "http"],
        );
      }
      for (const [decision, patch, authenticated, expected, called, transport] of cases) {
        const response = await control({
          mode,
          action: transport === "http" ? "protocol-http" : "authorize",
          method: "GET",
          path: "/oauth2/authorize",
          query: { ...baseQuery, ...patch },
          headers: {
            accept: "application/json",
            ...(authenticated ? { cookie } : {}),
            "x-signup-decision": decision,
            "x-signup-caller": "physical",
          },
        });
        const text = await response.text();
        let output: any;
        if (expected === "ordinary-error") {
          expect(response.status).toBe(500);
          expect(text).toBe("");
          output = text;
        } else if (expected.endsWith("-error")) {
          expect(response.status).toBe(expected === "upstream-error" ? 503 : 403);
          output = JSON.parse(text);
          expect(output).toEqual(
            expected === "native-error"
              ? { message: "Signup denied by native policy" }
              : expected === "upstream-error"
                ? { code: "SIGNUP_UNAVAILABLE", message: "Signup policy unavailable" }
                : {
                    code: "SIGNUP_DENIED",
                    message: "Signup denied by application",
                  },
          );
        } else {
          expect(response.status).toBe(200);
          output = JSON.parse(text);
          expect(output.redirect).toBe(true);
          if (expected === "code") {
            const code = new URL(output.url).searchParams.get("code");
            expect(code).toMatch(/^[a-zA-Z0-9]{32}$/);
            const proof = await (await control({ mode, action: "grant-row", token: code })).json();
            expect(proof.value.userId).toBe(owner.user.id);
            expect(proof.value.sessionId).toBe(session.session.id);
            expect(proof.value.query.client_id).toBe(client.client_id);
            expect(proof.value.query.scope).toBe(baseQuery.scope);
            results.push({ proof });
          } else if (
            expected.endsWith("required") ||
            expected === "invalid_scope" ||
            expected === "invalid_request"
          ) {
            const target = new URL(output.url);
            expect(target.searchParams.get("error")).toBe(expected);
            expect(target.searchParams.get("state")).toBe(baseQuery.state);
            if (expected === "interaction_required") {
              expect(target.searchParams.get("error_description")).toBe(
                "End-User interaction is required",
              );
            }
          } else {
            // The source preserves an empty configured page instead of defaulting it.
            expect(output.url.startsWith(`${expected}?`)).toBe(true);
            const signed = output.url.slice(expected.length + 1);
            const params = new URLSearchParams(signed);
            expect(params.get("client_id")).toBe(client.client_id);
            expect(params.get("state")).toBe(baseQuery.state);
            expect(params.get("scope")).toBe(baseQuery.scope);
            expect(params.get("extension")).toBe("bound");
            if (patch.max_age === "3600") expect(params.has("max_age")).toBe(false);
            const canonical = new URLSearchParams(
              [...params]
                .filter(([key]) => key !== "sig")
                .sort(([a, av], [b, bv]) =>
                  a < b ? -1 : a > b ? 1 : av < bv ? -1 : av > bv ? 1 : 0,
                ),
            );
            expect(params.get("sig")).toBe(
              createHmac("sha256", "compat-test-only-key-not-real-minimum-32chars")
                .update(canonical.toString())
                .digest("base64"),
            );
            if (
              mode === "signup-policy" &&
              decision === "true" &&
              Object.keys(patch).length === 0 &&
              authenticated
            ) {
              const forged = await control({
                mode,
                action: "continue",
                body: { created: true, oauth_query: `${signed}&extension=forged` },
                headers: { cookie, accept: "application/json" },
              });
              expect(forged.status).toBe(400);
              expect(await forged.json()).toEqual({ error: "invalid_signature" });
              // Completing registration changes the real operator's decision; created:true
              // does not bypass shouldRedirect in the pinned implementation.
              const resumed = await control({
                mode,
                action: "continue",
                body: { created: true, oauth_query: signed },
                headers: {
                  cookie,
                  accept: "application/json",
                  "x-signup-decision": "false",
                  "x-signup-caller": "physical",
                },
              });
              expect(resumed.status).toBe(200);
              const resumedValue = await resumed.json();
              const code = new URL(resumedValue.url).searchParams.get("code");
              expect(code).toMatch(/^[a-zA-Z0-9]{32}$/);
              const proof = await (
                await control({ mode, action: "grant-row", token: code })
              ).json();
              expect(proof.value.userId).toBe(owner.user.id);
              expect(proof.value.sessionId).toBe(session.session.id);
              expect(proof.value.query.client_id).toBe(client.client_id);
              expect(proof.value.query.extension).toBe("bound");
              results.push({ resumedValue, proof });
            }
          }
        }
        const calls = await (await control({ action: "signup-policy-calls" })).json();
        const receipt = {
          caller: "physical",
          decision,
          user: { id: owner.user.id, email: owner.user.email, name: owner.user.name },
          session: { id: session.session.id, userId: owner.user.id, token: owner.token },
          scopes: ["email", "email"],
        };
        expect(calls).toEqual(
          called
            ? mode === "signup-policy" &&
              decision === "true" &&
              Object.keys(patch).length === 0 &&
              authenticated
              ? [receipt, { ...receipt, decision: "false" }]
              : [receipt]
            : [],
        );
        results.push({
          mode,
          decision,
          patch,
          authenticated,
          status: response.status,
          output,
          calls,
        });
      }
    }
    return ctx.snapshot({ owner, authorizationSession: session, client, results });
  },
);
