import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

function cookies(response: Response) {
  return response.headers
    .getSetCookie()
    .filter((raw) => Boolean(Cookie.parse(raw)?.value))
    .map((raw) => raw.split(";")[0])
    .join("; ");
}

compatScenario(
  "Signed OAuth login resumes with the newly issued session across HTTP and private calls",
  async (ctx) => {
    const actor = ctx.actor("signin-resume");
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        redirect: "manual",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "postlogin-policy", ...input }),
      });
    const email = ctx.uniqueEmail("resume-owner");
    const signup = await control({
      action: "signup",
      body: { email, name: "Resume Owner", password: "password123" },
    });
    expect(signup.status).toBe(200);
    const owner = await signup.json();
    const otherSignup = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("prior-principal"),
        name: "Other Principal",
        password: "password123",
      },
    });
    expect(otherSignup.status).toBe(200);
    const other = await otherSignup.json();
    const oldCookie = cookies(otherSignup);
    const created = await control({
      headers: { cookie: cookies(signup) },
      body: {
        client_name: "Resume client",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "email",
        token_endpoint_auth_method: "none",
      },
    });
    expect(created.status).toBe(201);
    const client = await created.json();
    const query = {
      client_id: client.client_id,
      response_type: "code",
      redirect_uri: "https://app.fixture.test/callback",
      scope: "email",
      state: "resume-state",
      prompt: "login consent",
      max_age: "0",
      code_challenge: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
      code_challenge_method: "S256",
    };
    const producer = await control({
      action: "authorize",
      headers: { accept: "application/json" },
      query,
    });
    expect(producer.status).toBe(200);
    const login = await producer.json();
    const signed = new URL(login.url, ctx.baseURL).search.slice(1);
    const results = [];
    const receipts = async () => (await control({ action: "postlogin-policy-calls" })).json();
    expect(await receipts()).toEqual([]);
    const signedQuery = (location: string) => {
      const target = new URL(location, ctx.baseURL);
      const params = target.searchParams;
      const canonical = new URLSearchParams(
        [...params]
          .filter(([key]) => key !== "sig")
          .sort(([a, av], [b, bv]) => (a < b ? -1 : a > b ? 1 : av < bv ? -1 : av > bv ? 1 : 0)),
      );
      expect(params.get("sig")).toBe(
        createHmac("sha256", "compat-test-only-key-not-real-minimum-32chars")
          .update(canonical.toString())
          .digest("base64"),
      );
      return target;
    };
    for (const transport of ["http", "private", "navigation"] as const) {
      const body = { email, password: "password123", oauth_query: signed };
      const headers = {
        accept: transport === "navigation" ? "text/html" : "application/json",
        cookie: oldCookie,
        origin: ctx.baseURL,
        "x-policy-caller": "physical",
      };
      const response = await control(
        transport !== "private"
          ? {
              action: "protocol-http",
              method: "POST",
              path: "/sign-in/email",
              contentType: "application/json",
              headers,
              body,
            }
          : { action: "signin", headers, attachRequest: true, body },
      );
      expect(response.status, `${ctx.baseURL}:${transport}`).toBe(
        transport === "navigation" ? 302 : 200,
      );
      const raw = await response.text();
      const result = transport === "navigation" ? null : JSON.parse(raw);
      if (result) {
        expect(result.redirect).toBe(true);
      } else {
        expect(raw).toBe("");
      }
      const location = transport === "navigation" ? response.headers.get("location") : result.url;
      expect(location).toEqual(expect.any(String));
      const target = new URL(location, ctx.baseURL);
      expect(target.pathname).toBe("/post-login");
      expect(signedQuery(location).searchParams.has("ba_pl")).toBe(false);
      expect(target.searchParams.get("prompt")).toBe("consent");
      expect(target.searchParams.has("max_age")).toBe(false);
      expect(target.searchParams.get("client_id")).toBe(client.client_id);
      expect(target.searchParams.get("state")).toBe("resume-state");
      expect(target.searchParams.get("scope")).toBe("email");
      expect(cookies(response)).not.toBe("");
      const current = await (
        await control({ action: "session", headers: { cookie: cookies(response) } })
      ).json();
      expect(current.user.id).toBe(owner.user.id);
      expect(current.session.token).not.toBe(other.token);
      expect(current.session.token).not.toBe(owner.token);
      const receipt = {
        stage: "postLogin",
        isContinuation: false,
        caller: "physical",
        decision: null,
        user: { id: owner.user.id, email: owner.user.email, name: owner.user.name },
        session: { id: current.session.id, userId: owner.user.id, token: current.session.token },
        scopes: ["email"],
      };
      expect(await receipts()).toEqual([
        { stage: "signup", sessionId: current.session.id },
        receipt,
      ]);
      const postQuery = target.search.slice(1);
      const continuing = async (
        oauth_query: string,
        cookie: string,
        decision = "true",
        extra = {},
      ) =>
        control({
          action: "continue",
          body: { postLogin: true, oauth_query, ...extra },
          headers: { cookie, "x-postlogin-decision": decision, "x-policy-caller": "physical" },
        });
      // postLogin:true is not clearance: the real application must change its decision.
      const stillRequired = await continuing(postQuery, cookies(response));
      expect(stillRequired.status).toBe(200);
      expect(new URL((await stillRequired.json()).url, ctx.baseURL).pathname).toBe("/post-login");
      expect(await receipts()).toEqual([
        { stage: "signup", sessionId: current.session.id },
        { ...receipt, decision: "true", isContinuation: true },
      ]);
      const forged = await continuing(
        `${postQuery}&ba_pl=${current.session.id}`,
        cookies(response),
      );
      expect(forged.status).toBe(400);
      expect(await forged.json()).toEqual({ error: "invalid_signature" });
      expect(await receipts()).toEqual([]);
      const completed = await continuing(postQuery, cookies(response), "false");
      expect(completed.status).toBe(200);
      const consentValue = await completed.json();
      const consent = signedQuery(consentValue.url);
      expect(consent.pathname).toBe("/consent");
      expect(consent.searchParams.get("ba_pl")).toBe(current.session.id);
      expect(consent.searchParams.getAll("ba_param")).toContain("ba_pl");
      expect(await receipts()).toEqual([
        { stage: "signup", sessionId: current.session.id },
        { ...receipt, decision: "false", isContinuation: true },
      ]);
      for (const [cookie, principal] of [
        [cookies(signup), owner],
        [oldCookie, other],
      ] as const) {
        const switched = await continuing(consent.search.slice(1), cookie);
        expect(switched.status).toBe(200);
        const switchedValue = await switched.json();
        expect(signedQuery(switchedValue.url).pathname).toBe("/post-login");
        const calls = await receipts();
        expect(calls.map((call: any) => call.stage)).toEqual(["signup", "postLogin"]);
        expect(calls[1].user.id).toBe(principal.user.id);
        expect(calls[1].session.id).not.toBe(current.session.id);
        const switchedConsent = await control({
          action: "consent",
          headers: { cookie, "x-postlogin-decision": "true", "x-policy-caller": "physical" },
          body: { accept: true, oauth_query: consent.search.slice(1) },
        });
        expect(switchedConsent.status).toBe(200);
        expect(signedQuery((await switchedConsent.json()).url).pathname).toBe("/post-login");
        const consentCalls = await receipts();
        expect(consentCalls.map((call: any) => call.stage)).toEqual(["signup", "postLogin"]);
        expect(consentCalls[1].user.id).toBe(principal.user.id);
        expect(consentCalls[1].session.id).not.toBe(current.session.id);
      }
      // created/selected continuations do not inherit post-login clearance.
      for (const action of ["created", "selected"]) {
        const ignored = await continuing(consent.search.slice(1), cookies(response), "true", {
          [action]: true,
        });
        expect(signedQuery((await ignored.json()).url).pathname).toBe("/post-login");
        expect((await receipts()).map((call: any) => call.stage)).toEqual(["signup", "postLogin"]);
      }
      const accepted = await control({
        action: "consent",
        headers: { cookie: cookies(response), "x-postlogin-decision": "true" },
        body: { accept: true, oauth_query: consent.search.slice(1) },
      });
      expect(accepted.status).toBe(200);
      const acceptedValue = await accepted.json();
      const acceptedCode = new URL(acceptedValue.url).searchParams.get("code");
      const grant = await (await control({ action: "grant-row", token: acceptedCode })).json();
      expect(grant.value.sessionId).toBe(current.session.id);
      expect(grant.value.userId).toBe(owner.user.id);
      expect(grant.value.query.client_id).toBe(client.client_id);
      expect(grant.value.query).not.toHaveProperty("ba_pl");
      expect(grant.value.authTime).toBe(new Date(current.session.createdAt).getTime());
      expect(await receipts()).toEqual([{ stage: "signup", sessionId: current.session.id }]);
      const signupAgain = await control({
        action: "continue",
        headers: { cookie: cookies(response), "x-signup-decision": "true" },
        body: { postLogin: true, oauth_query: consent.search.slice(1) },
      });
      expect(signedQuery((await signupAgain.json()).url).pathname).toBe("/signup");
      expect(await receipts()).toEqual([{ stage: "signup", sessionId: current.session.id }]);
      // A valid consent flag also clears only this session in postLogin continuation.
      const cleared = await continuing(consent.search.slice(1), cookies(response));
      expect(signedQuery((await cleared.json()).url).pathname).toBe("/consent");
      expect(await receipts()).toEqual([{ stage: "signup", sessionId: current.session.id }]);
      results.push({
        transport,
        status: response.status,
        raw: result ?? raw,
        location,
        current,
        consentValue,
        acceptedValue,
        grant: {
          userId: grant.value.userId,
          sessionId: grant.value.sessionId,
          query: grant.value.query,
        },
      });
    }

    const managedResponse = await control({
      action: "admin-create",
      headers: { cookie: cookies(signup) },
      body: {
        client_name: "Direct continuation",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "email",
        skip_consent: true,
        require_pkce: false,
      },
    });
    expect(managedResponse.status).toBe(201);
    const managed = await managedResponse.json();
    const managedLogin = await (
      await control({
        action: "authorize",
        headers: { accept: "application/json" },
        query: {
          client_id: managed.client_id,
          response_type: "code",
          redirect_uri: "https://app.fixture.test/callback",
          scope: "email",
          prompt: "login",
          state: "issued-after-login",
          max_age: "0",
        },
      })
    ).json();
    const issuedResponse = await control({
      action: "signin",
      attachRequest: true,
      headers: {
        accept: "application/json",
        cookie: oldCookie,
        origin: ctx.baseURL,
        "x-postlogin-decision": "false",
      },
      body: {
        email,
        password: "password123",
        oauth_query: new URL(managedLogin.url, ctx.baseURL).search.slice(1),
      },
    });
    expect(issuedResponse.status).toBe(200);
    const issued = await issuedResponse.json();
    const callback = new URL(issued.url, ctx.baseURL);
    expect(callback.hostname).toBe("app.fixture.test");
    const code = callback.searchParams.get("code");
    expect(code).toMatch(/^[a-zA-Z0-9]{32}$/);
    const issuedSession = await (
      await control({ action: "session", headers: { cookie: cookies(issuedResponse) } })
    ).json();
    const proof = await (await control({ action: "grant-row", token: code })).json();
    expect(proof.value.userId).toBe(owner.user.id);
    expect(proof.value.query).not.toHaveProperty("max_age");
    expect(proof.value.sessionId).toBe(issuedSession.session.id);
    expect(proof.value.authTime).toBe(new Date(issuedSession.session.createdAt).getTime());
    expect((await receipts()).map((call: any) => call.stage)).toEqual(["signup", "postLogin"]);

    const policyResults = [];
    for (const [decision, patch, expected, signupDecision, mode] of [
      ["true", {}, "/post-login", "false", "postlogin-policy"],
      ["false", {}, "code", "false", "postlogin-policy"],
      ["true", { prompt: "consent" }, "/post-login", "false", "postlogin-policy"],
      ["true", { prompt: "none" }, "interaction_required", "false", "postlogin-policy"],
      ["true", {}, "/signup", "true", "postlogin-policy"],
      ["true", { scope: "forbidden" }, "invalid_scope", "false", "postlogin-policy"],
      ["true", { ba_pl: issuedSession.session.id }, "/post-login", "false", "postlogin-policy"],
      ["true", {}, "missing-page", "false", "postlogin-empty-page"],
      ...["ordinary-error", "native-error", "api-error", "upstream-error"].map((error) => [
        error,
        {},
        error,
        "false",
        "postlogin-policy",
      ]),
    ] as [string, Record<string, unknown>, string, string, string][]) {
      for (const transport of ["private", "http"]) {
        const response = await control({
          mode,
          action: transport === "http" ? "protocol-http" : "authorize",
          method: "GET",
          path: "/oauth2/authorize",
          query: {
            client_id: managed.client_id,
            response_type: "code",
            redirect_uri: "https://app.fixture.test/callback",
            scope: "email  email",
            state: "policy-state",
            ...patch,
          },
          headers: {
            cookie: cookies(signup),
            accept: "application/json",
            "x-policy-caller": "physical",
            "x-postlogin-decision": decision,
            "x-signup-decision": signupDecision,
          },
        });
        const raw = await response.text();
        let output: any;
        if (expected === "ordinary-error") {
          expect(response.status).toBe(500);
          expect(raw).toBe("");
          output = raw;
        } else if (expected === "missing-page") {
          expect(response.status).toBe(500);
          output = JSON.parse(raw);
          expect(output).toEqual({ error_description: "postLogin should have been defined" });
        } else if (expected.endsWith("-error")) {
          expect(response.status).toBe(expected === "upstream-error" ? 503 : 403);
          output = JSON.parse(raw);
          expect(output).toEqual(
            expected === "native-error"
              ? { message: "Post-login denied" }
              : expected === "upstream-error"
                ? { code: "POSTLOGIN_UNAVAILABLE", message: "Post-login unavailable" }
                : { code: "POSTLOGIN_DENIED", message: "Post-login denied" },
          );
        } else {
          expect(response.status).toBe(200);
          output = JSON.parse(raw);
          const target = new URL(output.url, ctx.baseURL);
          if (expected.startsWith("/")) {
            expect(signedQuery(output.url).pathname).toBe(expected);
            expect(target.searchParams.has("ba_pl")).toBe(false);
          } else if (expected === "code") expect(target.searchParams.has("code")).toBe(true);
          else expect(target.searchParams.get("error")).toBe(expected);
        }
        const calls = await receipts();
        expect(calls.map((call: any) => call.stage)).toEqual(
          expected === "invalid_scope"
            ? []
            : expected === "/signup"
              ? ["signup"]
              : ["signup", "postLogin"],
        );
        if (calls.length === 2) {
          expect(calls[1].user.id).toBe(owner.user.id);
          expect(calls[1].session.token).toBe(owner.token);
          expect(calls[1].scopes).toEqual(["email", "email"]);
        }
        policyResults.push({
          decision,
          patch,
          expected,
          transport,
          status: response.status,
          output,
          calls,
        });
      }
    }

    const missingRequest = await control({
      action: "signin",
      headers: { cookie: oldCookie, origin: ctx.baseURL },
      body: { email, password: "password123", oauth_query: signed },
    });
    expect(missingRequest.status, `${ctx.baseURL}:missing-request`).toBe(401);
    expect(await missingRequest.json()).toEqual({
      error: "invalid_request",
      error_description: "request not found",
    });
    expect(cookies(missingRequest)).not.toBe("");
    const afterFailure = await (
      await control({ action: "session", headers: { cookie: cookies(missingRequest) } })
    ).json();
    expect(afterFailure.user.id).toBe(owner.user.id);
    const ordinary = await control({ action: "signin", body: { email, password: "password123" } });
    expect(ordinary.status).toBe(200);
    const authenticated = await ordinary.json();
    expect(authenticated.user.id).toBe(owner.user.id);
    expect(authenticated.token).toEqual(expect.any(String));
    return ctx.snapshot({
      owner,
      other,
      client,
      login,
      results,
      managed,
      managedLogin,
      issued,
      authorizationSession: issuedSession,
      proof,
      afterFailure,
      authenticated,
      policyResults,
    });
  },
);
import { createHmac } from "node:crypto";
