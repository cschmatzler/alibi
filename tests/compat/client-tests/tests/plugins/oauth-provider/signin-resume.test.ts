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
        body: JSON.stringify({ mode: "interaction", ...input }),
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
      prompt: "login",
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
    for (const transport of ["http", "private", "navigation"] as const) {
      const body = { email, password: "password123", oauth_query: signed };
      const headers = {
        accept: transport === "navigation" ? "text/html" : "application/json",
        cookie: oldCookie,
        origin: ctx.baseURL,
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
      expect(target.pathname).toBe("/consent");
      expect(target.searchParams.has("prompt")).toBe(false);
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
      results.push({ transport, status: response.status, raw: result ?? raw, location, current });
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
      headers: { accept: "application/json", cookie: oldCookie, origin: ctx.baseURL },
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
    });
  },
);
