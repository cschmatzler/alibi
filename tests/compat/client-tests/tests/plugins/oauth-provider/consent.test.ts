import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Consent persists accepted scopes and issues an authorization code bound to the current user",
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
      body: { email: ctx.uniqueEmail("consent-owner"), name: "Owner", password: "password123" },
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
        client_name: "Consent client",
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
      scope: "email profile",
      state: "consent-state",
      code_challenge: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
      code_challenge_method: "S256",
    };
    const producer = await control({
      action: "authorize",
      query,
      headers: { accept: "application/json" },
    });
    expect(producer.status).toBe(200);
    const signed = new URL(((await producer.json()) as any).url, ctx.baseURL).search.slice(1);
    const denied = await control({
      action: "consent",
      headers: { cookie },
      body: { accept: false, oauth_query: signed },
    });
    expect(denied.status).toBe(200);
    const denial = (await denied.json()) as any;
    const denialURL = new URL(denial.url);
    expect(denialURL.searchParams.get("error")).toBe("access_denied");
    expect(denialURL.searchParams.get("state")).toBe("consent-state");
    const empty = await control({ action: "consent-row", clientId: id });
    expect(await empty.json()).toEqual([]);
    const failures = [];
    for (const [body, headers, status, error] of [
      [{ accept: true }, { cookie }, 400, "invalid_request"],
      [{ accept: true, scope: "openid", oauth_query: signed }, { cookie }, 400, "invalid_request"],
      [
        { accept: true, oauth_query: signed + "&sig=duplicate" },
        { cookie },
        400,
        "invalid_signature",
      ],
      [{ accept: true, oauth_query: signed }, {}, 401, null],
    ] as const) {
      const r = await control({ action: "consent", body, headers });
      expect(r.status).toBe(status);
      const text = await r.text();
      const value = text ? JSON.parse(text) : null;
      if (error) {
        expect(value.error).toBe(error);
      }
      failures.push({ status: r.status, body: value });
    }
    const sessionResponse = await control({ action: "session", headers: { cookie } });
    expect(sessionResponse.status).toBe(200);
    const session = (await sessionResponse.json()) as any;
    const accepted = await control({
      action: "consent",
      headers: { cookie },
      body: { accept: true, scope: "email", oauth_query: signed },
    });
    expect(accepted.status).toBe(200);
    const result = (await accepted.json()) as any;
    const callback = new URL(result.url);
    expect(callback.host).toBe("app.fixture.test");
    expect(callback.searchParams.get("state")).toBe("consent-state");
    const code = callback.searchParams.get("code");
    expect(code).toMatch(/^[A-Za-z0-9]{32}$/);
    const proofResponse = await control({ action: "grant-row", token: code });
    const proof = (await proofResponse.json()) as any;
    expect(proof.value.type).toBe("authorization_code");
    expect(proof.value.query.scope).toBe("email");
    expect(proof.value.query.client_id).toBe(id);
    expect(proof.value.userId).toBe(session.user.id);
    expect(proof.value.sessionId).toBe(session.session.id);
    expect(proof.value.authTime).toBe(new Date(session.session.createdAt).getTime());
    const rowsResponse = await control({ action: "consent-row", clientId: id });
    const rows = (await rowsResponse.json()) as any[];
    expect(rows).toHaveLength(1);
    expect(rows[0].scopes).toEqual(["email"]);
    expect(rows[0].userId).toBe(session.user.id);
    const replay = await control({
      action: "consent",
      headers: { cookie },
      body: { accept: true, oauth_query: signed },
    });
    expect(replay.status).toBe(200);
    const replayResult = (await replay.json()) as any;
    expect(new URL(replayResult.url).searchParams.get("code")).toMatch(/^[A-Za-z0-9]{32}$/);
    const updatedResponse = await control({ action: "consent-row", clientId: id });
    const updated = (await updatedResponse.json()) as any[];
    expect(updated).toHaveLength(1);
    expect(updated[0].id).toBe(rows[0].id);
    expect(updated[0].createdAt).toBe(rows[0].createdAt);
    expect(updated[0].scopes).toEqual(["email", "profile"]);
    expect(updated[0].resources ?? []).toEqual([]);

    // Scope consent alone must not silently grant a newly requested audience.
    const resource = `${ctx.baseURL}/api/auth/oauth2/userinfo`;
    const authorizeResource = async (
      headers: Record<string, string>,
      prompt?: string,
      http = false,
      resources: string | string[] = resource,
    ) => {
      const response = await control({
        ...(http
          ? { action: "protocol-http", path: "/oauth2/authorize" }
          : { action: "authorize" }),
        headers: { ...headers, accept: "application/json" },
        query: { ...query, resource: resources, ...(prompt ? { prompt } : {}) },
      });
      expect(response.status).toBe(200);
      return new URL(((await response.json()) as any).url, ctx.baseURL);
    };
    const silent = await authorizeResource({ cookie }, "none", false, [resource]);
    expect(silent.searchParams.get("error")).toBe("consent_required");
    expect(silent.searchParams.get("state")).toBe(query.state);
    expect(silent.searchParams.has("code")).toBe(false);
    const expanded = await authorizeResource({ cookie }, undefined, true);
    expect(expanded.pathname).toBe("/consent");
    expect(expanded.searchParams.get("resource")).toBe(resource);
    expect(expanded.searchParams.get("sig")).toBeTruthy();
    expect(expanded.searchParams.has("code")).toBe(false);
    const unchanged = await control({ action: "consent-row", clientId: id });
    expect(await unchanged.json()).toEqual(updated);

    const resourceAccepted = await control({
      action: "consent",
      headers: { cookie },
      body: { accept: true, oauth_query: expanded.search.slice(1) },
    });
    expect(resourceAccepted.status).toBe(200);
    const resourceResult = (await resourceAccepted.json()) as any;
    const remembered = await authorizeResource({ cookie }, "none", true, [resource]);
    for (const target of [new URL(resourceResult.url), remembered]) {
      expect(target.host).toBe("app.fixture.test");
      expect(target.searchParams.get("state")).toBe(query.state);
      expect(target.searchParams.has("error")).toBe(false);
      const code = target.searchParams.get("code");
      expect(code).toMatch(/^[A-Za-z0-9]{32}$/);
      const stored = await control({ action: "grant-row", token: code });
      const grant = ((await stored.json()) as any).value;
      expect(grant.type).toBe("authorization_code");
      expect(grant.query.client_id).toBe(id);
      expect(grant.query.scope).toBe(query.scope);
      expect(grant.query.redirect_uri).toBe(query.redirect_uri);
      expect(grant.query.code_challenge).toBe(query.code_challenge);
      expect(grant.resource).toEqual([resource]);
      expect(grant.userId).toBe(session.user.id);
      expect(grant.sessionId).toBe(session.session.id);
      expect(grant.authTime).toBe(new Date(session.session.createdAt).getTime());
    }
    const resourceRows = await control({ action: "consent-row", clientId: id });
    const resourceConsents = (await resourceRows.json()) as any[];
    expect(resourceConsents).toHaveLength(1);
    expect(resourceConsents[0]).toMatchObject({
      id: updated[0].id,
      createdAt: updated[0].createdAt,
      userId: session.user.id,
      clientId: id,
      scopes: ["email", "profile"],
      resources: [resource],
    });

    const foreignSignup = await control({
      action: "signup",
      body: { email: ctx.uniqueEmail("consent-foreign"), name: "Other", password: "password123" },
    });
    expect(foreignSignup.status).toBe(200);
    const foreignCookie = foreignSignup.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const foreign = await authorizeResource({ cookie: foreignCookie }, "none", true);
    expect(foreign.searchParams.get("error")).toBe("consent_required");
    expect(foreign.searchParams.has("code")).toBe(false);
    const foreignConsent = await authorizeResource({ cookie: foreignCookie });
    expect(foreignConsent.pathname).toBe("/consent");
    expect(foreignConsent.searchParams.has("code")).toBe(false);
    const isolated = await control({ action: "consent-row", clientId: id });
    expect(await isolated.json()).toEqual(resourceConsents);
    return ctx.snapshot({
      authorizationSession: session,
      denial,
      failures,
      result,
      replayResult,
      consent: {
        id: rows[0].id,
        clientId: rows[0].clientId,
        userId: rows[0].userId,
        scopes: rows[0].scopes,
        requestedUserInfoClaims: rows[0].requestedUserInfoClaims,
      },
      updated: { id: updated[0].id, scopes: updated[0].scopes },
      resourceTransition: {
        silentError: silent.searchParams.get("error"),
        consentPath: expanded.pathname,
        resourcePaths: resourceConsents[0].resources.map(
          (value: string) => new URL(value).pathname,
        ),
        foreignError: foreign.searchParams.get("error"),
      },
    });
  },
);
