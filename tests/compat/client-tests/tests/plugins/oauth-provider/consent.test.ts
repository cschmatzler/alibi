import { createHash } from "node:crypto";

import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Consent persists accepted scopes and issues an authorization code bound to the current user",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "consent-reference", ...input }),
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
        scope: "openid email profile offline_access",
        token_endpoint_auth_method: "none",
      },
    });
    expect(created.status).toBe(201);
    const id = ((await created.json()) as any).client_id;
    const verifier = "consent-reference-verifier-with-at-least-43-characters";
    const query = {
      client_id: id,
      response_type: "code",
      redirect_uri: "https://app.fixture.test/callback",
      scope: "email profile",
      state: "consent-state",
      code_challenge: createHash("sha256").update(verifier).digest("base64url"),
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
    const choose = async (reference: string | undefined, sessionId = session.session.id) => {
      expect(
        (await control({ action: "consent-reference-choice", sessionId, reference })).status,
      ).toBe(200);
    };
    const referenceCalls = async () =>
      (await control({ action: "consent-reference-calls" })).json() as Promise<any[]>;
    await choose("team-a");
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
    expect(proof.value.referenceId).toBe("team-a");
    const selectionCalls = await referenceCalls();
    expect(selectionCalls).toHaveLength(2);
    for (const call of selectionCalls) {
      expect(call).toEqual({
        user: { id: session.user.id, email: session.user.email, name: session.user.name },
        session: { id: session.session.id, userId: session.user.id, token: session.session.token },
        scopes: ["email"],
      });
    }
    expect(proof.value.authTime).toBe(new Date(session.session.createdAt).getTime());
    const rowsResponse = await control({ action: "consent-row", clientId: id });
    const rows = (await rowsResponse.json()) as any[];
    expect(rows).toHaveLength(1);
    expect(rows[0].scopes).toEqual(["email"]);
    expect(rows[0].userId).toBe(session.user.id);
    expect(rows[0].referenceId).toBe("team-a");
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
      scope = query.scope,
    ) => {
      const response = await control({
        ...(http
          ? { action: "protocol-http", path: "/oauth2/authorize" }
          : { action: "authorize" }),
        headers: { ...headers, accept: "application/json" },
        query: { ...query, scope, resource: resources, ...(prompt ? { prompt } : {}) },
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

    // A real application selection is stored against the actual session, not
    // inferred from a fixture user's name, client, or hardcoded affinity.
    await choose("team-b");
    const partitionDenied = await authorizeResource({ cookie }, "none");
    expect(partitionDenied.searchParams.get("error")).toBe("consent_required");
    const partitionConsent = await authorizeResource(
      { cookie },
      undefined,
      false,
      resource,
      "email profile offline_access",
    );
    expect(partitionConsent.pathname).toBe("/consent");
    const partitionAccept = await control({
      action: "consent",
      headers: { cookie },
      body: {
        accept: true,
        scope: "email offline_access",
        oauth_query: partitionConsent.search.slice(1),
      },
    });
    expect(partitionAccept.status).toBe(200);
    const partitionResult = (await partitionAccept.json()) as any;
    const partitionRows = (await (
      await control({ action: "consent-row", clientId: id })
    ).json()) as any[];
    expect(partitionRows).toHaveLength(2);
    const a = partitionRows.find((row) => row.referenceId === "team-a")!;
    const b = partitionRows.find((row) => row.referenceId === "team-b")!;
    expect(a.id).toBe(resourceConsents[0].id);
    expect(b.id).not.toBe(a.id);
    expect(a.scopes).toEqual(["email", "profile"]);
    expect(b.scopes).toEqual(["email", "offline_access"]);
    const secondLogin = await control({
      action: "signin",
      body: { email: session.user.email, password: "password123" },
    });
    expect(secondLogin.status).toBe(200);
    const secondCookie = secondLogin.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const secondSession = (await (
      await control({ action: "session", headers: { cookie: secondCookie } })
    ).json()) as any;
    expect(secondSession.user.id).toBe(session.user.id);
    expect(secondSession.session.id).not.toBe(session.session.id);
    await choose("team-a", secondSession.session.id);
    expect(
      (await authorizeResource({ cookie: secondCookie }, "none")).searchParams.has("code"),
    ).toBe(true);
    const fallbackReferences = [];
    for (const fallback of ["", undefined]) {
      await choose(fallback);
      const target = await authorizeResource({ cookie }, "none");
      expect(target.searchParams.has("code")).toBe(true);
      const grant = (await (
        await control({ action: "grant-row", token: target.searchParams.get("code") })
      ).json()) as any;
      expect(grant.value.referenceId).toBe(fallback);
      fallbackReferences.push(grant.value.referenceId ?? null);
    }
    // Management endpoints use user ownership, irrespective of selected reference.
    await choose("team-b");
    expect(
      (
        await control({
          action: "consent-update",
          headers: { cookie },
          body: { id: b.id, update: { scopes: ["email", "profile"] } },
        })
      ).status,
    ).toBe(200);
    const changed = await control({
      action: "consent-update",
      headers: { cookie },
      body: { id: a.id, update: { scopes: ["email"] } },
    });
    expect(changed.status).toBe(200);
    expect(((await changed.json()) as any).referenceId).toBe("team-a");
    for (const action of ["consent-get", "consent-update", "consent-delete"]) {
      const denied = await control({
        action,
        headers: { cookie: foreignCookie },
        query: { id: a.id },
        body: { id: a.id, update: { scopes: ["email"] } },
      });
      expect(denied.status).toBe(401);
    }
    // Undefined selects the first row, not any later consent with more authority.
    await choose(undefined);
    expect((await authorizeResource({ cookie }, "none")).searchParams.get("error")).toBe(
      "consent_required",
    );
    const errors = [];
    for (const [choice, status] of [
      ["ordinary-error", 500],
      ["native-error", 403],
      ["api-error", 403],
      ["upstream-error", 503],
    ] as const) {
      await choose(choice);
      for (const action of ["authorize", "consent"]) {
        const failed = await control({
          action,
          headers: { cookie, accept: "application/json" },
          query,
          body: { accept: true, oauth_query: partitionConsent.search.slice(1) },
        });
        expect(failed.status).toBe(status);
        const text = await failed.text();
        if (choice === "ordinary-error") expect(text).toBe("");
        errors.push({ choice, action, status, body: text ? JSON.parse(text) : null });
      }
    }
    await choose("team-b");
    // Reference propagation follows the actual code through the public token grant.
    const boundCode = new URL(partitionResult.url).searchParams.get("code");
    const boundGrant = (await (
      await control({ action: "grant-row", token: boundCode })
    ).json()) as any;
    expect(boundGrant.value.referenceId).toBe("team-b");
    const tokens = await control({
      action: "token",
      body: {
        grant_type: "authorization_code",
        client_id: id,
        code: boundCode,
        redirect_uri: query.redirect_uri,
        code_verifier: verifier,
      },
    });
    expect(tokens.status).toBe(200);
    const token = (await tokens.json()) as any;
    const access = (await (
      await control({ action: "token-row", token: token.access_token })
    ).json()) as any;
    expect(access.referenceId).toBe("team-b");
    expect(access.userId).toBe(session.user.id);
    expect(access.sessionId).toBe(session.session.id);
    expect(access.scopes).toEqual(["email", "offline_access"]);
    const refresh = (await (
      await control({ action: "token-row", kind: "refresh", token: token.refresh_token })
    ).json()) as any;
    expect(refresh.referenceId).toBe("team-b");
    expect(refresh.userId).toBe(session.user.id);
    expect(refresh.sessionId).toBe(session.session.id);
    expect(refresh.scopes).toEqual(["email", "offline_access"]);
    expect(access.authorizationCodeId).toBe(
      createHash("sha256").update(boundCode!).digest("base64url"),
    );
    expect(access.resources).toEqual([resource]);
    expect(boundGrant.value.resource).toEqual([resource]);
    expect(boundGrant.value.query.resource).toBe(resource);
    // Same reference does not grant another real user the owner's consent.
    const foreignSession = (await (
      await control({ action: "session", headers: { cookie: foreignCookie } })
    ).json()) as any;
    await choose("team-a", foreignSession.session.id);
    expect(
      (await authorizeResource({ cookie: foreignCookie }, "none")).searchParams.get("error"),
    ).toBe("consent_required");
    // A falsy selection updates the first row without overwriting its reference.
    for (const fallback of ["", undefined]) {
      await choose(fallback);
      const accepted = await control({
        action: "consent",
        headers: { cookie },
        body: { accept: true, oauth_query: signed },
      });
      expect(accepted.status).toBe(200);
      const persisted = (await (
        await control({ action: "consent-row", clientId: id })
      ).json()) as any[];
      expect(persisted).toHaveLength(2);
      expect(persisted.find((row) => row.id === a.id)).toMatchObject({
        referenceId: "team-a",
        resources: [resource],
        scopes: ["email", "profile"],
      });
    }
    // Accepted UserInfo claims are bound to the selected consent, not borrowed
    // from another reference or from the originally requested claim set.
    await choose("team-b");
    const claimsQuery = {
      ...query,
      scope: "openid email",
      resource,
      claims: JSON.stringify({ userinfo: { email: null, name: null } }),
    };
    const claimsStart = await control({
      action: "authorize",
      headers: { cookie, accept: "application/json" },
      query: claimsQuery,
    });
    const claimsConsent = new URL(((await claimsStart.json()) as any).url, ctx.baseURL);
    expect(claimsConsent.pathname).toBe("/consent");
    const claimsAccept = await control({
      action: "consent",
      headers: { cookie },
      body: {
        accept: true,
        claims: { userinfo: { email: null } },
        oauth_query: claimsConsent.search.slice(1),
      },
    });
    expect(claimsAccept.status).toBe(200);
    const claimsRows = (await (
      await control({ action: "consent-row", clientId: id })
    ).json()) as any[];
    expect(claimsRows.find((row) => row.id === b.id)).toMatchObject({
      referenceId: "team-b",
      scopes: ["openid", "email"],
      requestedUserInfoClaims: ["email"],
      resources: [resource],
    });
    expect(claimsRows.find((row) => row.id === a.id).requestedUserInfoClaims).toEqual([]);
    const claimDecisions = [];
    for (const claim of ["email", "name"]) {
      const response = await control({
        action: "authorize",
        headers: { cookie, accept: "application/json" },
        query: {
          ...claimsQuery,
          prompt: "none",
          claims: JSON.stringify({ userinfo: { [claim]: null } }),
        },
      });
      const target = new URL(((await response.json()) as any).url);
      expect(target.searchParams.has("code")).toBe(claim === "email");
      if (claim === "name") expect(target.searchParams.get("error")).toBe("consent_required");
      claimDecisions.push({ claim, error: target.searchParams.get("error") });
    }
    // A fresh empty reference is persisted as empty, not treated as undefined.
    await choose("", foreignSession.session.id);
    const emptyAccept = await control({
      action: "consent",
      headers: { cookie: foreignCookie },
      body: { accept: true, oauth_query: signed },
    });
    expect(emptyAccept.status).toBe(200);
    const foreignConsents = (await (
      await control({ action: "consents", headers: { cookie: foreignCookie } })
    ).json()) as any[];
    expect(foreignConsents).toHaveLength(1);
    expect(foreignConsents[0].referenceId).toBe("");
    await choose(undefined, foreignSession.session.id);
    expect(
      (
        await control({
          action: "consent",
          headers: { cookie: foreignCookie },
          body: { accept: true, oauth_query: signed },
        })
      ).status,
    ).toBe(200);
    expect(
      (
        (await (
          await control({ action: "consents", headers: { cookie: foreignCookie } })
        ).json()) as any[]
      )[0],
    ).toMatchObject({ id: foreignConsents[0].id, referenceId: "" });
    const listed = (await (
      await control({ action: "consents", headers: { cookie } })
    ).json()) as any[];
    expect(listed.map((row) => row.referenceId).sort()).toEqual(["team-a", "team-b"]);
    const removed = await control({
      action: "consent-delete",
      headers: { cookie },
      body: { id: a.id },
    });
    expect(removed.status).toBe(200);
    expect(
      ((await (await control({ action: "consents", headers: { cookie } })).json()) as any[]).map(
        (row) => row.id,
      ),
    ).toEqual([b.id]);
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
      referencePartitions: {
        fallbackReferences,
        errors,
        selectionCalls,
        partitionResult,
        claimDecisions,
        tokenBinding: {
          referenceId: access.referenceId,
          userId: access.userId,
          sessionId: access.sessionId,
          scopes: access.scopes,
          resourcePaths: access.resources.map((value: string) => new URL(value).pathname),
        },
      },
    });
  },
);
