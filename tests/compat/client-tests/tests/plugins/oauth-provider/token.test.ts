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
    // Keep the existing server-API success/persistence owner. Every callback
    // failure uses the actual public router, whose complete headers and body
    // must agree (not the private control route's shape-only trace).
    const tokenRequest = (input: Record<string, string>, outcome: string) =>
      outcome === "success"
        ? control({ action: "token", body: input })
        : publicActor.fetch(tokenEndpoint, {
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
    const errors = [];
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
      const response = await tokenRequest(
        {
          grant_type: "authorization_code",
          client_id: client.client_id,
          code: code!,
          code_verifier: verifier,
          redirect_uri: "https://app.fixture.test/callback",
        },
        mode,
      );
      if (mode === "success") {
        expect(response.status).toBe(200);
        issued = await response.json();
        expect(issued.application_metadata).toEqual({ service: "billing", plan: "pro" });
      } else {
        expect(response.status).toBe(
          { ordinary: 500, api: 422, forbidden: 403, upstream: 409 }[mode],
        );
        const text = await response.text();
        if (mode === "api") {
          expect(JSON.parse(text)).toEqual({
            code: "RESPONSE_REJECTED",
            message: "Operator response denied",
          });
        }
        errors.push({
          mode,
          status: response.status,
          headers: applicationHeaders(response.headers),
          text,
        });
        expect(await counts()).toEqual({ access: 0, refresh: 0 });
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
    for (const mode of ["ordinary", "api", "forbidden", "upstream", "success"]) {
      await state(mode);
      const response = await tokenRequest(
        {
          grant_type: "refresh_token",
          client_id: client.client_id,
          refresh_token: original,
          scope: "email",
        },
        mode,
      );
      if (mode === "success") {
        expect(response.status).toBe(200);
        issued = await response.json();
      } else {
        expect(response.status).toBe(
          { ordinary: 500, api: 422, forbidden: 403, upstream: 409 }[mode],
        );
        const text = await response.text();
        if (mode === "api") {
          expect(JSON.parse(text)).toEqual({
            code: "RESPONSE_REJECTED",
            message: "Operator response denied",
          });
        }
        errors.push({
          mode,
          status: response.status,
          headers: applicationHeaders(response.headers),
          text,
        });
        expect(await counts()).toEqual({ access: 1, refresh: 1 });
        const row = (await (
          await control({ action: "token-row", kind: "refresh", token: original })
        ).json()) as any;
        expect(row.revoked).toBeNull();
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
      expect(row.scopes).toEqual(["email"]);
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
    for (const [field, wrong, status, description] of [
      ["code_verifier", "wrong-verifier", 401, "code verification failed"],
      ["redirect_uri", "https://app.fixture.test/other", 400, "redirect_uri mismatch"],
    ] as const) {
      const produced = await control({
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
      expect(produced.status).toBe(200);
      const callback = new URL(((await produced.json()) as any).url);
      const grantCode = callback.searchParams.get("code");
      expect(grantCode).toBeTruthy();
      const input = {
        grant_type: "authorization_code",
        client_id: id,
        code: grantCode,
        code_verifier: verifier,
        redirect_uri: "https://app.fixture.test/callback",
        [field]: wrong,
      };
      const rejected = await control({ action: "token", body: input });
      expect(rejected.status).toBe(status);
      expect(await rejected.json()).toEqual({
        error: status === 401 ? "invalid_request" : "invalid_grant",
        error_description: description,
      });
      const retry = await control({
        action: "token",
        body: {
          ...input,
          [field]: field === "code_verifier" ? verifier : "https://app.fixture.test/callback",
        },
      });
      expect(retry.status).toBe(400);
      expect(await retry.json()).toEqual({
        error: "invalid_grant",
        error_description: "invalid code",
      });
      denials.push({ status, description, retry: retry.status });
    }
    return {
      denials,
      scope: token.scope,
      type: token.token_type,
      lifetime: token.expires_in,
      persistedScopes: stored.scopes,
      replay: replay.status,
      removed: true,
    };
  },
);
