import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

import { SignJWT, importJWK } from "jose";
import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "UserInfo resolves scoped claims from real access authority with strict token transport and liveness",
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
      body: {
        email: ctx.uniqueEmail("userinfo-owner"),
        name: "Native owner",
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
      action: "admin-create",
      headers: { cookie },
      body: {
        client_name: "Token client",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "openid email profile",
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
        scope: "openid email profile",
        state: "token-state",
        nonce: "oidc-nonce",
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
    expect(token.scope).toBe("openid email profile");
    expect(token.token_type).toBe("Bearer");
    expect(token.expires_in).toBe(3600);
    expect(token.access_token).toMatch(/^[A-Za-z]{32}$/);
    expect(token.refresh_token).toBeUndefined();

    const sessionResponse = await control({ action: "session", headers: { cookie } });
    expect(sessionResponse.status).toBe(200);
    const session = (await sessionResponse.json()) as any;
    const claims = {
      sub: session.user.id,
      name: "Native owner",
      given_name: "Native",
      family_name: "owner",
      email: session.user.email,
      email_verified: false,
    };
    const successes = [];
    for (const [headers, body, method, attachRequest] of [
      [{ authorization: `Bearer ${token.access_token}` }, undefined, "GET", true],
      [{ authorization: `bearer   ${token.access_token}  ` }, undefined, "GET", true],
      [{ authorization: token.access_token }, undefined, "GET", true],
      [{ authorization: `Bearer ${token.access_token}` }, undefined, "GET", false],
      [{}, { access_token: token.access_token }, "POST", true],
    ] as const) {
      const r = await control({ action: "userinfo", headers, body, method, attachRequest });
      expect(r.status).toBe(200);
      expect(r.headers.get("cache-control")).toBe("no-store");
      expect(r.headers.get("pragma")).toBe("no-cache");
      const info = await r.json();
      expect(info).toEqual(claims);
      const { sub, ...fields } = info as any;
      successes.push({ userId: sub, ...fields });
    }
    const failures = [];
    for (const [headers, body, method, attachRequest, status, error, description] of [
      [{}, undefined, "GET", true, 401, "invalid_request", "access token not found"],
      [
        {},
        { access_token: token.access_token },
        "GET",
        true,
        401,
        "invalid_request",
        "access token not found",
      ],
      [
        {},
        { access_token: token.access_token },
        "POST",
        false,
        401,
        "invalid_request",
        "access token not found",
      ],
      [
        { authorization: `Bearer ${token.access_token}` },
        { access_token: token.access_token },
        "POST",
        true,
        400,
        "invalid_request",
        "Multiple access token transport methods are not allowed",
      ],
      [
        { authorization: "Bearer missing-token" },
        undefined,
        "GET",
        true,
        401,
        "invalid_token",
        "Invalid access token",
      ],
      [
        { authorization: `DPoP ${token.access_token}` },
        undefined,
        "GET",
        true,
        401,
        "invalid_token",
        "DPoP authorization requires a DPoP-bound access token",
      ],
    ] as const) {
      const r = await control({ action: "userinfo", headers, body, method, attachRequest });
      expect(r.status).toBe(status);
      const errorBody = await r.json();
      expect(errorBody).toEqual({ error, error_description: description });
      if (description === "Invalid access token") {
        expect(r.headers.get("www-authenticate")).toBe(
          'Bearer error="invalid_token", error_description="Invalid access token"',
        );
      }
      failures.push({ status, body: errorBody });
    }

    // Unlike the private API controls above, this crosses auth.handler with a
    // real form Request. Assert read/error authority before any retirement.
    const http = (input: object) =>
      control({
        action: "protocol-http",
        path: "/oauth2/userinfo",
        method: "POST",
        body: {},
        ...input,
      });
    const row = async (token: string) => {
      const response = await control({ action: "token-row", kind: "access", token });
      expect(response.status).toBe(200);
      return response.json();
    };
    const original = await row(token.access_token);
    expect(original).toMatchObject({
      clientId: id,
      userId: session.user.id,
      sessionId: session.session.id,
    });
    for (const [value, kind] of [
      [null, "null"],
      [17, "number"],
      [[token.access_token], "array"],
    ] as const) {
      const response = await control({
        action: "userinfo",
        headers: { authorization: `Bearer ${token.access_token}` },
        body: { access_token: value },
        method: "POST",
      });
      expect(response.status).toBe(400);
      expect(await response.json()).toEqual({
        code: "VALIDATION_ERROR",
        message: `[body.access_token] Invalid input: expected string, received ${kind}`,
      });
      expect(await row(token.access_token)).toEqual(original);
    }
    const publicTransports = [];
    for (const [headers, rawBody, method, status, expected] of [
      [{}, `access_token=${token.access_token}`, "POST", 200, claims],
      [{ authorization: " \t " }, `access_token=${token.access_token}`, "POST", 200, claims],
      [
        { authorization: `Bearer ${token.access_token}` },
        `access_token=${token.access_token}`,
        "POST",
        400,
        {
          error: "invalid_request",
          error_description: "Multiple access token transport methods are not allowed",
        },
      ],
      [{ authorization: `Bearer ${token.access_token}` }, "access_token=", "POST", 200, claims],
      [{ authorization: `Bearer ${token.access_token}` }, "", "POST", 200, claims],
      [{ authorization: `Bearer ${token.access_token}` }, "", "GET", 200, claims],
      [
        {},
        "",
        "GET",
        401,
        { error: "invalid_request", error_description: "access token not found" },
      ],
      [{}, `access_token=missing&access_token=${token.access_token}`, "POST", 200, claims],
      [
        {},
        `access_token=${token.access_token}&access_token=`,
        "POST",
        401,
        { error: "invalid_request", error_description: "access token not found" },
      ],
    ] as const) {
      const response = await http({
        headers,
        rawBody,
        method,
        query: { access_token: token.access_token },
      });
      expect(response.status).toBe(status);
      expect(response.headers.get("cache-control")).toBe("no-store");
      expect(response.headers.get("pragma")).toBe("no-cache");
      expect(await response.json()).toEqual(expected);
      expect(await row(token.access_token)).toEqual(original);
      publicTransports.push(response.status);
    }

    const key = JSON.parse(
      await readFile(
        new URL("../../../../../fixtures/oauth/client-assertion-keys.json", import.meta.url),
        "utf8",
      ),
    ).keys.find((key: any) => key.family === "Ed25519");
    const hash = (value: string) => createHash("sha256").update(value).digest("base64url");
    const issuer = `${ctx.baseURL}/api/auth`;
    const proof = async (method: string, url: string, jti: string, accessToken?: string) =>
      new SignJWT({
        htm: method,
        htu: url,
        jti,
        iat: Math.floor(Date.now() / 1000),
        ...(accessToken ? { ath: hash(accessToken) } : {}),
      })
        .setProtectedHeader({ typ: "dpop+jwt", alg: "EdDSA", jwk: key.publicJwk })
        .sign(await importJWK(key.privateJwk, "EdDSA"));
    const boundGrant = await control({
      action: "authorize",
      headers: { cookie, accept: "application/json" },
      query: {
        client_id: id,
        response_type: "code",
        redirect_uri: input.redirect_uri,
        scope: "openid email profile",
        state: "bound-state",
        nonce: "bound-nonce",
        code_challenge: challenge,
        code_challenge_method: "S256",
      },
    });
    expect(boundGrant.status).toBe(200);
    const boundCallback = new URL(((await boundGrant.json()) as any).url);
    expect(boundCallback.pathname).toBe("/callback");
    expect(boundCallback.searchParams.get("state")).toBe("bound-state");
    const boundCode = boundCallback.searchParams.get("code");
    expect(boundCode).toBeTruthy();
    const boundIssued = await control({
      action: "token",
      body: { ...input, code: boundCode },
      headers: { dpop: await proof("POST", `${issuer}/oauth2/token`, "userinfo-issue") },
    });
    expect(boundIssued.status).toBe(200);
    const boundToken = (await boundIssued.json()) as any;
    expect(boundToken.token_type).toBe("DPoP");
    const bound = boundToken.access_token;
    const boundOriginal = await row(bound);
    expect(boundOriginal).toMatchObject({
      clientId: id,
      userId: session.user.id,
      sessionId: session.session.id,
      confirmation: { jkt: "yAJQz9pEsZrW3t2ISLq2eQ2bDNmV0AHCGdbF-8RSbko" },
    });
    const uri = `${issuer}/oauth2/userinfo`;
    const acceptedProof = await proof("POST", uri, "userinfo-post", bound);
    const publicBound = [];
    for (const [method, authorization, rawBody, dpop, status, expected] of [
      [
        "POST",
        `DPoP ${bound}`,
        `access_token=${bound}`,
        await proof("POST", uri, "userinfo-mixed", bound),
        400,
        {
          error: "invalid_request",
          error_description: "Multiple access token transport methods are not allowed",
        },
      ],
      [
        "POST",
        "",
        `access_token=${bound}`,
        await proof("POST", uri, "userinfo-body", bound),
        401,
        {
          error: "invalid_token",
          error_description: "DPoP-bound access token requires the DPoP authorization scheme",
        },
      ],
      [
        "POST",
        `DPoP ${bound}`,
        "",
        await proof("GET", uri, "userinfo-method", bound),
        401,
        {
          error: "invalid_dpop_proof",
          error_description: "DPoP proof htm does not match the request method",
        },
      ],
      [
        "POST",
        `DPoP ${bound}`,
        "",
        await proof("POST", "https://wrong.test/userinfo", "userinfo-url", bound),
        401,
        {
          error: "invalid_dpop_proof",
          error_description: "DPoP proof htu does not match the request URL",
        },
      ],
      ["POST", `DPoP ${bound}`, "", acceptedProof, 200, claims],
      [
        "POST",
        `DPoP ${bound}`,
        "",
        acceptedProof,
        401,
        { error: "invalid_dpop_proof", error_description: "DPoP proof jti has already been used" },
      ],
      ["GET", `DPoP ${bound}`, "", await proof("GET", uri, "userinfo-get", bound), 200, claims],
    ] as const) {
      const response = await http({
        method,
        headers: { authorization, dpop },
        rawBody,
        query: { ignored: "1" },
      });
      expect(response.status).toBe(status);
      expect(await response.json()).toEqual(expected);
      expect(await row(bound)).toEqual(boundOriginal);
      publicBound.push(response.status);
    }
    const noPhysical = await control({
      action: "userinfo",
      attachRequest: false,
      headers: { authorization: `DPoP ${bound}` },
    });
    expect(noPhysical.status).toBe(401);
    expect(await noPhysical.json()).toEqual({
      error: "invalid_token",
      error_description: "DPoP-bound access token requires an HTTP request context",
    });
    expect(await row(bound)).toEqual(boundOriginal);

    const scoped = [];
    for (const scope of ["openid", "email"]) {
      const grant = await control({
        action: "authorize",
        headers: { cookie, accept: "application/json" },
        query: {
          client_id: id,
          response_type: "code",
          redirect_uri: "https://app.fixture.test/callback",
          scope,
          state: "token-state",
          code_challenge: challenge,
          code_challenge_method: "S256",
          ...(scope === "openid" ? { nonce: "oidc-nonce" } : {}),
        },
      });
      expect(grant.status).toBe(200);
      const code = new URL(((await grant.json()) as any).url).searchParams.get("code");
      expect(code).toBeTruthy();
      const issued = await control({ action: "token", body: { ...input, code } });
      expect(issued.status).toBe(200);
      const scopedToken = ((await issued.json()) as any).access_token;
      const r = await control({
        action: "userinfo",
        headers: { authorization: `Bearer ${scopedToken}` },
      });
      if (scope === "openid") {
        expect(r.status).toBe(200);
        expect(await r.json()).toEqual({ sub: session.user.id });
        const retired = await control({
          action: "revoke",
          body: { client_id: id, token: scopedToken, token_type_hint: "access_token" },
        });
        expect(retired.status).toBe(200);
        const denied = await control({
          action: "userinfo",
          headers: { authorization: `Bearer ${scopedToken}` },
        });
        expect(denied.status).toBe(401);
        expect(await denied.json()).toEqual({
          error: "invalid_token",
          error_description: "Invalid access token",
        });
        scoped.push({ scope, status: r.status, retired: denied.status });
      } else {
        expect(r.status).toBe(400);
        expect(await r.json()).toEqual({
          error: "invalid_scope",
          error_description: "Missing required scope",
        });
        scoped.push({ scope, status: r.status });
      }
    }
    const expired = await control({ action: "expire-session", token: session.session.token });
    expect(expired.status).toBe(200);
    expect(await expired.json()).toEqual({ expired: true });
    const denied = await control({
      action: "userinfo",
      headers: { authorization: `Bearer ${token.access_token}` },
    });
    expect(denied.status).toBe(401);
    expect(await denied.json()).toEqual({
      error: "invalid_token",
      error_description: "Invalid access token",
    });
    expect(denied.headers.get("www-authenticate")).toBe(
      'Bearer error="invalid_token", error_description="Invalid access token"',
    );
    return ctx.snapshot({
      authorizationSession: session,
      successes,
      failures,
      publicTransports,
      publicBound,
      scoped,
      expired: denied.status,
    });
  },
);
