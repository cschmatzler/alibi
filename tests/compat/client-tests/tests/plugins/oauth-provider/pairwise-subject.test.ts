import { createHash } from "node:crypto";

import { createLocalJWKSet, jwtVerify } from "jose";
import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "Pairwise OIDC subjects stay sector-bound without replacing stored identity",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: object) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "pairwise", ...input }),
      });
    const signup = await control({
      action: "signup",
      body: { email: ctx.uniqueEmail("pairwise"), name: "Private Owner", password: "password123" },
    });
    expect(signup.status).toBe(200);
    const owner = (await signup.json()) as any;
    expect(owner.user.id).toBe("pairwise-owner");
    const cookie = signup.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const receipts = [];
    let logout: { clientId: string; hint: string } | undefined;
    for (const [subjectType, redirect, expectedSub] of [
      [
        "pairwise",
        "https://app.fixture.test/callback",
        "pXrBQW8RVZxizqoE0yPPjNWilWCkov57HwhsIQTIwdw=",
      ],
      [
        "pairwise",
        "https://app.fixture.test/another",
        "pXrBQW8RVZxizqoE0yPPjNWilWCkov57HwhsIQTIwdw=",
      ],
      [
        "pairwise",
        "https://app.fixture.test:8443/callback",
        "ESRSfh6C97vNCTcN2wp268zZl3lqWrmeLhktRLBtjwI=",
      ],
      [
        "pairwise",
        "https://other.fixture.test/callback",
        "FNakr2C0b9TSjk0ygPwHF9LrmPKwsNDuVcDFIMSUTZs=",
      ],
      ["public", "https://app.fixture.test/callback", "pairwise-owner"],
    ]) {
      expect(
        (
          await control({
            action: "userinfo-claims-state",
            value: "pairwise",
            reset: true,
          })
        ).status,
      ).toBe(200);
      const created = await control({
        action: "admin-create",
        headers: { cookie },
        body: {
          client_name: "Subject consumer",
          redirect_uris: [redirect],
          scope: "openid profile offline_access",
          subject_type: subjectType,
          token_endpoint_auth_method: "client_secret_post",
          grant_types: ["authorization_code", "refresh_token"],
          skip_consent: true,
          enable_end_session: true,
        },
      });
      expect(created.status).toBe(201);
      const client = (await created.json()) as any;
      const grant = await control({
        action: "authorize",
        headers: { cookie, accept: "application/json" },
        query: {
          client_id: client.client_id,
          response_type: "code",
          redirect_uri: redirect,
          scope: "openid profile offline_access",
          nonce: "pairwise-nonce",
          code_challenge: challenge,
          code_challenge_method: "S256",
        },
      });
      expect(grant.status).toBe(200);
      const code = new URL(((await grant.json()) as any).url).searchParams.get("code");
      expect(typeof code).toBe("string");
      const issued = await control({
        action: "protocol-http",
        path: "/oauth2/token",
        method: "POST",
        body: {
          grant_type: "authorization_code",
          client_id: client.client_id,
          client_secret: client.client_secret,
          code,
          code_verifier: verifier,
          redirect_uri: redirect,
        },
      });
      expect(issued.status).toBe(200);
      const tokens = (await issued.json()) as any;
      const keys = createLocalJWKSet((await (await control({ action: "jwks" })).json()) as any);
      const { payload } = await jwtVerify(tokens.id_token, keys, {
        issuer: `${ctx.baseURL}/api/auth`,
        audience: client.client_id,
      });
      expect(payload.sub).toBe(expectedSub);
      const info = await control({
        action: "protocol-http",
        path: "/oauth2/userinfo",
        method: "GET",
        headers: { authorization: `Bearer ${tokens.access_token}` },
      });
      expect(info.status).toBe(200);
      const claims = await info.json();
      expect(claims).toEqual({
        sub: expectedSub,
        name: "Operator pairwise",
        email: "operator-pairwise@example.test",
        extension_owner: "operator-pairwise",
        toString: "operator-toString-pairwise",
        given_name: "Private",
        family_name: "Owner",
      });
      const callbackResponse = await control({ action: "userinfo-claims-state" });
      expect(callbackResponse.status).toBe(200);
      const callback = (await callbackResponse.json()) as any;
      expect(callback.calls).toEqual([
        {
          userId: "pairwise-owner",
          userName: "Private Owner",
          userEmail: owner.user.email,
          scopes: ["openid", "profile", "offline_access"],
          requestedClaims: [],
          payloadSub: "pairwise-owner",
          payloadClientId: client.client_id,
          payloadScope: "openid profile offline_access",
        },
      ]);
      expect(callback.events).toEqual(["operator"]);
      const inspected = [];
      for (const kind of ["access_token", "refresh_token"]) {
        const response = await control({
          action: "introspect",
          body: {
            client_id: client.client_id,
            client_secret: client.client_secret,
            token: tokens[kind],
            token_type_hint: kind,
          },
        });
        expect(response.status).toBe(200);
        const value = (await response.json()) as any;
        expect(value.active).toBe(true);
        expect(value.sub).toBe(expectedSub);
        inspected.push({ active: value.active, sub: value.sub, scope: value.scope });
      }
      const row = await control({ action: "token-row", token: tokens.access_token });
      expect(row.status).toBe(200);
      const stored = (await row.json()) as any;
      expect(stored.userId).toBe("pairwise-owner");
      if (!logout) logout = { clientId: client.client_id, hint: tokens.id_token };
      receipts.push({
        subjectType,
        redirect,
        subject: payload.sub,
        claims,
        callback: {
          ...callback,
          calls: callback.calls.map(
            ({ payloadSub, payloadClientId, payloadScope, ...args }: any) => ({
              ...args,
              payload: { userId: payloadSub, clientId: payloadClientId, scope: payloadScope },
            }),
          ),
        },
        inspected,
        storedUserId: stored.userId,
      });
    }
    const ended = await control({
      action: "end-session",
      query: { client_id: logout!.clientId, id_token_hint: logout!.hint },
    });
    expect(ended.status).toBe(200);
    expect(await ended.json()).toBeNull();
    const retired = await control({ action: "session", headers: { cookie } });
    expect(retired.status).toBe(200);
    expect(await retired.json()).toBeNull();
    return ctx.snapshot({ owner, receipts, retired: true });
  },
);
