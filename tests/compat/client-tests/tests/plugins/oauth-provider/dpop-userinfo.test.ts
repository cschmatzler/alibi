import { expect } from "bun:test";
import { createHash } from "node:crypto";

import { SignJWT, importJWK } from "jose";
import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
const hash = (value: string) => createHash("sha256").update(value).digest("base64url");
compatScenario(
  "UserInfo enforces sender proof before exposing opaque and signed user authority",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: object) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const signup = await control({
      action: "signup",
      body: { email: ctx.uniqueEmail("dpop-info"), name: "Bound Owner", password: "password123" },
    });
    expect(signup.status).toBe(200);
    const owner = (await signup.json()) as any;
    const cookie = signup.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const created = await control({
      action: "admin-create",
      headers: { cookie },
      body: {
        client_name: "Bound UserInfo",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "openid email profile",
        token_endpoint_auth_method: "none",
      },
    });
    expect(created.status).toBe(201);
    const client = (await created.json()) as any;
    const key = (
      await Bun.file(
        new URL("../../../../../fixtures/oauth/client-assertion-keys.json", import.meta.url),
      ).json()
    ).keys.find((key: any) => key.family === "Ed25519");
    const jkt = hash(
      JSON.stringify({ crv: key.publicJwk.crv, kty: key.publicJwk.kty, x: key.publicJwk.x }),
    );
    const userinfo = `${ctx.baseURL}/api/auth/oauth2/userinfo`;
    const failures = [];
    const successes = [];
    for (const kind of ["opaque", "jwt"]) {
      const issued = await control({
        action: "issue-tokens",
        body: {
          clientId: client.client_id,
          userId: owner.user.id,
          grantType: "urn:fixture:info",
          params: {
            scopes: ["openid", "email", "profile"],
            confirmation: { jkt },
            ...(kind === "jwt" ? { resources: [userinfo] } : {}),
          },
        },
      });
      expect(issued.status).toBe(200);
      const tokens = (await issued.json()) as any;
      const proof = async (label: string, payload: object = {}) =>
        new SignJWT({
          htm: "GET",
          htu: userinfo,
          jti: kind + "-" + label,
          iat: Math.floor(Date.now() / 1000),
          ath: hash(tokens.access_token),
          ...payload,
        })
          .setProtectedHeader({ typ: "dpop+jwt", alg: "EdDSA", jwk: key.publicJwk })
          .sign(await importJWK(key.privateJwk, "EdDSA"));
      const info = (headers: object, extra: object = {}) =>
        control({ action: "userinfo", headers, ...extra });
      for (const [headers, extra, error, description] of [
        [
          { authorization: `Bearer ${tokens.access_token}` },
          {},
          "invalid_token",
          "DPoP-bound access token requires the DPoP authorization scheme",
        ],
        [
          { authorization: `DPoP ${tokens.access_token}` },
          { attachRequest: false },
          "invalid_token",
          "DPoP-bound access token requires an HTTP request context",
        ],
        [
          { authorization: `DPoP ${tokens.access_token}` },
          {},
          "invalid_dpop_proof",
          "DPoP proof header is required",
        ],
        [
          {
            authorization: `DPoP ${tokens.access_token}`,
            dpop: await proof("bad-ath", { ath: "wrong" }),
          },
          {},
          "invalid_dpop_proof",
          "DPoP proof ath does not match the access token",
        ],
        [
          {
            authorization: `DPoP ${tokens.access_token}`,
            dpop: await proof("bad-method", { htm: "POST" }),
          },
          {},
          "invalid_dpop_proof",
          "DPoP proof htm does not match the request method",
        ],
      ] as const) {
        const denied = await info(headers, extra);
        expect(denied.status).toBe(401);
        const body = await denied.json();
        expect(body).toEqual({ error, error_description: description });
        failures.push({ kind, body });
      }
      const jwt = await proof("accepted", { htu: userinfo + "?ignored=1" });
      const accepted = await info({ authorization: `DPoP ${tokens.access_token}`, dpop: jwt });
      expect(accepted.status).toBe(200);
      const claims = (await accepted.json()) as any;
      expect(claims).toEqual({
        sub: owner.user.id,
        name: "Bound Owner",
        given_name: "Bound",
        family_name: "Owner",
        email: owner.user.email,
        email_verified: false,
      });
      const { sub, ...fields } = claims;
      successes.push({ kind, userId: sub, ...fields });
      const replay = await info({ authorization: `DPoP ${tokens.access_token}`, dpop: jwt });
      expect(replay.status).toBe(401);
      expect(await replay.json()).toEqual({
        error: "invalid_dpop_proof",
        error_description: "DPoP proof jti has already been used",
      });
      const post = await info(
        {
          authorization: `DPoP ${tokens.access_token}`,
          dpop: await proof("post", { htm: "POST" }),
        },
        { method: "POST" },
      );
      expect(post.status).toBe(200);
      expect(await post.json()).toEqual(claims);
    }
    return ctx.snapshot({ owner: owner.user, successes, failures });
  },
);
