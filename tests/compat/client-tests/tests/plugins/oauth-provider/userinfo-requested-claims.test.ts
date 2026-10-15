import { expect } from "bun:test";

import { decodeJwt } from "jose";
import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Opaque UserInfo delivers only individually requested claims and retains them through refresh",
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
      body: {
        email: ctx.uniqueEmail("requested-info"),
        name: "Claim Owner",
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
    const created = await control({
      action: "admin-create",
      headers: { cookie },
      body: {
        client_name: "Requested claims",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "openid offline_access",
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
      },
    });
    expect(created.status).toBe(201);
    const client = (await created.json()) as any;
    const issue = (params: object, originalRefreshToken?: string) =>
      control({
        action: "issue-tokens",
        body: {
          clientId: client.client_id,
          userId: owner.user.id,
          grantType: "urn:fixture:claims",
          ...(originalRefreshToken ? { originalRefreshToken } : {}),
          params: { scopes: ["openid", "offline_access"], ...params },
        },
      });
    const info = async (token: string) => {
      const response = await control({
        action: "userinfo",
        headers: { authorization: `Bearer ${token}` },
      });
      expect(response.status).toBe(200);
      return (await response.json()) as any;
    };
    const receipts = [];
    for (const [names, fields] of [
      [["email"], { email: owner.user.email }],
      [["given_name"], { given_name: "Claim" }],
      [["email_verified", "picture", "unsupported"], { email_verified: false }],
      [["name", "family_name"], { name: "Claim Owner", family_name: "Owner" }],
    ] as const) {
      const response = await issue({ requestedUserInfoClaims: names });
      expect(response.status).toBe(200);
      const token = (await response.json()) as any;
      const claims = await info(token.access_token);
      expect(claims).toEqual({ sub: owner.user.id, ...fields });
      for (const name of [
        "email",
        "email_verified",
        "given_name",
        "family_name",
        "name",
        "picture",
      ]) {
        expect(decodeJwt(token.id_token)).not.toHaveProperty(name);
      }
      const { sub, ...values } = claims;
      receipts.push({ names, userId: sub, values });
    }
    const seedResponse = await issue({ requestedUserInfoClaims: ["email"] });
    expect(seedResponse.status).toBe(200);
    const seed = (await seedResponse.json()) as any;
    const inheritedResponse = await issue({}, seed.refresh_token);
    expect(inheritedResponse.status).toBe(200);
    const inherited = (await inheritedResponse.json()) as any;
    expect(await info(inherited.access_token)).toEqual({
      sub: owner.user.id,
      email: owner.user.email,
    });
    const clearedResponse = await issue({ requestedUserInfoClaims: [] }, inherited.refresh_token);
    expect(clearedResponse.status).toBe(200);
    const cleared = (await clearedResponse.json()) as any;
    expect(await info(cleared.access_token)).toEqual({ sub: owner.user.id });
    // JWT access authority deliberately has no persisted per-issuance claim list.
    const signedResponse = await issue({
      requestedUserInfoClaims: ["email"],
      resources: [`${ctx.baseURL}/api/auth/oauth2/userinfo`],
    });
    expect(signedResponse.status).toBe(200);
    const signed = (await signedResponse.json()) as any;
    expect(await info(signed.access_token)).toEqual({ sub: owner.user.id });
    return ctx.snapshot({ receipts, inherited: true, cleared: true, signed: true });
  },
);
