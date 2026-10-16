import { createHash } from "node:crypto";

import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Authorization claims requests validate ACR and capture individual UserInfo delivery",
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
        email: ctx.uniqueEmail("claims-request"),
        name: "Claims Owner",
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
        client_name: "Claims request",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "openid email offline_access",
        token_endpoint_auth_method: "none",
        skip_consent: true,
        grant_types: ["authorization_code"],
      },
    });
    expect(created.status).toBe(201);
    const client = (await created.json()) as any;
    const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const authorize = async (claims: unknown, scope = "openid offline_access") => {
      const response = await control({
        action: "authorize",
        headers: { cookie, accept: "application/json" },
        query: {
          client_id: client.client_id,
          response_type: "code",
          redirect_uri: "https://app.fixture.test/callback",
          scope,
          state: "claims-state",
          code_challenge: challenge,
          code_challenge_method: "S256",
          claims,
        },
      });
      expect(response.status).toBe(200);
      return new URL(((await response.json()) as any).url);
    };
    const accepted = [];
    for (const asString of [false, true]) {
      const request = {
        userinfo: { family_name: { essential: true }, email: null, unsupported: null },
        id_token: { acr: { essential: true, value: "0" } },
      };
      const target = await authorize(asString ? JSON.stringify(request) : request);
      expect(target.searchParams.get("error")).toBeNull();
      const code = target.searchParams.get("code");
      expect(code).toBeTruthy();
      const issued = await control({
        action: "token",
        body: {
          grant_type: "authorization_code",
          client_id: client.client_id,
          code,
          code_verifier: verifier,
          redirect_uri: "https://app.fixture.test/callback",
        },
      });
      expect(issued.status).toBe(200);
      const tokens = (await issued.json()) as any;
      const info = await control({
        action: "userinfo",
        headers: { authorization: `Bearer ${tokens.access_token}` },
      });
      expect(info.status).toBe(200);
      const fields = (await info.json()) as any;
      expect(fields).toEqual({ sub: owner.user.id, email: owner.user.email, family_name: "Owner" });
      const row = await control({ action: "token-row", token: tokens.access_token });
      expect(((await row.json()) as any).requestedUserInfoClaims).toEqual(["family_name", "email"]);
      accepted.push({
        asString,
        userId: fields.sub,
        email: fields.email,
        family_name: fields.family_name,
      });
    }
    const failures = [];
    for (const claims of [
      "{",
      "null",
      { userinfo: { email: 17 } },
      { userinfo: ["email"] },
      { id_token: { acr: { essential: "true" } } },
      { id_token: { acr: { values: [1] } } },
    ]) {
      const target = await authorize(claims);
      expect(target.searchParams.get("error")).toBe("invalid_request");
      expect(target.searchParams.get("error_description")).toBe(
        "claims must be a valid Claims request object",
      );
      expect(target.searchParams.has("code")).toBe(false);
      failures.push("invalid_request");
    }
    for (const claims of [
      { id_token: { acr: { essential: true, value: "strong" } } },
      { id_token: { acr: { essential: true, value: "0", values: [] } } },
    ]) {
      const target = await authorize(claims);
      expect(target.searchParams.get("error")).toBe("access_denied");
      expect(target.searchParams.get("error_description")).toBe(
        "essential acr requirement cannot be met",
      );
      failures.push("access_denied");
    }
    const nonOidc = await authorize("{", "email");
    expect(nonOidc.searchParams.get("error")).toBe("invalid_request");
    expect(nonOidc.searchParams.get("error_description")).toBe(
      "openid scope must be requested when using the claims parameter",
    );
    // Only the ACR member is typed; arbitrary UserInfo member properties remain valid.
    const loose = await authorize(
      '{"userinfo":{"email":{"essential":"not-a-boolean","value":1e400}}}',
    );
    expect(loose.searchParams.get("error")).toBeNull();
    expect(loose.searchParams.get("code")).toBeTruthy();
    return ctx.snapshot({ accepted, failures, loose: true, nonOidc: "invalid_request" });
  },
);
