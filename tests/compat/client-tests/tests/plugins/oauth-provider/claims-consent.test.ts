import { createHash } from "node:crypto";

import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Consent bounds individual UserInfo claims and never silently expands remembered scopes",
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
        email: ctx.uniqueEmail("claims-consent"),
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
        client_name: "Claims consent",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "openid",
        token_endpoint_auth_method: "none",
        skip_consent: false,
        grant_types: ["authorization_code"],
      },
    });
    expect(created.status).toBe(201);
    const client = (await created.json()) as any;
    const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const original = { userinfo: { email: null, family_name: null } };
    const authorize = async (claims?: object, prompt?: string) => {
      const response = await control({
        action: "authorize",
        headers: { cookie, accept: "application/json" },
        query: {
          client_id: client.client_id,
          response_type: "code",
          redirect_uri: "https://app.fixture.test/callback",
          scope: "openid",
          state: "claims-consent",
          code_challenge: challenge,
          code_challenge_method: "S256",
          ...(claims ? { claims } : {}),
          ...(prompt ? { prompt } : {}),
        },
      });
      expect(response.status).toBe(200);
      return new URL(((await response.json()) as any).url, ctx.baseURL);
    };
    const consent = (target: URL, claims?: object) =>
      control({
        action: "consent",
        headers: { cookie },
        body: { accept: true, oauth_query: target.search.slice(1), ...(claims ? { claims } : {}) },
      });
    const redeem = async (target: string) => {
      const code = new URL(target, ctx.baseURL).searchParams.get("code");
      expect(code).toBeTruthy();
      const response = await control({
        action: "token",
        body: {
          grant_type: "authorization_code",
          client_id: client.client_id,
          code,
          code_verifier: verifier,
          redirect_uri: "https://app.fixture.test/callback",
        },
      });
      expect(response.status).toBe(200);
      const token = (await response.json()) as any;
      const info = await control({
        action: "userinfo",
        headers: { authorization: `Bearer ${token.access_token}` },
      });
      expect(info.status).toBe(200);
      return (await info.json()) as any;
    };
    const initial = await authorize();
    expect(initial.pathname).toBe("/consent");
    const accepted = await consent(initial);
    expect(accepted.status).toBe(200);
    expect(await redeem(((await accepted.json()) as any).url)).toEqual({ sub: owner.user.id });
    const silent = await authorize(original, "none");
    expect(silent.searchParams.get("error")).toBe("consent_required");
    expect(silent.searchParams.has("code")).toBe(false);
    const request = await authorize(original);
    expect(request.pathname).toBe("/consent");
    for (const claims of ["{", null, [], { userinfo: { email: 17 } }]) {
      const malformed = await control({
        action: "consent",
        headers: { cookie },
        body: { accept: true, oauth_query: request.search.slice(1), claims },
      });
      expect(malformed.status).toBe(400);
      expect(((await malformed.json()) as any).code).toBe("VALIDATION_ERROR");
    }
    const invalid = await consent(request, { userinfo: { name: null } });
    expect(invalid.status).toBe(400);
    expect(await invalid.json()).toEqual({
      error: "invalid_request",
      error_description: "Claim not originally requested",
    });
    const subset = await consent(request, { userinfo: { email: null } });
    expect(subset.status).toBe(200);
    expect(await redeem(((await subset.json()) as any).url)).toEqual({
      sub: owner.user.id,
      email: owner.user.email,
    });
    const records = await control({ action: "consents", headers: { cookie } });
    expect(records.status).toBe(200);
    const rows = (await records.json()) as any[];
    expect(rows).toHaveLength(1);
    expect(rows[0].requestedUserInfoClaims).toEqual(["email"]);
    const remembered = await authorize({ userinfo: { email: null } }, "none");
    expect(remembered.searchParams.get("code")).toBeTruthy();
    const expanded = await authorize(original, "none");
    expect(expanded.searchParams.get("error")).toBe("consent_required");
    const clear = await consent(await authorize(original), { userinfo: {} });
    expect(clear.status).toBe(200);
    expect(await redeem(((await clear.json()) as any).url)).toEqual({ sub: owner.user.id });
    return ctx.snapshot({
      silent: "consent_required",
      subset: ["email"],
      expanded: "consent_required",
      cleared: true,
    });
  },
);
