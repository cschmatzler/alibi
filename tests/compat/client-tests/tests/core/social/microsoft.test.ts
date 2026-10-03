import { expect } from "bun:test";

import { credential, issuedAt } from "../../../support/id-token";
import { authProfilePath, type FixtureProfile } from "../../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../../support/scenario";

type Row = Record<string, unknown>;

type Stored = {
  users: Array<Row & { id: string }>;
  accounts: Array<Row & { id: string }>;
  sessions: Array<Row & { id: string }>;
};

async function state(ctx: ScenarioContext) {
  const response = await ctx.rawRequest({ path: "/__test/social-provider/state" });
  expect(response.status).toBe(200);
  return response.body as Stored;
}

async function control(ctx: ScenarioContext, value: Row) {
  const response = await ctx.rawRequest({
    path: "/__test/microsoft/control",
    method: "POST",
    json: value,
  });
  expect(response.status).toBe(200);
  return response;
}

async function receipts(ctx: ScenarioContext) {
  const response = await ctx.rawRequest({ path: "/__test/microsoft/receipts" });
  expect(response.status).toBe(200);
  return (
    response.body as Array<{
      path: string;
      method: string;
      authorization: string | null;
      contentType: string | null;
      body: Record<string, string> | null;
    }>
  ).map((row) => ({
    ...row,
    body: row.body?.code_verifier
      ? {
          ...row.body,
          code_verifier: { token: row.body.code_verifier, length: row.body.code_verifier.length },
        }
      : row.body,
  }));
}

async function proof(ctx: ScenarioContext, claims: Row = {}, header: Row = {}, wrong = false) {
  return credential(
    {
      iss: ctx.baseURL + "/fixture-tenant/v2.0",
      tid: "fixture-tenant",
      aud: "fixture-social-client",
      oid: ctx.uniqueToken("microsoft-subject"),
      email: ctx.uniqueEmail("microsoft"),
      email_verified: true,
      name: "Microsoft JWT Name",
      picture: "https://images.example.invalid/microsoft.png",
      ...claims,
    },
    header,
    wrong,
  );
}

async function foreign(ctx: ScenarioContext) {
  const actor = ctx.actor("foreign");
  const signup = await actor.client.signUp.email({
    email: ctx.uniqueEmail("foreign"),
    password: "Password123!",
    name: "Foreign",
  });
  expect(signup.error).toBeNull();

  return { actor, signup, before: await state(ctx) };
}

function unchangedForeign(before: Stored, after: Stored) {
  for (const key of ["users", "accounts", "sessions"] as const) {
    for (const row of before[key]) {
      expect(after[key].find((candidate) => candidate.id === row.id)).toEqual(row);
    }
  }
}

async function callback(
  ctx: ScenarioContext,
  mode: FixtureProfile = "social-microsoft-public",
  requestSignUp = false,
) {
  const actor = ctx.actor("microsoft", mode);
  const start = await actor.client.signIn.social({
    provider: "microsoft",
    callbackURL: "/dashboard",
    requestSignUp,
  });
  expect(start.error).toBeNull();

  const url = new URL(start.data!.url!);
  const path =
    authProfilePath(mode) +
    `/callback/microsoft?code=fixture-code&state=${encodeURIComponent(url.searchParams.get("state")!)}`;
  const response = await actor.fetch(ctx.baseURL + path, { redirect: "manual" });
  return { actor, start, url, path, response };
}

const defaults = ["openid", "profile", "email", "User.Read", "offline_access"];
for (const mode of [
  "default",
  "configured",
  "disabled-scope",
  "disabled-configured",
  "authority-slashes",
  "organizations",
  "consumers",
  "fixed-tenant",
  "client-array",
] as const) {
  compatScenario(
    `microsoft ${mode} authorization preserves scopes PKCE hint prompt authority and foreign rows`,
    async (ctx) => {
      const other = await foreign(ctx);
      const profile = `social-microsoft-${mode}` as const;
      const result = await ctx.actor("microsoft", profile).client.signIn.social({
        provider: "microsoft",
        callbackURL: "/dashboard",
        scopes: ["requested-scope", "openid"],
        loginHint: "login@example.invalid",
        additionalParams: { custom: "value with space" },
      });
      expect(result.error).toBeNull();
      const url = new URL(result.data!.url!);
      const tenant = ["organizations", "consumers"].includes(mode)
        ? mode
        : mode === "fixed-tenant"
          ? "fixture-tenant"
          : "common";
      expect(url.origin).toBe(
        mode === "default" ? "https://login.microsoftonline.com" : ctx.baseURL,
      );
      expect(url.pathname).toBe(`/${tenant}/oauth2/v2.0/authorize`);
      const configured = ["configured", "disabled-configured"].includes(mode);
      expect(url.searchParams.getAll("scope")).toEqual([
        [
          ...(mode.startsWith("disabled-") ? [] : defaults),
          ...(configured ? ["configured-scope", "openid", "punctuation-!~*'()"] : []),
          "requested-scope",
          "openid",
        ].join(" "),
      ]);
      expect(url.searchParams.getAll("client_id")).toEqual(["fixture-social-client"]);
      expect(url.searchParams.getAll("state")).toHaveLength(1);
      expect(url.searchParams.get("state")).toBeTruthy();
      expect(url.searchParams.get("response_type")).toBe("code");
      expect(url.searchParams.get("code_challenge_method")).toBe("S256");
      expect(url.searchParams.get("code_challenge")).toBeTruthy();
      expect(url.searchParams.get("login_hint")).toBe("login@example.invalid");
      expect(url.searchParams.get("prompt")).toBe(configured ? "login" : null);
      expect(url.searchParams.get("custom")).toBe("value with space");
      expect(url.searchParams.has("nonce")).toBeFalse();
      expect(url.searchParams.get("redirect_uri")).toBe(
        ctx.baseURL + authProfilePath(profile) + "/callback/microsoft",
      );
      const after = await state(ctx);
      expect(after).toEqual(other.before);
      expect(await receipts(ctx)).toEqual([]);
      if (mode === "default") {
        expect((await ctx.rawRequest({ path: "/__test/microsoft/constructor" })).body).toEqual({
          error: "Microsoft Entra ID clientAssertion cannot be combined with clientSecret",
        });
      }
      return { result: ctx.snapshot(result), before: other.before, after };
    },
    ["POST /sign-in/social"],
  );
}
for (const variant of [
  "signature",
  "issuer",
  "audience",
  "expired",
  "old",
  "future",
  "nonce",
  "unknown-kid",
  "missing-tid",
  "numeric-tid",
  "bound-issuer",
  "consumer-organizations",
  "organization-consumers",
  "fixed-issuer",
  "missing-oid",
  "null-oid",
  "blank-oid",
  "numeric-oid",
  "missing-email",
  "null-email",
  "empty-email",
  "disabled-idtoken",
  "implicit-disabled",
] as const) {
  compatScenario(
    `microsoft genuine signed ${variant} rejection preserves all foreign rows and pre-photo mapping order`,
    async (ctx) => {
      const other = await foreign(ctx);
      let claims: Row = {};
      switch (variant) {
        case "issuer":
        case "bound-issuer":
          claims = { iss: "https://untrusted.invalid/fixture-tenant/v2.0" };
          break;
        case "audience":
          claims = { aud: "foreign-client" };
          break;
        case "expired":
          claims = { exp: issuedAt - 10 };
          break;
        case "old":
          claims = { iat: issuedAt - 7200 };
          break;
        case "future":
          claims = { iat: issuedAt + 7200 };
          break;
        case "nonce":
          claims = { nonce: "wrong-nonce" };
          break;
        case "missing-tid":
          claims = { tid: undefined };
          break;
        case "numeric-tid":
          claims = { tid: 123 };
          break;
        case "consumer-organizations":
          claims = {
            tid: "9188040d-6c67-4c5b-b112-36a304b66dad",
            iss: ctx.baseURL + "/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
          };
          break;
        case "fixed-issuer":
          claims = { tid: "another-tenant", iss: ctx.baseURL + "/another-tenant/v2.0" };
          break;
        case "missing-oid":
          claims = { oid: undefined };
          break;
        case "null-oid":
          claims = { oid: null };
          break;
        case "blank-oid":
          claims = { oid: "\uFEFF " };
          break;
        case "numeric-oid":
          claims = { oid: 123 };
          break;
        case "missing-email":
          claims = { email: undefined };
          break;
        case "null-email":
          claims = { email: null };
          break;
        case "empty-email":
          claims = { email: "" };
          break;
      }
      const token = await proof(
        ctx,
        claims,
        variant === "unknown-kid" ? { kid: "foreign-kid" } : {},
        variant === "signature",
      );
      const mode =
        variant === "consumer-organizations"
          ? "organizations"
          : variant === "organization-consumers"
            ? "consumers"
            : variant === "fixed-issuer"
              ? "fixed-tenant"
              : ["disabled-idtoken", "implicit-disabled", "signup-disabled"].includes(variant)
                ? variant
                : variant.endsWith("email")
                  ? "public"
                  : "mapped";
      const actor = ctx.actor("microsoft", `social-microsoft-${mode}` as FixtureProfile);
      const result = await actor.client.signIn.social({
        provider: "microsoft",
        idToken: { token, ...(variant === "nonce" ? { nonce: "request-nonce" } : {}) },
      });
      expect(result.error).not.toBeNull();
      expect(result.error?.code).toBe(
        variant === "disabled-idtoken"
          ? "ID_TOKEN_NOT_SUPPORTED"
          : ["implicit-disabled", "signup-disabled"].includes(variant)
            ? "OAUTH_LINK_ERROR"
            : variant.endsWith("email")
              ? "USER_EMAIL_NOT_FOUND"
              : variant.endsWith("oid")
                ? "FAILED_TO_GET_USER_INFO"
                : "INVALID_TOKEN",
      );
      const after = await state(ctx);
      expect(after).toEqual(other.before);
      const mapper = (await ctx.rawRequest({ path: "/__test/microsoft/mapper-receipts" })).body;
      expect(mapper).toEqual([]);
      const requests = await receipts(ctx);
      expect(
        requests.map((row) => ({
          path: row.path,
          method: row.method,
          authorization: row.authorization,
          body: row.body,
        })),
      ).toEqual(
        variant === "disabled-idtoken"
          ? []
          : [
              {
                path: `/${mode === "organizations" || mode === "consumers" ? mode : mode === "fixed-tenant" ? "fixture-tenant" : "common"}/discovery/v2.0/keys`,
                method: "GET",
                authorization: null,
                body: null,
              },
            ],
      );
      return {
        result: ctx.snapshot(result),
        before: other.before,
        after,
        mapper,
        receipts: requests,
      };
    },
  );
}
for (const variant of [
  "common",
  "organizations",
  "consumers",
  "fixed-tenant",
  "client-array",
  "exact-nonce",
  "explicit-signup",
  "verified-primary",
  "verified-secondary",
  "explicit-false",
  "explicit-true",
  "signup-option",
] as const) {
  compatScenario(
    `microsoft signed ${variant} admission persists raw oid using configured authority`,
    async (ctx) => {
      const other = await foreign(ctx);
      const consumer = variant === "consumers";
      const tid = consumer ? "9188040d-6c67-4c5b-b112-36a304b66dad" : "fixture-tenant";
      const email = ctx.uniqueEmail("microsoft");
      const claims: Row = {
        tid,
        iss: ctx.baseURL + `/${tid}/v2.0`,
        email,
        ...(variant === "client-array"
          ? { aud: ["foreign-client", "fixture-microsoft-secondary"] }
          : {}),
        ...(variant === "exact-nonce" ? { nonce: "matching-nonce" } : {}),
        ...(["verified-primary", "verified-secondary"].includes(variant)
          ? {
              email_verified: undefined,
              [variant === "verified-primary"
                ? "verified_primary_email"
                : "verified_secondary_email"]: ["foreign@example.invalid", email],
            }
          : {}),
        ...(variant === "explicit-false"
          ? { email_verified: false, verified_primary_email: [email] }
          : {}),
      };
      const token = await proof(ctx, claims);
      const mode = ["organizations", "consumers", "fixed-tenant", "client-array"].includes(variant)
        ? variant
        : variant === "signup-option"
          ? "signup-disabled"
          : variant === "explicit-signup"
            ? "implicit-disabled"
            : "public";
      const actor = ctx.actor("microsoft", `social-microsoft-${mode}` as FixtureProfile);
      const result = await actor.client.signIn.social({
        provider: "microsoft",
        requestSignUp: variant === "explicit-signup",
        idToken: { token, ...(variant === "exact-nonce" ? { nonce: "matching-nonce" } : {}) },
      });
      expect(result.error).toBeNull();
      const stored = await state(ctx);
      unchangedForeign(other.before, stored);
      for (const key of ["users", "accounts", "sessions"] as const) {
        expect(stored[key]).toHaveLength(other.before[key].length + 1);
      }
      const user = stored.users.find(
        (row) => !other.before.users.some((old) => old.id === row.id),
      )!;
      const account = stored.accounts.find((row) => row.userId === user.id)!;
      const decoded = JSON.parse(Buffer.from(token.split(".")[1]!, "base64url").toString());
      expect(account).toMatchObject({
        providerId: "microsoft",
        accountId: decoded.oid,
        idToken: token,
      });
      expect(user.emailVerified).toBe(variant !== "explicit-false");
      expect((await actor.client.getSession()).data?.user.id).toBe(user.id);
      return {
        result: ctx.snapshot(result),
        before: other.before,
        stored,
        receipts: await receipts(ctx),
      };
    },
    ["POST /sign-in/social"],
  );
}

for (const mode of [
  "public",
  "configured",
  "disabled-configured",
  "mapped",
  "client-key",
  "assertion",
  "photo64",
  "no-photo",
] as const) {
  compatScenario(
    `microsoft ${mode} exchange refresh replay logout preserves raw oid and real grant photo assertion receipts`,
    async (ctx) => {
      const other = await foreign(ctx);
      const token = await proof(
        ctx,
        {
          email: ctx.uniqueEmail("exchange"),
          name: "Exchange Name",
          iss: "https://unverified-code-issuer.invalid",
          tid: 123,
        },
        {},
        true,
      );
      // Source code exchange decodes rather than reusing the distinct direct-token verifier.
      await control(ctx, { idToken: token });
      const profile = `social-microsoft-${mode}` as const;
      const flow = await callback(ctx, profile);
      expect(flow.response.status).toBe(302);
      expect(flow.response.headers.get("location")).toBe("/dashboard");
      const session = await flow.actor.client.getSession();
      expect(session.error).toBeNull();
      const stored = await state(ctx);
      unchangedForeign(other.before, stored);
      for (const key of ["users", "accounts", "sessions"] as const) {
        expect(stored[key]).toHaveLength(other.before[key].length + 1);
      }
      const decoded = JSON.parse(Buffer.from(token.split(".")[1]!, "base64url").toString());
      const user = stored.users.find(
        (row) => !other.before.users.some((old) => old.id === row.id),
      )!;
      const account = stored.accounts.find((row) => row.userId === user.id)!;
      const photo = "data:image/jpeg;base64, /9gAQf/Z";
      expect(user).toMatchObject({
        name: mode === "mapped" ? "Mapped Exchange Name" : "Exchange Name",
        email: mode === "mapped" ? "mapped-microsoft@example.invalid" : decoded.email,
        emailVerified: mode !== "mapped",
        image:
          mode === "mapped"
            ? "https://images.example.invalid/mapped-microsoft.png"
            : mode === "no-photo"
              ? decoded.picture
              : photo,
      });
      expect(account).toMatchObject({
        providerId: "microsoft",
        accountId: decoded.oid,
        accessToken: "fixture-microsoft-access",
        refreshToken: "fixture-microsoft-refresh",
        idToken: token,
        scope: "",
      });
      expect(session.data?.user.id).toBe(user.id);
      const requests = await receipts(ctx);
      const exchange = requests[0]!.body! as Record<string, unknown>;
      const verifier = exchange.code_verifier as unknown as { token: string; length: number };
      expect(verifier.length).toBe(128);
      expect(flow.url.searchParams.get("code_challenge")).toBe(
        Buffer.from(
          await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier.token)),
        ).toString("base64url"),
      );
      expect(exchange).toEqual({
        grant_type: "authorization_code",
        code: "fixture-code",
        code_verifier: verifier,
        client_id: "fixture-social-client",
        redirect_uri: ctx.baseURL + authProfilePath(profile) + "/callback/microsoft",
        ...(mode === "public"
          ? {}
          : mode === "assertion"
            ? {
                client_assertion: "fixture-assertion-authorization_code",
                client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
              }
            : { client_secret: "fixture-social-secret" }),
        ...(mode === "client-key" ? { client_key: "fixture-microsoft-client-key" } : {}),
      });
      expect(requests.map((row) => row.path)).toEqual([
        "/common/oauth2/v2.0/token",
        ...(mode === "no-photo" ? [] : ["/photo/" + (mode === "photo64" ? "64x64" : "48x48")]),
      ]);
      if (mode !== "no-photo") {
        expect(requests[1]).toMatchObject({
          authorization: "Bearer fixture-microsoft-access",
          body: null,
        });
      }
      const mapper = (await ctx.rawRequest({ path: "/__test/microsoft/mapper-receipts" })).body;
      expect(mapper).toEqual(mode === "mapped" ? [{ ...decoded, picture: photo }] : []);
      const replay = await flow.actor.fetch(ctx.baseURL + flow.path, { redirect: "manual" });
      expect(replay.status).toBe(302);
      expect(
        new URL(replay.headers.get("location")!, ctx.baseURL).searchParams.get("error"),
      ).toBeTruthy();
      expect(await state(ctx)).toEqual(stored);
      expect(await receipts(ctx)).toHaveLength(requests.length);
      await control(ctx, {
        tokenResponse: {
          access_token: "rotated-access",
          refresh_token: "rotated-refresh",
          expires_in: 1800,
          scope: "rotated-scope",
        },
      });
      const denied = await other.actor.client.refreshToken({ accountId: account.id });
      expect(denied.error).not.toBeNull();
      expect(await state(ctx)).toEqual(stored);
      expect(await receipts(ctx)).toHaveLength(requests.length);
      const refreshed = await flow.actor.client.refreshToken({ accountId: account.id });
      expect(refreshed.error).toBeNull();
      const rotated = await state(ctx);
      unchangedForeign(other.before, rotated);
      expect(rotated.users).toEqual(stored.users);
      expect(rotated.sessions).toEqual(stored.sessions);
      expect(rotated.accounts.find((row) => row.id === account.id)).toMatchObject({
        accountId: decoded.oid,
        userId: user.id,
        accessToken: "rotated-access",
        refreshToken: "rotated-refresh",
        scope: account.scope,
      });
      const afterRequests = await receipts(ctx);
      expect(afterRequests.at(-1)!.body).toEqual({
        grant_type: "refresh_token",
        refresh_token: "fixture-microsoft-refresh",
        client_id: "fixture-social-client",
        scope: [
          ...(mode === "disabled-configured" ? [] : defaults),
          ...(["configured", "disabled-configured"].includes(mode)
            ? ["configured-scope", "openid", "punctuation-!~*'()"]
            : []),
        ].join(" "),
        ...(mode === "public"
          ? {}
          : mode === "assertion"
            ? {
                client_assertion: "fixture-assertion-refresh_token",
                client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
              }
            : { client_secret: "fixture-social-secret" }),
      });
      const assertions = (await ctx.rawRequest({ path: "/__test/microsoft/assertion-receipts" }))
        .body;
      expect(assertions).toEqual(
        mode === "assertion"
          ? ["authorization_code", "refresh_token"].map((grantType) => ({
              clientId: "fixture-social-client",
              tokenEndpoint: ctx.baseURL + "/common/oauth2/v2.0/token",
              grantType,
            }))
          : [],
      );
      const logout = await flow.actor.client.signOut();
      expect(logout.error).toBeNull();
      expect((await flow.actor.client.getSession()).data).toBeNull();
      const signedOut = await state(ctx);
      expect(signedOut.users).toEqual(rotated.users);
      expect(signedOut.accounts).toEqual(rotated.accounts);
      expect(signedOut.sessions).toEqual(other.before.sessions);
      expect(await receipts(ctx)).toHaveLength(afterRequests.length);
      return {
        start: ctx.snapshot(flow.start),
        session: ctx.snapshot(session),
        before: other.before,
        stored,
        rotated,
        signedOut,
        refreshed: ctx.snapshot(refreshed),
        mapper,
        assertions: (assertions as Array<Record<string, unknown>>).map((row) => ({
          ...row,
          tokenEndpoint: { url: row.tokenEndpoint },
        })),
        requests: afterRequests,
      };
    },
    ["POST /sign-in/social", "GET /callback/{}", "POST /refresh-token", "POST /sign-out"],
  );
}
for (const variant of [
  "photo-failure",
  "missing-oid",
  "null-oid",
  "blank-oid",
  "numeric-oid",
  "redirect-grant",
  "error-grant",
] as const) {
  compatScenario(
    `microsoft exchange ${variant} proves optional photo versus identity and grant denial ordering`,
    async (ctx) => {
      const other = await foreign(ctx);
      const token = await proof(
        ctx,
        variant === "missing-oid"
          ? { oid: undefined }
          : variant === "null-oid"
            ? { oid: null }
            : variant === "blank-oid"
              ? { oid: " " }
              : variant === "numeric-oid"
                ? { oid: 123 }
                : {},
      );
      await control(ctx, {
        idToken: token,
        ...(variant === "photo-failure"
          ? { photoStatus: 404 }
          : variant === "redirect-grant"
            ? { tokenRedirect: ctx.baseURL + "/common/oauth2/v2.0/token" }
            : variant === "error-grant"
              ? { tokenStatus: 400 }
              : {}),
      });
      const flow = await callback(ctx, "social-microsoft-mapped");
      expect(flow.response.status).toBe(302);
      const stored = await state(ctx);
      const mapper = (await ctx.rawRequest({ path: "/__test/microsoft/mapper-receipts" })).body;
      const requests = await receipts(ctx);
      if (variant === "photo-failure") {
        expect(flow.response.headers.get("location")).toBe("/dashboard");
        const decoded = JSON.parse(Buffer.from(token.split(".")[1]!, "base64url").toString());
        expect(mapper).toEqual([decoded]);
        unchangedForeign(other.before, stored);
        expect(stored.accounts.find((row) => row.accountId === decoded.oid)).toBeTruthy();
        expect(requests).toHaveLength(2);
      } else {
        expect(
          new URL(flow.response.headers.get("location")!, ctx.baseURL).searchParams.get("error"),
        ).toBeTruthy();
        expect(stored).toEqual(other.before);
        expect(mapper).toEqual([]);
        expect(requests).toHaveLength(1);
      }
      return {
        start: ctx.snapshot(flow.start),
        callback: { status: flow.response.status, location: flow.response.headers.get("location") },
        before: other.before,
        stored,
        mapper,
        requests,
      };
    },
    ["POST /sign-in/social", "GET /callback/{}"],
  );
}

compatScenario(
  "microsoft mapped account info preserves enriched public properties independently of physical raw oid",
  async (ctx) => {
    const token = await proof(ctx, { name: "Public Name" });
    await control(ctx, { idToken: token });
    const flow = await callback(ctx, "social-microsoft-mapped");
    expect(flow.response.headers.get("location")).toBe("/dashboard");
    const before = await state(ctx);
    const account = before.accounts[0]!;
    const decoded = JSON.parse(Buffer.from(token.split(".")[1]!, "base64url").toString());
    const result = await flow.actor.client.$fetch("/account-info", {
      query: { accountId: account.id },
    });
    expect(result.error).toBeNull();
    expect(result.data).toEqual({
      user: {
        id: "cannot-replace-raw-oid",
        microsoftMapped: { oid: decoded.oid },
        name: "Mapped Public Name",
        email: "mapped-microsoft@example.invalid",
        emailVerified: false,
        image: "https://images.example.invalid/mapped-microsoft.png",
      },
      data: { ...decoded, picture: "data:image/jpeg;base64, /9gAQf/Z" },
      account: { id: account.id, providerId: "microsoft", accountId: decoded.oid },
    });
    expect(await state(ctx)).toEqual(before);
    expect((await flow.actor.client.getSession()).data?.user.id).toBe(before.users[0]!.id);
    const mapper = (await ctx.rawRequest({ path: "/__test/microsoft/mapper-receipts" })).body;
    expect(mapper).toEqual(
      Array(2).fill({ ...decoded, picture: "data:image/jpeg;base64, /9gAQf/Z" }),
    );
    return {
      before,
      after: await state(ctx),
      result: ctx.snapshot(result),
      mapper,
      receipts: await receipts(ctx),
    };
  },
  ["GET /account-info"],
);
for (const variant of [
  "missing-name",
  "empty-name",
  "null-name",
  "numeric-name",
  "empty-image",
  "numeric-image",
  "null-image",
  "missing-image",
  "string-primary",
  "null-primary",
  "explicit-null",
] as const) {
  compatScenario(
    `microsoft signed ${variant} retains measured profile and verification fallback`,
    async (ctx) => {
      const other = await foreign(ctx);
      const email = ctx.uniqueEmail("profile");
      const claims: Row = { email };
      switch (variant) {
        case "empty-name":
          claims.name = "";
          break;
        case "numeric-image":
          claims.picture = 123;
          break;
        case "missing-name":
          claims.name = undefined;
          break;
        case "null-name":
          claims.name = null;
          break;
        case "numeric-name":
          claims.name = 123;
          break;
        case "empty-image":
          claims.picture = "";
          break;
        case "null-image":
          claims.picture = null;
          break;
        case "missing-image":
          claims.picture = undefined;
          break;
        case "string-primary":
          claims.email_verified = undefined;
          claims.verified_primary_email = "prefix-" + email + "-suffix";
          break;
        case "null-primary":
          claims.email_verified = undefined;
          claims.verified_primary_email = null;
          break;
        case "explicit-null":
          claims.email_verified = null;
          claims.verified_primary_email = [email];
          break;
      }
      const token = await proof(ctx, claims);
      const actor = ctx.actor("microsoft", "social-microsoft-no-photo");
      const result = await actor.client.signIn.social({
        provider: "microsoft",
        idToken: { token, accessToken: "fixture-microsoft-profile-access" },
      });
      expect(result.error).toBeNull();
      const stored = await state(ctx);
      expect(stored.accounts.find((row) => row.providerId === "microsoft")!.accountId).toBe(
        JSON.parse(Buffer.from(token.split(".")[1]!, "base64url").toString()).oid,
      );
      expect(stored.users.find((row) => row.email === email)!.emailVerified).toBe(
        !["null-primary", "explicit-null"].includes(variant),
      );
      unchangedForeign(other.before, stored);
      const ownedUser = stored.users.find(
        (row) => !other.before.users.some((old) => old.id === row.id),
      )!;
      const ownedAccount = stored.accounts.find((row) => row.userId === ownedUser.id)!;
      const session = await actor.client.getSession();
      expect(session.data?.user.id).toBe(ownedUser.id);
      const decoded = JSON.parse(Buffer.from(token.split(".")[1]!, "base64url").toString());
      const info = await actor.client.$fetch("/account-info", {
        query: { accountId: ownedAccount.id },
      });
      expect(info.error).toBeNull();
      expect(info.data).toEqual({
        user: {
          ...(Object.hasOwn(decoded, "name") ? { name: decoded.name } : {}),
          email: decoded.email,
          ...(Object.hasOwn(decoded, "picture") ? { image: decoded.picture } : {}),
          emailVerified: variant === "explicit-null" ? null : variant !== "null-primary",
        },
        data: decoded,
        account: { id: ownedAccount.id, providerId: "microsoft", accountId: decoded.oid },
      });
      expect(await state(ctx)).toEqual(stored);
      return {
        result: ctx.snapshot(result),
        before: other.before,
        stored,
        session: ctx.snapshot(session),
        info: ctx.snapshot(info),
        receipts: await receipts(ctx),
      };
    },
    ["POST /sign-in/social", "GET /account-info"],
  );
}

for (const variant of [
  "missing-key",
  "missing-algorithm",
  "mismatched-algorithm",
  "first-duplicate-import",
] as const) {
  compatScenario(
    `microsoft selected JWK ${variant} rejects genuine signed admission at configured trusted tenant`,
    async (ctx) => {
      const other = await foreign(ctx);
      const jwks = await Bun.file(
        new URL("../../../../../fixtures/one-tap/jwks.json", import.meta.url),
      ).json();
      const key = { ...jwks.keys[0] };
      if (variant === "missing-algorithm") delete key.alg;
      if (variant === "mismatched-algorithm") key.alg = "RS384";
      await control(ctx, {
        keys: {
          keys:
            variant === "missing-key"
              ? []
              : variant === "first-duplicate-import"
                ? [{ ...key, n: "AA" }, key]
                : [key],
        },
      });
      const token = await proof(ctx);
      const actor = ctx.actor("microsoft", "social-microsoft-public");
      const result = await actor.client.signIn.social({
        provider: "microsoft",
        idToken: { token },
      });
      expect(result.error?.code).toBe("INVALID_TOKEN");
      expect(await state(ctx)).toEqual(other.before);
      const requests = await receipts(ctx);
      expect(requests.map((row) => row.path)).toEqual(["/common/discovery/v2.0/keys"]);
      return {
        result: ctx.snapshot(result),
        before: other.before,
        after: await state(ctx),
        receipts: requests,
      };
    },
  );
}
