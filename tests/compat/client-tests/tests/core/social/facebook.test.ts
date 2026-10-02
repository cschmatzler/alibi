import { expect } from "bun:test";
import { createPublicKey, generateKeyPairSync, sign } from "node:crypto";

import { credential, issuedAt } from "../../../support/id-token";
import { authProfilePath, type FixtureProfile } from "../../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../../support/scenario";

type Row = Record<string, unknown>;

type Stored = {
  users: Array<Row & { id: string }>;
  accounts: Array<Row & { id: string }>;
  sessions: Array<Row & { id: string }>;
};

type Receipt = {
  path: string;
  method: string;
  authorization: string | null;
  contentType: string | null;
  query: Record<string, string>;
  body: Record<string, string> | null;
};

async function state(ctx: ScenarioContext) {
  const result = await ctx.rawRequest({ path: "/__test/social-provider/state" });
  expect(result.status).toBe(200);
  return result.body as Stored;
}

async function control(ctx: ScenarioContext, value: Row) {
  const result = await ctx.rawRequest({
    path: "/__test/facebook/control",
    method: "POST",
    json: value,
  });
  expect(result.status).toBe(200);
}

async function receipts(ctx: ScenarioContext) {
  const result = await ctx.rawRequest({ path: "/__test/facebook/receipts" });
  expect(result.status).toBe(200);
  return result.body as Receipt[];
}

async function mapperReceipts(ctx: ScenarioContext) {
  const result = await ctx.rawRequest({ path: "/__test/facebook/mapper-receipts" });
  expect(result.status).toBe(200);
  return result.body;
}

function profile(ctx: ScenarioContext): Row {
  return {
    id: ctx.uniqueToken("facebook-subject"),
    name: "Facebook User",
    email: ctx.uniqueEmail("facebook"),
    email_verified: true,
    picture: {
      data: {
        url: "https://images.example.invalid/facebook.png",
        height: 50,
        width: 50,
        is_silhouette: false,
      },
    },
    originalApplicationField: { retained: true },
  };
}

async function foreign(ctx: ScenarioContext) {
  const actor = ctx.actor("foreign");
  const signup = await actor.client.signUp.email({
    email: ctx.uniqueEmail("foreign"),
    name: "Foreign",
    password: "Password123!",
  });
  expect(signup.error).toBeNull();

  return { actor, signup, before: await state(ctx) };
}

function unchangedForeign(before: Stored, after: Stored) {
  for (const table of ["users", "accounts", "sessions"] as const) {
    for (const row of before[table]) {
      expect(after[table].find((candidate) => candidate.id === row.id)).toEqual(row);
    }
  }
}

async function proof(
  ctx: ScenarioContext,
  claims: Row = {},
  header: Row = {},
  wrong = false,
  rawIat?: string,
) {
  const payload: Row = {
    iss: "https://www.facebook.com",
    aud: "fixture-social-client",
    sub: ctx.uniqueToken("facebook-jwt-subject"),
    name: "Facebook JWT User",
    email: ctx.uniqueEmail("facebook-jwt"),
    picture: "https://images.example.invalid/facebook-jwt.png",
    ...claims,
  };
  const raw =
    rawIat === undefined
      ? undefined
      : JSON.stringify({ iat: "overflow-numeric-date", exp: issuedAt + 3600, ...payload }).replace(
          '"iat":"overflow-numeric-date"',
          `"iat":${rawIat}`,
        );
  return credential(payload, header, wrong, raw);
}

async function callback(
  ctx: ScenarioContext,
  fixture: FixtureProfile = "social-facebook-default",
  requestSignUp = false,
) {
  const actor = ctx.actor("facebook", fixture);
  const start = await actor.client.signIn.social({
    provider: "facebook",
    callbackURL: "/dashboard",
    requestSignUp,
  });
  expect(start.error).toBeNull();

  const url = new URL(start.data!.url!);
  const path =
    authProfilePath(fixture) +
    `/callback/facebook?code=fixture-code&state=${encodeURIComponent(url.searchParams.get("state")!)}`;
  const response = await actor.fetch(ctx.baseURL + path, { redirect: "manual" });
  return { actor, start, url, path, response };
}

for (const mode of [
  "default",
  "configured",
  "disabled-scope",
  "disabled-configured",
  "configured-endpoint",
] as const) {
  compatScenario(
    `facebook published ${mode} authorization omits PKCE and preserves ordered configuration`,
    async (ctx) => {
      const other = await foreign(ctx);
      const fixture: FixtureProfile = `social-facebook-${mode}`;
      const result = await ctx.actor("facebook", fixture).client.signIn.social({
        provider: "facebook",
        scopes: ["requested-scope", "email"],
        loginHint: "facebook-login@example.invalid",
        additionalParams: { config_id: "RequestedFacebook", custom: "value with space" },
      });
      expect(result.error).toBeNull();

      const url = new URL(result.data!.url!);
      expect(url.searchParams.has("code_challenge")).toBeFalse();
      expect(url.searchParams.has("code_challenge_method")).toBeFalse();
      expect(url.origin).toBe(
        mode === "configured-endpoint"
          ? "https://alternate-facebook.example.invalid"
          : "https://www.facebook.com",
      );
      expect(url.pathname).toBe(
        mode === "configured-endpoint" ? "/authorize" : "/v24.0/dialog/oauth",
      );
      expect(url.searchParams.getAll("client_id")).toEqual(["fixture-social-client"]);
      expect(url.searchParams.getAll("state")).toHaveLength(1);
      expect(url.searchParams.get("state")).toBeTruthy();
      expect(url.searchParams.get("state")).not.toBe("stale");

      const scopes = [
        ...(mode.startsWith("disabled") ? [] : ["email", "public_profile"]),
        ...(["configured", "disabled-configured"].includes(mode)
          ? ["configured-scope", "email", "punctuation !~*'()"]
          : []),
        "requested-scope",
        "email",
      ];
      expect(url.searchParams.get("scope")).toBe(scopes.join(" "));
      expect(url.searchParams.get("login_hint")).toBe("facebook-login@example.invalid");
      expect(url.searchParams.get("config_id")).toBe("RequestedFacebook");
      expect(url.searchParams.get("custom")).toBe("value with space");
      expect(url.searchParams.get("redirect_uri")).toBe(
        mode === "configured-endpoint"
          ? "https://client.example.invalid/facebook-return"
          : ctx.baseURL + authProfilePath(fixture) + "/callback/facebook",
      );
      expect(await state(ctx)).toEqual(other.before);
      expect(await receipts(ctx)).toEqual([]);

      return { result: ctx.snapshot(result), before: other.before, after: await state(ctx) };
    },
    ["POST /sign-in/social"],
  );
}

for (const mode of [
  "default",
  "mapped",
  "configured-endpoint",
  "client-key",
  "client-array",
  "fields",
] as const) {
  compatScenario(
    `facebook ${mode} real Graph exchange binds app and identity before mapper refresh replay and logout`,
    async (ctx) => {
      const other = await foreign(ctx);
      const original = profile(ctx);
      const fixture: FixtureProfile = `social-facebook-${mode}`;
      await control(ctx, {
        profile: original,
        ...(mode === "client-array"
          ? {
              inspection: {
                data: {
                  is_valid: true,
                  app_id: "fixture-facebook-secondary",
                  user_id: original.id,
                },
              },
            }
          : {}),
      });
      const flow = await callback(ctx, fixture);
      expect(flow.response.headers.get("location")).toBe("/dashboard");

      const session = await flow.actor.client.getSession();
      expect(session.error).toBeNull();

      const after = await state(ctx);
      unchangedForeign(other.before, after);

      for (const table of ["users", "accounts", "sessions"] as const) {
        expect(after[table]).toHaveLength(other.before[table].length + 1);
      }

      const user = after.users.find((row) => !other.before.users.some((old) => old.id === row.id))!;
      const account = after.accounts.find((row) => row.userId === user.id)!;
      expect(user).toMatchObject({
        name: mode === "mapped" ? "Mapped Facebook User" : original.name,
        email: mode === "mapped" ? "mapped-facebook@example.invalid" : original.email,
        emailVerified: mode !== "mapped",
        image:
          mode === "mapped"
            ? "https://images.example.invalid/mapped-facebook.png"
            : "https://images.example.invalid/facebook.png",
      });
      expect(account).toMatchObject({
        providerId: "facebook",
        accountId: original.id,
        accessToken: "fixture-facebook-access",
        refreshToken: "fixture-facebook-refresh",
        idToken: null,
        scope: "",
      });
      expect(account.accessTokenExpiresAt).toBeTruthy();
      expect(session.data?.user.id).toBe(user.id);

      const requests = await receipts(ctx);
      expect(requests.map((row) => row.path)).toEqual(["/token", "/debug", "/userinfo"]);
      expect(requests[0]).toEqual({
        path: "/token",
        method: "POST",
        authorization: null,
        contentType: "application/x-www-form-urlencoded",
        query: {},
        body: {
          grant_type: "authorization_code",
          code: "fixture-code",
          client_id: "fixture-social-client",
          client_secret: "fixture-social-secret",
          ...(mode === "client-key" ? { client_key: "fixture-facebook-client-key" } : {}),
          redirect_uri:
            mode === "configured-endpoint"
              ? "https://client.example.invalid/facebook-return"
              : ctx.baseURL + authProfilePath(fixture) + "/callback/facebook",
        },
      });
      expect(requests[1]).toEqual({
        path: "/debug",
        method: "GET",
        authorization: null,
        contentType: null,
        query: {
          input_token: "fixture-facebook-access",
          access_token: "fixture-social-client|fixture-social-secret",
        },
        body: null,
      });
      expect(requests[2]).toEqual({
        path: "/userinfo",
        method: "GET",
        authorization: "Bearer fixture-facebook-access",
        contentType: null,
        query: {
          fields:
            mode === "fields"
              ? "id,name,email,picture,email,birthday,locale"
              : "id,name,email,picture",
        },
        body: null,
      });

      const mapper = await mapperReceipts(ctx);
      expect(mapper).toEqual(mode === "mapped" ? [original] : []);

      const replay = await flow.actor.fetch(ctx.baseURL + flow.path, { redirect: "manual" });
      expect(replay.status).toBe(302);
      expect(
        new URL(replay.headers.get("location")!, ctx.baseURL).searchParams.get("error"),
      ).toBeTruthy();
      expect(await state(ctx)).toEqual(after);
      expect(await receipts(ctx)).toEqual(requests);

      await control(ctx, {
        tokenResponse: {
          access_token: "fixture-facebook-access-rotated",
          refresh_token: "fixture-facebook-refresh-rotated",
          expires_in: 1800,
          scope: "changed-scope",
        },
      });
      const denied = await other.actor.client.refreshToken({ accountId: account.id });
      expect(denied.error).not.toBeNull();
      expect(await state(ctx)).toEqual(after);
      expect(await receipts(ctx)).toEqual(requests);

      const refreshed = await flow.actor.client.refreshToken({ accountId: account.id });
      expect(refreshed.error).toBeNull();

      const rotated = await state(ctx);
      expect(rotated.users).toEqual(after.users);
      expect(rotated.sessions).toEqual(after.sessions);

      unchangedForeign(other.before, rotated);
      expect(rotated.accounts.find((row) => row.id === account.id)).toMatchObject({
        accountId: original.id,
        userId: user.id,
        accessToken: "fixture-facebook-access-rotated",
        refreshToken: "fixture-facebook-refresh-rotated",
        scope: account.scope,
      });
      expect((await receipts(ctx))[3]!.body).toEqual({
        grant_type: "refresh_token",
        refresh_token: "fixture-facebook-refresh",
        client_id: "fixture-social-client",
        client_secret: "fixture-social-secret",
      });

      const signOut = await flow.actor.client.signOut();
      expect(signOut.error).toBeNull();

      const signedOut = await state(ctx);
      expect(signedOut.users).toEqual(rotated.users);
      expect(signedOut.accounts).toEqual(rotated.accounts);
      expect(signedOut.sessions).toEqual(other.before.sessions);
      expect((await flow.actor.client.getSession()).data).toBeNull();
      expect(await receipts(ctx)).toHaveLength(4);

      return {
        before: other.before,
        start: ctx.snapshot(flow.start),
        callback: { status: flow.response.status, location: flow.response.headers.get("location") },
        session: ctx.snapshot(session),
        after,
        replay: { status: replay.status, location: replay.headers.get("location") },
        mapper,
        denied: ctx.snapshot(denied),
        refreshed: ctx.snapshot(refreshed),
        rotated,
        signOut: ctx.snapshot(signOut),
        signedOut,
        receipts: await receipts(ctx),
      };
    },
    ["POST /sign-in/social", "GET /callback/{}", "POST /refresh-token", "POST /sign-out"],
  );
}

for (const variant of [
  "invalid",
  "foreign-app",
  "missing-app",
  "missing-user",
  "false-user",
  "mismatched-user",
  "string-valid",
  "inspection-http-error",
  "profile-http-error",
  "missing-access",
] as const) {
  compatScenario(
    `facebook opaque ${variant} rejects before mapping or any owned and foreign identity write`,
    async (ctx) => {
      const other = await foreign(ctx);
      const original = profile(ctx);
      const inspection: Row = {
        is_valid: true,
        app_id: "fixture-social-client",
        user_id: original.id,
      };

      if (variant === "invalid") {
        inspection.is_valid = false;
      }

      if (variant === "foreign-app") {
        inspection.app_id = "unrelated-facebook-app";
      }

      if (variant === "missing-app") {
        delete inspection.app_id;
      }

      if (variant === "missing-user") {
        delete inspection.user_id;
      }

      if (variant === "false-user") {
        inspection.user_id = false;
      }

      if (variant === "mismatched-user") {
        inspection.user_id = "different-facebook-user";
      }

      if (variant === "string-valid") {
        inspection.is_valid = "true";
      }

      await control(ctx, {
        profile: original,
        inspection: { data: inspection },
        ...(variant === "inspection-http-error" ? { inspectionStatus: 503 } : {}),
        ...(variant === "profile-http-error" ? { userInfoStatus: 503 } : {}),
      });
      const actor = ctx.actor("facebook", "social-facebook-mapped");
      const result = await actor.client.signIn.social({
        provider: "facebook",
        idToken: {
          token: "opaque-facebook-candidate",
          ...(variant === "missing-access" ? {} : { accessToken: "fixture-facebook-access" }),
        },
      });
      expect(result.error?.code).toBe("FAILED_TO_GET_USER_INFO");
      expect(await state(ctx)).toEqual(other.before);
      expect((await actor.client.getSession()).data).toBeNull();
      expect(await mapperReceipts(ctx)).toEqual([]);

      const requests = await receipts(ctx);
      expect(requests.map((row) => row.path)).toEqual(
        variant === "missing-access"
          ? []
          : ["mismatched-user", "profile-http-error"].includes(variant)
            ? ["/debug", "/userinfo"]
            : ["/debug"],
      );

      return {
        before: other.before,
        result: ctx.snapshot(result),
        after: await state(ctx),
        mapper: await mapperReceipts(ctx),
        receipts: requests,
      };
    },
  );
}

for (const variant of [
  "default",
  "client-array",
  "mapped",
  "no-iat",
  "old",
  "future",
  "raw-positive-iat",
  "raw-negative-iat",
  "numeric-name",
  "null-name",
  "empty-image",
] as const) {
  compatScenario(
    `facebook Limited Login ${variant} authenticates signed identity with optional age and original mapping`,
    async (ctx) => {
      const other = await foreign(ctx);
      const claims: Row =
        variant === "client-array"
          ? { aud: ["foreign-client", "fixture-facebook-secondary"] }
          : variant === "no-iat"
            ? { iat: undefined }
            : variant === "old"
              ? { iat: issuedAt - 7200 }
              : variant === "future"
                ? { iat: issuedAt + 7200 }
                : variant === "numeric-name"
                  ? { name: 7 }
                  : variant === "null-name"
                    ? { name: null }
                    : variant === "empty-image"
                      ? { picture: "" }
                      : {};
      const token = await proof(
        ctx,
        {
          ...claims,
          nonce: "exact-facebook-nonce",
          email_verified: true,
          originalApplicationField: { retained: true },
        },
        {},
        false,
        variant === "raw-positive-iat"
          ? "1e500"
          : variant === "raw-negative-iat"
            ? "-1e500"
            : undefined,
      );
      const decoded = JSON.parse(Buffer.from(token.split(".")[1]!, "base64url").toString());
      const fixture: FixtureProfile = ["default", "client-array", "mapped"].includes(variant)
        ? `social-facebook-${variant as "default" | "client-array" | "mapped"}`
        : `social-facebook-jwt-${variant as "no-iat" | "old" | "future" | "raw-positive-iat" | "raw-negative-iat" | "numeric-name" | "null-name" | "empty-image"}`;
      const actor = ctx.actor("facebook", fixture);
      const result = await actor.client.signIn.social({
        provider: "facebook",
        idToken: { token, nonce: "exact-facebook-nonce" },
      });
      expect(result.error).toBeNull();

      const stored = await state(ctx);
      unchangedForeign(other.before, stored);

      for (const table of ["users", "accounts", "sessions"] as const) {
        expect(stored[table]).toHaveLength(other.before[table].length + 1);
      }

      const user = stored.users.find(
        (row) => !other.before.users.some((old) => old.id === row.id),
      )!;
      const account = stored.accounts.find((row) => row.userId === user.id)!;
      expect(account).toMatchObject({
        accountId: decoded.sub,
        providerId: "facebook",
        idToken: token,
        accessToken: null,
        refreshToken: null,
      });
      expect(user).toMatchObject({
        name:
          variant === "mapped"
            ? "Mapped Facebook User"
            : variant === "numeric-name"
              ? "7"
              : variant === "null-name"
                ? ""
                : "Facebook JWT User",
        email: variant === "mapped" ? "mapped-facebook@example.invalid" : decoded.email,
        emailVerified: false,
        image:
          variant === "mapped"
            ? "https://images.example.invalid/mapped-facebook.png"
            : decoded.picture,
      });
      expect((await actor.client.getSession()).data?.user.id).toBe(user.id);
      expect(await mapperReceipts(ctx)).toEqual(variant === "mapped" ? [decoded] : []);
      expect((await receipts(ctx)).map((row) => row.path)).toEqual(["/keys"]);

      return {
        before: other.before,
        result: ctx.snapshot(result),
        stored,
        mapper: await mapperReceipts(ctx),
        receipts: await receipts(ctx),
      };
    },
    ["POST /sign-in/social"],
  );
}

for (const variant of [
  "issuer",
  "audience",
  "expired",
  "not-before",
  "iat-type",
  "nonce",
  "hashed-nonce",
  "signature",
  "unknown-kid",
  "missing-subject",
  "null-subject",
  "blank-subject",
  "missing-email",
  "null-email",
  "empty-email",
  "disabled",
] as const) {
  compatScenario(
    `facebook Limited Login ${variant} denies genuine invalid proof or profile before identity writes`,
    async (ctx) => {
      const other = await foreign(ctx);
      const nonce = "facebook-request-nonce";
      const hash = Buffer.from(
        await crypto.subtle.digest("SHA-256", new TextEncoder().encode(nonce)),
      ).toString("hex");
      const claims: Row =
        variant === "issuer"
          ? { iss: "https://untrusted.invalid" }
          : variant === "audience"
            ? { aud: "foreign-client" }
            : variant === "expired"
              ? { exp: issuedAt - 10 }
              : variant === "not-before"
                ? { nbf: issuedAt + 7200 }
                : variant === "iat-type"
                  ? { iat: "not-a-number" }
                  : variant === "nonce"
                    ? { nonce: "wrong-nonce" }
                    : variant === "hashed-nonce"
                      ? { nonce: hash }
                      : variant === "missing-subject"
                        ? { sub: undefined }
                        : variant === "null-subject"
                          ? { sub: null }
                          : variant === "blank-subject"
                            ? { sub: "\uFEFF " }
                            : variant === "missing-email"
                              ? { email: undefined }
                              : variant === "null-email"
                                ? { email: null }
                                : variant === "empty-email"
                                  ? { email: "" }
                                  : {};
      const token = await proof(
        ctx,
        claims,
        variant === "unknown-kid" ? { kid: "foreign-kid" } : {},
        variant === "signature",
      );
      const fixture: FixtureProfile =
        variant === "disabled"
          ? "social-facebook-disabled-idtoken"
          : `social-facebook-jwt-${variant}`;
      const actor = ctx.actor("facebook", fixture);
      const result = await actor.client.signIn.social({
        provider: "facebook",
        idToken: { token, ...(variant.includes("nonce") ? { nonce } : {}) },
      });
      expect(result.error?.code).toBe(
        variant === "disabled"
          ? "ID_TOKEN_NOT_SUPPORTED"
          : variant.endsWith("email")
            ? "USER_EMAIL_NOT_FOUND"
            : variant.endsWith("subject")
              ? "FAILED_TO_GET_USER_INFO"
              : "INVALID_TOKEN",
      );
      expect(await state(ctx)).toEqual(other.before);
      expect((await actor.client.getSession()).data).toBeNull();
      expect(await mapperReceipts(ctx)).toEqual([]);

      return {
        before: other.before,
        result: ctx.snapshot(result),
        after: await state(ctx),
        receipts: await receipts(ctx),
      };
    },
  );
}

for (const variant of [
  "removed",
  "algorithm",
  "use",
  "operations",
  "private",
  "duplicate",
  "invalid-ext",
  "duplicate-import",
  "weak-modulus",
] as const) {
  compatScenario(
    `facebook remote JWKS ${variant} applies usable public key selection to actual signed proof`,
    async (ctx) => {
      const other = await foreign(ctx);
      const original = JSON.parse(
        await Bun.file(
          new URL("../../../../../fixtures/one-tap/jwks.json", import.meta.url),
        ).text(),
      );
      const key = original.keys[0];
      const wrong = createPublicKey(
        await Bun.file(
          new URL("../../../../../fixtures/one-tap/wrong-private-key.pem", import.meta.url),
        ).text(),
      ).export({ format: "jwk" });
      const weak =
        variant === "weak-modulus" ? generateKeyPairSync("rsa", { modulusLength: 1024 }) : null;
      const keys = weak
        ? [{ ...weak.publicKey.export({ format: "jwk" }), kid: key.kid, alg: "RS256" }]
        : variant === "removed"
          ? []
          : variant === "algorithm"
            ? [{ ...key, alg: "RS512" }]
            : variant === "use"
              ? [{ ...key, use: "enc" }]
              : variant === "operations"
                ? [{ ...key, key_ops: ["sign"] }]
                : variant === "private"
                  ? [{ ...key, d: "not-a-public-key" }]
                  : variant === "invalid-ext"
                    ? [{ ...key, ext: "true" }]
                    : variant === "duplicate-import"
                      ? [{ kty: "RSA", kid: key.kid, alg: "RS256" }, key]
                      : [{ ...wrong, kid: key.kid, alg: "RS256" }, key];
      await control(ctx, { keys: { keys } });
      const validToken = await proof(ctx);
      const signed = validToken.split(".").slice(0, 2).join(".");
      const token = weak
        ? `${signed}.${sign("RSA-SHA256", Buffer.from(signed), weak.privateKey).toString("base64url")}`
        : validToken;
      const fixture: FixtureProfile = `social-facebook-keys-${variant}`;
      const actor = ctx.actor("facebook", fixture);
      const result = await actor.client.signIn.social({ provider: "facebook", idToken: { token } });
      expect(result.error?.code).toBe("INVALID_TOKEN");
      expect(await state(ctx)).toEqual(other.before);
      expect((await actor.client.getSession()).data).toBeNull();
      expect((await receipts(ctx)).map((row) => row.path)).toEqual(["/keys"]);

      return {
        before: other.before,
        result: ctx.snapshot(result),
        stored: await state(ctx),
        receipts: await receipts(ctx),
      };
    },
    ["POST /sign-in/social"],
  );
}

for (const mode of ["missing-secret", "empty-clients"] as const) {
  compatScenario(
    `facebook ${mode} rejects authorization before provider requests or identity writes`,
    async (ctx) => {
      const other = await foreign(ctx);
      const result = await ctx
        .actor("facebook", `social-facebook-${mode}`)
        .client.signIn.social({ provider: "facebook" });
      expect(result.error?.status).toBe(500);
      expect(await state(ctx)).toEqual(other.before);
      expect(await receipts(ctx)).toEqual([]);

      return { before: other.before, result: ctx.snapshot(result), after: await state(ctx) };
    },
  );
}

compatScenario(
  "facebook disabled default scopes omit an empty scope parameter",
  async (ctx) => {
    const before = await state(ctx);
    const result = await ctx
      .actor("facebook", "social-facebook-disabled-scope")
      .client.signIn.social({ provider: "facebook" });
    expect(result.error).toBeNull();
    expect(new URL(result.data!.url!).searchParams.has("scope")).toBeFalse();
    expect(await state(ctx)).toEqual(before);
    expect(await receipts(ctx)).toEqual([]);

    return { result: ctx.snapshot(result), before, after: await state(ctx) };
  },
  ["POST /sign-in/social"],
);

const graphMappings: Array<{
  name: string;
  patch: Row;
  expectedName?: string;
  expectedImage?: string | null;
  expectedSubject?: string;
  verified?: boolean;
}> = [
  { name: "numeric name", patch: { name: 7 }, expectedName: "7" },
  { name: "empty name", patch: { name: "" }, expectedName: "" },
  { name: "null name", patch: { name: null }, expectedName: "" },
  { name: "missing name", patch: { name: undefined }, expectedName: "" },
  { name: "numeric identity", patch: { id: 42 }, expectedSubject: "42" },
  { name: "null image", patch: { picture: { data: { url: null } } }, expectedImage: null },
  { name: "empty image", patch: { picture: { data: { url: "" } } }, expectedImage: "" },
  { name: "numeric image", patch: { picture: { data: { url: 7 } } }, expectedImage: "7" },
  { name: "missing verified", patch: { email_verified: undefined }, verified: false },
  { name: "null verified", patch: { email_verified: null }, verified: false },
  { name: "false verified", patch: { email_verified: false }, verified: false },
  {
    name: "present subject",
    patch: { sub: "graph-present-subject" },
    expectedSubject: "graph-present-subject",
  },
];

for (const mapping of graphMappings) {
  compatScenario(
    `facebook opaque ${mapping.name} maps real inspected profile and preserves physical identity`,
    async (ctx) => {
      const other = await foreign(ctx);
      const original = { ...profile(ctx), ...mapping.patch };
      await control(ctx, { profile: original });
      const actor = ctx.actor("facebook", "social-facebook-default");
      const result = await actor.client.signIn.social({
        provider: "facebook",
        idToken: { token: "opaque-facebook-candidate", accessToken: "fixture-facebook-access" },
      });
      expect(result.error).toBeNull();

      const stored = await state(ctx);
      unchangedForeign(other.before, stored);

      for (const table of ["users", "accounts", "sessions"] as const) {
        expect(stored[table]).toHaveLength(other.before[table].length + 1);
      }

      const user = stored.users.find(
        (row) => !other.before.users.some((old) => old.id === row.id),
      )!;
      const account = stored.accounts.find((row) => row.userId === user.id)!;
      expect(user).toMatchObject({
        name: mapping.expectedName ?? "Facebook User",
        email: original.email,
        image:
          mapping.expectedImage === undefined
            ? "https://images.example.invalid/facebook.png"
            : mapping.expectedImage,
        emailVerified: mapping.verified ?? true,
      });
      expect(account).toMatchObject({
        providerId: "facebook",
        accountId: mapping.expectedSubject ?? original.id,
        accessToken: "fixture-facebook-access",
        idToken: "opaque-facebook-candidate",
      });
      expect((await actor.client.getSession()).data?.user.id).toBe(user.id);
      expect((await receipts(ctx)).map((row) => row.path)).toEqual(["/debug", "/userinfo"]);

      return {
        before: other.before,
        result: ctx.snapshot(result),
        stored,
        receipts: await receipts(ctx),
      };
    },
    ["POST /sign-in/social"],
  );
}

compatScenario(
  "facebook Graph null subject remains distinct from absent subject after actual mapping and app inspection",
  async (ctx) => {
    const other = await foreign(ctx);
    const original = { ...profile(ctx), sub: null };
    await control(ctx, { profile: original });
    const actor = ctx.actor("facebook", "social-facebook-mapped");
    const result = await actor.client.signIn.social({
      provider: "facebook",
      idToken: { token: "opaque-facebook-candidate", accessToken: "fixture-facebook-access" },
    });
    expect(result.error?.code).toBe("FAILED_TO_GET_USER_INFO");
    expect(await mapperReceipts(ctx)).toEqual([original]);
    expect(await state(ctx)).toEqual(other.before);
    expect((await actor.client.getSession()).data).toBeNull();
    expect((await receipts(ctx)).map((row) => row.path)).toEqual(["/debug", "/userinfo"]);

    return {
      before: other.before,
      result: ctx.snapshot(result),
      after: await state(ctx),
      mapper: await mapperReceipts(ctx),
      receipts: await receipts(ctx),
    };
  },
);

for (const expiry of ["absent", "zero", "fractional"] as const) {
  compatScenario(
    `facebook ${expiry} access expiry follows actual token helper`,
    async (ctx) => {
      await control(ctx, {
        profile: profile(ctx),
        tokenResponse: {
          access_token: "fixture-facebook-access",
          refresh_token: "fixture-facebook-refresh",
          ...(expiry === "zero"
            ? { expires_in: 0 }
            : expiry === "fractional"
              ? { expires_in: 0.5 }
              : {}),
        },
      });
      const flow = await callback(ctx);
      expect(flow.response.headers.get("location")).toBe("/dashboard");

      const stored = await state(ctx);
      expect(stored.accounts).toHaveLength(1);
      expect(stored.accounts[0]!.scope).toBe("");

      if (expiry === "fractional") {
        expect(stored.accounts[0]!.accessTokenExpiresAt).toBeTruthy();
      } else {
        expect(stored.accounts[0]!.accessTokenExpiresAt).toBeNull();
      }

      return {
        start: ctx.snapshot(flow.start),
        callback: { status: flow.response.status, location: flow.response.headers.get("location") },
        stored,
        receipts: await receipts(ctx),
      };
    },
    ["POST /sign-in/social", "GET /callback/{}"],
  );
}

for (const variant of [
  "wrong-state",
  "wrong-provider",
  "token-http-error",
  "foreign-app",
  "mismatched-user",
  "missing-email",
  "signup-disabled",
  "implicit-disabled",
] as const) {
  compatScenario(
    `facebook browser ${variant} preserves state inspection and owned and foreign admission guards`,
    async (ctx) => {
      const other = await foreign(ctx);
      const original = profile(ctx);

      if (variant === "missing-email") {
        delete original.email;
      }

      await control(ctx, {
        profile: original,
        ...(variant === "token-http-error" ? { tokenStatus: 503 } : {}),
        ...(["foreign-app", "mismatched-user"].includes(variant)
          ? {
              inspection: {
                data: {
                  is_valid: true,
                  app_id:
                    variant === "foreign-app" ? "foreign-facebook-app" : "fixture-social-client",
                  user_id: variant === "mismatched-user" ? "different-facebook-user" : original.id,
                },
              },
            }
          : {}),
      });
      const fixture: FixtureProfile =
        variant === "signup-disabled"
          ? "social-facebook-signup-disabled"
          : variant === "implicit-disabled"
            ? "social-facebook-implicit-disabled"
            : "social-facebook-default";
      const actor = ctx.actor("facebook", fixture);
      const start = await actor.client.signIn.social({
        provider: "facebook",
        callbackURL: "/dashboard",
        requestSignUp: variant === "signup-disabled",
      });
      expect(start.error).toBeNull();

      const url = new URL(start.data!.url!);
      const callbackState =
        variant === "wrong-state" ? ctx.uniqueToken("wrong-state") : url.searchParams.get("state")!;
      const provider = variant === "wrong-provider" ? "unknown-facebook" : "facebook";
      const response = await actor.fetch(
        ctx.baseURL +
          authProfilePath(fixture) +
          `/callback/${provider}?code=fixture-code&state=${encodeURIComponent(callbackState)}`,
        { redirect: "manual" },
      );
      expect(response.status).toBe(302);

      const location = response.headers.get("location")!;
      const error = new URL(location, ctx.baseURL).searchParams.get("error");
      expect(error).toBe(
        variant === "wrong-state"
          ? "state_mismatch"
          : variant === "wrong-provider"
            ? "oauth_provider_not_found"
            : variant === "token-http-error"
              ? "invalid_code"
              : variant === "missing-email"
                ? "email_not_found"
                : variant.endsWith("disabled")
                  ? "signup_disabled"
                  : "unable_to_get_user_info",
      );
      expect(await state(ctx)).toEqual(other.before);
      expect((await actor.client.getSession()).data).toBeNull();

      const paths = (await receipts(ctx)).map((row) => row.path);
      expect(paths).toEqual(
        ["wrong-state", "wrong-provider"].includes(variant)
          ? []
          : variant === "token-http-error"
            ? ["/token"]
            : variant === "foreign-app"
              ? ["/token", "/debug"]
              : ["/token", "/debug", "/userinfo"],
      );

      return {
        before: other.before,
        start: ctx.snapshot(start),
        callback: { status: response.status, location },
        after: await state(ctx),
        receipts: await receipts(ctx),
      };
    },
    ["GET /callback/{}"],
  );
}

compatScenario(
  "facebook explicit signup overrides implicit signup policy with a genuinely app-bound Graph identity",
  async (ctx) => {
    await control(ctx, { profile: profile(ctx) });
    const flow = await callback(ctx, "social-facebook-implicit-disabled", true);
    expect(flow.response.headers.get("location")).toBe("/dashboard");

    const stored = await state(ctx);

    for (const table of ["users", "accounts", "sessions"] as const) {
      expect(stored[table]).toHaveLength(1);
    }

    expect((await flow.actor.client.getSession()).data?.user.id).toBe(stored.users[0]!.id);

    return {
      start: ctx.snapshot(flow.start),
      callback: { status: flow.response.status, location: flow.response.headers.get("location") },
      stored,
      receipts: await receipts(ctx),
    };
  },
  ["POST /sign-in/social", "GET /callback/{}"],
);

for (const variant of ["decoded-idtoken", "mapped-decoded-idtoken", "opaque-idtoken"] as const) {
  compatScenario(
    `facebook ${variant} code exchange uses real Limited Login decode or app-inspected Graph profile`,
    async (ctx) => {
      const other = await foreign(ctx);
      const original = profile(ctx);
      const idToken =
        variant === "opaque-idtoken"
          ? "opaque-facebook-candidate"
          : await proof(ctx, { originalApplicationField: { retained: true } });
      await control(ctx, { profile: original, idToken });
      const fixture: FixtureProfile =
        variant === "mapped-decoded-idtoken" ? "social-facebook-mapped" : "social-facebook-default";
      const flow = await callback(ctx, fixture);
      expect(flow.response.headers.get("location")).toBe("/dashboard");

      const stored = await state(ctx);
      unchangedForeign(other.before, stored);
      const user = stored.users.find(
        (row) => !other.before.users.some((old) => old.id === row.id),
      )!;
      const account = stored.accounts.find((row) => row.userId === user.id)!;
      const decoded =
        variant === "opaque-idtoken"
          ? null
          : JSON.parse(Buffer.from(idToken.split(".")[1]!, "base64url").toString());
      expect(user).toMatchObject({
        name:
          variant === "mapped-decoded-idtoken"
            ? "Mapped Facebook User"
            : decoded
              ? "Facebook JWT User"
              : "Facebook User",
        email:
          variant === "mapped-decoded-idtoken"
            ? "mapped-facebook@example.invalid"
            : (decoded?.email ?? original.email),
        emailVerified: variant === "opaque-idtoken",
        image:
          variant === "mapped-decoded-idtoken"
            ? "https://images.example.invalid/mapped-facebook.png"
            : (decoded?.picture ?? "https://images.example.invalid/facebook.png"),
      });
      expect(account).toMatchObject({
        accountId: decoded?.sub ?? original.id,
        idToken,
        accessToken: "fixture-facebook-access",
        refreshToken: "fixture-facebook-refresh",
        scope: "",
      });
      expect((await flow.actor.client.getSession()).data?.user.id).toBe(user.id);
      expect(await mapperReceipts(ctx)).toEqual(
        variant === "mapped-decoded-idtoken" ? [decoded] : [],
      );
      expect((await receipts(ctx)).map((row) => row.path)).toEqual(
        decoded ? ["/token"] : ["/token", "/debug", "/userinfo"],
      );

      return {
        before: other.before,
        start: ctx.snapshot(flow.start),
        callback: { status: flow.response.status, location: flow.response.headers.get("location") },
        stored,
        mapper: await mapperReceipts(ctx),
        receipts: await receipts(ctx),
      };
    },
    ["POST /sign-in/social", "GET /callback/{}"],
  );
}

compatScenario(
  "facebook explicit browser link retains the actual local owner and foreign rows through app-inspected raw identity admission",
  async (ctx) => {
    const other = await foreign(ctx);
    const owner = ctx.actor("facebook", "social-facebook-default");
    const email = ctx.uniqueEmail("facebook-owner");
    const signup = await owner.client.signUp.email({
      email,
      name: "Existing Facebook Owner",
      password: "Password123!",
    });
    expect(signup.error).toBeNull();

    const before = await state(ctx);
    const original: Row = { ...profile(ctx), email };
    await control(ctx, { profile: original });
    const start = await owner.client.linkSocial({ provider: "facebook", callbackURL: "/linked" });
    expect(start.error).toBeNull();

    const url = new URL(start.data!.url!);
    const path =
      authProfilePath("social-facebook-default") +
      `/callback/facebook?code=fixture-code&state=${encodeURIComponent(url.searchParams.get("state")!)}`;
    const response = await owner.fetch(ctx.baseURL + path, { redirect: "manual" });
    expect(response.headers.get("location")).toBe("/linked");

    const linked = await state(ctx);
    expect(linked.users).toEqual(before.users);
    expect(linked.sessions).toEqual(before.sessions);

    unchangedForeign(other.before, linked);
    expect(linked.accounts).toHaveLength(before.accounts.length + 1);

    const account = linked.accounts.find(
      (row) => !before.accounts.some((old) => old.id === row.id),
    )!;
    expect(account).toMatchObject({
      providerId: "facebook",
      accountId: original.id,
      userId: signup.data!.user.id,
      accessToken: "fixture-facebook-access",
      refreshToken: "fixture-facebook-refresh",
    });
    expect((await owner.client.getSession()).data?.user.id).toBe(signup.data!.user.id);

    const observed = await receipts(ctx);
    expect(observed.map((row) => row.path)).toEqual(["/token", "/debug", "/userinfo"]);

    const replay = await owner.fetch(ctx.baseURL + path, { redirect: "manual" });
    expect(
      new URL(replay.headers.get("location")!, ctx.baseURL).searchParams.get("error"),
    ).toBeTruthy();
    expect(await state(ctx)).toEqual(linked);
    expect(await receipts(ctx)).toEqual(observed);

    return {
      before,
      start: ctx.snapshot(start),
      callback: { status: response.status, location: response.headers.get("location") },
      linked,
      replay: { status: replay.status, location: replay.headers.get("location") },
      receipts: observed,
    };
  },
  ["POST /link-social", "GET /callback/{}"],
);
