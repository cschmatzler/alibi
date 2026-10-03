import { expect } from "bun:test";

import { SignJWT, jwtVerify } from "jose";

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
  body: Record<string, string> | string;
};

async function state(ctx: ScenarioContext): Promise<Stored> {
  const response = await ctx.rawRequest({ path: "/__test/social-provider/state" });
  expect(response.status).toBe(200);
  return response.body as Stored;
}
async function control(ctx: ScenarioContext, value: Row) {
  const response = await ctx.rawRequest({
    path: "/__test/line/control",
    method: "POST",
    json: value,
  });
  expect(response.status).toBe(200);
}
async function receipts(ctx: ScenarioContext) {
  const response = await ctx.rawRequest({ path: "/__test/line/receipts" });
  expect(response.status).toBe(200);
  return (response.body as Receipt[]).map((row) => ({
    ...row,
    body:
      typeof row.body === "object" && row.body.code_verifier
        ? {
            ...row.body,
            code_verifier: { token: row.body.code_verifier, length: row.body.code_verifier.length },
          }
        : row.body,
  }));
}
async function foreign(ctx: ScenarioContext) {
  const actor = ctx.actor("foreign"),
    signup = await actor.client.signUp.email({
      email: ctx.uniqueEmail("foreign"),
      password: "Password123!",
      name: "Foreign",
    });
  expect(signup.error).toBeNull();
  return { actor, before: await state(ctx) };
}
function unchangedForeign(before: Stored, after: Stored) {
  for (const table of ["users", "accounts", "sessions"] as const)
    for (const row of before[table])
      expect(after[table].find((candidate) => candidate.id === row.id)).toEqual(row);
}
function profile(ctx: ScenarioContext): Row {
  return {
    sub: ctx.uniqueToken("line-subject"),
    name: "Line User",
    email: ctx.uniqueEmail("line"),
    email_verified: true,
    picture: "https://images.example.invalid/line.png",
    originalApplicationField: { retained: true },
  };
}
async function callback(
  ctx: ScenarioContext,
  mode: FixtureProfile = "social-line-default",
  requestSignUp = false,
) {
  const actor = ctx.actor("line", mode),
    start = await actor.client.signIn.social({
      provider: "line",
      callbackURL: "/dashboard",
      requestSignUp,
    });
  expect(start.error).toBeNull();
  const url = new URL(start.data!.url!),
    path =
      authProfilePath(mode) +
      `/callback/line?code=fixture-code&state=${encodeURIComponent(url.searchParams.get("state")!)}`;
  return {
    actor,
    start,
    url,
    path,
    response: await actor.fetch(ctx.baseURL + path, { redirect: "manual" }),
  };
}

for (const mode of [
  "default",
  "configured",
  "disabled-scope",
  "disabled-configured",
  "configured-endpoint",
] as const) {
  compatScenario(
    `line published ${mode} authorization retains ordered scopes and required PKCE`,
    async (ctx) => {
      const other = await foreign(ctx),
        fixture: FixtureProfile = `social-line-${mode}`;
      const result = await ctx.actor("line", fixture).client.signIn.social({
        provider: "line",
        callbackURL: "/dashboard",
        scopes: ["requested-scope", "openid"],
        loginHint: "ignored@example.invalid",
        additionalParams: { custom: "value with space" },
      });
      expect(result.error).toBeNull();
      const url = new URL(result.data!.url!),
        configured = ["configured", "disabled-configured"].includes(mode);
      expect(url.origin).toBe(
        mode === "configured-endpoint"
          ? "https://alternate-line.example.invalid"
          : "https://access.line.me",
      );
      expect(url.pathname).toBe(
        mode === "configured-endpoint" ? "/authorize" : "/oauth2/v2.1/authorize",
      );
      const scopes = [
        ...(mode.startsWith("disabled-") ? [] : ["openid", "profile", "email"]),
        ...(configured ? ["configured-scope", "openid", "punctuation !~*'()"] : []),
        "requested-scope",
        "openid",
      ];
      expect(url.searchParams.getAll("scope")).toEqual([scopes.join(" ")]);
      expect(result.data!.url).toContain(
        `scope=${new URLSearchParams({ scope: scopes.join(" ") }).toString().slice(6)}`,
      );
      expect(url.searchParams.getAll("client_id")).toEqual(["fixture-social-client"]);
      expect(url.searchParams.get("response_type")).toBe("code");
      expect(url.searchParams.getAll("state")).toHaveLength(1);
      expect(url.searchParams.get("state")).not.toBe("stale");
      expect(url.searchParams.get("code_challenge_method")).toBe("S256");
      expect(url.searchParams.get("code_challenge")).toBeTruthy();
      expect(url.searchParams.get("login_hint")).toBe("ignored@example.invalid");
      expect(url.searchParams.get("custom")).toBe("value with space");
      expect(url.searchParams.get("redirect_uri")).toBe(
        mode === "configured-endpoint"
          ? "https://client.example.invalid/line-return"
          : ctx.baseURL + authProfilePath(fixture) + "/callback/line",
      );
      if (mode === "configured-endpoint") expect(url.searchParams.get("retained")).toBe("value");
      expect(await state(ctx)).toEqual(other.before);
      expect(await receipts(ctx)).toEqual([]);
      return {
        result: ctx.snapshot(result),
        before: other.before,
        after: await state(ctx),
        receipts: await receipts(ctx),
      };
    },
    ["POST /sign-in/social"],
  );
}

for (const mode of ["default", "public", "mapped", "configured-endpoint", "client-key"] as const) {
  compatScenario(
    `line ${mode} real secret or public exchange and GET profile refresh replay and local logout preserve foreign authority`,
    async (ctx) => {
      const other = await foreign(ctx),
        original = profile(ctx);
      await control(ctx, { profile: original });
      const fixture: FixtureProfile = `social-line-${mode}`,
        flow = await callback(ctx, fixture);
      expect(flow.response.status).toBe(302);
      expect(flow.response.headers.get("location")).toBe("/dashboard");
      const session = await flow.actor.client.getSession(),
        after = await state(ctx);
      expect(session.error).toBeNull();
      unchangedForeign(other.before, after);
      for (const table of ["users", "accounts", "sessions"] as const)
        expect(after[table]).toHaveLength(other.before[table].length + 1);
      const user = after.users.find((row) => !other.before.users.some((old) => old.id === row.id))!,
        account = after.accounts.find((row) => row.userId === user.id)!;
      expect(user).toMatchObject({
        name: mode === "mapped" ? "Mapped Line User" : "Line User",
        email: mode === "mapped" ? "mapped-line@example.invalid" : original.email,
        emailVerified: mode === "mapped",
        image:
          mode === "mapped" ? "https://images.example.invalid/mapped-line.png" : original.picture,
      });
      expect(account).toMatchObject({
        providerId: "line",
        accountId: original.sub,
        accessToken: "fixture-line-access",
        refreshToken: "fixture-line-refresh",
        scope: "openid,profile,email",
        idToken: null,
      });
      expect(account.accessTokenExpiresAt).toBeTruthy();
      expect(session.data?.user.id).toBe(user.id);
      const raw = (await ctx.rawRequest({ path: "/__test/line/receipts" })).body as Receipt[],
        exchange = raw[0]!.body as Record<string, string>,
        verifier = exchange.code_verifier!;
      expect(verifier).toHaveLength(128);
      expect(flow.url.searchParams.get("code_challenge")).toBe(
        Buffer.from(
          await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
        ).toString("base64url"),
      );
      expect(exchange).toEqual({
        grant_type: "authorization_code",
        code: "fixture-code",
        code_verifier: verifier,
        client_id: "fixture-social-client",
        ...(mode === "public" ? {} : { client_secret: "fixture-social-secret" }),
        ...(mode === "client-key" ? { client_key: "fixture-line-client-key" } : {}),
        redirect_uri:
          mode === "configured-endpoint"
            ? "https://client.example.invalid/line-return"
            : ctx.baseURL + authProfilePath(fixture) + "/callback/line",
      });
      expect(raw[0]!.authorization).toBeNull();
      expect(raw[1]).toEqual({
        path: "/userinfo",
        method: "GET",
        authorization: "Bearer fixture-line-access",
        contentType: null,
        body: "",
      });
      const mapper = (await ctx.rawRequest({ path: "/__test/line/mapper-receipts" })).body;
      expect(mapper).toEqual(mode === "mapped" ? [original] : []);
      const replay = await flow.actor.fetch(ctx.baseURL + flow.path, { redirect: "manual" });
      expect(replay.status).toBe(302);
      expect(
        new URL(replay.headers.get("location")!, ctx.baseURL).searchParams.get("error"),
      ).toBeTruthy();
      expect(await state(ctx)).toEqual(after);
      expect(await receipts(ctx)).toHaveLength(2);
      await control(ctx, {
        tokenResponse: {
          access_token: "fixture-line-access-rotated",
          refresh_token: "fixture-line-refresh-rotated",
          expires_in: 1800,
          scope: "rotated-scope",
        },
      });
      const denied = await other.actor.client.refreshToken({ accountId: account.id });
      expect(denied.error).not.toBeNull();
      expect(await state(ctx)).toEqual(after);
      expect(await receipts(ctx)).toHaveLength(2);
      const refreshed = await flow.actor.client.refreshToken({ accountId: account.id });
      expect(refreshed.error).toBeNull();
      const rotated = await state(ctx);
      expect(rotated.users).toEqual(after.users);
      expect(rotated.sessions).toEqual(after.sessions);
      unchangedForeign(other.before, rotated);
      expect(rotated.accounts.find((row) => row.id === account.id)).toMatchObject({
        accountId: original.sub,
        userId: user.id,
        accessToken: "fixture-line-access-rotated",
        refreshToken: "fixture-line-refresh-rotated",
        scope: account.scope,
      });
      const requests = await receipts(ctx);
      expect(requests[2]!.body).toEqual({
        grant_type: "refresh_token",
        refresh_token: "fixture-line-refresh",
        client_id: "fixture-social-client",
        ...(mode === "public" ? {} : { client_secret: "fixture-social-secret" }),
      });
      expect(requests[2]!.authorization).toBeNull();
      const signedOut = await flow.actor.client.signOut();
      expect(signedOut.error).toBeNull();
      expect((await flow.actor.client.getSession()).data).toBeNull();
      const final = await state(ctx);
      expect(final.users).toEqual(rotated.users);
      expect(final.accounts).toEqual(rotated.accounts);
      unchangedForeign(other.before, final);
      expect(final.sessions).toEqual(other.before.sessions);
      expect(await receipts(ctx)).toEqual(requests);
      return {
        before: other.before,
        start: ctx.snapshot(flow.start),
        callback: { status: flow.response.status, location: flow.response.headers.get("location") },
        session: ctx.snapshot(session),
        after,
        mapper,
        denied: ctx.snapshot(denied),
        refreshed: ctx.snapshot(refreshed),
        rotated,
        signedOut: ctx.snapshot(signedOut),
        final,
        receipts: requests,
      };
    },
    ["POST /sign-in/social", "GET /callback/{}", "POST /refresh-token", "POST /sign-out"],
  );
}

const mappings: Array<{
  name: string;
  patch: Row;
  expectedName: string;
  expectedImage?: string | null;
  expectedSubject?: string;
}> = [
  { name: "numeric name", patch: { name: 7 }, expectedName: "7" },
  { name: "empty name", patch: { name: "" }, expectedName: "" },
  { name: "null name", patch: { name: null }, expectedName: "" },
  { name: "missing name", patch: { name: undefined }, expectedName: "" },
  { name: "numeric subject", patch: { sub: 42 }, expectedName: "Line User", expectedSubject: "42" },
  {
    name: "missing image",
    patch: { picture: undefined },
    expectedName: "Line User",
    expectedImage: null,
  },
  { name: "null image", patch: { picture: null }, expectedName: "Line User", expectedImage: null },
  { name: "empty image", patch: { picture: "" }, expectedName: "Line User", expectedImage: "" },
  { name: "numeric image", patch: { picture: 7 }, expectedName: "Line User", expectedImage: "7" },
];
for (const mapping of mappings)
  compatScenario(
    `line ${mapping.name} userinfo profile retains original raw account and typed persistence`,
    async (ctx) => {
      const other = await foreign(ctx),
        original = { ...profile(ctx), ...mapping.patch };
      await control(ctx, { profile: original });
      const flow = await callback(ctx);
      expect(flow.response.headers.get("location")).toBe("/dashboard");
      const stored = await state(ctx);
      unchangedForeign(other.before, stored);
      const user = stored.users.find(
          (row) => !other.before.users.some((old) => old.id === row.id),
        )!,
        account = stored.accounts.find((row) => row.userId === user.id)!;
      expect(user).toMatchObject({
        name: mapping.expectedName,
        email: original.email,
        emailVerified: false,
        image: mapping.expectedImage === undefined ? original.picture : mapping.expectedImage,
      });
      expect(account.accountId).toBe(mapping.expectedSubject ?? original.sub);
      expect((await flow.actor.client.getSession()).data?.user.id).toBe(user.id);
      return {
        before: other.before,
        start: ctx.snapshot(flow.start),
        callback: { status: flow.response.status, location: flow.response.headers.get("location") },
        stored,
        receipts: await receipts(ctx),
      };
    },
    ["POST /sign-in/social", "GET /callback/{}"],
  );

for (const expiry of ["absent", "zero", "fractional"] as const)
  compatScenario(
    `line ${expiry} access expiry follows actual token helper`,
    async (ctx) => {
      await control(ctx, {
        profile: profile(ctx),
        tokenResponse: {
          access_token: "fixture-line-access",
          refresh_token: "fixture-line-refresh",
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
      if (expiry === "fractional") expect(stored.accounts[0]!.accessTokenExpiresAt).toBeTruthy();
      else expect(stored.accounts[0]!.accessTokenExpiresAt).toBeNull();
      return {
        start: ctx.snapshot(flow.start),
        callback: { status: flow.response.status, location: flow.response.headers.get("location") },
        stored,
        receipts: await receipts(ctx),
      };
    },
    ["POST /sign-in/social", "GET /callback/{}"],
  );

for (const variant of [
  "wrong-state",
  "wrong-provider",
  "token-http-error",
  "userinfo-http-error",
  "missing-subject",
  "null-subject",
  "blank-subject",
  "missing-email",
  "signup-disabled",
  "implicit-disabled",
] as const)
  compatScenario(
    `line browser ${variant} denies before any owned or foreign identity write`,
    async (ctx) => {
      const other = await foreign(ctx),
        original = profile(ctx);
      if (variant === "missing-subject") delete original.sub;
      if (variant === "null-subject") original.sub = null;
      if (variant === "blank-subject") original.sub = " ";
      if (variant === "missing-email") delete original.email;
      await control(ctx, {
        profile: original,
        ...(variant === "token-http-error" ? { tokenStatus: 503 } : {}),
        ...(variant === "userinfo-http-error" ? { userInfoStatus: 503 } : {}),
      });
      const fixture: FixtureProfile =
          variant === "signup-disabled"
            ? "social-line-signup-disabled"
            : variant === "implicit-disabled"
              ? "social-line-implicit-disabled"
              : "social-line-default",
        actor = ctx.actor("line", fixture),
        start = await actor.client.signIn.social({
          provider: "line",
          callbackURL: "/dashboard",
          requestSignUp: variant === "signup-disabled",
        });
      expect(start.error).toBeNull();
      const url = new URL(start.data!.url!),
        callbackState =
          variant === "wrong-state"
            ? ctx.uniqueToken("wrong-state")
            : url.searchParams.get("state")!,
        provider = variant === "wrong-provider" ? "unknown-line" : "line",
        response = await actor.fetch(
          ctx.baseURL +
            authProfilePath(fixture) +
            `/callback/${provider}?code=fixture-code&state=${encodeURIComponent(callbackState)}`,
          { redirect: "manual" },
        );
      expect(response.status).toBe(302);
      const location = response.headers.get("location")!,
        error = new URL(location, ctx.baseURL).searchParams.get("error");
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
      const requests = await receipts(ctx);
      expect(requests.map((row) => row.path)).toEqual(
        ["wrong-state", "wrong-provider"].includes(variant)
          ? []
          : variant === "token-http-error"
            ? ["/token"]
            : ["/token", "/userinfo"],
      );
      return {
        before: other.before,
        start: ctx.snapshot(start),
        callback: { status: response.status, location },
        after: await state(ctx),
        receipts: requests,
      };
    },
    ["GET /callback/{}"],
  );

compatScenario(
  "line disabled default scope omits an empty scope parameter",
  async (ctx) => {
    const before = await state(ctx),
      result = await ctx
        .actor("line", "social-line-disabled-scope")
        .client.signIn.social({ provider: "line" });
    expect(result.error).toBeNull();
    expect(new URL(result.data!.url!).searchParams.has("scope")).toBeFalse();
    expect(await state(ctx)).toEqual(before);
    expect(await receipts(ctx)).toEqual([]);
    return { result: ctx.snapshot(result), before, after: await state(ctx) };
  },
  ["POST /sign-in/social"],
);
compatScenario(
  "line explicit signup overrides implicit signup policy",
  async (ctx) => {
    await control(ctx, { profile: profile(ctx) });
    const flow = await callback(ctx, "social-line-implicit-disabled", true);
    expect(flow.response.headers.get("location")).toBe("/dashboard");
    const stored = await state(ctx);
    for (const table of ["users", "accounts", "sessions"] as const)
      expect(stored[table]).toHaveLength(1);
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
for (const mode of ["empty-clients"] as const)
  compatScenario(`line ${mode} requires a real client before identity writes`, async (ctx) => {
    const other = await foreign(ctx),
      result = await ctx
        .actor("line", `social-line-${mode}`)
        .client.signIn.social({ provider: "line" });
    expect(result.error?.status).toBe(500);
    expect(await state(ctx)).toEqual(other.before);
    expect(await receipts(ctx)).toEqual([]);
    return { result: ctx.snapshot(result), before: other.before, after: await state(ctx) };
  });

for (const variant of ["default-unverified", "mapped-verified", "missing-raw"] as const)
  compatScenario(
    `line explicit browser link ${variant} retains existing and foreign authority`,
    async (ctx) => {
      const other = await foreign(ctx),
        fixture = variant === "default-unverified" ? "social-line-default" : "social-line-mapped",
        actor = ctx.actor("line", fixture),
        email =
          variant === "default-unverified"
            ? ctx.uniqueEmail("line-link")
            : "mapped-line@example.invalid";
      const signup = await actor.client.signUp.email({
        email,
        password: "Password123!",
        name: "Existing local user",
      });
      expect(signup.error).toBeNull();
      const before = await state(ctx),
        original: Row = { ...profile(ctx), email };
      if (variant === "missing-raw") delete original.sub;
      await control(ctx, { profile: original });
      const start = await actor.client.linkSocial({ provider: "line", callbackURL: "/linked" });
      expect(start.error).toBeNull();
      const url = new URL(start.data!.url!),
        path =
          authProfilePath(fixture) +
          `/callback/line?code=fixture-code&state=${encodeURIComponent(url.searchParams.get("state")!)}`,
        response = await actor.fetch(ctx.baseURL + path, { redirect: "manual" });
      expect(response.status).toBe(302);
      const location = response.headers.get("location")!,
        after = await state(ctx);
      unchangedForeign(other.before, after);
      expect(after.users).toEqual(before.users);
      expect(after.sessions).toEqual(before.sessions);
      if (variant === "mapped-verified") {
        expect(location).toBe("/linked");
        expect(after.accounts).toHaveLength(before.accounts.length + 1);
        expect(after.accounts.find((row) => row.providerId === "line")).toMatchObject({
          accountId: original.sub,
          userId: signup.data!.user.id,
        });
      } else {
        expect(new URL(location, ctx.baseURL).searchParams.get("error")).toBe(
          variant === "missing-raw" ? "unable_to_get_user_info" : "unable_to_link_account",
        );
        expect(after).toEqual(before);
      }
      expect((await actor.client.getSession()).data?.user.id).toBe(signup.data!.user.id);
      expect((await receipts(ctx)).map((row) => row.path)).toEqual(["/token", "/userinfo"]);
      const replay = await actor.fetch(ctx.baseURL + path, { redirect: "manual" });
      expect(replay.status).toBe(302);
      expect(
        new URL(replay.headers.get("location")!, ctx.baseURL).searchParams.get("error"),
      ).toBeTruthy();
      expect(await state(ctx)).toEqual(after);
      expect(await receipts(ctx)).toHaveLength(2);
      return {
        before,
        start: ctx.snapshot(start),
        callback: { status: response.status, location },
        after,
        receipts: await receipts(ctx),
      };
    },
    ["POST /link-social", "GET /callback/{}"],
  );

compatScenario(
  "line existing account info uses real GET without readmitting a changed raw account subject",
  async (ctx) => {
    const other = await foreign(ctx),
      original = profile(ctx);
    await control(ctx, { profile: original });
    const flow = await callback(ctx);
    expect(flow.response.headers.get("location")).toBe("/dashboard");
    const before = await state(ctx),
      user = before.users.find((row) => !other.before.users.some((old) => old.id === row.id))!,
      account = before.accounts.find((row) => row.userId === user.id)!;
    delete original.sub;
    await control(ctx, { profile: original });
    const denied = await other.actor.client.$fetch("/account-info", {
      query: { accountId: account.id },
    });
    expect(denied.error).not.toBeNull();
    expect(await receipts(ctx)).toHaveLength(2);
    expect(await state(ctx)).toEqual(before);
    const result = await flow.actor.client.$fetch("/account-info", {
      query: { accountId: account.id },
    });
    expect(result.error).toBeNull();
    expect(result.data).toEqual({
      user: {
        name: "Line User",
        email: original.email,
        image: original.picture,
        emailVerified: false,
      },
      data: original,
      account: { id: account.id, providerId: "line", accountId: account.accountId },
    });
    expect(await state(ctx)).toEqual(before);
    expect((await receipts(ctx))[2]).toEqual({
      path: "/userinfo",
      method: "GET",
      authorization: "Bearer fixture-line-access",
      contentType: null,
      body: "",
    });
    return {
      before,
      denied: ctx.snapshot(denied),
      result: ctx.snapshot(result),
      after: await state(ctx),
      receipts: await receipts(ctx),
    };
  },
  ["GET /account-info"],
);

const lineIssuedAt = Math.floor(Date.now() / 1000);
const proofKey = new TextEncoder().encode("fixture-line-independent-hmac-key-32");
async function signedProfile(ctx: ScenarioContext, patch: Row = {}, wrong = false) {
  const claims: Row = {
    iss: "https://access.line.me",
    aud: "fixture-social-client",
    iat: lineIssuedAt,
    exp: lineIssuedAt + 3600,
    ...profile(ctx),
    ...patch,
  };
  const token = await new SignJWT(claims)
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .sign(wrong ? new TextEncoder().encode("foreign-line-independent-hmac-key-32") : proofKey);
  return { claims, token };
}
for (const mode of [
  "default",
  "public",
  "mapped",
  "nonce",
  "empty-nonce",
  "falsy-returned-nonce",
] as const)
  compatScenario(
    `line delegated signed direct proof ${mode} binds actual remote receipt and raw account`,
    async (ctx) => {
      const other = await foreign(ctx),
        nonce =
          mode === "nonce" || mode === "falsy-returned-nonce"
            ? "line-exact-nonce"
            : mode === "empty-nonce"
              ? ""
              : undefined;
      const proof = await signedProfile(ctx, nonce ? { nonce } : {}),
        accessToken = mode === "default" ? undefined : "fixture-line-direct-access";
      const verified = await jwtVerify(proof.token, proofKey, {
        algorithms: ["HS256"],
        issuer: "https://access.line.me",
        audience: "fixture-social-client",
      });
      expect(verified.payload).toEqual(proof.claims);
      await control(
        ctx,
        mode === "falsy-returned-nonce"
          ? { verifyResponse: { ...proof.claims, nonce: false } }
          : {},
      );
      const fixture: FixtureProfile =
          mode === "public"
            ? "social-line-public"
            : mode === "mapped"
              ? "social-line-mapped"
              : "social-line-default",
        actor = ctx.actor("line", fixture),
        result = await actor.client.signIn.social({
          provider: "line",
          idToken: {
            token: proof.token,
            ...(nonce !== undefined ? { nonce } : {}),
            ...(accessToken ? { accessToken } : {}),
          },
        });
      expect(result.error).toBeNull();
      const after = await state(ctx);
      unchangedForeign(other.before, after);
      for (const table of ["users", "accounts", "sessions"] as const)
        expect(after[table]).toHaveLength(other.before[table].length + 1);
      const user = after.users.find((row) => !other.before.users.some((old) => old.id === row.id))!,
        account = after.accounts.find((row) => row.userId === user.id)!;
      expect(user).toMatchObject({
        name: mode === "mapped" ? "Mapped Line User" : "Line User",
        email: mode === "mapped" ? "mapped-line@example.invalid" : proof.claims.email,
        emailVerified: mode === "mapped",
        image:
          mode === "mapped"
            ? "https://images.example.invalid/mapped-line.png"
            : proof.claims.picture,
      });
      expect(account).toMatchObject({
        providerId: "line",
        accountId: proof.claims.sub,
        idToken: proof.token,
      });
      expect((await actor.client.getSession()).data?.user.id).toBe(user.id);
      const remote = await receipts(ctx);
      expect(remote).toEqual([
        {
          path: "/verify",
          method: "POST",
          authorization: null,
          contentType: "application/x-www-form-urlencoded",
          body: {
            id_token: proof.token,
            client_id: "fixture-social-client",
            ...(nonce ? { nonce } : {}),
          },
        },
      ]);
      const mapper = (await ctx.rawRequest({ path: "/__test/line/mapper-receipts" })).body;
      expect(mapper).toEqual(mode === "mapped" ? [proof.claims] : []);
      const denied = await other.actor.client.$fetch("/account-info", {
        query: { accountId: account.id },
      });
      expect(denied.error).not.toBeNull();
      expect(await state(ctx)).toEqual(after);
      expect(await receipts(ctx)).toEqual(remote);
      const info = await actor.client.$fetch("/account-info", { query: { accountId: account.id } });
      if (accessToken) {
        expect(info.error).toBeNull();
        expect((info.data as { data: Row }).data).toEqual(proof.claims);
      } else {
        expect(info.error).toMatchObject({ code: "ACCESS_TOKEN_NOT_FOUND", status: 400 });
      }
      expect(await state(ctx)).toEqual(after);
      expect(await receipts(ctx)).toEqual(remote);
      return {
        before: other.before,
        result: ctx.snapshot(result),
        after,
        mapper,
        denied: ctx.snapshot(denied),
        info: ctx.snapshot(info),
        receipts: remote,
      };
    },
    ["POST /sign-in/social", "GET /account-info"],
  );

const proofDenials: Array<{
  name: string;
  claims?: Row;
  response?: Row;
  wrong?: boolean;
  nonce?: string;
  status?: number;
  mode?: FixtureProfile;
  code?: string;
}> = [
  { name: "foreign signature", wrong: true },
  { name: "foreign issuer", claims: { iss: "https://foreign.invalid" } },
  { name: "foreign audience", claims: { aud: "foreign-client" } },
  { name: "expired", claims: { exp: 1 } },
  { name: "nonce mismatch", claims: { nonce: "signed-nonce" }, nonce: "different-nonce" },
  { name: "HTTP failure", status: 503 },
  { name: "remote foreign audience", response: { aud: "foreign-client" } },
  { name: "remote array audience", response: { aud: ["fixture-social-client"] } },
  { name: "remote boolean audience", response: { aud: true } },
  { name: "unexpected remote string nonce", response: { nonce: "unexpected" } },
  { name: "unexpected remote boolean nonce", response: { nonce: true } },
  { name: "unexpected remote array nonce", response: { nonce: [] } },
  { name: "unexpected remote object nonce", response: { nonce: {} } },
  { name: "missing raw subject", claims: { sub: undefined }, code: "FAILED_TO_GET_USER_INFO" },
  {
    name: "mapped missing raw subject",
    claims: { sub: undefined },
    mode: "social-line-mapped",
    code: "FAILED_TO_GET_USER_INFO",
  },
  { name: "missing email", claims: { email: undefined }, code: "USER_EMAIL_NOT_FOUND" },
  { name: "disabled", mode: "social-line-disabled-idtoken", code: "ID_TOKEN_NOT_SUPPORTED" },
];
for (const denial of proofDenials)
  compatScenario(
    `line delegated direct ${denial.name} rejects before owned or foreign writes`,
    async (ctx) => {
      const other = await foreign(ctx),
        proof = await signedProfile(ctx, denial.claims, denial.wrong);
      await control(ctx, {
        ...(denial.response ? { verifyResponse: { ...proof.claims, ...denial.response } } : {}),
        ...(denial.status ? { verifyStatus: denial.status } : {}),
      });
      const result = await ctx
        .actor("line", denial.mode ?? "social-line-default")
        .client.signIn.social({
          provider: "line",
          idToken: { token: proof.token, ...(denial.nonce ? { nonce: denial.nonce } : {}) },
        });
      expect(result.error?.code).toBe(denial.code ?? "INVALID_TOKEN");
      expect(await state(ctx)).toEqual(other.before);
      const remote = await receipts(ctx);
      expect(remote.map((row) => row.path)).toEqual(denial.name === "disabled" ? [] : ["/verify"]);
      if (remote.length)
        expect(remote[0]!.body).toEqual({
          id_token: proof.token,
          client_id: "fixture-social-client",
          ...(denial.nonce ? { nonce: denial.nonce } : {}),
        });
      return {
        before: other.before,
        result: ctx.snapshot(result),
        after: await state(ctx),
        receipts: remote,
      };
    },
  );

for (const nonce of [null, false, 0, ""] as const)
  compatScenario(
    `line false remote nonce ${JSON.stringify(nonce)} preserves delegated admission`,
    async (ctx) => {
      const proof = await signedProfile(ctx);
      await control(ctx, { verifyResponse: { ...proof.claims, nonce } });
      const actor = ctx.actor("line", "social-line-default"),
        result = await actor.client.signIn.social({
          provider: "line",
          idToken: { token: proof.token },
        });
      expect(result.error).toBeNull();
      const after = await state(ctx);
      expect(after.users).toHaveLength(1);
      expect(after.accounts[0]!.accountId).toBe(proof.claims.sub);
      expect((await actor.client.getSession()).data?.user.id).toBe(after.users[0]!.id);
      expect((await receipts(ctx)).map((row) => row.path)).toEqual(["/verify"]);
      return { result: ctx.snapshot(result), after, receipts: await receipts(ctx) };
    },
    ["POST /sign-in/social"],
  );

for (const variant of ["valid", "expired", "foreign-audience", "malformed-fallback"] as const)
  compatScenario(
    `line code-grant ${variant} profile uses actual decode or bearer fallback without direct verification`,
    async (ctx) => {
      const other = await foreign(ctx),
        signed = await signedProfile(
          ctx,
          variant === "expired"
            ? { exp: 1 }
            : variant === "foreign-audience"
              ? { aud: "foreign-client" }
              : {},
        ),
        fallback = profile(ctx),
        idToken = variant === "malformed-fallback" ? "not-a-jwt" : signed.token;
      await control(ctx, { idToken, profile: fallback });
      const flow = await callback(ctx);
      expect(flow.response.headers.get("location")).toBe("/dashboard");
      const after = await state(ctx);
      unchangedForeign(other.before, after);
      const account = after.accounts.find((row) => row.providerId === "line")!,
        user = after.users.find((row) => row.id === account.userId)!;
      expect(account.accountId).toBe(
        variant === "malformed-fallback" ? fallback.sub : signed.claims.sub,
      );
      expect(account.idToken).toBe(idToken);
      expect(user.emailVerified).toBeFalse();
      expect((await flow.actor.client.getSession()).data?.user.id).toBe(user.id);
      const remote = await receipts(ctx);
      expect(remote.map((row) => row.path)).toEqual(
        variant === "malformed-fallback" ? ["/token", "/userinfo"] : ["/token"],
      );
      expect(remote.some((row) => row.path === "/verify")).toBeFalse();
      return {
        before: other.before,
        start: ctx.snapshot(flow.start),
        callback: { status: flow.response.status, location: flow.response.headers.get("location") },
        after,
        receipts: remote,
      };
    },
    ["POST /sign-in/social", "GET /callback/{}"],
  );
