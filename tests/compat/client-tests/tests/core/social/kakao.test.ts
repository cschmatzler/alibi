import { expect } from "bun:test";

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
    path: "/__test/kakao/control",
    method: "POST",
    json: value,
  });
  expect(response.status).toBe(200);
}

async function receipts(ctx: ScenarioContext) {
  const response = await ctx.rawRequest({ path: "/__test/kakao/receipts" });
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
  const actor = ctx.actor("foreign");
  const signup = await actor.client.signUp.email({
    email: ctx.uniqueEmail("foreign"),
    password: "Password123!",
    name: "Foreign",
  });
  expect(signup.error).toBeNull();

  return { actor, before: await state(ctx) };
}

function unchangedForeign(before: Stored, after: Stored) {
  for (const table of ["users", "accounts", "sessions"] as const) {
    for (const row of before[table]) {
      expect(after[table].find((candidate) => candidate.id === row.id)).toEqual(row);
    }
  }
}

function profile(ctx: ScenarioContext): Row {
  return {
    id: 4242,
    kakao_account: {
      name: "Kakao Account",
      email: ctx.uniqueEmail("kakao"),
      is_email_valid: true,
      is_email_verified: true,
      profile: {
        nickname: "Kakao User",
        profile_image_url: "https://images.example.invalid/kakao.png",
        thumbnail_image_url: "https://images.example.invalid/kakao-thumb.png",
      },
    },
    originalApplicationField: { retained: true },
  };
}

function email(original: Row) {
  return (original.kakao_account as Row).email;
}

function image(original: Row) {
  return ((original.kakao_account as Row).profile as Row).profile_image_url;
}

async function callback(
  ctx: ScenarioContext,
  mode: FixtureProfile = "social-kakao-default",
  requestSignUp = false,
) {
  const actor = ctx.actor("kakao", mode);
  const start = await actor.client.signIn.social({
    provider: "kakao",
    callbackURL: "/dashboard",
    requestSignUp,
  });
  expect(start.error).toBeNull();

  const url = new URL(start.data!.url!);
  const path =
    authProfilePath(mode) +
    `/callback/kakao?code=fixture-code&state=${encodeURIComponent(url.searchParams.get("state")!)}`;
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
    `kakao published ${mode} authorization retains ordered scopes while omitting PKCE`,
    async (ctx) => {
      const other = await foreign(ctx);
      const fixture: FixtureProfile = `social-kakao-${mode}`;
      const result = await ctx.actor("kakao", fixture).client.signIn.social({
        provider: "kakao",
        callbackURL: "/dashboard",
        scopes: ["requested-scope", "account_email"],
        loginHint: "ignored@example.invalid",
        additionalParams: { custom: "value with space" },
      });
      expect(result.error).toBeNull();

      const url = new URL(result.data!.url!);
      const configured = ["configured", "disabled-configured"].includes(mode);
      expect(url.origin).toBe(
        mode === "configured-endpoint"
          ? "https://alternate-kakao.example.invalid"
          : "https://kauth.kakao.com",
      );
      expect(url.pathname).toBe(mode === "configured-endpoint" ? "/authorize" : "/oauth/authorize");

      const scopes = [
        ...(mode.startsWith("disabled-")
          ? []
          : ["account_email", "profile_image", "profile_nickname"]),
        ...(configured ? ["friends", "account_email", "punctuation !~*'()"] : []),
        "requested-scope",
        "account_email",
      ];
      expect(url.searchParams.getAll("scope")).toEqual([scopes.join(" ")]);
      expect(result.data!.url).toContain(
        `scope=${new URLSearchParams({ scope: scopes.join(" ") }).toString().slice(6)}`,
      );
      expect(url.searchParams.getAll("client_id")).toEqual(["fixture-social-client"]);
      expect(url.searchParams.get("response_type")).toBe("code");
      expect(url.searchParams.getAll("state")).toHaveLength(1);
      expect(url.searchParams.get("state")).not.toBe("stale");
      expect(url.searchParams.has("code_challenge_method")).toBeFalse();
      expect(url.searchParams.has("code_challenge")).toBeFalse();
      expect(url.searchParams.has("login_hint")).toBeFalse();
      expect(url.searchParams.get("custom")).toBe("value with space");
      expect(url.searchParams.get("redirect_uri")).toBe(
        mode === "configured-endpoint"
          ? "https://client.example.invalid/kakao-return"
          : ctx.baseURL + authProfilePath(fixture) + "/callback/kakao",
      );

      if (mode === "configured-endpoint") {
        expect(url.searchParams.get("retained")).toBe("value");
      }

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
    `kakao ${mode} real secret or public exchange and GET profile refresh replay and local logout preserve foreign authority`,
    async (ctx) => {
      const other = await foreign(ctx);
      const original = profile(ctx);
      await control(ctx, { profile: original });
      const fixture: FixtureProfile = `social-kakao-${mode}`;
      const flow = await callback(ctx, fixture);
      expect(flow.response.status).toBe(302);
      expect(flow.response.headers.get("location")).toBe("/dashboard");

      const session = await flow.actor.client.getSession();
      const after = await state(ctx);
      expect(session.error).toBeNull();

      unchangedForeign(other.before, after);

      for (const table of ["users", "accounts", "sessions"] as const) {
        expect(after[table]).toHaveLength(other.before[table].length + 1);
      }

      const user = after.users.find((row) => !other.before.users.some((old) => old.id === row.id))!;
      const account = after.accounts.find((row) => row.userId === user.id)!;
      expect(user).toMatchObject({
        name: mode === "mapped" ? "Mapped Kakao User" : "Kakao User",
        email: mode === "mapped" ? "mapped-kakao@example.invalid" : email(original),
        emailVerified: mode !== "mapped",
        image:
          mode === "mapped" ? "https://images.example.invalid/mapped-kakao.png" : image(original),
      });
      expect(account).toMatchObject({
        providerId: "kakao",
        accountId: String(original.id),
        accessToken: "fixture-kakao-access",
        refreshToken: "fixture-kakao-refresh",
        scope: "account_email,profile_image,profile_nickname",
        idToken: null,
      });
      expect(account.accessTokenExpiresAt).toBeTruthy();
      expect(session.data?.user.id).toBe(user.id);

      const raw = (await ctx.rawRequest({ path: "/__test/kakao/receipts" })).body as Receipt[];
      const exchange = raw[0]!.body as Record<string, string>;
      expect(exchange).toEqual({
        grant_type: "authorization_code",
        code: "fixture-code",
        client_id: "fixture-social-client",
        ...(mode === "public" ? {} : { client_secret: "fixture-social-secret" }),
        ...(mode === "client-key" ? { client_key: "fixture-kakao-client-key" } : {}),
        redirect_uri:
          mode === "configured-endpoint"
            ? "https://client.example.invalid/kakao-return"
            : ctx.baseURL + authProfilePath(fixture) + "/callback/kakao",
      });
      expect(flow.url.searchParams.has("code_challenge")).toBeFalse();
      expect(raw[0]!.authorization).toBeNull();
      expect(raw[1]).toEqual({
        path: "/userinfo",
        method: "GET",
        authorization: "Bearer fixture-kakao-access",
        contentType: null,
        body: "",
      });

      const mapper = (await ctx.rawRequest({ path: "/__test/kakao/mapper-receipts" })).body;
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
          access_token: "fixture-kakao-access-rotated",
          refresh_token: "fixture-kakao-refresh-rotated",
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
        accountId: String(original.id),
        userId: user.id,
        accessToken: "fixture-kakao-access-rotated",
        refreshToken: "fixture-kakao-refresh-rotated",
        scope: account.scope,
      });

      const requests = await receipts(ctx);
      expect(requests[2]!.body).toEqual({
        grant_type: "refresh_token",
        refresh_token: "fixture-kakao-refresh",
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
  nickname?: unknown;
  accountName?: unknown;
  primaryImage?: unknown;
  thumbnail?: unknown;
  valid?: unknown;
  verified?: unknown;
  id?: unknown;
  expectedName?: string;
  expectedImage?: string | null;
  expectedSubject?: string;
  expectedVerified?: boolean;
}> = [
  { name: "numeric nickname", nickname: 7, expectedName: "7" },
  { name: "empty nickname", nickname: "", expectedName: "Kakao Account" },
  { name: "null nickname", nickname: null, expectedName: "Kakao Account" },
  { name: "missing nickname", nickname: undefined, expectedName: "Kakao Account" },
  { name: "zero nickname", nickname: 0, expectedName: "Kakao Account" },
  { name: "false nickname", nickname: false, expectedName: "Kakao Account" },
  { name: "empty nickname and account", nickname: "", accountName: "", expectedName: "" },
  {
    name: "missing nickname and account",
    nickname: undefined,
    accountName: undefined,
    expectedName: "",
  },
  { name: "numeric account name", nickname: null, accountName: 7, expectedName: "7" },
  { name: "numeric image", primaryImage: 7, expectedImage: "7" },
  {
    name: "empty image",
    primaryImage: "",
    expectedImage: "https://images.example.invalid/kakao-thumb.png",
  },
  {
    name: "null image",
    primaryImage: null,
    expectedImage: "https://images.example.invalid/kakao-thumb.png",
  },
  {
    name: "missing image",
    primaryImage: undefined,
    expectedImage: "https://images.example.invalid/kakao-thumb.png",
  },
  {
    name: "false image",
    primaryImage: false,
    expectedImage: "https://images.example.invalid/kakao-thumb.png",
  },
  {
    name: "zero image",
    primaryImage: 0,
    expectedImage: "https://images.example.invalid/kakao-thumb.png",
  },
  { name: "empty both images", primaryImage: "", thumbnail: "", expectedImage: "" },
  {
    name: "missing both images",
    primaryImage: undefined,
    thumbnail: undefined,
    expectedImage: null,
  },
  { name: "numeric thumbnail", primaryImage: null, thumbnail: 7, expectedImage: "7" },
  { name: "string raw subject", id: "raw-kakao-subject", expectedSubject: "raw-kakao-subject" },
  { name: "invalid email", valid: false, expectedVerified: false },
  { name: "missing valid email", valid: undefined, expectedVerified: false },
  { name: "null valid email", valid: null, expectedVerified: false },
  { name: "zero valid email", valid: 0, expectedVerified: false },
  { name: "unverified email", verified: false, expectedVerified: false },
  { name: "missing verified email", verified: undefined, expectedVerified: false },
  { name: "null verified email", verified: null, expectedVerified: false },
  { name: "empty verified email", verified: "", expectedVerified: false },
  { name: "truthy numeric email flags", valid: 1, verified: 1, expectedVerified: true },
];

for (const mapping of mappings) {
  compatScenario(
    `kakao ${mapping.name} nested profile retains original raw account and typed persistence`,
    async (ctx) => {
      const other = await foreign(ctx);
      const original = profile(ctx);
      const accountProfile = original.kakao_account as Row;
      const nested = accountProfile.profile as Row;

      if ("nickname" in mapping) {
        nested.nickname = mapping.nickname;
      }

      if ("accountName" in mapping) {
        accountProfile.name = mapping.accountName;
      }

      if ("primaryImage" in mapping) {
        nested.profile_image_url = mapping.primaryImage;
      }

      if ("thumbnail" in mapping) {
        nested.thumbnail_image_url = mapping.thumbnail;
      }

      if ("valid" in mapping) {
        accountProfile.is_email_valid = mapping.valid;
      }

      if ("verified" in mapping) {
        accountProfile.is_email_verified = mapping.verified;
      }

      if ("id" in mapping) {
        original.id = mapping.id;
      }

      await control(ctx, { profile: original });
      const flow = await callback(ctx);
      expect(flow.response.headers.get("location")).toBe("/dashboard");

      const stored = await state(ctx);
      unchangedForeign(other.before, stored);
      const user = stored.users.find(
        (row) => !other.before.users.some((old) => old.id === row.id),
      )!;
      const account = stored.accounts.find((row) => row.userId === user.id)!;
      expect(user).toMatchObject({
        name: mapping.expectedName ?? "Kakao User",
        email: email(original),
        emailVerified: mapping.expectedVerified ?? true,
        image: mapping.expectedImage === undefined ? image(original) : mapping.expectedImage,
      });
      expect(account.accountId).toBe(mapping.expectedSubject ?? String(original.id));
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
}

for (const expiry of ["absent", "zero", "fractional"] as const) {
  compatScenario(
    `kakao ${expiry} access expiry follows actual token helper`,
    async (ctx) => {
      await control(ctx, {
        profile: profile(ctx),
        tokenResponse: {
          access_token: "fixture-kakao-access",
          refresh_token: "fixture-kakao-refresh",
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
  "userinfo-http-error",
  "missing-subject",
  "null-subject",
  "blank-subject",
  "missing-email",
  "signup-disabled",
  "implicit-disabled",
] as const) {
  compatScenario(
    `kakao browser ${variant} denies before any owned or foreign identity write`,
    async (ctx) => {
      const other = await foreign(ctx);
      const original = profile(ctx);

      if (variant === "missing-subject") {
        delete original.id;
      }

      if (variant === "null-subject") {
        original.id = null;
      }

      if (variant === "blank-subject") {
        original.id = " ";
      }

      if (variant === "missing-email") {
        delete (original.kakao_account as Row).email;
      }

      await control(ctx, {
        profile: original,
        ...(variant === "token-http-error" ? { tokenStatus: 503 } : {}),
        ...(variant === "userinfo-http-error" ? { userInfoStatus: 503 } : {}),
      });
      const fixture: FixtureProfile =
        variant === "signup-disabled"
          ? "social-kakao-signup-disabled"
          : variant === "implicit-disabled"
            ? "social-kakao-implicit-disabled"
            : "social-kakao-default";
      const actor = ctx.actor("kakao", fixture);
      const start = await actor.client.signIn.social({
        provider: "kakao",
        callbackURL: "/dashboard",
        requestSignUp: variant === "signup-disabled",
      });
      expect(start.error).toBeNull();

      const url = new URL(start.data!.url!);
      const callbackState =
        variant === "wrong-state" ? ctx.uniqueToken("wrong-state") : url.searchParams.get("state")!;
      const provider = variant === "wrong-provider" ? "unknown-kakao" : "kakao";
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
}

compatScenario(
  "kakao disabled default scope omits an empty scope parameter",
  async (ctx) => {
    const before = await state(ctx);
    const result = await ctx
      .actor("kakao", "social-kakao-disabled-scope")
      .client.signIn.social({ provider: "kakao" });
    expect(result.error).toBeNull();
    expect(new URL(result.data!.url!).searchParams.has("scope")).toBeFalse();
    expect(await state(ctx)).toEqual(before);
    expect(await receipts(ctx)).toEqual([]);

    return { result: ctx.snapshot(result), before, after: await state(ctx) };
  },
  ["POST /sign-in/social"],
);

compatScenario(
  "kakao explicit signup overrides implicit signup policy",
  async (ctx) => {
    await control(ctx, { profile: profile(ctx) });
    const flow = await callback(ctx, "social-kakao-implicit-disabled", true);
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

compatScenario(
  "kakao rejects direct ID-token sign-in without remote verification or identity writes",
  async (ctx) => {
    const other = await foreign(ctx);
    const result = await ctx
      .actor("kakao", "social-kakao-default")
      .client.signIn.social({ provider: "kakao", idToken: { token: "unsupported-proof" } });
    expect(result.error?.code).toBe("ID_TOKEN_NOT_SUPPORTED");
    expect(await state(ctx)).toEqual(other.before);
    expect(await receipts(ctx)).toEqual([]);

    return { result: ctx.snapshot(result), before: other.before, after: await state(ctx) };
  },
);

for (const mode of ["empty-clients"] as const) {
  compatScenario(`kakao ${mode} requires a real client before identity writes`, async (ctx) => {
    const other = await foreign(ctx);
    const result = await ctx
      .actor("kakao", `social-kakao-${mode}`)
      .client.signIn.social({ provider: "kakao" });
    expect(result.error?.status).toBe(500);
    expect(await state(ctx)).toEqual(other.before);
    expect(await receipts(ctx)).toEqual([]);

    return { result: ctx.snapshot(result), before: other.before, after: await state(ctx) };
  });
}

for (const valid of [true, false]) {
  compatScenario(
    `kakao explicit browser link ${valid ? "admits raw account" : "rejects missing raw account"} while retaining the existing principal`,
    async (ctx) => {
      const other = await foreign(ctx);
      const actor = ctx.actor("kakao", "social-kakao-default");
      const email = ctx.uniqueEmail("kakao-link");
      const signup = await actor.client.signUp.email({
        email,
        password: "Password123!",
        name: "Existing local user",
      });
      expect(signup.error).toBeNull();

      const before = await state(ctx);
      const original = profile(ctx);
      (original.kakao_account as Row).email = email;

      if (!valid) {
        delete original.id;
      }

      await control(ctx, { profile: original });
      const start = await actor.client.linkSocial({ provider: "kakao", callbackURL: "/linked" });
      expect(start.error).toBeNull();

      const url = new URL(start.data!.url!);
      const path =
        authProfilePath("social-kakao-default") +
        `/callback/kakao?code=fixture-code&state=${encodeURIComponent(url.searchParams.get("state")!)}`;
      const response = await actor.fetch(ctx.baseURL + path, { redirect: "manual" });
      expect(response.status).toBe(302);

      const location = response.headers.get("location")!;
      const after = await state(ctx);
      unchangedForeign(other.before, after);
      expect(after.users).toEqual(before.users);
      expect(after.sessions).toEqual(before.sessions);

      if (valid) {
        expect(location).toBe("/linked");
        expect(after.accounts).toHaveLength(before.accounts.length + 1);
        expect(after.accounts.find((row) => row.providerId === "kakao")).toMatchObject({
          accountId: String(original.id),
          userId: signup.data!.user.id,
        });
      } else {
        expect(new URL(location, ctx.baseURL).searchParams.get("error")).toBe(
          "unable_to_get_user_info",
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
}

compatScenario(
  "kakao existing account info uses real GET without readmitting a changed raw account subject",
  async (ctx) => {
    const other = await foreign(ctx);
    const original = profile(ctx);
    await control(ctx, { profile: original });
    const flow = await callback(ctx);
    expect(flow.response.headers.get("location")).toBe("/dashboard");

    const before = await state(ctx);
    const user = before.users.find((row) => !other.before.users.some((old) => old.id === row.id))!;
    const account = before.accounts.find((row) => row.userId === user.id)!;
    delete original.id;
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
        name: "Kakao User",
        email: email(original),
        image: image(original),
        emailVerified: true,
      },
      data: original,
      account: { id: account.id, providerId: "kakao", accountId: account.accountId },
    });
    expect(await state(ctx)).toEqual(before);
    expect((await receipts(ctx))[2]).toEqual({
      path: "/userinfo",
      method: "GET",
      authorization: "Bearer fixture-kakao-access",
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
