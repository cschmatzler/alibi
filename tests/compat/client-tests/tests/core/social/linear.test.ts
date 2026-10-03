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
    path: "/__test/linear/control",
    method: "POST",
    json: value,
  });
  expect(response.status).toBe(200);
}
function assertGraphQL(receipt: Receipt | undefined) {
  expect(receipt).toBeDefined();
  expect(receipt).toMatchObject({
    path: "/userinfo",
    method: "POST",
    authorization: "Bearer fixture-linear-access",
    contentType: "application/json",
  });
  expect(typeof receipt!.body).toBe("object");
  const body = receipt!.body as Record<string, string>;
  expect(Object.keys(body)).toEqual(["query"]);
  expect(body.query!.replace(/\s+/g, " ").trim()).toBe(
    "query { viewer { id name email avatarUrl active createdAt updatedAt } }",
  );
}
async function receipts(ctx: ScenarioContext) {
  const response = await ctx.rawRequest({ path: "/__test/linear/receipts" });
  expect(response.status).toBe(200);
  return response.body as Receipt[];
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
    id: ctx.uniqueToken("linear-subject"),
    name: "Linear User",
    email: ctx.uniqueEmail("linear"),
    active: true,
    createdAt: "2020-01-01T00:00:00.000Z",
    updatedAt: "2020-01-02T00:00:00.000Z",
    avatarUrl: "https://images.example.invalid/linear.png",
    originalApplicationField: { retained: true },
  };
}
async function callback(
  ctx: ScenarioContext,
  mode: FixtureProfile = "social-linear-default",
  requestSignUp = false,
) {
  const actor = ctx.actor("linear", mode);
  const start = await actor.client.signIn.social({
    provider: "linear",
    callbackURL: "/dashboard",
    requestSignUp,
  });
  expect(start.error).toBeNull();
  const url = new URL(start.data!.url!);
  const path =
    authProfilePath(mode) +
    `/callback/linear?code=fixture-code&state=${encodeURIComponent(url.searchParams.get("state")!)}`;
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
    `linear published ${mode} authorization retains ordered scopes and absent PKCE`,
    async (ctx) => {
      const other = await foreign(ctx);
      const fixture: FixtureProfile = `social-linear-${mode}`;
      const result = await ctx.actor("linear", fixture).client.signIn.social({
        provider: "linear",
        callbackURL: "/dashboard",
        scopes: ["requested-scope", "read"],
        loginHint: "ignored@example.invalid",
        additionalParams: { custom: "value with space" },
      });
      expect(result.error).toBeNull();
      const url = new URL(result.data!.url!);
      const configured = ["configured", "disabled-configured"].includes(mode);
      expect(url.origin).toBe(
        mode === "configured-endpoint"
          ? "https://alternate-linear.example.invalid"
          : "https://linear.app",
      );
      expect(url.pathname).toBe(mode === "configured-endpoint" ? "/authorize" : "/oauth/authorize");
      const scopes = [
        ...(mode.startsWith("disabled-") ? [] : ["read"]),
        ...(configured ? ["configured-scope", "read", "punctuation !~*'()"] : []),
        "requested-scope",
        "read",
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
      expect(url.searchParams.get("login_hint")).toBe("ignored@example.invalid");
      expect(url.searchParams.get("custom")).toBe("value with space");
      expect(url.searchParams.get("redirect_uri")).toBe(
        mode === "configured-endpoint"
          ? "https://client.example.invalid/linear-return"
          : ctx.baseURL + authProfilePath(fixture) + "/callback/linear",
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
    `linear ${mode} real secret or public exchange and GraphQL viewer refresh replay and local logout preserve foreign authority`,
    async (ctx) => {
      const other = await foreign(ctx);
      const original = profile(ctx);
      await control(ctx, { profile: original });
      const fixture: FixtureProfile = `social-linear-${mode}`;
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
        name: mode === "mapped" ? "Mapped Linear User" : "Linear User",
        email: mode === "mapped" ? "mapped-linear@example.invalid" : original.email,
        emailVerified: mode === "mapped",
        image:
          mode === "mapped"
            ? "https://images.example.invalid/mapped-linear.png"
            : original.avatarUrl,
      });
      expect(account).toMatchObject({
        providerId: "linear",
        accountId: original.id,
        accessToken: "fixture-linear-access",
        refreshToken: "fixture-linear-refresh",
        scope: "read",
        idToken: null,
      });
      expect(account.accessTokenExpiresAt).toBeTruthy();
      expect(session.data?.user.id).toBe(user.id);
      const raw = (await ctx.rawRequest({ path: "/__test/linear/receipts" })).body as Receipt[];
      const exchange = raw[0]!.body as Record<string, string>;
      expect(exchange).toEqual({
        grant_type: "authorization_code",
        code: "fixture-code",
        client_id: "fixture-social-client",
        ...(mode === "public" ? {} : { client_secret: "fixture-social-secret" }),
        ...(mode === "client-key" ? { client_key: "fixture-linear-client-key" } : {}),
        redirect_uri:
          mode === "configured-endpoint"
            ? "https://client.example.invalid/linear-return"
            : ctx.baseURL + authProfilePath(fixture) + "/callback/linear",
      });
      expect(raw[0]!.authorization).toBeNull();
      assertGraphQL(raw[1]);
      const mapper = (await ctx.rawRequest({ path: "/__test/linear/mapper-receipts" })).body;
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
          access_token: "fixture-linear-access-rotated",
          refresh_token: "fixture-linear-refresh-rotated",
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
        accountId: original.id,
        userId: user.id,
        accessToken: "fixture-linear-access-rotated",
        refreshToken: "fixture-linear-refresh-rotated",
        scope: account.scope,
      });
      const requests = await receipts(ctx);
      expect(requests[2]!.body).toEqual({
        grant_type: "refresh_token",
        refresh_token: "fixture-linear-refresh",
        client_id: "fixture-social-client",
        ...(mode === "public" ? {} : { client_secret: "fixture-social-secret" }),
      });
      expect(requests[2]!.authorization).toBeNull();
      let info: unknown;
      if (mode === "mapped") {
        await control(ctx, { profile: original });
        const beforeInfo = await state(ctx);
        const result = await flow.actor.client.$fetch("/account-info", {
          query: { accountId: account.id },
        });
        expect(result.error).toBeNull();
        expect(ctx.snapshot(result.data)).toEqual({
          user: {
            id: "cannot-replace-raw-account",
            name: "Mapped Linear User",
            email: "mapped-linear@example.invalid",
            emailVerified: true,
            image: "https://images.example.invalid/mapped-linear.png",
            linearPublic: { source: original.id, scopes: ["read"] },
          },
          data: original,
          account: { id: account.id, providerId: "linear", accountId: original.id },
        });
        expect(user).not.toHaveProperty("linearPublic");
        expect(await state(ctx)).toEqual(beforeInfo);
        const observed = (await receipts(ctx))[3];
        expect(observed).toMatchObject({
          path: "/userinfo",
          method: "POST",
          authorization: "Bearer fixture-linear-access-rotated",
          contentType: "application/json",
        });
        expect((observed!.body as Record<string, string>).query).toBe(
          (raw[1]!.body as Record<string, string>).query,
        );
        info = {
          result: ctx.snapshot(result),
          before: beforeInfo,
          after: await state(ctx),
          mapper: (await ctx.rawRequest({ path: "/__test/linear/mapper-receipts" })).body,
        };
      }
      const beforeLogoutRequests = await receipts(ctx);
      const signedOut = await flow.actor.client.signOut();
      expect(signedOut.error).toBeNull();
      expect((await flow.actor.client.getSession()).data).toBeNull();
      const final = await state(ctx);
      expect(final.users).toEqual(rotated.users);
      expect(final.accounts).toEqual(rotated.accounts);
      unchangedForeign(other.before, final);
      expect(final.sessions).toEqual(other.before.sessions);
      expect(await receipts(ctx)).toEqual(beforeLogoutRequests);
      return {
        before: other.before,
        start: ctx.snapshot(flow.start),
        callback: { status: flow.response.status, location: flow.response.headers.get("location") },
        session: ctx.snapshot(session),
        after,
        mapper,
        info,
        denied: ctx.snapshot(denied),
        refreshed: ctx.snapshot(refreshed),
        rotated,
        signedOut: ctx.snapshot(signedOut),
        final,
        receipts: beforeLogoutRequests,
      };
    },
    [
      "POST /sign-in/social",
      "GET /callback/{}",
      "POST /refresh-token",
      "POST /sign-out",
      "GET /account-info",
    ],
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
  {
    name: "numeric subject",
    patch: { id: 42 },
    expectedName: "Linear User",
    expectedSubject: "42",
  },
  {
    name: "missing image",
    patch: { avatarUrl: undefined },
    expectedName: "Linear User",
    expectedImage: null,
  },
  {
    name: "null image",
    patch: { avatarUrl: null },
    expectedName: "Linear User",
    expectedImage: null,
  },
  { name: "empty image", patch: { avatarUrl: "" }, expectedName: "Linear User", expectedImage: "" },
  {
    name: "numeric image",
    patch: { avatarUrl: 7 },
    expectedName: "Linear User",
    expectedImage: "7",
  },
];
for (const mapping of mappings) {
  compatScenario(
    `linear ${mapping.name} GraphQL viewer retains original raw account and typed persistence`,
    async (ctx) => {
      const other = await foreign(ctx);
      const original = { ...profile(ctx), ...mapping.patch };
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
        name: mapping.expectedName,
        email: original.email,
        emailVerified: false,
        image: mapping.expectedImage === undefined ? original.avatarUrl : mapping.expectedImage,
      });
      expect(account.accountId).toBe(mapping.expectedSubject ?? original.id);
      expect((await flow.actor.client.getSession()).data?.user.id).toBe(user.id);
      const info = await flow.actor.client.$fetch("/account-info", {
        query: { accountId: account.id },
      });
      expect(info.error).toBeNull();
      const published = Object.fromEntries(
        [
          ["name", "name"],
          ["email", "email"],
          ["avatarUrl", "image"],
        ]
          .filter(([key]) => original[key!] !== undefined)
          .map(([key, target]) => [target, original[key!]]),
      );
      expect(ctx.snapshot(info.data)).toEqual({
        user: { ...published, emailVerified: false },
        data: JSON.parse(JSON.stringify(original)),
        account: { id: account.id, providerId: "linear", accountId: account.accountId },
      });
      expect(await state(ctx)).toEqual(stored);
      assertGraphQL((await receipts(ctx))[2]);
      return {
        before: other.before,
        start: ctx.snapshot(flow.start),
        callback: { status: flow.response.status, location: flow.response.headers.get("location") },
        stored,
        info: ctx.snapshot(info),
        receipts: await receipts(ctx),
      };
    },
    ["POST /sign-in/social", "GET /callback/{}", "GET /account-info"],
  );
}

for (const expiry of ["absent", "zero", "fractional"] as const) {
  compatScenario(
    `linear ${expiry} access expiry follows actual token helper`,
    async (ctx) => {
      await control(ctx, {
        profile: profile(ctx),
        tokenResponse: {
          access_token: "fixture-linear-access",
          refresh_token: "fixture-linear-refresh",
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
    `linear browser ${variant} denies before any owned or foreign identity write`,
    async (ctx) => {
      const other = await foreign(ctx);
      const original = profile(ctx);
      if (variant === "missing-subject") delete original.id;
      if (variant === "null-subject") original.id = null;
      if (variant === "blank-subject") original.id = " ";
      if (variant === "missing-email") delete original.email;
      await control(ctx, {
        profile: original,
        ...(variant === "token-http-error" ? { tokenStatus: 503 } : {}),
        ...(variant === "userinfo-http-error" ? { userInfoStatus: 503 } : {}),
      });
      const fixture: FixtureProfile =
        variant === "signup-disabled"
          ? "social-linear-signup-disabled"
          : variant === "implicit-disabled"
            ? "social-linear-implicit-disabled"
            : "social-linear-default";
      const actor = ctx.actor("linear", fixture);
      const start = await actor.client.signIn.social({
        provider: "linear",
        callbackURL: "/dashboard",
        requestSignUp: variant === "signup-disabled",
      });
      expect(start.error).toBeNull();
      const url = new URL(start.data!.url!);
      const callbackState =
        variant === "wrong-state" ? ctx.uniqueToken("wrong-state") : url.searchParams.get("state")!;
      const provider = variant === "wrong-provider" ? "unknown-linear" : "linear";
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
  "linear disabled default scope omits an empty scope parameter",
  async (ctx) => {
    const before = await state(ctx);
    const result = await ctx
      .actor("linear", "social-linear-disabled-scope")
      .client.signIn.social({ provider: "linear" });
    expect(result.error).toBeNull();
    expect(new URL(result.data!.url!).searchParams.has("scope")).toBeFalse();
    expect(await state(ctx)).toEqual(before);
    expect(await receipts(ctx)).toEqual([]);
    return { result: ctx.snapshot(result), before, after: await state(ctx) };
  },
  ["POST /sign-in/social"],
);
compatScenario(
  "linear explicit signup overrides implicit signup policy",
  async (ctx) => {
    await control(ctx, { profile: profile(ctx) });
    const flow = await callback(ctx, "social-linear-implicit-disabled", true);
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
  "linear rejects direct ID-token sign-in without remote verification or identity writes",
  async (ctx) => {
    const other = await foreign(ctx);
    const result = await ctx
      .actor("linear", "social-linear-default")
      .client.signIn.social({ provider: "linear", idToken: { token: "unsupported-proof" } });
    expect(result.error?.code).toBe("ID_TOKEN_NOT_SUPPORTED");
    expect(await state(ctx)).toEqual(other.before);
    expect(await receipts(ctx)).toEqual([]);
    return { result: ctx.snapshot(result), before: other.before, after: await state(ctx) };
  },
);
for (const mode of ["empty-clients"] as const) {
  compatScenario(`linear ${mode} requires a real client before identity writes`, async (ctx) => {
    const other = await foreign(ctx);
    const result = await ctx
      .actor("linear", `social-linear-${mode}`)
      .client.signIn.social({ provider: "linear" });
    expect(result.error?.status).toBe(500);
    expect(await state(ctx)).toEqual(other.before);
    expect(await receipts(ctx)).toEqual([]);
    return { result: ctx.snapshot(result), before: other.before, after: await state(ctx) };
  });
}

for (const variant of ["default-unverified", "mapped-verified", "missing-raw"] as const) {
  compatScenario(
    `linear explicit browser link ${variant} retains existing and foreign authority`,
    async (ctx) => {
      const other = await foreign(ctx);
      const fixture =
        variant === "default-unverified" ? "social-linear-default" : "social-linear-mapped";
      const actor = ctx.actor("linear", fixture);
      const email =
        variant === "default-unverified"
          ? ctx.uniqueEmail("linear-link")
          : "mapped-linear@example.invalid";
      const signup = await actor.client.signUp.email({
        email,
        password: "Password123!",
        name: "Existing local user",
      });
      expect(signup.error).toBeNull();
      const before = await state(ctx);
      const original: Row = { ...profile(ctx), email };
      if (variant === "missing-raw") delete original.id;
      await control(ctx, { profile: original });
      const start = await actor.client.linkSocial({ provider: "linear", callbackURL: "/linked" });
      expect(start.error).toBeNull();
      const url = new URL(start.data!.url!);
      const path =
        authProfilePath(fixture) +
        `/callback/linear?code=fixture-code&state=${encodeURIComponent(url.searchParams.get("state")!)}`;
      const response = await actor.fetch(ctx.baseURL + path, { redirect: "manual" });
      expect(response.status).toBe(302);
      const location = response.headers.get("location")!;
      const after = await state(ctx);
      unchangedForeign(other.before, after);
      expect(after.users).toEqual(before.users);
      expect(after.sessions).toEqual(before.sessions);
      if (variant === "mapped-verified") {
        expect(location).toBe("/linked");
        expect(after.accounts).toHaveLength(before.accounts.length + 1);
        expect(after.accounts.find((row) => row.providerId === "linear")).toMatchObject({
          accountId: original.id,
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
}

compatScenario(
  "linear existing account info uses real GraphQL POST without readmitting a changed raw account subject",
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
    expect(ctx.snapshot(result.data)).toEqual({
      user: {
        name: "Linear User",
        email: original.email,
        image: original.avatarUrl,
        emailVerified: false,
      },
      data: original,
      account: { id: account.id, providerId: "linear", accountId: account.accountId },
    });
    expect(await state(ctx)).toEqual(before);
    assertGraphQL((await receipts(ctx))[2]);
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

for (const variant of ["inactive", "partial-errors"] as const) {
  compatScenario(
    `linear GraphQL ${variant} preserves declared viewer mapping and raw admission`,
    async (ctx) => {
      const other = await foreign(ctx);
      const original: Row = { ...profile(ctx), active: variant !== "inactive" };
      await control(ctx, {
        envelope: {
          data: { viewer: original },
          ...(variant === "partial-errors"
            ? { errors: [{ message: "Unrelated field failure", path: ["unselectedField"] }] }
            : {}),
        },
      });
      const flow = await callback(ctx);
      expect(flow.response.headers.get("location")).toBe("/dashboard");
      const after = await state(ctx);
      unchangedForeign(other.before, after);
      const account = after.accounts.find((row) => row.providerId === "linear")!;
      const user = after.users.find((row) => row.id === account.userId)!;
      expect(account.accountId).toBe(original.id);
      expect(user).toMatchObject({
        name: original.name,
        email: original.email,
        emailVerified: false,
        image: original.avatarUrl,
      });
      expect((await flow.actor.client.getSession()).data?.user.id).toBe(user.id);
      assertGraphQL((await receipts(ctx))[1]);
      return {
        before: other.before,
        start: ctx.snapshot(flow.start),
        callback: { status: flow.response.status, location: flow.response.headers.get("location") },
        after,
        receipts: await receipts(ctx),
      };
    },
    ["POST /sign-in/social", "GET /callback/{}"],
  );
}
for (const envelope of [{}, { data: null }, { data: {} }, { data: { viewer: null } }]) {
  compatScenario(
    `linear missing GraphQL viewer ${JSON.stringify(envelope)} rejects before mapper or identity writes`,
    async (ctx) => {
      const other = await foreign(ctx);
      await control(ctx, { envelope });
      const flow = await callback(ctx, "social-linear-mapped");
      expect(
        new URL(flow.response.headers.get("location")!, ctx.baseURL).searchParams.get("error"),
      ).toBe("unable_to_get_user_info");
      expect(await state(ctx)).toEqual(other.before);
      expect((await ctx.rawRequest({ path: "/__test/linear/mapper-receipts" })).body).toEqual([]);
      expect((await receipts(ctx)).map((row) => row.path)).toEqual(["/token", "/userinfo"]);
      assertGraphQL((await receipts(ctx))[1]);
      return {
        before: other.before,
        start: ctx.snapshot(flow.start),
        callback: { status: flow.response.status, location: flow.response.headers.get("location") },
        after: await state(ctx),
        mapper: (await ctx.rawRequest({ path: "/__test/linear/mapper-receipts" })).body,
        receipts: await receipts(ctx),
      };
    },
    ["GET /callback/{}"],
  );
}

compatScenario(
  "linear truthy nonobject GraphQL viewer invokes original mapper before raw identity denial",
  async (ctx) => {
    const other = await foreign(ctx);
    const viewer: unknown[] = [];
    await control(ctx, { envelope: { data: { viewer } } });
    const flow = await callback(ctx, "social-linear-mapped");
    expect(flow.response.status).toBe(302);
    const location = flow.response.headers.get("location")!;
    expect(new URL(location, ctx.baseURL).searchParams.get("error")).toBe(
      "unable_to_get_user_info",
    );
    expect(await state(ctx)).toEqual(other.before);
    const mapper = (await ctx.rawRequest({ path: "/__test/linear/mapper-receipts" })).body;
    expect(mapper).toEqual([viewer]);
    const requests = await receipts(ctx);
    expect(requests.map((row) => row.path)).toEqual(["/token", "/userinfo"]);
    assertGraphQL(requests[1]);
    expect((await flow.actor.client.getSession()).data).toBeNull();
    return {
      before: other.before,
      start: ctx.snapshot(flow.start),
      callback: { status: flow.response.status, location },
      after: await state(ctx),
      mapper,
      receipts: requests,
    };
  },
  ["GET /callback/{}"],
);
