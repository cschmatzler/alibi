import { expect } from "bun:test";
import { authProfilePath, type FixtureProfile } from "../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../support/scenario";

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
    path: "/__test/kick/control",
    method: "POST",
    json: value,
  });
  expect(response.status).toBe(200);
}
async function receipts(ctx: ScenarioContext) {
  const response = await ctx.rawRequest({ path: "/__test/kick/receipts" });
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
    user_id: ctx.uniqueToken("kick-subject"),
    name: "Kick User",
    email: ctx.uniqueEmail("kick"),
    email_verified: true,
    profile_picture: "https://images.example.invalid/kick.png",
    originalApplicationField: { retained: true },
  };
}
async function callback(
  ctx: ScenarioContext,
  mode: FixtureProfile = "social-kick-default",
  requestSignUp = false,
) {
  const actor = ctx.actor("kick", mode),
    start = await actor.client.signIn.social({
      provider: "kick",
      callbackURL: "/dashboard",
      requestSignUp,
    });
  expect(start.error).toBeNull();
  const url = new URL(start.data!.url!),
    path =
      authProfilePath(mode) +
      `/callback/kick?code=fixture-code&state=${encodeURIComponent(url.searchParams.get("state")!)}`;
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
    `kick published ${mode} authorization retains ordered scopes and required PKCE`,
    async (ctx) => {
      const other = await foreign(ctx),
        fixture: FixtureProfile = `social-kick-${mode}`;
      const result = await ctx.actor("kick", fixture).client.signIn.social({
        provider: "kick",
        callbackURL: "/dashboard",
        scopes: ["requested-scope", "user:read"],
        loginHint: "ignored@example.invalid",
        additionalParams: { custom: "value with space" },
      });
      expect(result.error).toBeNull();
      const url = new URL(result.data!.url!),
        configured = ["configured", "disabled-configured"].includes(mode);
      expect(url.origin).toBe(
        mode === "configured-endpoint"
          ? "https://alternate-kick.example.invalid"
          : "https://id.kick.com",
      );
      expect(url.pathname).toBe(mode === "configured-endpoint" ? "/authorize" : "/oauth/authorize");
      const scopes = [
        ...(mode.startsWith("disabled-") ? [] : ["user:read"]),
        ...(configured ? ["channel:read", "user:read", "punctuation !~*'()"] : []),
        "requested-scope",
        "user:read",
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
      expect(url.searchParams.has("login_hint")).toBeFalse();
      expect(url.searchParams.get("custom")).toBe("value with space");
      expect(url.searchParams.get("redirect_uri")).toBe(
        mode === "configured-endpoint"
          ? "https://client.example.invalid/kick-return"
          : ctx.baseURL + authProfilePath(fixture) + "/callback/kick",
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
    `kick ${mode} real secret or public exchange and GET profile refresh replay and local logout preserve foreign authority`,
    async (ctx) => {
      const other = await foreign(ctx),
        original = profile(ctx);
      await control(ctx, { profile: original });
      const fixture: FixtureProfile = `social-kick-${mode}`,
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
        name: mode === "mapped" ? "Mapped Kick User" : "Kick User",
        email: mode === "mapped" ? "mapped-kick@example.invalid" : original.email,
        emailVerified: mode === "mapped",
        image:
          mode === "mapped"
            ? "https://images.example.invalid/mapped-kick.png"
            : original.profile_picture,
      });
      expect(account).toMatchObject({
        providerId: "kick",
        accountId: original.user_id,
        accessToken: "fixture-kick-access",
        refreshToken: "fixture-kick-refresh",
        scope: "user:read",
        idToken: null,
      });
      expect(account.accessTokenExpiresAt).toBeTruthy();
      expect(session.data?.user.id).toBe(user.id);
      const raw = (await ctx.rawRequest({ path: "/__test/kick/receipts" })).body as Receipt[],
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
        ...(mode === "client-key" ? { client_key: "fixture-kick-client-key" } : {}),
        redirect_uri:
          mode === "configured-endpoint"
            ? "https://client.example.invalid/kick-return"
            : ctx.baseURL + authProfilePath(fixture) + "/callback/kick",
      });
      expect(raw[0]!.authorization).toBeNull();
      expect(raw[1]).toEqual({
        path: "/userinfo",
        method: "GET",
        authorization: "Bearer fixture-kick-access",
        contentType: null,
        body: "",
      });
      const mapper = (await ctx.rawRequest({ path: "/__test/kick/mapper-receipts" })).body;
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
          access_token: "fixture-kick-access-rotated",
          refresh_token: "fixture-kick-refresh-rotated",
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
        accountId: original.user_id,
        userId: user.id,
        accessToken: "fixture-kick-access-rotated",
        refreshToken: "fixture-kick-refresh-rotated",
        scope: account.scope,
      });
      const requests = await receipts(ctx);
      expect(requests[2]!.body).toEqual({
        grant_type: "refresh_token",
        refresh_token: "fixture-kick-refresh",
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
  {
    name: "numeric subject",
    patch: { user_id: 42 },
    expectedName: "Kick User",
    expectedSubject: "42",
  },
  {
    name: "missing image",
    patch: { profile_picture: undefined },
    expectedName: "Kick User",
    expectedImage: null,
  },
  {
    name: "null image",
    patch: { profile_picture: null },
    expectedName: "Kick User",
    expectedImage: null,
  },
  {
    name: "empty image",
    patch: { profile_picture: "" },
    expectedName: "Kick User",
    expectedImage: "",
  },
  {
    name: "numeric image",
    patch: { profile_picture: 7 },
    expectedName: "Kick User",
    expectedImage: "7",
  },
];
for (const mapping of mappings)
  compatScenario(
    `kick ${mapping.name} first envelope profile retains original raw account and typed persistence`,
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
        image:
          mapping.expectedImage === undefined ? original.profile_picture : mapping.expectedImage,
      });
      expect(account.accountId).toBe(mapping.expectedSubject ?? original.user_id);
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
    `kick ${expiry} access expiry follows actual token helper`,
    async (ctx) => {
      await control(ctx, {
        profile: profile(ctx),
        tokenResponse: {
          access_token: "fixture-kick-access",
          refresh_token: "fixture-kick-refresh",
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
    `kick browser ${variant} denies before any owned or foreign identity write`,
    async (ctx) => {
      const other = await foreign(ctx),
        original = profile(ctx);
      if (variant === "missing-subject") delete original.user_id;
      if (variant === "null-subject") original.user_id = null;
      if (variant === "blank-subject") original.user_id = " ";
      if (variant === "missing-email") delete original.email;
      await control(ctx, {
        profile: original,
        ...(variant === "token-http-error" ? { tokenStatus: 503 } : {}),
        ...(variant === "userinfo-http-error" ? { userInfoStatus: 503 } : {}),
      });
      const fixture: FixtureProfile =
          variant === "signup-disabled"
            ? "social-kick-signup-disabled"
            : variant === "implicit-disabled"
              ? "social-kick-implicit-disabled"
              : "social-kick-default",
        actor = ctx.actor("kick", fixture),
        start = await actor.client.signIn.social({
          provider: "kick",
          callbackURL: "/dashboard",
          requestSignUp: variant === "signup-disabled",
        });
      expect(start.error).toBeNull();
      const url = new URL(start.data!.url!),
        callbackState =
          variant === "wrong-state"
            ? ctx.uniqueToken("wrong-state")
            : url.searchParams.get("state")!,
        provider = variant === "wrong-provider" ? "unknown-kick" : "kick",
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
  "kick disabled default scope omits an empty scope parameter",
  async (ctx) => {
    const before = await state(ctx),
      result = await ctx
        .actor("kick", "social-kick-disabled-scope")
        .client.signIn.social({ provider: "kick" });
    expect(result.error).toBeNull();
    expect(new URL(result.data!.url!).searchParams.has("scope")).toBeFalse();
    expect(await state(ctx)).toEqual(before);
    expect(await receipts(ctx)).toEqual([]);
    return { result: ctx.snapshot(result), before, after: await state(ctx) };
  },
  ["POST /sign-in/social"],
);
compatScenario(
  "kick explicit signup overrides implicit signup policy",
  async (ctx) => {
    await control(ctx, { profile: profile(ctx) });
    const flow = await callback(ctx, "social-kick-implicit-disabled", true);
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
compatScenario(
  "kick rejects direct ID-token sign-in without remote verification or identity writes",
  async (ctx) => {
    const other = await foreign(ctx),
      result = await ctx
        .actor("kick", "social-kick-default")
        .client.signIn.social({ provider: "kick", idToken: { token: "unsupported-proof" } });
    expect(result.error?.code).toBe("ID_TOKEN_NOT_SUPPORTED");
    expect(await state(ctx)).toEqual(other.before);
    expect(await receipts(ctx)).toEqual([]);
    return { result: ctx.snapshot(result), before: other.before, after: await state(ctx) };
  },
);
for (const mode of ["empty-clients"] as const)
  compatScenario(`kick ${mode} requires a real client before identity writes`, async (ctx) => {
    const other = await foreign(ctx),
      result = await ctx
        .actor("kick", `social-kick-${mode}`)
        .client.signIn.social({ provider: "kick" });
    expect(result.error?.status).toBe(500);
    expect(await state(ctx)).toEqual(other.before);
    expect(await receipts(ctx)).toEqual([]);
    return { result: ctx.snapshot(result), before: other.before, after: await state(ctx) };
  });

for (const variant of ["default-unverified", "mapped-verified", "missing-raw"] as const)
  compatScenario(
    `kick explicit browser link ${variant} retains existing and foreign authority`,
    async (ctx) => {
      const other = await foreign(ctx),
        fixture = variant === "default-unverified" ? "social-kick-default" : "social-kick-mapped",
        actor = ctx.actor("kick", fixture),
        email =
          variant === "default-unverified"
            ? ctx.uniqueEmail("kick-link")
            : "mapped-kick@example.invalid";
      const signup = await actor.client.signUp.email({
        email,
        password: "Password123!",
        name: "Existing local user",
      });
      expect(signup.error).toBeNull();
      const before = await state(ctx),
        original: Row = { ...profile(ctx), email };
      if (variant === "missing-raw") delete original.user_id;
      await control(ctx, { profile: original });
      const start = await actor.client.linkSocial({ provider: "kick", callbackURL: "/linked" });
      expect(start.error).toBeNull();
      const url = new URL(start.data!.url!),
        path =
          authProfilePath(fixture) +
          `/callback/kick?code=fixture-code&state=${encodeURIComponent(url.searchParams.get("state")!)}`,
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
        expect(after.accounts.find((row) => row.providerId === "kick")).toMatchObject({
          accountId: original.user_id,
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
  "kick existing account info uses real GET without readmitting a changed raw account subject",
  async (ctx) => {
    const other = await foreign(ctx),
      original = profile(ctx);
    await control(ctx, { profile: original });
    const flow = await callback(ctx);
    expect(flow.response.headers.get("location")).toBe("/dashboard");
    const before = await state(ctx),
      user = before.users.find((row) => !other.before.users.some((old) => old.id === row.id))!,
      account = before.accounts.find((row) => row.userId === user.id)!;
    delete original.user_id;
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
        name: "Kick User",
        email: original.email,
        image: original.profile_picture,
        emailVerified: false,
      },
      data: original,
      account: { id: account.id, providerId: "kick", accountId: account.accountId },
    });
    expect(await state(ctx)).toEqual(before);
    expect((await receipts(ctx))[2]).toEqual({
      path: "/userinfo",
      method: "GET",
      authorization: "Bearer fixture-kick-access",
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
