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
    path: "/__test/figma/control",
    method: "POST",
    json: value,
  });
  expect(response.status).toBe(200);
}

async function receipts(ctx: ScenarioContext) {
  const response = await ctx.rawRequest({ path: "/__test/figma/receipts" });
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
    id: ctx.uniqueToken("figma-subject"),
    handle: "Figma User",
    email: ctx.uniqueEmail("figma"),
    email_verified: true,
    img_url: "https://images.example.invalid/figma.png",
    originalApplicationField: { retained: true },
  };
}

async function callback(
  ctx: ScenarioContext,
  mode: FixtureProfile = "social-figma-default",
  requestSignUp = false,
) {
  const actor = ctx.actor("figma", mode);
  const start = await actor.client.signIn.social({
    provider: "figma",
    callbackURL: "/dashboard",
    requestSignUp,
  });
  expect(start.error).toBeNull();

  const url = new URL(start.data!.url!);
  const path =
    authProfilePath(mode) +
    `/callback/figma?code=fixture-code&state=${encodeURIComponent(url.searchParams.get("state")!)}`;
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
    `figma published ${mode} authorization retains ordered scopes and required PKCE`,
    async (ctx) => {
      const other = await foreign(ctx);
      const fixture: FixtureProfile = `social-figma-${mode}`;
      const result = await ctx.actor("figma", fixture).client.signIn.social({
        provider: "figma",
        callbackURL: "/dashboard",
        scopes: ["requested-scope", "current_user:read"],
        loginHint: "ignored@example.invalid",
        additionalParams: { custom: "value with space" },
      });
      expect(result.error).toBeNull();

      const url = new URL(result.data!.url!);
      const configured = ["configured", "disabled-configured"].includes(mode);
      expect(url.origin).toBe(
        mode === "configured-endpoint"
          ? "https://alternate-figma.example.invalid"
          : "https://www.figma.com",
      );
      expect(url.pathname).toBe(mode === "configured-endpoint" ? "/authorize" : "/oauth");

      const scopes = [
        ...(mode.startsWith("disabled-") ? [] : ["current_user:read"]),
        ...(configured ? ["file_content:read", "current_user:read", "punctuation !~*'()"] : []),
        "requested-scope",
        "current_user:read",
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
          ? "https://client.example.invalid/figma-return"
          : ctx.baseURL + authProfilePath(fixture) + "/callback/figma",
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

for (const mode of ["default", "mapped", "configured-endpoint", "client-key"] as const) {
  compatScenario(
    `figma ${mode} real Basic exchange and GET profile refresh replay and local logout preserve foreign authority`,
    async (ctx) => {
      const other = await foreign(ctx);
      const original = profile(ctx);
      await control(ctx, { profile: original });
      const fixture: FixtureProfile = `social-figma-${mode}`;
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
        name: mode === "mapped" ? "Mapped Figma User" : "Figma User",
        email: mode === "mapped" ? "mapped-figma@example.invalid" : original.email,
        emailVerified: mode === "mapped",
        image:
          mode === "mapped" ? "https://images.example.invalid/mapped-figma.png" : original.img_url,
      });
      expect(account).toMatchObject({
        providerId: "figma",
        accountId: original.id,
        accessToken: "fixture-figma-access",
        refreshToken: "fixture-figma-refresh",
        scope: "current_user:read",
        idToken: null,
      });
      expect(account.accessTokenExpiresAt).toBeTruthy();
      expect(session.data?.user.id).toBe(user.id);

      const raw = (await ctx.rawRequest({ path: "/__test/figma/receipts" })).body as Receipt[];
      const exchange = raw[0]!.body as Record<string, string>;
      const verifier = exchange.code_verifier!;
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
        ...(mode === "client-key" ? { client_key: "fixture-figma-client-key" } : {}),
        redirect_uri:
          mode === "configured-endpoint"
            ? "https://client.example.invalid/figma-return"
            : ctx.baseURL + authProfilePath(fixture) + "/callback/figma",
      });
      expect(raw[0]!.authorization).toBe(
        "Basic " + Buffer.from("fixture-social-client:fixture-social-secret").toString("base64"),
      );
      expect(raw[1]).toEqual({
        path: "/userinfo",
        method: "GET",
        authorization: "Bearer fixture-figma-access",
        contentType: null,
        body: "",
      });

      const mapper = (await ctx.rawRequest({ path: "/__test/figma/mapper-receipts" })).body;
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
          access_token: "fixture-figma-access-rotated",
          refresh_token: "fixture-figma-refresh-rotated",
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
        accessToken: "fixture-figma-access-rotated",
        refreshToken: "fixture-figma-refresh-rotated",
        scope: account.scope,
      });

      const requests = await receipts(ctx);
      expect(requests[2]!.body).toEqual({
        grant_type: "refresh_token",
        refresh_token: "fixture-figma-refresh",
      });
      expect(requests[2]!.authorization).toBe(
        "Basic " + Buffer.from("fixture-social-client:fixture-social-secret").toString("base64"),
      );

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
  verified?: boolean;
}> = [
  { name: "numeric name", patch: { handle: 7 }, expectedName: "7" },
  { name: "empty name", patch: { handle: "" }, expectedName: "" },
  { name: "null handle", patch: { handle: null }, expectedName: "" },
  { name: "missing name", patch: { handle: undefined }, expectedName: "" },
  { name: "numeric subject", patch: { id: 42 }, expectedName: "Figma User", expectedSubject: "42" },
  {
    name: "missing image",
    patch: { img_url: undefined },
    expectedName: "Figma User",
    expectedImage: null,
  },
  { name: "null image", patch: { img_url: null }, expectedName: "Figma User", expectedImage: null },
  { name: "empty image", patch: { img_url: "" }, expectedName: "Figma User", expectedImage: "" },
  { name: "numeric image", patch: { img_url: 7 }, expectedName: "Figma User", expectedImage: "7" },
];

for (const mapping of mappings) {
  compatScenario(
    `figma ${mapping.name} profile retains original raw account and typed persistence`,
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
        image: mapping.expectedImage === undefined ? original.img_url : mapping.expectedImage,
      });
      expect(account.accountId).toBe(mapping.expectedSubject ?? original.id);
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
    `figma ${expiry} access expiry follows actual token helper`,
    async (ctx) => {
      await control(ctx, {
        profile: profile(ctx),
        tokenResponse: {
          access_token: "fixture-figma-access",
          refresh_token: "fixture-figma-refresh",
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
    `figma browser ${variant} denies before any owned or foreign identity write`,
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
        delete original.email;
      }

      await control(ctx, {
        profile: original,
        ...(variant === "token-http-error" ? { tokenStatus: 503 } : {}),
        ...(variant === "userinfo-http-error" ? { userInfoStatus: 503 } : {}),
      });
      const fixture: FixtureProfile =
        variant === "signup-disabled"
          ? "social-figma-signup-disabled"
          : variant === "implicit-disabled"
            ? "social-figma-implicit-disabled"
            : "social-figma-default";
      const actor = ctx.actor("figma", fixture);
      const start = await actor.client.signIn.social({
        provider: "figma",
        callbackURL: "/dashboard",
        requestSignUp: variant === "signup-disabled",
      });
      expect(start.error).toBeNull();

      const url = new URL(start.data!.url!);
      const callbackState =
        variant === "wrong-state" ? ctx.uniqueToken("wrong-state") : url.searchParams.get("state")!;
      const provider = variant === "wrong-provider" ? "unknown-figma" : "figma";
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
  "figma disabled default scope omits an empty scope parameter",
  async (ctx) => {
    const before = await state(ctx);
    const result = await ctx
      .actor("figma", "social-figma-disabled-scope")
      .client.signIn.social({ provider: "figma" });
    expect(result.error).toBeNull();
    expect(new URL(result.data!.url!).searchParams.has("scope")).toBeFalse();
    expect(await state(ctx)).toEqual(before);
    expect(await receipts(ctx)).toEqual([]);

    return { result: ctx.snapshot(result), before, after: await state(ctx) };
  },
  ["POST /sign-in/social"],
);

compatScenario(
  "figma explicit signup overrides implicit signup policy",
  async (ctx) => {
    await control(ctx, { profile: profile(ctx) });
    const flow = await callback(ctx, "social-figma-implicit-disabled", true);
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
  "figma rejects direct ID-token sign-in without remote verification or identity writes",
  async (ctx) => {
    const other = await foreign(ctx);
    const result = await ctx
      .actor("figma", "social-figma-default")
      .client.signIn.social({ provider: "figma", idToken: { token: "unsupported-proof" } });
    expect(result.error?.code).toBe("ID_TOKEN_NOT_SUPPORTED");
    expect(await state(ctx)).toEqual(other.before);
    expect(await receipts(ctx)).toEqual([]);

    return { result: ctx.snapshot(result), before: other.before, after: await state(ctx) };
  },
);

for (const mode of ["empty-clients", "public"] as const) {
  compatScenario(
    `figma ${mode} requires real client and secret before identity writes`,
    async (ctx) => {
      const other = await foreign(ctx);
      const result = await ctx
        .actor("figma", `social-figma-${mode}`)
        .client.signIn.social({ provider: "figma" });
      expect(result.error?.status).toBe(500);
      expect(await state(ctx)).toEqual(other.before);
      expect(await receipts(ctx)).toEqual([]);

      return { result: ctx.snapshot(result), before: other.before, after: await state(ctx) };
    },
  );
}

for (const variant of ["default-unverified", "mapped-verified", "missing-raw"] as const) {
  compatScenario(
    `figma explicit browser link ${variant} retains existing and foreign authority`,
    async (ctx) => {
      const other = await foreign(ctx);
      const fixture =
        variant === "default-unverified" ? "social-figma-default" : "social-figma-mapped";
      const actor = ctx.actor("figma", fixture);
      const email =
        variant === "default-unverified"
          ? ctx.uniqueEmail("figma-link")
          : "mapped-figma@example.invalid";
      const signup = await actor.client.signUp.email({
        email,
        password: "Password123!",
        name: "Existing local user",
      });
      expect(signup.error).toBeNull();

      const before = await state(ctx);
      const original: Row = { ...profile(ctx), email };

      if (variant === "missing-raw") {
        delete original.id;
      }

      await control(ctx, { profile: original });
      const start = await actor.client.linkSocial({ provider: "figma", callbackURL: "/linked" });
      expect(start.error).toBeNull();

      const url = new URL(start.data!.url!);
      const path =
        authProfilePath(fixture) +
        `/callback/figma?code=fixture-code&state=${encodeURIComponent(url.searchParams.get("state")!)}`;
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
        expect(after.accounts.find((row) => row.providerId === "figma")).toMatchObject({
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
  "figma existing account info uses real GET without readmitting a changed raw account subject",
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
        name: "Figma User",
        email: original.email,
        image: original.img_url,
        emailVerified: false,
      },
      data: original,
      account: { id: account.id, providerId: "figma", accountId: account.accountId },
    });
    expect(await state(ctx)).toEqual(before);
    expect((await receipts(ctx))[2]).toEqual({
      path: "/userinfo",
      method: "GET",
      authorization: "Bearer fixture-figma-access",
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
