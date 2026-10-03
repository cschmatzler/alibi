import { expect } from "bun:test";
import { createHash } from "node:crypto";

import { authProfilePath, type FixtureProfile } from "../../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../../support/scenario";

compatScenario(
  "railway mapped invalid subjects reach application mapper before denial",
  async (ctx) => {
    const foreign = ctx.actor("foreign");
    expect(
      (
        await foreign.client.signUp.email({
          email: ctx.uniqueEmail("foreign"),
          password: "Password123!",
          name: "Foreign Owner",
        })
      ).error,
    ).toBeNull();

    const before = await state(ctx);
    const originals: Record<string, unknown>[] = [];
    const callbacks: unknown[] = [];

    for (const variant of ["missing", "null", "empty"] as const) {
      const original: Record<string, unknown> = {
        ...profile(ctx),
        applicationField: "Original profile receipt",
      };

      if (variant === "missing") {
        delete original.sub;
      } else {
        original.sub = variant === "null" ? null : "";
      }

      originals.push(original);
      await control(ctx, { profile: original });
      const flow = await callback(ctx, "social-railway-mapped");
      const observed = await ctx.rawRequest({ path: "/__test/railway/mapper-receipts" });
      expect(observed.status).toBe(200);
      expect(observed.body).toEqual(originals);
      expect(flow.response.status).toBe(302);

      const error = new URL(flow.response.headers.get("location")!, ctx.baseURL).searchParams.get(
        "error",
      );
      expect(error).toBe("unable_to_get_user_info");
      expect(await state(ctx)).toEqual(before);
      expect((await flow.actor.client.getSession()).data).toBeNull();
      expect(await receipts(ctx)).toHaveLength(originals.length * 2);

      callbacks.push({ status: flow.response.status, error });
    }

    const mapperReceipts = (await ctx.rawRequest({ path: "/__test/railway/mapper-receipts" }))
      .body as Record<string, unknown>[];
    return {
      before,
      after: await state(ctx),
      callbacks,
      mapperReceipts: mapperReceipts.map(({ sub: rawSubject, ...fields }) => ({
        ...fields,
        rawSubject,
      })),
    };
  },
  ["GET /callback/{}"],
);

async function state(ctx: ScenarioContext) {
  const r = await ctx.rawRequest({ path: "/__test/social-provider/state" });
  expect(r.status).toBe(200);
  return r.body as {
    users: Array<Record<string, unknown>>;
    accounts: Array<Record<string, unknown>>;
    sessions: Array<Record<string, unknown>>;
  };
}

async function control(ctx: ScenarioContext, value: Record<string, unknown>) {
  expect(
    (await ctx.rawRequest({ path: "/__test/railway/control", method: "POST", json: value })).status,
  ).toBe(200);
}

async function receipts(ctx: ScenarioContext) {
  const r = await ctx.rawRequest({ path: "/__test/railway/receipts" });
  expect(r.status).toBe(200);
  return (
    r.body as Array<{
      path: string;
      authorization: string | null;
      body: Record<string, string> | null;
    }>
  ).map((row) => ({
    ...row,
    body: (row.body?.code_verifier
      ? {
          ...row.body,
          code_verifier: { token: row.body.code_verifier, length: row.body.code_verifier.length },
        }
      : row.body) as Record<string, unknown> | null,
  }));
}

function profile(ctx: ScenarioContext) {
  return {
    sub: ctx.uniqueToken("railway-subject"),
    name: "Railway Name",
    username: "railway-user",
    email: ctx.uniqueEmail("railway"),
    country: "Synthetic Country",
    two_factor_authentication_enabled: true,
  };
}

async function callback(
  ctx: ScenarioContext,
  mode: FixtureProfile = "social-railway-default",
  requestSignUp = false,
) {
  const actor = ctx.actor("railway", mode);
  const start = await actor.client.signIn.social({
    provider: "railway",
    callbackURL: "/dashboard",
    requestSignUp,
  });
  expect(start.error).toBeNull();

  const url = new URL(start.data!.url!);
  const path =
    authProfilePath(mode) +
    `/callback/railway?code=fixture-code&state=${encodeURIComponent(url.searchParams.get("state")!)}`;
  const response = await actor.fetch(ctx.baseURL + path, { redirect: "manual" });
  return { actor, start, url, path, response };
}

for (const mode of [
  "default",
  "configured",
  "disabled-scope",
  "disabled-configured",
  "configured-endpoint",
  "prompt",
  "empty-endpoint",
] as const) {
  compatScenario(
    `railway published ${mode} authorization preserves scope order and PKCE`,
    async (ctx) => {
      const result = await ctx.actor("railway", `social-railway-${mode}`).client.signIn.social({
        provider: "railway",
        callbackURL: "/dashboard",
        scopes: ["requested-scope", "shared-scope", "requested-scope"],
        loginHint: "login@example.invalid",
        additionalParams: {
          ...(mode === "prompt" ? {} : { prompt: "caller-prompt" }),
          custom: "caller-value",
        },
      });
      expect(result.error).toBeNull();

      const url = new URL(result.data!.url!);
      expect(url.origin).toBe(
        mode === "configured-endpoint"
          ? "https://configured.example.invalid"
          : "https://backboard.railway.com",
      );
      expect(url.pathname).toBe(mode === "configured-endpoint" ? "/authorize" : "/oauth/auth");
      expect(url.searchParams.get("response_type")).toBe("code");
      expect(url.searchParams.get("response_mode")).toBeNull();
      expect(url.searchParams.get("login_hint")).toBeNull();
      expect(url.searchParams.get("custom")).toBe("caller-value");
      expect(url.searchParams.get("prompt")).toBe(mode === "prompt" ? null : "caller-prompt");
      expect(url.searchParams.get("code_challenge_method")).toBe("S256");
      expect(url.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(url.searchParams.get("scope")).toBe(
        mode === "configured" || mode === "disabled-configured"
          ? `${mode === "configured" ? "openid email profile " : ""}configured-scope shared-scope configured-scope requested-scope shared-scope requested-scope`
          : `${mode === "disabled-scope" ? "" : "openid email profile "}requested-scope shared-scope requested-scope`,
      );
      expect(url.searchParams.get("redirect_uri")).toBe(
        mode === "configured-endpoint"
          ? "https://configured.example.invalid/callback"
          : ctx.baseURL + authProfilePath(`social-railway-${mode}`) + "/callback/railway",
      );

      return {
        result: ctx.snapshot(result),
        persisted: await state(ctx),
        receipts: await receipts(ctx),
      };
    },
  );
}

compatScenario("railway disabled defaults with no requested scopes omits scope", async (ctx) => {
  const result = await ctx
    .actor("railway", "social-railway-disabled-scope")
    .client.signIn.social({ provider: "railway", loginHint: "" });
  expect(result.error).toBeNull();
  expect(new URL(result.data!.url!).searchParams.get("scope")).toBeNull();
  expect(new URL(result.data!.url!).searchParams.get("login_hint")).toBeNull();

  return { result: ctx.snapshot(result) };
});

for (const mode of ["default", "encoded", "configured-endpoint", "client-key"] as const) {
  compatScenario(
    `railway ${mode} credentials reach real token exchange refresh and owned persistence`,
    async (ctx) => {
      const foreign = ctx.actor("foreign");
      expect(
        (
          await foreign.client.signUp.email({
            email: ctx.uniqueEmail("foreign"),
            password: "Password123!",
            name: "Foreign Owner",
          })
        ).error,
      ).toBeNull();

      const before = await state(ctx);
      const data = profile(ctx);
      await control(ctx, { profile: data });
      const fixtureMode = `social-railway-${mode}` as const;
      const flow = await callback(ctx, fixtureMode);
      expect(flow.response.status).toBe(302);
      expect(flow.response.headers.get("location")).toBe("/dashboard");

      const session = await flow.actor.client.getSession();
      expect(session.data?.user).toBeTruthy();

      const after = await state(ctx);

      for (const table of ["users", "accounts", "sessions"] as const) {
        expect(after[table]).toHaveLength(before[table].length + 1);
        expect(after[table].find((row) => row.id === before[table][0]!.id)).toEqual(
          before[table][0],
        );
      }

      const owner = after.users.find((row) => row.id !== before.users[0]!.id)!;
      expect(owner).toMatchObject({
        name: "Railway Name",
        email: data.email,
        emailVerified: false,
        image: null,
      });

      const account = after.accounts.find((row) => row.userId === owner.id)!;
      expect(account).toMatchObject({
        providerId: "railway",
        accountId: data.sub,
        accessToken: "fixture-railway-access",
        refreshToken: "fixture-railway-refresh",
        idToken: null,
        scope: "openid,email,profile",
      });

      const raw = await ctx.rawRequest({ path: "/__test/railway/receipts" });
      const rows = raw.body as Array<{
        path: string;
        authorization: string | null;
        body: Record<string, string>;
      }>;
      const exchange = rows[0]!.body;
      expect(exchange.code_verifier).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(createHash("sha256").update(exchange.code_verifier!).digest("base64url")).toBe(
        flow.url.searchParams.get("code_challenge")!,
      );
      expect(exchange).toEqual({
        code_verifier: exchange.code_verifier!,
        grant_type: "authorization_code",
        code: "fixture-code",
        ...(mode === "client-key" ? { client_key: "fixture-client-key" } : {}),
        redirect_uri:
          mode === "configured-endpoint"
            ? "https://configured.example.invalid/callback"
            : ctx.baseURL + authProfilePath(fixtureMode) + "/callback/railway",
      });

      const basic =
        "Basic " +
        Buffer.from(
          mode === "encoded"
            ? "client+%3A%2B%21*%27%28%29:secret+%3A%2B%21*%27%28%29"
            : "fixture-social-client:fixture-social-secret",
        ).toString("base64");
      expect(rows[0]!.authorization).toBe(basic);
      expect(rows[1]).toMatchObject({
        path: "/user",
        authorization: "Bearer fixture-railway-access",
        body: null,
      });

      const replay = await flow.actor.fetch(ctx.baseURL + flow.path, { redirect: "manual" });
      expect(replay.status).toBe(302);
      expect(await state(ctx)).toEqual(after);
      expect(await receipts(ctx)).toHaveLength(2);

      const denied = await foreign.client.refreshToken({ accountId: String(account.id) });
      expect(denied.error).toBeTruthy();
      const foreignInfo = await foreign.client.$fetch("/account-info", {
        query: { accountId: String(account.id) },
      });
      expect(foreignInfo.error).toBeTruthy();
      expect(await state(ctx)).toEqual(after);
      expect(await receipts(ctx)).toHaveLength(2);

      await control(ctx, {
        tokenResponse: {
          access_token: "rotated-railway-access",
          refresh_token: "rotated-railway-refresh",
          token_type: "Bearer",
          expires_in: 1800,
          scope: "openid email profile updated",
        },
      });
      const refreshed = await flow.actor.client.refreshToken({ accountId: String(account.id) });
      expect(refreshed.error).toBeNull();

      const rotated = await state(ctx);
      expect(rotated.accounts.find((row) => row.id === account.id)).toMatchObject({
        accessToken: "rotated-railway-access",
        refreshToken: "rotated-railway-refresh",
        scope: "openid,email,profile",
      });
      expect(rotated.users).toEqual(after.users);
      expect(rotated.sessions).toEqual(after.sessions);
      expect(rotated.accounts.find((row) => row.id === before.accounts[0]!.id)).toEqual(
        before.accounts[0],
      );

      const refreshRequests = await receipts(ctx);
      expect(refreshRequests[2]).toMatchObject({
        path: "/token",
        authorization: basic,
        body: {
          grant_type: "refresh_token",
          refresh_token: "fixture-railway-refresh",
        },
      });
      expect((await flow.actor.client.signOut()).error).toBeNull();

      const logout = await state(ctx);
      expect(logout.users).toEqual(rotated.users);
      expect(logout.accounts).toEqual(rotated.accounts);
      expect(logout.sessions).toEqual(before.sessions);
      expect(await receipts(ctx)).toEqual(refreshRequests);

      return {
        start: ctx.snapshot(flow.start),
        callback: { status: flow.response.status, location: flow.response.headers.get("location") },
        session: ctx.snapshot(session),
        before,
        after,
        replay: { status: replay.status, location: replay.headers.get("location") },
        denied: ctx.snapshot(denied),
        foreignInfo: ctx.snapshot(foreignInfo),
        refreshed: ctx.snapshot(refreshed),
        rotated,
        logout,
        receipts: refreshRequests,
      };
    },
    ["POST /sign-in/social", "GET /callback/{}", "POST /refresh-token", "POST /sign-out"],
  );
}

for (const variant of [
  "missing-name",
  "null-name",
  "empty-name",
  "zero-name",
  "numeric-name",
  "numeric-subject",
  "zero-subject",
  "large-subject",
  "null-verified",
  "verified",
  "missing-image",
  "null-image",
  "empty-image",
  "numeric-image",
  "mapped",
] as const) {
  compatScenario(
    `railway ${variant} profile preserves raw profile and account info`,
    async (ctx) => {
      const data: Record<string, unknown> = {
        ...profile(ctx),
        picture: "https://images.example.invalid/railway.png",
      };
      if (variant === "null-verified") data.email_verified = null;
      if (variant === "verified") data.email_verified = true;
      if (variant === "missing-name") delete data.name;
      if (variant === "null-name") data.name = null;
      if (variant === "empty-name") data.name = "";
      if (variant === "zero-name") data.name = 0;
      if (variant === "numeric-name") data.name = 42;
      if (variant === "numeric-subject") data.sub = 42;
      if (variant === "zero-subject") data.sub = 0;
      if (variant === "large-subject") data.sub = 1e21;
      if (variant === "missing-image") delete data.picture;
      if (variant === "null-image") data.picture = null;
      if (variant === "empty-image") data.picture = "";
      if (variant === "numeric-image") data.picture = 42;
      await control(ctx, { profile: data });
      const flow = await callback(
        ctx,
        variant === "mapped" ? "social-railway-mapped" : "social-railway-default",
      );
      expect(flow.response.headers.get("location")).toBe("/dashboard");
      const persisted = await state(ctx);
      expect(persisted.users).toHaveLength(1);
      expect(persisted.accounts).toHaveLength(1);
      expect(persisted.sessions).toHaveLength(1);
      expect(persisted.accounts[0]!.accountId).toBe(String(data.sub));
      const mapped = variant === "mapped";
      const name = ["missing-name", "null-name", "empty-name", "zero-name"].includes(variant)
        ? ""
        : variant === "numeric-name"
          ? "42"
          : "Railway Name";
      expect(persisted.users[0]).toMatchObject({
        name: mapped ? "Mapped Railway Name" : name,
        email: mapped ? "mapped-railway@example.invalid" : data.email,
        emailVerified: mapped,
        image: mapped
          ? "https://images.example.invalid/mapped-railway.png"
          : data.picture == null
            ? null
            : String(data.picture),
      });
      const info = await flow.actor.client.$fetch("/account-info", {
        query: { accountId: String(persisted.accounts[0]!.id) },
      });
      expect(info.error).toBeNull();
      expect(info.data).toEqual({
        user: mapped
          ? {
              id: "cannot-replace-account-subject",
              name: "Mapped Railway Name",
              email: "mapped-railway@example.invalid",
              emailVerified: true,
              image: "https://images.example.invalid/mapped-railway.png",
            }
          : {
              ...(Object.hasOwn(data, "name") ? { name: data.name } : {}),
              email: data.email,
              emailVerified: false,
              ...(Object.hasOwn(data, "picture") ? { image: data.picture } : {}),
            },
        data,
        account: {
          id: persisted.accounts[0]!.id,
          providerId: "railway",
          accountId: String(data.sub),
        },
      });
      expect(await state(ctx)).toEqual(persisted);
      expect((await receipts(ctx))[2]).toMatchObject({
        path: "/user",
        authorization: "Bearer fixture-railway-access",
      });
      return {
        start: ctx.snapshot(flow.start),
        persisted,
        info: ctx.snapshot(info),
        receipts: await receipts(ctx),
      };
    },
    ["POST /sign-in/social", "GET /callback/{}", "GET /account-info"],
  );
}

for (const variant of [
  "missing-subject",
  "null-subject",
  "empty-subject",
  "missing-email",
  "null-email",
  "empty-email",
  "null-profile",
  "userinfo-status",
  "token-status",
  "token-redirect",
  "implicit-disabled",
  "signup-disabled",
  "missing-secret",
] as const) {
  compatScenario(
    `railway rejects ${variant} without foreign writes`,
    async (ctx) => {
      const foreign = ctx.actor("foreign");
      expect(
        (
          await foreign.client.signUp.email({
            email: ctx.uniqueEmail("foreign"),
            password: "Password123!",
            name: "Foreign Owner",
          })
        ).error,
      ).toBeNull();

      const before = await state(ctx);
      const data: Record<string, unknown> = profile(ctx);

      if (variant === "missing-subject") {
        delete data.sub;
      }

      if (variant === "null-subject") {
        data.sub = null;
      }

      if (variant === "empty-subject") {
        data.sub = "";
      }

      if (variant === "missing-email") {
        delete data.email;
      }

      if (variant === "null-email") {
        data.email = null;
      }

      if (variant === "empty-email") {
        data.email = "";
      }

      await control(ctx, {
        profile: variant === "null-profile" ? null : data,
        ...(variant === "userinfo-status" ? { profileStatus: 500 } : {}),
        ...(variant === "token-status" ? { tokenStatus: 400 } : {}),
        ...(variant === "token-redirect" ? { tokenStatus: 307, tokenRedirect: true } : {}),
      });
      const flow = await callback(
        ctx,
        variant === "implicit-disabled"
          ? "social-railway-implicit-disabled"
          : variant === "signup-disabled"
            ? "social-railway-signup-disabled"
            : variant === "missing-secret"
              ? "social-railway-public"
              : "social-railway-default",
      );
      expect(flow.response.status).toBe(302);
      expect(
        new URL(flow.response.headers.get("location")!, ctx.baseURL).searchParams.get("error"),
      ).toBe(
        variant.endsWith("email")
          ? "email_not_found"
          : variant.startsWith("token-") || variant === "missing-secret"
            ? "invalid_code"
            : variant.endsWith("disabled")
              ? "signup_disabled"
              : "unable_to_get_user_info",
      );

      const after = await state(ctx);
      expect(after).toEqual(before);

      if (variant === "missing-secret") expect(await receipts(ctx)).toHaveLength(0);
      if (variant === "token-redirect") {
        expect(await receipts(ctx)).toHaveLength(1);
      }

      expect((await flow.actor.client.getSession()).data).toBeNull();

      return {
        start: ctx.snapshot(flow.start),
        callback: { status: flow.response.status, location: flow.response.headers.get("location") },
        before,
        after,
        receipts: await receipts(ctx),
      };
    },
    ["GET /callback/{}"],
  );
}

compatScenario(
  "railway explicit signup admits disabled implicit signup",
  async (ctx) => {
    await control(ctx, { profile: profile(ctx) });
    const flow = await callback(ctx, "social-railway-implicit-disabled", true);
    expect(flow.response.headers.get("location")).toBe("/dashboard");

    const persisted = await state(ctx);
    expect(persisted.users).toHaveLength(1);
    expect(persisted.accounts).toHaveLength(1);
    expect(persisted.sessions).toHaveLength(1);

    return {
      start: ctx.snapshot(flow.start),
      callback: { status: flow.response.status, location: flow.response.headers.get("location") },
      persisted,
      receipts: await receipts(ctx),
    };
  },
  ["POST /sign-in/social", "GET /callback/{}"],
);

compatScenario(
  "railway unverified email gate stores account without issuing session",
  async (ctx) => {
    await control(ctx, { profile: profile(ctx) });
    const flow = await callback(ctx, "social-railway-required");
    expect(
      new URL(flow.response.headers.get("location")!, ctx.baseURL).searchParams.get("error"),
    ).toBe("email_not_verified");

    const persisted = await state(ctx);
    expect(persisted.users).toHaveLength(1);
    expect(persisted.users[0]!.emailVerified).toBeFalse();
    expect(persisted.accounts).toHaveLength(1);
    expect(persisted.sessions).toHaveLength(0);
    expect((await flow.actor.client.getSession()).data).toBeNull();

    return {
      callback: { status: flow.response.status, location: flow.response.headers.get("location") },
      persisted,
      receipts: await receipts(ctx),
    };
  },
  ["POST /sign-in/social", "GET /callback/{}"],
);

for (const expiry of ["absent", "zero", "fractional"] as const) {
  compatScenario(
    `railway ${expiry} token expiry has no fabricated default`,
    async (ctx) => {
      const started = Date.now();
      const tokenResponse = {
        access_token: "fixture-railway-access",
        refresh_token: "fixture-railway-refresh",
        token_type: "Bearer",
        scope: "openid,email,profile",
        ...(expiry === "absent" ? {} : { expires_in: expiry === "zero" ? 0 : 120.5 }),
      };
      await control(ctx, { profile: profile(ctx), tokenResponse });
      const flow = await callback(ctx);
      expect(flow.response.headers.get("location")).toBe("/dashboard");

      const persisted = await state(ctx);
      const expires = persisted.accounts[0]!.accessTokenExpiresAt;

      if (expiry === "fractional") {
        expect(typeof expires).toBe("string");
        expect(Date.parse(String(expires))).toBeGreaterThanOrEqual(started + 120500);
        expect(Date.parse(String(expires))).toBeLessThanOrEqual(Date.now() + 120500);
      } else {
        expect(expires).toBeNull();
      }

      return { persisted, receipts: await receipts(ctx) };
    },
    ["POST /sign-in/social", "GET /callback/{}"],
  );
}

compatScenario(
  "railway unsupported ID token and invalid provider state produce no requests",
  async (ctx) => {
    const before = await state(ctx);
    const actor = ctx.actor("railway", "social-railway-default");
    const reserved = await actor.client.signIn.social({
      provider: "railway",
      additionalParams: { state: "attacker-state", code_challenge: "attacker-challenge" },
    });
    expect(reserved.error?.code).toBe("VALIDATION_ERROR");
    const direct = await actor.client.signIn.social({
      provider: "railway",
      idToken: { token: "untrusted.not-signed.token" },
    });
    expect(direct.error?.code).toBe("ID_TOKEN_NOT_SUPPORTED");

    const wrong = await actor.client.signIn.social({ provider: "google" });
    expect(wrong.error?.code).toBe("PROVIDER_NOT_FOUND");

    const response = await actor.fetch(
      ctx.baseURL +
        authProfilePath("social-railway-default") +
        "/callback/railway?code=fixture-code&state=unissued",
      { redirect: "manual" },
    );
    expect(response.status).toBe(302);
    expect(new URL(response.headers.get("location")!, ctx.baseURL).searchParams.get("error")).toBe(
      "state_mismatch",
    );
    expect(await state(ctx)).toEqual(before);
    expect(await receipts(ctx)).toEqual([]);

    return {
      reserved: ctx.snapshot(reserved),
      direct: ctx.snapshot(direct),
      wrong: ctx.snapshot(wrong),
      persisted: await state(ctx),
      receipts: await receipts(ctx),
    };
  },
  ["POST /sign-in/social", "GET /callback/{}"],
);
