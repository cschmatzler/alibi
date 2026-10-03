import { expect } from "bun:test";
import { createHash } from "node:crypto";

import { authProfilePath, type FixtureProfile } from "../../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../../support/scenario";

compatScenario(
  "polar mapped invalid subjects reach application mapper before denial",
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
        delete original.id;
      } else {
        original.id = variant === "null" ? null : "";
      }

      originals.push(original);
      await control(ctx, { profile: original });
      const flow = await callback(ctx, "social-polar-mapped");
      const observed = await ctx.rawRequest({ path: "/__test/polar/mapper-receipts" });
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

    const mapperReceipts = (await ctx.rawRequest({ path: "/__test/polar/mapper-receipts" }))
      .body as Record<string, unknown>[];
    return {
      before,
      after: await state(ctx),
      callbacks,
      mapperReceipts: mapperReceipts.map(({ id: rawSubject, ...fields }) => ({
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
    (await ctx.rawRequest({ path: "/__test/polar/control", method: "POST", json: value })).status,
  ).toBe(200);
}

async function receipts(ctx: ScenarioContext) {
  const r = await ctx.rawRequest({ path: "/__test/polar/receipts" });
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
    id: ctx.uniqueToken("polar-subject"),
    public_name: "Polar Name",
    username: "polar-user",
    email: ctx.uniqueEmail("polar"),
    country: "Synthetic Country",
    two_factor_authentication_enabled: true,
  };
}

async function callback(
  ctx: ScenarioContext,
  mode: FixtureProfile = "social-polar-default",
  requestSignUp = false,
) {
  const actor = ctx.actor("polar", mode);
  const start = await actor.client.signIn.social({
    provider: "polar",
    callbackURL: "/dashboard",
    requestSignUp,
  });
  expect(start.error).toBeNull();

  const url = new URL(start.data!.url!);
  const path =
    authProfilePath(mode) +
    `/callback/polar?code=fixture-code&state=${encodeURIComponent(url.searchParams.get("state")!)}`;
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
    `polar published ${mode} authorization preserves scope order and PKCE`,
    async (ctx) => {
      const result = await ctx.actor("polar", `social-polar-${mode}`).client.signIn.social({
        provider: "polar",
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
        mode === "configured-endpoint" ? "https://configured.example.invalid" : "https://polar.sh",
      );
      expect(url.pathname).toBe(
        mode === "configured-endpoint" ? "/authorize" : "/oauth2/authorize",
      );
      expect(url.searchParams.get("response_type")).toBe("code");
      expect(url.searchParams.get("response_mode")).toBeNull();
      expect(url.searchParams.get("login_hint")).toBeNull();
      expect(url.searchParams.get("custom")).toBe("caller-value");
      expect(url.searchParams.get("prompt")).toBe(mode === "prompt" ? "consent" : "caller-prompt");
      expect(url.searchParams.get("code_challenge_method")).toBe("S256");
      expect(url.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(url.searchParams.get("scope")).toBe(
        mode === "configured" || mode === "disabled-configured"
          ? `${mode === "configured" ? "openid profile email " : ""}configured-scope shared-scope configured-scope requested-scope shared-scope requested-scope`
          : `${mode === "disabled-scope" ? "" : "openid profile email "}requested-scope shared-scope requested-scope`,
      );
      expect(url.searchParams.get("redirect_uri")).toBe(
        mode === "configured-endpoint"
          ? "https://configured.example.invalid/callback"
          : ctx.baseURL + authProfilePath(`social-polar-${mode}`) + "/callback/polar",
      );

      return {
        result: ctx.snapshot(result),
        persisted: await state(ctx),
        receipts: await receipts(ctx),
      };
    },
  );
}

compatScenario("polar disabled defaults with no requested scopes omits scope", async (ctx) => {
  const result = await ctx
    .actor("polar", "social-polar-disabled-scope")
    .client.signIn.social({ provider: "polar", loginHint: "" });
  expect(result.error).toBeNull();
  expect(new URL(result.data!.url!).searchParams.get("scope")).toBeNull();
  expect(new URL(result.data!.url!).searchParams.get("login_hint")).toBeNull();

  return { result: ctx.snapshot(result) };
});

for (const mode of ["default", "public", "encoded", "configured-endpoint", "client-key"] as const) {
  compatScenario(
    `polar ${mode} credentials reach real token exchange refresh and owned persistence`,
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
      const fixtureMode = `social-polar-${mode}` as const;
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
        name: "Polar Name",
        email: data.email,
        emailVerified: false,
        image: null,
      });

      const account = after.accounts.find((row) => row.userId === owner.id)!;
      expect(account).toMatchObject({
        providerId: "polar",
        accountId: data.id,
        accessToken: "fixture-polar-access",
        refreshToken: "fixture-polar-refresh",
        idToken: null,
        scope: "openid,profile,email",
      });

      const raw = await ctx.rawRequest({ path: "/__test/polar/receipts" });
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
        client_id: mode === "encoded" ? "client :+!*'()" : "fixture-social-client",
        ...(mode === "public"
          ? {}
          : { client_secret: mode === "encoded" ? "secret :+!*'()" : "fixture-social-secret" }),
        grant_type: "authorization_code",
        code: "fixture-code",
        ...(mode === "client-key" ? { client_key: "fixture-client-key" } : {}),
        redirect_uri:
          mode === "configured-endpoint"
            ? "https://configured.example.invalid/callback"
            : ctx.baseURL + authProfilePath(fixtureMode) + "/callback/polar",
      });

      expect(rows[0]!.authorization).toBeNull();
      expect(rows[1]).toMatchObject({
        path: "/user",
        authorization: "Bearer fixture-polar-access",
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
          access_token: "rotated-polar-access",
          refresh_token: "rotated-polar-refresh",
          token_type: "Bearer",
          expires_in: 1800,
          scope: "openid profile email updated",
        },
      });
      const refreshed = await flow.actor.client.refreshToken({ accountId: String(account.id) });
      expect(refreshed.error).toBeNull();

      const rotated = await state(ctx);
      expect(rotated.accounts.find((row) => row.id === account.id)).toMatchObject({
        accessToken: "rotated-polar-access",
        refreshToken: "rotated-polar-refresh",
        scope: "openid,profile,email",
      });
      expect(rotated.users).toEqual(after.users);
      expect(rotated.sessions).toEqual(after.sessions);
      expect(rotated.accounts.find((row) => row.id === before.accounts[0]!.id)).toEqual(
        before.accounts[0],
      );

      const refreshRequests = await receipts(ctx);
      expect(refreshRequests[2]).toMatchObject({
        path: "/token",
        authorization: null,
        body: {
          grant_type: "refresh_token",
          refresh_token: "fixture-polar-refresh",
          client_id: mode === "encoded" ? "client :+!*'()" : "fixture-social-client",
          ...(mode === "public"
            ? {}
            : { client_secret: mode === "encoded" ? "secret :+!*'()" : "fixture-social-secret" }),
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
  "missing-username",
  "null-username",
  "empty-username",
  "numeric-username",
  "null-verified",
  "verified",
  "missing-image",
  "null-image",
  "empty-image",
  "numeric-image",
  "mapped",
] as const) {
  compatScenario(
    `polar ${variant} profile preserves raw profile and account info`,
    async (ctx) => {
      const data: Record<string, unknown> = {
        ...profile(ctx),
        avatar_url: "https://images.example.invalid/polar.png",
      };
      if (variant.endsWith("username")) {
        delete data.public_name;
        if (variant === "missing-username") delete data.username;
        if (variant === "null-username") data.username = null;
        if (variant === "empty-username") data.username = "";
        if (variant === "numeric-username") data.username = 42;
      }
      if (variant === "null-verified") data.email_verified = null;
      if (variant === "verified") data.email_verified = true;
      if (variant === "missing-name") delete data.public_name;
      if (variant === "null-name") data.public_name = null;
      if (variant === "empty-name") data.public_name = "";
      if (variant === "zero-name") data.public_name = 0;
      if (variant === "numeric-name") data.public_name = 42;
      if (variant === "numeric-subject") data.id = 42;
      if (variant === "zero-subject") data.id = 0;
      if (variant === "large-subject") data.id = 1e21;
      if (variant === "missing-image") delete data.avatar_url;
      if (variant === "null-image") data.avatar_url = null;
      if (variant === "empty-image") data.avatar_url = "";
      if (variant === "numeric-image") data.avatar_url = 42;
      await control(ctx, { profile: data });
      const flow = await callback(
        ctx,
        variant === "mapped" ? "social-polar-mapped" : "social-polar-default",
      );
      expect(flow.response.headers.get("location")).toBe("/dashboard");
      const persisted = await state(ctx);
      expect(persisted.users).toHaveLength(1);
      expect(persisted.accounts).toHaveLength(1);
      expect(persisted.sessions).toHaveLength(1);
      expect(persisted.accounts[0]!.accountId).toBe(String(data.id));
      const mapped = variant === "mapped";
      const name = variant.endsWith("username")
        ? variant === "numeric-username"
          ? "42"
          : ""
        : ["missing-name", "null-name", "empty-name", "zero-name"].includes(variant)
          ? "polar-user"
          : variant === "numeric-name"
            ? "42"
            : "Polar Name";
      expect(persisted.users[0]).toMatchObject({
        name: mapped ? "Mapped Polar Name" : name,
        email: mapped ? "mapped-polar@example.invalid" : data.email,
        emailVerified: mapped || variant === "verified",
        image: mapped
          ? "https://images.example.invalid/mapped-polar.png"
          : data.avatar_url == null
            ? null
            : String(data.avatar_url),
      });
      const info = await flow.actor.client.$fetch("/account-info", {
        query: { accountId: String(persisted.accounts[0]!.id) },
      });
      expect(info.error).toBeNull();
      expect(info.data).toEqual({
        user: mapped
          ? {
              id: "cannot-replace-account-subject",
              name: "Mapped Polar Name",
              email: "mapped-polar@example.invalid",
              emailVerified: true,
              image: "https://images.example.invalid/mapped-polar.png",
            }
          : {
              name: data.public_name || data.username || "",
              email: data.email,
              emailVerified: data.email_verified ?? false,
              ...(Object.hasOwn(data, "avatar_url") ? { image: data.avatar_url } : {}),
            },
        data,
        account: {
          id: persisted.accounts[0]!.id,
          providerId: "polar",
          accountId: String(data.id),
        },
      });
      expect(await state(ctx)).toEqual(persisted);
      expect((await receipts(ctx))[2]).toMatchObject({
        path: "/user",
        authorization: "Bearer fixture-polar-access",
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
  "userinfo-status",
  "token-status",
  "token-redirect",
  "implicit-disabled",
  "signup-disabled",
] as const) {
  compatScenario(
    `polar rejects ${variant} without foreign writes`,
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
        delete data.id;
      }

      if (variant === "null-subject") {
        data.id = null;
      }

      if (variant === "empty-subject") {
        data.id = "";
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
        profile: data,
        ...(variant === "userinfo-status" ? { profileStatus: 500 } : {}),
        ...(variant === "token-status" ? { tokenStatus: 400 } : {}),
        ...(variant === "token-redirect" ? { tokenStatus: 307, tokenRedirect: true } : {}),
      });
      const flow = await callback(
        ctx,
        variant === "implicit-disabled"
          ? "social-polar-implicit-disabled"
          : variant === "signup-disabled"
            ? "social-polar-signup-disabled"
            : "social-polar-default",
      );
      expect(flow.response.status).toBe(302);
      expect(
        new URL(flow.response.headers.get("location")!, ctx.baseURL).searchParams.get("error"),
      ).toBe(
        variant.endsWith("email")
          ? "email_not_found"
          : variant.startsWith("token-")
            ? "invalid_code"
            : variant.endsWith("disabled")
              ? "signup_disabled"
              : "unable_to_get_user_info",
      );

      const after = await state(ctx);
      expect(after).toEqual(before);

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
  "polar explicit signup admits disabled implicit signup",
  async (ctx) => {
    await control(ctx, { profile: profile(ctx) });
    const flow = await callback(ctx, "social-polar-implicit-disabled", true);
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
  "polar unverified email gate stores account without issuing session",
  async (ctx) => {
    await control(ctx, { profile: profile(ctx) });
    const flow = await callback(ctx, "social-polar-required");
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
    `polar ${expiry} token expiry has no fabricated default`,
    async (ctx) => {
      const started = Date.now();
      const tokenResponse = {
        access_token: "fixture-polar-access",
        refresh_token: "fixture-polar-refresh",
        token_type: "Bearer",
        scope: "openid,profile,email",
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
  "polar unsupported ID token and invalid provider state produce no requests",
  async (ctx) => {
    const before = await state(ctx);
    const actor = ctx.actor("polar", "social-polar-default");
    const reserved = await actor.client.signIn.social({
      provider: "polar",
      additionalParams: { state: "attacker-state", code_challenge: "attacker-challenge" },
    });
    expect(reserved.error?.code).toBe("VALIDATION_ERROR");
    const direct = await actor.client.signIn.social({
      provider: "polar",
      idToken: { token: "untrusted.not-signed.token" },
    });
    expect(direct.error?.code).toBe("ID_TOKEN_NOT_SUPPORTED");

    const wrong = await actor.client.signIn.social({ provider: "google" });
    expect(wrong.error?.code).toBe("PROVIDER_NOT_FOUND");

    const response = await actor.fetch(
      ctx.baseURL +
        authProfilePath("social-polar-default") +
        "/callback/polar?code=fixture-code&state=unissued",
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
