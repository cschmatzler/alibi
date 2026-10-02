import { expect } from "bun:test";
import { authProfilePath, type FixtureProfile } from "../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../support/scenario";

compatScenario(
  "atlassian mapped invalid subjects reach application mapper before denial",
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
      if (variant === "missing") delete original.account_id;
      else original.account_id = variant === "null" ? null : "";
      originals.push(original);
      await control(ctx, { profile: original });
      const flow = await callback(ctx, "social-atlassian-mapped");
      const observed = await ctx.rawRequest({ path: "/__test/atlassian/mapper-receipts" });
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
    return {
      before,
      after: await state(ctx),
      callbacks,
      mapperReceipts: (await ctx.rawRequest({ path: "/__test/atlassian/mapper-receipts" })).body,
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
    (await ctx.rawRequest({ path: "/__test/atlassian/control", method: "POST", json: value }))
      .status,
  ).toBe(200);
}
async function receipts(ctx: ScenarioContext) {
  const r = await ctx.rawRequest({ path: "/__test/atlassian/receipts" });
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
    account_id: ctx.uniqueToken("atlassian-subject"),
    name: "Atlassian Name",
    email: ctx.uniqueEmail("atlassian"),
    picture: "https://images.example.invalid/atlassian.png",
    nickname: "unchanged-profile",
    extended_profile: { organization: "Synthetic Organization" },
  };
}
async function callback(
  ctx: ScenarioContext,
  mode: FixtureProfile = "social-atlassian-default",
  requestSignUp = false,
) {
  const actor = ctx.actor("atlassian", mode);
  const start = await actor.client.signIn.social({
    provider: "atlassian",
    callbackURL: "/dashboard",
    requestSignUp,
  });
  expect(start.error).toBeNull();
  const url = new URL(start.data!.url!);
  const path =
    authProfilePath(mode) +
    `/callback/atlassian?code=fixture-code&state=${encodeURIComponent(url.searchParams.get("state")!)}`;
  const response = await actor.fetch(ctx.baseURL + path, { redirect: "manual" });
  return { actor, start, url, path, response };
}
for (const mode of [
  "default",
  "configured",
  "disabled-scope",
  "disabled-configured",
  "configured-endpoint",
] as const)
  compatScenario(
    `atlassian published ${mode} authorization audience scopes and PKCE`,
    async (ctx) => {
      const result = await ctx.actor("atlassian", `social-atlassian-${mode}`).client.signIn.social({
        provider: "atlassian",
        callbackURL: "/dashboard",
        scopes: ["requested-scope", "read:jira-user"],
        loginHint: "ignored@example.invalid",
      });
      expect(result.error).toBeNull();
      const url = new URL(result.data!.url!);
      expect(url.origin).toBe(
        mode === "configured-endpoint"
          ? "https://configured.example.invalid"
          : "https://auth.atlassian.com",
      );
      expect(url.pathname).toBe("/authorize");
      expect(url.searchParams.get("audience")).toBe("api.atlassian.com");
      expect(url.searchParams.get("response_type")).toBe("code");
      expect(url.searchParams.get("response_mode")).toBeNull();
      expect(url.searchParams.get("login_hint")).toBeNull();
      expect(url.searchParams.get("code_challenge_method")).toBe("S256");
      expect(url.searchParams.get("code_challenge")).toBeTruthy();
      expect(url.searchParams.get("scope")).toBe(
        [
          ...(mode.startsWith("disabled-") ? [] : ["read:jira-user", "offline_access"]),
          ...(["configured", "disabled-configured"].includes(mode)
            ? ["configured-scope", "read:jira-user"]
            : []),
          "requested-scope",
          "read:jira-user",
        ].join(" "),
      );
      expect(url.searchParams.get("prompt")).toBe(
        ["configured", "disabled-configured"].includes(mode) ? "consent" : null,
      );
      expect(url.searchParams.get("redirect_uri")).toBe(
        mode === "configured-endpoint"
          ? "https://configured.example.invalid/callback"
          : ctx.baseURL + authProfilePath(`social-atlassian-${mode}`) + "/callback/atlassian",
      );
      return {
        result: ctx.snapshot(result),
        persisted: await state(ctx),
        receipts: await receipts(ctx),
      };
    },
  );
for (const variant of [
  "named",
  "missing-name",
  "null-name",
  "empty-name",
  "numeric-name",
  "zero-name",
  "numeric-subject",
  "missing-image",
  "null-image",
  "numeric-image",
  "zero-image",
  "mapped",
] as const)
  compatScenario(
    `atlassian actual userinfo ${variant} mapping and callback replay`,
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
      if (variant === "missing-name") delete data.name;
      if (variant === "null-name") data.name = null;
      if (variant === "empty-name") data.name = "";
      if (variant === "numeric-name") data.name = 7;
      if (variant === "zero-name") data.name = 0;
      if (variant === "numeric-subject") data.account_id = 42;
      if (variant === "missing-image") delete data.picture;
      if (variant === "null-image") data.picture = null;
      if (variant === "numeric-image") data.picture = 7;
      if (variant === "zero-image") data.picture = 0;
      await control(ctx, { profile: data });
      const mode = variant === "mapped" ? "social-atlassian-mapped" : "social-atlassian-default";
      const flow = await callback(ctx, mode);
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
      expect(owner.name).toBe(
        variant === "mapped"
          ? "Mapped Atlassian Name"
          : variant === "numeric-name"
            ? "7"
            : ["missing-name", "null-name", "empty-name", "zero-name"].includes(variant)
              ? ""
              : "Atlassian Name",
      );
      expect(owner.image).toBe(
        variant === "mapped"
          ? "https://images.example.invalid/mapped-atlassian.png"
          : ["missing-image", "null-image"].includes(variant)
            ? null
            : String(data.picture),
      );
      expect(owner.emailVerified).toBe(variant === "mapped");
      expect(owner.email).toBe(
        variant === "mapped" ? "mapped-atlassian@example.invalid" : data.email,
      );
      expect(after.accounts.find((row) => row.userId === owner.id)).toMatchObject({
        providerId: "atlassian",
        accountId: String(data.account_id),
        accessToken: "fixture-atlassian-access",
        refreshToken: "fixture-atlassian-refresh",
        idToken: null,
        scope: "read:jira-user,offline_access",
      });
      const raw = await ctx.rawRequest({ path: "/__test/atlassian/receipts" });
      const rows = raw.body as Array<{
        path: string;
        authorization: string;
        body: Record<string, string>;
      }>;
      const exchange = rows[0]!.body;
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
        client_id: "fixture-social-client",
        client_secret: "fixture-social-secret",
        redirect_uri: ctx.baseURL + authProfilePath(mode) + "/callback/atlassian",
      });
      expect(rows[1]).toMatchObject({
        path: "/me",
        authorization: "Bearer fixture-atlassian-access",
        body: null,
      });
      const replay = await flow.actor.fetch(ctx.baseURL + flow.path, { redirect: "manual" });
      expect(replay.status).toBe(302);
      const afterReplay = await state(ctx);
      expect(afterReplay).toEqual(after);
      expect(await receipts(ctx)).toHaveLength(2);
      return {
        start: ctx.snapshot(flow.start),
        callback: { status: flow.response.status, location: flow.response.headers.get("location") },
        session: ctx.snapshot(session),
        before,
        after,
        replay: { status: replay.status, location: replay.headers.get("location") },
        afterReplay,
        receipts: await receipts(ctx),
      };
    },
    ["POST /sign-in/social", "GET /callback/{}"],
  );
for (const variant of [
  "missing-subject",
  "null-subject",
  "empty-subject",
  "missing-email",
  "null-email",
  "empty-email",
  "userinfo-status",
  "token-status",
  "implicit-disabled",
  "signup-disabled",
] as const)
  compatScenario(`atlassian rejects ${variant} without foreign writes`, async (ctx) => {
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
    if (variant === "missing-subject") delete data.account_id;
    if (variant === "null-subject") data.account_id = null;
    if (variant === "empty-subject") data.account_id = "";
    if (variant === "missing-email") delete data.email;
    if (variant === "null-email") data.email = null;
    if (variant === "empty-email") data.email = "";
    await control(ctx, {
      profile: data,
      ...(variant === "userinfo-status" ? { profileStatus: 500 } : {}),
      ...(variant === "token-status" ? { tokenStatus: 400 } : {}),
    });
    const flow = await callback(
      ctx,
      variant === "implicit-disabled"
        ? "social-atlassian-implicit-disabled"
        : variant === "signup-disabled"
          ? "social-atlassian-signup-disabled"
          : "social-atlassian-default",
    );
    expect(flow.response.status).toBe(302);
    expect(
      new URL(flow.response.headers.get("location")!, ctx.baseURL).searchParams.get("error"),
    ).toBe(
      variant.endsWith("email")
        ? "email_not_found"
        : variant === "token-status"
          ? "invalid_code"
          : variant.endsWith("disabled")
            ? "signup_disabled"
            : "unable_to_get_user_info",
    );
    const after = await state(ctx);
    expect(after).toEqual(before);
    expect((await flow.actor.client.getSession()).data).toBeNull();
    return {
      start: ctx.snapshot(flow.start),
      callback: { status: flow.response.status, location: flow.response.headers.get("location") },
      before,
      after,
      receipts: await receipts(ctx),
    };
  });
compatScenario(
  "atlassian configured redirect URI is retained in token exchange",
  async (ctx) => {
    await control(ctx, { profile: profile(ctx) });
    const flow = await callback(ctx, "social-atlassian-configured-endpoint");
    expect(flow.response.headers.get("location")).toBe("/dashboard");
    const requests = await receipts(ctx);
    expect(requests[0]!.body!.redirect_uri).toBe("https://configured.example.invalid/callback");
    return {
      start: ctx.snapshot(flow.start),
      callback: { status: flow.response.status, location: flow.response.headers.get("location") },
      persisted: await state(ctx),
      receipts: requests,
    };
  },
  ["POST /sign-in/social", "GET /callback/{}"],
);
compatScenario("atlassian explicit signup admits disabled implicit signup", async (ctx) => {
  await control(ctx, { profile: profile(ctx) });
  const flow = await callback(ctx, "social-atlassian-implicit-disabled", true);
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
});
compatScenario(
  "atlassian unverified email gate stores account without issuing session",
  async (ctx) => {
    await control(ctx, { profile: profile(ctx) });
    const flow = await callback(ctx, "social-atlassian-required");
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
compatScenario(
  "atlassian refresh rotates owned credentials and local logout revokes session",
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
    await control(ctx, { profile: profile(ctx) });
    const flow = await callback(ctx);
    expect(flow.response.headers.get("location")).toBe("/dashboard");
    const before = await state(ctx);
    const account = before.accounts.find((row) => row.providerId === "atlassian")!;
    await control(ctx, {
      tokenResponse: {
        access_token: "fixture-atlassian-access-rotated",
        refresh_token: "fixture-atlassian-refresh-rotated",
        expires_in: 1800,
        scope: "configured-scope offline_access",
      },
    });
    const denied = await foreign.client.refreshToken({ accountId: String(account.id) });
    expect(denied.error).not.toBeNull();
    expect(await state(ctx)).toEqual(before);
    expect(await receipts(ctx)).toHaveLength(2);
    const refreshed = await flow.actor.client.refreshToken({ accountId: String(account.id) });
    expect(refreshed.error).toBeNull();
    const after = await state(ctx);
    expect(after.users).toEqual(before.users);
    expect(after.sessions).toEqual(before.sessions);
    expect(after.accounts.find((row) => row.id !== account.id)).toEqual(
      before.accounts.find((row) => row.id !== account.id),
    );
    expect(after.accounts.find((row) => row.id === account.id)).toMatchObject({
      userId: account.userId,
      accountId: account.accountId,
      accessToken: "fixture-atlassian-access-rotated",
      refreshToken: "fixture-atlassian-refresh-rotated",
    });
    const requests = await receipts(ctx);
    expect(requests[2]!.body).toEqual({
      grant_type: "refresh_token",
      refresh_token: "fixture-atlassian-refresh",
      client_id: "fixture-social-client",
      client_secret: "fixture-social-secret",
    });
    const signOut = await flow.actor.client.signOut();
    expect(signOut.error).toBeNull();
    expect((await flow.actor.client.getSession()).data).toBeNull();
    expect(await receipts(ctx)).toHaveLength(3);
    return {
      before,
      denied: ctx.snapshot(denied),
      refreshed: ctx.snapshot(refreshed),
      after,
      signOut: ctx.snapshot(signOut),
      signedOut: await state(ctx),
      receipts: requests,
    };
  },
  ["POST /refresh-token", "POST /sign-out"],
);
for (const expiry of ["absent", "zero", "fractional"] as const)
  compatScenario(
    `atlassian ${expiry} token expiry has no fabricated default`,
    async (ctx) => {
      await control(ctx, {
        profile: profile(ctx),
        tokenResponse: {
          access_token: "fixture-atlassian-access",
          refresh_token: "fixture-atlassian-refresh",
          scope: "read:jira-user offline_access",
          ...(expiry === "zero"
            ? { expires_in: 0 }
            : expiry === "fractional"
              ? { expires_in: 0.5 }
              : {}),
        },
      });
      const flow = await callback(ctx);
      expect(flow.response.headers.get("location")).toBe("/dashboard");
      const persisted = await state(ctx);
      expect(persisted.accounts).toHaveLength(1);
      if (expiry !== "fractional") expect(persisted.accounts[0]!.accessTokenExpiresAt).toBeNull();
      else expect(persisted.accounts[0]!.accessTokenExpiresAt).toBeTruthy();
      return {
        callback: { status: flow.response.status, location: flow.response.headers.get("location") },
        persisted,
        receipts: await receipts(ctx),
      };
    },
    ["POST /sign-in/social", "GET /callback/{}"],
  );
compatScenario(
  "atlassian unsupported ID token and invalid provider/state produce no requests",
  async (ctx) => {
    const actor = ctx.actor("atlassian", "social-atlassian-default");
    const before = await state(ctx);
    const token = await actor.client.signIn.social({
      provider: "atlassian",
      idToken: { token: "untrusted.payload.signature", nonce: "untrusted-nonce" },
    });
    expect(token.error?.code).toBe("ID_TOKEN_NOT_SUPPORTED");
    const wrong = await actor.client.signIn.social({ provider: "google" });
    expect(wrong.error?.code).toBe("PROVIDER_NOT_FOUND");
    const badState = await actor.fetch(
      ctx.baseURL +
        authProfilePath("social-atlassian-default") +
        "/callback/atlassian?code=fixture-code&state=unissued-state",
      { redirect: "manual" },
    );
    expect(badState.status).toBe(302);
    expect(new URL(badState.headers.get("location")!, ctx.baseURL).searchParams.get("error")).toBe(
      "state_mismatch",
    );
    expect(await state(ctx)).toEqual(before);
    expect(await receipts(ctx)).toHaveLength(0);
    return {
      token: ctx.snapshot(token),
      wrong: ctx.snapshot(wrong),
      badState: { status: badState.status, location: badState.headers.get("location") },
      before,
      after: await state(ctx),
      receipts: await receipts(ctx),
    };
  },
);
