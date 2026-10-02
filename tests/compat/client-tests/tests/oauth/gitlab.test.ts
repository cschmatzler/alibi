import { expect } from "bun:test";

import { authProfilePath, type FixtureProfile } from "../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../support/scenario";

type Receipt = {
  path: string;
  method: string;
  authorization: string | null;
  contentType: string | null;
  body: Record<string, string> | null;
};

type State = {
  users: Record<string, unknown>[];
  accounts: Record<string, unknown>[];
  sessions: Record<string, unknown>[];
  receipts: Receipt[];
};

async function state(ctx: ScenarioContext): Promise<State> {
  const response = await ctx.rawRequest({ path: "/__test/social-provider/state" });
  expect(response.status).toBe(200);
  return response.body as State;
}

function rows(snapshot: State) {
  const { receipts, ...stored } = snapshot;
  return stored;
}

function observed(snapshot: State) {
  return {
    ...snapshot,
    receipts: snapshot.receipts.map((receipt) => ({
      ...receipt,
      body: receipt.body?.code_verifier
        ? {
            ...receipt.body,
            code_verifier: {
              token: receipt.body.code_verifier,
              length: receipt.body.code_verifier.length,
            },
          }
        : receipt.body,
    })),
  };
}

async function configure(ctx: ScenarioContext, profile: Record<string, unknown>) {
  const response = await ctx.rawRequest({
    path: "/__test/social-provider/profile",
    method: "POST",
    json: profile,
  });
  expect(response.status).toBe(200);
  expect(response.body).toEqual({ status: true, profile });

  return response;
}

async function callback(
  actor: ReturnType<ScenarioContext["actor"]>,
  fixture: FixtureProfile,
  url: string,
) {
  const state = new URL(url).searchParams.get("state");

  if (!state) {
    throw new Error("actual issued state required");
  }

  const path = `${authProfilePath(fixture)}/callback/gitlab?${new URLSearchParams({ code: "fixture-code", state })}`;
  const response = await actor.fetch(path, { redirect: "manual" });
  return {
    path,
    response: {
      status: response.status,
      location: response.headers.get("location"),
      body: await response.text(),
    },
  };
}

async function assertExchange(
  ctx: ScenarioContext,
  url: string,
  receipt: Receipt,
  fixture: FixtureProfile,
) {
  const verifier = receipt.body?.code_verifier;

  if (!verifier) {
    throw new Error("actual provider PKCE verifier required");
  }

  expect(verifier).toHaveLength(128);
  expect(verifier).toMatch(/^[a-zA-Z0-9_-]+$/);

  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  const challenge = Buffer.from(digest).toString("base64url");
  expect(new URL(url).searchParams.get("code_challenge")).toBe(challenge);
  expect(receipt).toEqual({
    path: "/__test/social-provider/gitlab/oauth/token",
    method: "POST",
    authorization: null,
    contentType: "application/x-www-form-urlencoded",
    body: {
      grant_type: "authorization_code",
      code: "fixture-code",
      code_verifier: verifier,
      redirect_uri: `${ctx.baseURL}${authProfilePath(fixture)}/callback/gitlab`,
      client_id: "fixture-social-client",
      client_secret: "fixture-social-secret",
    },
  });
}

compatScenario(
  "GitLab authorization preserves hosted issuer ordered scopes and authenticated link PKCE",
  async (ctx) => {
    const owner = ctx.actor("owner", "social-gitlab-issuer");
    const signup = await owner.client.signUp.email({
      email: ctx.uniqueEmail("gitlab-authorization"),
      password: "password123",
      name: "GitLab Link Owner",
    });
    expect(signup.error).toBeNull();

    const before = await state(ctx);
    const ownerBefore = await ctx.readUserState({ userId: signup.data!.user.id });

    const table = [
      ["default", ["read_user", "read_user", "read_user requested requested", "read_user "]],
      [
        "configured",
        [
          "read_user configured-scope",
          "read_user configured-scope",
          "read_user configured-scope requested requested",
          "read_user configured-scope ",
        ],
      ],
      ["disabled", [null, null, "requested requested", ""]],
      [
        "disabled-configured",
        [
          "configured-scope",
          "configured-scope",
          "configured-scope requested requested",
          "configured-scope ",
        ],
      ],
      ["issuer", ["read_user", "read_user", "read_user requested requested", "read_user "]],
      ["issuer-slashes", ["read_user", "read_user", "read_user requested requested", "read_user "]],
    ] as const;

    const results = [];

    for (const [mode, scopes] of table) {
      const fixture = `social-gitlab-${mode}` as FixtureProfile;
      const actor = ctx.actor(mode, fixture);
      for (const [index, requested] of [
        undefined,
        [],
        ["requested", "requested"],
        [""],
      ].entries()) {
        const result = await actor.client.signIn.social({
          provider: "gitlab",
          callbackURL: "/gitlab-done",
          disableRedirect: true,
          ...(requested ? { scopes: requested } : {}),
        });
        expect(result.error).toBeNull();

        const url = new URL(result.data!.url!);
        expect(`${url.origin}${url.pathname}`).toBe(
          mode.startsWith("issuer")
            ? `${ctx.baseURL}/__test/social-provider/gitlab/oauth/authorize`
            : "https://gitlab.com/oauth/authorize",
        );
        expect(url.searchParams.getAll("scope")).toEqual(
          scopes[index] === null ? [] : [scopes[index]!],
        );
        expect(url.searchParams.get("code_challenge_method")).toBe("S256");
        expect(url.searchParams.get("code_challenge")).toBeTruthy();
        expect(url.searchParams.get("redirect_uri")).toBe(
          `${ctx.baseURL}${authProfilePath(fixture)}/callback/gitlab`,
        );

        results.push({ mode, requested: requested ?? null, result: ctx.snapshot(result) });
      }
    }

    const guest = await ctx.actor("guest", "social-gitlab-issuer").client.linkSocial({
      provider: "gitlab",
      callbackURL: "/gitlab-done",
      disableRedirect: true,
    });
    expect(guest.error?.status).toBe(401);

    const linked = await owner.client.linkSocial({
      provider: "gitlab",
      callbackURL: "/gitlab-done",
      disableRedirect: true,
      scopes: ["requested", "requested"],
    });
    expect(linked.error).toBeNull();

    const url = new URL(linked.data!.url!);
    expect(url.searchParams.get("scope")).toBe("read_user requested requested");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(await state(ctx)).toEqual(before);
    expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(ownerBefore);

    return {
      signup: ctx.snapshot(signup),
      before,
      ownerBefore,
      results,
      guest: ctx.snapshot(guest),
      linked: ctx.snapshot(linked),
      after: await state(ctx),
      ownerAfter: await ctx.readUserState({ userId: signup.data!.user.id }),
    };
  },
  ["POST /sign-in/social", "POST /link-social"],
);

compatScenario(
  "GitLab self hosted callback login link refresh and replay preserve actual account and foreign owners",
  async (ctx) => {
    const fixture = "social-gitlab-issuer";
    const primary = ctx.actor("primary", fixture);
    const foreign = ctx.actor("foreign", fixture);
    const foreignSignup = await foreign.client.signUp.email({
      email: ctx.uniqueEmail("gitlab-foreign"),
      password: "password123",
      name: "Foreign Owner",
    });
    expect(foreignSignup.error).toBeNull();

    const foreignBefore = await ctx.readUserState({ userId: foreignSignup.data!.user.id });

    const profile = {
      id: 9007199254740992,
      email: ctx.uniqueEmail("gitlab-owner"),
      name: null,
      username: "GitLab Owner",
      avatar_url: "https://example.test/gitlab-avatar.png",
      email_verified: true,
      state: "active",
      locked: false,
    };
    const control = await configure(ctx, profile);
    const before = await state(ctx);
    const signin = await primary.client.signIn.social({
      provider: "gitlab",
      callbackURL: "/gitlab-done",
      disableRedirect: true,
      scopes: ["requested-scope"],
    });
    expect(signin.error).toBeNull();

    const completed = await callback(primary, fixture, signin.data!.url!);
    expect(completed.response).toMatchObject({ status: 302, location: "/gitlab-done" });

    const current = await primary.client.getSession();
    expect(current.data!.user).toMatchObject({
      email: profile.email,
      name: "GitLab Owner",
      image: profile.avatar_url,
      emailVerified: true,
    });
    expect(current.data!.session.userId).toBe(current.data!.user.id);
    expect(current.data!.user.id).not.toBe(foreignSignup.data!.user.id);

    const after = await state(ctx);
    expect(after.users).toHaveLength(before.users.length + 1);
    expect(after.accounts).toHaveLength(before.accounts.length + 1);
    expect(after.sessions).toHaveLength(before.sessions.length + 1);
    expect(after.receipts).toHaveLength(2);

    await assertExchange(ctx, signin.data!.url!, after.receipts[0]!, fixture);
    expect(after.receipts[1]).toEqual({
      path: "/__test/social-provider/gitlab/api/v4/user",
      method: "GET",
      authorization: "Bearer fixture-gitlab-access",
      contentType: null,
      body: null,
    });

    const account = after.accounts.find((row) => row.providerId === "gitlab")!;
    expect(account).toMatchObject({
      userId: current.data!.user.id,
      accountId: "9007199254740992",
      accessToken: "fixture-gitlab-access",
      refreshToken: "fixture-gitlab-refresh",
      scope: "read_user,issued-scope",
    });
    expect(await ctx.readUserState({ userId: foreignSignup.data!.user.id })).toEqual(foreignBefore);

    const replayResponse = await primary.fetch(completed.path, { redirect: "manual" });
    const replay = {
      status: replayResponse.status,
      location: replayResponse.headers.get("location"),
      body: await replayResponse.text(),
    };
    expect(replay.status).toBe(302);
    expect(replay.location).toBe(
      `${ctx.baseURL}${authProfilePath(fixture)}/error?error=state_mismatch`,
    );
    expect(await state(ctx)).toEqual(after);

    const refreshed = await primary.client.refreshToken({ accountId: String(account.id) });
    expect(refreshed.error).toBeNull();
    expect(refreshed.data).toHaveProperty("idToken", null);
    expect(refreshed.data).toMatchObject({
      accessToken: "fixture-gitlab-refreshed-access",
      refreshToken: "fixture-gitlab-refreshed-refresh",
    });

    const afterRefresh = await state(ctx);
    expect(afterRefresh.users).toEqual(after.users);
    expect(afterRefresh.sessions).toEqual(after.sessions);
    expect(afterRefresh.accounts.find((row) => row.id === account.id)).toMatchObject({
      accountId: account.accountId,
      userId: account.userId,
      accessToken: "fixture-gitlab-refreshed-access",
      refreshToken: "fixture-gitlab-refreshed-refresh",
      scope: "read_user,issued-scope",
    });
    expect(afterRefresh.receipts[2]).toEqual({
      path: "/__test/social-provider/gitlab/oauth/token",
      method: "POST",
      authorization: null,
      contentType: "application/x-www-form-urlencoded",
      body: {
        grant_type: "refresh_token",
        refresh_token: "fixture-gitlab-refresh",
        client_id: "fixture-social-client",
        client_secret: "fixture-social-secret",
      },
    });

    const accessed = await primary.client.getAccessToken({ accountId: String(account.id) });
    expect(accessed.error).toBeNull();
    expect(Object.hasOwn(accessed.data!, "idToken")).toBe(false);
    expect(accessed.data).toMatchObject({
      accessToken: "fixture-gitlab-refreshed-access",
      scopes: ["read_user", "issued-scope"],
    });
    expect(await state(ctx)).toEqual(afterRefresh);

    const guest = ctx.actor("guest", fixture);
    const guestAccess = await guest.client.getAccessToken({ accountId: String(account.id) });
    const guestRefresh = await guest.client.refreshToken({ accountId: String(account.id) });
    const guestLink = await guest.client.linkSocial({
      provider: "gitlab",
      callbackURL: "/gitlab-done",
      disableRedirect: true,
    });

    for (const result of [guestAccess, guestRefresh]) {
      expect(result).toEqual({ data: null, error: { status: 401, statusText: "Unauthorized" } });
    }

    expect(guestLink).toEqual({
      data: null,
      error: {
        status: 401,
        statusText: "Unauthorized",
        code: "UNAUTHORIZED",
        message: "Unauthorized",
      },
    });
    expect(await state(ctx)).toEqual(afterRefresh);
    expect(await ctx.readUserState({ userId: foreignSignup.data!.user.id })).toEqual(foreignBefore);

    const deniedAccess = await foreign.client.getAccessToken({ accountId: String(account.id) });
    expect(deniedAccess.error).not.toBeNull();
    expect(await state(ctx)).toEqual(afterRefresh);

    const deniedRefresh = await foreign.client.refreshToken({ accountId: String(account.id) });
    expect(deniedRefresh.error).not.toBeNull();
    expect(await state(ctx)).toEqual(afterRefresh);

    const another = ctx.actor("another", fixture);
    const anotherSignin = await another.client.signIn.social({
      provider: "gitlab",
      callbackURL: "/gitlab-done",
      disableRedirect: true,
    });
    expect(anotherSignin.error).toBeNull();

    const anotherCallback = await callback(another, fixture, anotherSignin.data!.url!);
    expect(anotherCallback.response.location).toBe("/gitlab-done");

    const anotherCurrent = await another.client.getSession();
    expect(anotherCurrent.data!.user.id).toBe(current.data!.user.id);
    expect(anotherCurrent.data!.session.token).not.toBe(current.data!.session.token);

    const afterLogin = await state(ctx);
    expect(afterLogin.users).toEqual(afterRefresh.users);
    expect(afterLogin.accounts).toHaveLength(afterRefresh.accounts.length);
    expect(afterLogin.sessions).toHaveLength(afterRefresh.sessions.length + 1);

    await assertExchange(ctx, anotherSignin.data!.url!, afterLogin.receipts[3]!, fixture);

    const conflict = await foreign.client.linkSocial({
      provider: "gitlab",
      callbackURL: "/gitlab-done",
      disableRedirect: true,
    });
    expect(conflict.error).toBeNull();

    const conflictCallback = await callback(foreign, fixture, conflict.data!.url!);
    expect(conflictCallback.response.status).toBe(302);
    expect(conflictCallback.response.location).toBe(
      `${ctx.baseURL}${authProfilePath(fixture)}/error?error=email_does_not_match`,
    );

    const afterConflict = await state(ctx);
    expect(rows(afterConflict)).toEqual(rows(afterLogin));

    await assertExchange(ctx, conflict.data!.url!, afterConflict.receipts[5]!, fixture);

    const ownProfile = {
      ...profile,
      id: 42,
      email: foreignSignup.data!.user.email,
      name: "Foreign GitLab",
    };
    const ownControl = await configure(ctx, ownProfile);
    const link = await foreign.client.linkSocial({
      provider: "gitlab",
      callbackURL: "/gitlab-done",
      disableRedirect: true,
    });
    expect(link.error).toBeNull();

    const linkCallback = await callback(foreign, fixture, link.data!.url!);
    expect(linkCallback.response.location).toBe("/gitlab-done");

    const afterLink = await state(ctx);
    expect(afterLink.users).toEqual(afterConflict.users);
    expect(afterLink.sessions).toEqual(afterConflict.sessions);
    expect(
      afterLink.accounts.filter(
        (row) => row.userId === foreignSignup.data!.user.id && row.providerId === "gitlab",
      ),
    ).toEqual([
      expect.objectContaining({
        accountId: "42",
        userId: foreignSignup.data!.user.id,
        accessToken: "fixture-gitlab-access",
      }),
    ]);

    const foreignCurrent = await foreign.client.getSession();
    expect(foreignCurrent.data!.session.token).toBe(foreignSignup.data!.token!);
    expect(afterLink.accounts.find((row) => row.id === account.id)?.userId).toBe(
      current.data!.user.id,
    );

    await assertExchange(ctx, link.data!.url!, afterLink.receipts[7]!, fixture);

    return {
      foreignSignup: ctx.snapshot(foreignSignup),
      foreignBefore,
      control,
      before,
      signin: ctx.snapshot(signin),
      completed: completed.response,
      current: ctx.snapshot(current),
      after: observed(after),
      replay,
      refreshed: ctx.snapshot(refreshed),
      afterRefresh: observed(afterRefresh),
      accessed: ctx.snapshot(accessed),
      guestAccess: ctx.snapshot(guestAccess),
      guestRefresh: ctx.snapshot(guestRefresh),
      guestLink: ctx.snapshot(guestLink),
      deniedAccess: ctx.snapshot(deniedAccess),
      deniedRefresh: ctx.snapshot(deniedRefresh),
      anotherSignin: ctx.snapshot(anotherSignin),
      anotherCallback: anotherCallback.response,
      anotherCurrent: ctx.snapshot(anotherCurrent),
      afterLogin: observed(afterLogin),
      conflict: ctx.snapshot(conflict),
      conflictCallback: conflictCallback.response,
      afterConflict: observed(afterConflict),
      ownControl,
      link: ctx.snapshot(link),
      linkCallback: linkCallback.response,
      afterLink: observed(afterLink),
      foreignCurrent: ctx.snapshot(foreignCurrent),
    };
  },
  [
    "POST /sign-in/social",
    "GET /callback/{}",
    "POST /refresh-token",
    "POST /get-access-token",
    "POST /link-social",
  ],
);

compatScenario(
  "GitLab profile admission rejects inactive and truthy locked rows and preserves nullish defaults",
  async (ctx) => {
    const fixture = "social-gitlab-issuer-slashes";
    const foreign = ctx.actor("foreign", fixture);
    const signup = await foreign.client.signUp.email({
      email: ctx.uniqueEmail("gitlab-rejection-foreign"),
      password: "password123",
      name: "Foreign Owner",
    });
    expect(signup.error).toBeNull();

    const foreignBefore = await ctx.readUserState({ userId: signup.data!.user.id });
    const results = [];

    const cases = [
      { mode: "locked", locked: true, allowed: false },
      { mode: "locked-string", locked: "false", allowed: false },
      { mode: "locked-array", locked: [], allowed: false },
      { mode: "inactive", state: "blocked", allowed: false },
      { mode: "missing-state", state: null, allowed: false },
      { mode: "zero-lock", locked: 0, allowed: true },
      { mode: "empty-name", name: "", allowed: true },
      { mode: "missing-name", name: null, username: null, allowed: true },
      { mode: "verified", email_verified: true, allowed: true },
      { mode: "numeric-exponent", id: 1e21, allowed: true },
    ] as const;

    for (const [index, entry] of cases.entries()) {
      const { mode, allowed, ...changes } = entry;
      const profile = {
        id: index + 100,
        email: ctx.uniqueEmail(`gitlab-${mode}`),
        name: null,
        username: "Fallback",
        avatar_url: null,
        state: "active",
        locked: false,
        ...changes,
      };
      const control = await configure(ctx, profile);
      const before = await state(ctx);
      const actor = ctx.actor(mode, fixture);
      const signin = await actor.client.signIn.social({
        provider: "gitlab",
        callbackURL: "/gitlab-done",
        disableRedirect: true,
      });
      expect(signin.error).toBeNull();

      const completed = await callback(actor, fixture, signin.data!.url!);
      const after = await state(ctx);
      expect(after.receipts).toHaveLength(before.receipts.length + 2);

      await assertExchange(ctx, signin.data!.url!, after.receipts.at(-2)!, fixture);
      const current = await actor.client.getSession();
      expect(current.error).toBeNull();

      if (allowed) {
        expect(completed.response.location).toBe("/gitlab-done");
        expect(current.data!.user).toMatchObject({
          email: profile.email,
          name: mode === "empty-name" || mode === "missing-name" ? "" : "Fallback",
          image: null,
          emailVerified: mode === "verified",
        });
        expect(
          after.accounts.filter(
            (row) => row.userId === current.data!.user.id && row.providerId === "gitlab",
          ),
        ).toEqual([
          expect.objectContaining({ accountId: String(profile.id), userId: current.data!.user.id }),
        ]);
        expect(after.users).toHaveLength(before.users.length + 1);
        expect(after.sessions).toHaveLength(before.sessions.length + 1);
      } else {
        expect(completed.response.status).toBe(302);
        expect(completed.response.location).toBe(
          `${ctx.baseURL}${authProfilePath(fixture)}/error?error=unable_to_get_user_info`,
        );
        expect(current.data).toBeNull();
        expect(rows(after)).toEqual(rows(before));

        const replayResponse = await actor.fetch(completed.path, { redirect: "manual" });
        expect(replayResponse.headers.get("location")).toContain("state_mismatch");
        expect(await state(ctx)).toEqual(after);
      }

      expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(foreignBefore);

      results.push({
        mode,
        control,
        before: observed(before),
        signin: ctx.snapshot(signin),
        completed: completed.response,
        current: ctx.snapshot(current),
        after: observed(after),
      });
    }

    return {
      signup: ctx.snapshot(signup),
      foreignBefore,
      results,
      foreignAfter: await ctx.readUserState({ userId: signup.data!.user.id }),
    };
  },
  ["POST /sign-in/social", "GET /callback/{}"],
);
