import { expect } from "bun:test";
import { createHmac } from "node:crypto";

import { createAuthClient } from "better-auth/client";
import { anonymousClient } from "better-auth/client/plugins";
import { jwtVerify } from "jose";
import { Cookie } from "tough-cookie";

import { authProfilePath, type FixtureProfile } from "../../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../../support/scenario";

type State = { users: any[]; accounts: any[]; sessions: any[]; events: any[] };

function actor(ctx: ScenarioContext, name: string, mode = "standard") {
  const profile = `anonymous-${mode}` as FixtureProfile;
  const transport = ctx.actor(name, profile);
  return {
    ...transport,
    profile,
    anonymous: createAuthClient({
      baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
      plugins: [anonymousClient()],
      fetchOptions: { customFetchImpl: transport.fetch },
    }),
  };
}

async function state(ctx: ScenarioContext): Promise<State> {
  const response = await ctx.rawRequest({ path: "/__test/anonymous/state" });
  expect(response.status).toBe(200);
  return response.body as State;
}

function stored(value: State) {
  const { events, ...rows } = value;
  return rows;
}

const fixtureSecret = ["compat", "test", "only", "key", "not", "real", "minimum", "32chars"].join(
  "-",
);

function signedPayload(value: string) {
  const decoded = decodeURIComponent(value);
  const separator = decoded.lastIndexOf(".");
  expect(separator).toBeGreaterThan(0);

  const payload = decoded.slice(0, separator);
  const signature = decoded.slice(separator + 1);
  expect(signature).toBe(createHmac("sha256", fixtureSecret).update(payload).digest("base64"));

  return payload;
}

async function observedCookies(
  ctx: ScenarioContext,
  headers: string[],
  binding: { state?: string; token?: string } = {},
) {
  const result = [];
  for (const header of headers) {
    const cookie = Cookie.parse(header);
    expect(cookie).toBeDefined();

    if (!cookie) {
      throw new Error("Actual issued cookie must parse");
    }

    const encoded = Buffer.from(cookie.value).toString("base64url");
    expect(Buffer.from(encoded, "base64url").toString()).toBe(cookie.value);

    if (cookie.value && cookie.key.endsWith(".state")) {
      expect(binding.state).toBeTruthy();
      if (cookie.value.split(".").length === 3) {
        const checked = await jwtVerify(cookie.value, new TextEncoder().encode(fixtureSecret), {
          algorithms: ["HS256"],
        });
        expect(checked.protectedHeader).toEqual({ typ: "JWT", alg: "HS256" });
        expect(Object.keys(checked.payload).sort()).toEqual(["exp", "iat", "state"]);
        expect(checked.payload.state).toBe(binding.state!);
        expect(checked.payload.exp! - checked.payload.iat!).toBe(600);
        expect(Math.abs(Date.now() / 1000 - checked.payload.iat!)).toBeLessThan(5);
      } else {
        expect(signedPayload(cookie.value)).toBe(binding.state!);
      }
    }

    if (cookie.value && cookie.key.endsWith(".session_token")) {
      expect(binding.token).toBeTruthy();
      expect(signedPayload(cookie.value)).toBe(binding.token!);
    }

    result.push({
      name: cookie.key,
      value: cookie.value ? { token: encoded } : { literal: "" },
      domain: cookie.domain ?? null,
      path: cookie.path ?? null,
      httpOnly: cookie.httpOnly,
      secure: cookie.secure,
      sameSite: cookie.sameSite ?? null,
      maxAge: cookie.maxAge ?? null,
      // Existing transport semantics: Max-Age takes precedence over Expires.
      // Original inactive Expires, spelling, and attribute order remain in raw evidence.
      expiresAt:
        cookie.maxAge === undefined && cookie.expires instanceof Date
          ? cookie.expires.toISOString()
          : null,
      extensions: cookie.extensions ?? null,
      ...(cookie.value && cookie.key.endsWith(".state")
        ? { payload: { state: binding.state } }
        : {}),
      ...(cookie.value && cookie.key.endsWith(".session_token")
        ? { payload: { token: binding.token } }
        : {}),
    });
  }
  return result;
}

compatScenario(
  "anonymous official client issues repeats and deletes only its actual authenticated owner",
  async (ctx) => {
    const primary = actor(ctx, "primary");
    const foreign = actor(ctx, "foreign");
    const guest = actor(ctx, "guest");
    const foreignSignup = await foreign.client.signUp.email({
      email: ctx.uniqueEmail("anonymous-foreign"),
      name: "Foreign Owner",
      password: "password123",
    });
    expect(foreignSignup.error).toBeNull();

    const foreignBefore = await ctx.readUserState({ userId: foreignSignup.data!.user.id });
    const guestDenied = await guest.anonymous.deleteAnonymousUser();
    expect(guestDenied.error).toMatchObject({ status: 401, code: "UNAUTHORIZED" });

    const before = await state(ctx);
    const issued = await primary.anonymous.signIn.anonymous();
    expect(issued.error).toBeNull();
    expect(issued.data!.user).toMatchObject({
      email: "anonymous-1@fixture.test",
      name: "Configured Anonymous",
      emailVerified: false,
      isAnonymous: true,
    });

    const current = await primary.client.getSession();
    expect(current.data!.session.userId).toBe(issued.data!.user.id);
    expect(current.data!.session.token).toBe(issued.data!.token);

    const afterIssued = await state(ctx);
    expect(afterIssued.users).toHaveLength(before.users.length + 1);
    expect(afterIssued.accounts).toEqual(before.accounts);
    expect(afterIssued.sessions).toHaveLength(before.sessions.length + 1);
    expect(afterIssued.events).toHaveLength(0);

    const repeated = await primary.anonymous.signIn.anonymous();
    expect(repeated.error).toMatchObject({
      status: 400,
      code: "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY",
    });

    const regularDenied = await foreign.anonymous.deleteAnonymousUser();
    expect(regularDenied.error).toMatchObject({ status: 403, code: "USER_IS_NOT_ANONYMOUS" });
    expect(await state(ctx)).toEqual(afterIssued);

    const deleted = await primary.anonymous.deleteAnonymousUser();
    expect(deleted.data).toEqual({ success: true });

    const afterDelete = await state(ctx);
    expect(stored(afterDelete)).toEqual(stored(before));

    const stale = await primary.client.getSession();
    const replay = await primary.anonymous.deleteAnonymousUser();
    expect(stale.data).toBeNull();
    expect(replay.error).toMatchObject({ status: 401, code: "UNAUTHORIZED" });
    expect(await state(ctx)).toEqual(afterDelete);
    expect(await ctx.readUserState({ userId: foreignSignup.data!.user.id })).toEqual(foreignBefore);

    return {
      foreignSignup,
      foreignBefore,
      guestDenied,
      before,
      issued,
      current,
      afterIssued,
      repeated,
      regularDenied,
      deleted,
      afterDelete,
      stale,
      replay,
      final: await state(ctx),
      foreignAfter: await ctx.readUserState({ userId: foreignSignup.data!.user.id }),
    };
  },
  ["POST /sign-in/anonymous", "POST /delete-anonymous-user"],
);

compatScenario(
  "anonymous upgrade transfers original completed user and session snapshots before cleanup",
  async (ctx) => {
    const primary = actor(ctx, "primary", "snapshot");
    const foreign = actor(ctx, "foreign", "snapshot");
    const foreignSignup = await foreign.client.signUp.email({
      email: ctx.uniqueEmail("anonymous-snapshot-foreign"),
      name: "Foreign Snapshot",
      password: "password123",
    });
    expect(foreignSignup.error).toBeNull();

    const foreignBefore = await ctx.readUserState({ userId: foreignSignup.data!.user.id });
    const anonymous = await primary.anonymous.signIn.anonymous();
    expect(anonymous.error).toBeNull();

    const oldSession = await primary.client.getSession();
    const before = await state(ctx);
    const upgrade = await primary.client.signUp.email({
      email: ctx.uniqueEmail("anonymous-upgrade"),
      name: "Original New Owner",
      password: "password123",
    });
    expect(upgrade.error).toBeNull();
    expect(upgrade.data!.user.name).toBe("Original New Owner");

    const after = await state(ctx);
    expect(after.events).toHaveLength(1);

    const receipt = after.events[0];
    expect(receipt).toMatchObject(
      ctx.snapshot({
        mode: "snapshot",
        path: "/sign-up/email",
        anonymousUser: { user: anonymous.data!.user, session: oldSession.data!.session },
        newUser: {
          user: upgrade.data!.user,
          session: { userId: upgrade.data!.user.id, token: upgrade.data!.token },
        },
      }) as any,
    );
    expect(receipt.newUser.user.name).toBe("Original New Owner");
    expect(after.users.find((row) => row.id === upgrade.data!.user.id)?.name).toBe(
      "Stored Hook Name",
    );
    expect(after.users.some((row) => row.id === anonymous.data!.user.id)).toBe(false);
    expect(after.sessions.some((row) => row.userId === anonymous.data!.user.id)).toBe(false);

    const current = await primary.client.getSession();
    expect(current.data!.user).toMatchObject({
      id: upgrade.data!.user.id,
      name: "Stored Hook Name",
      isAnonymous: false,
    });
    expect(current.data!.session.token).toBe(upgrade.data!.token!);
    expect(await ctx.readUserState({ userId: foreignSignup.data!.user.id })).toEqual(foreignBefore);

    return {
      foreignSignup,
      foreignBefore,
      anonymous,
      oldSession,
      before,
      upgrade,
      after,
      current,
      foreignAfter: await ctx.readUserState({ userId: foreignSignup.data!.user.id }),
    };
  },
  ["POST /sign-in/anonymous", "POST /sign-up/email"],
);

compatScenario(
  "anonymous cancellation application errors and disabled cleanup retain stage-specific committed state",
  async (ctx) => {
    const results = [];

    for (const [mode, status, code, userCount] of [
      ["user-cancel", 500, "FAILED_TO_CREATE_USER", 0],
      ["user-forbidden", 403, "FORBIDDEN", 0],
      ["session-cancel", 400, "COULD_NOT_CREATE_SESSION", 1],
      ["session-forbidden", 403, "FORBIDDEN", 1],
      ["invalid-email", 400, "INVALID_EMAIL_FORMAT", 0],
    ] as const) {
      const owner = actor(ctx, mode, mode);
      const before = await state(ctx);
      const result = await owner.anonymous.signIn.anonymous();
      expect(result.error).toMatchObject(
        code === "FORBIDDEN"
          ? {
              status,
              message: `${mode.startsWith("user") ? "user" : "session"} creation cancelled by database hook`,
            }
          : { status, code },
      );

      const after = await state(ctx);
      expect(after.users).toHaveLength(before.users.length + userCount);
      expect(after.sessions).toEqual(before.sessions);
      expect(after.accounts).toEqual(before.accounts);
      expect(after.events).toEqual(before.events);

      const current = await owner.client.getSession();
      expect(current.data).toBeNull();

      results.push({ mode, before, result, after, current });
    }

    const emptyName = await actor(ctx, "empty-name", "empty-name").anonymous.signIn.anonymous();
    expect(emptyName.data!.user.name).toBe("Anonymous");

    const disabled = actor(ctx, "disabled", "disabled");
    const anonymous = await disabled.anonymous.signIn.anonymous();
    const beforeDisabled = await state(ctx);
    const deleteDenied = await disabled.anonymous.deleteAnonymousUser();
    expect(deleteDenied.error).toMatchObject({
      status: 400,
      code: "DELETE_ANONYMOUS_USER_DISABLED",
    });
    expect(await state(ctx)).toEqual(beforeDisabled);

    const upgraded = await disabled.client.signUp.email({
      email: ctx.uniqueEmail("anonymous-disabled"),
      name: "Retained Upgrade",
      password: "password123",
    });
    expect(upgraded.error).toBeNull();

    const afterDisabled = await state(ctx);
    expect(afterDisabled.events).toHaveLength(1);
    expect(afterDisabled.users.find((row) => row.id === anonymous.data!.user.id)?.isAnonymous).toBe(
      true,
    );
    expect(afterDisabled.sessions.some((row) => row.userId === anonymous.data!.user.id)).toBe(true);

    const errors = actor(ctx, "errors", "link-error");
    const errorAnonymous = await errors.anonymous.signIn.anonymous();
    const beforeError = await state(ctx);
    const deniedUpgrade = await errors.client.signUp.email({
      email: ctx.uniqueEmail("anonymous-transfer-error"),
      name: "Committed Transfer",
      password: "password123",
    });
    expect(deniedUpgrade.error).toMatchObject({ status: 403, code: "APPLICATION_LINK_DENIED" });

    const afterError = await state(ctx);
    expect(afterError.users).toHaveLength(beforeError.users.length + 1);
    expect(afterError.sessions).toHaveLength(beforeError.sessions.length + 1);
    expect(afterError.accounts).toHaveLength(beforeError.accounts.length + 1);
    expect(afterError.users.some((row) => row.id === errorAnonymous.data!.user.id)).toBe(true);
    expect(afterError.events).toHaveLength(beforeError.events.length + 1);

    return {
      results,
      emptyName,
      anonymous,
      beforeDisabled,
      deleteDenied,
      upgraded,
      afterDisabled,
      errorAnonymous,
      beforeError,
      deniedUpgrade,
      afterError,
      errorCurrent: await errors.client.getSession(),
    };
  },
  ["POST /sign-in/anonymous", "POST /sign-up/email"],
);

compatScenario(
  "anonymous OAuth recovers only server-captured owner without the original anonymous cookie",
  async (ctx) => {
    const primary = actor(ctx, "primary");
    const foreign = actor(ctx, "foreign");
    const foreignAnonymous = await foreign.anonymous.signIn.anonymous();
    const foreignBefore = await ctx.readUserState({ userId: foreignAnonymous.data!.user.id });
    const issued = await primary.anonymous.signIn.anonymous();
    const oldSession = await primary.client.getSession();
    expect(issued.error).toBeNull();

    const profile = {
      id: 123456,
      email: ctx.uniqueEmail("anonymous-oauth"),
      name: "OAuth Upgrade",
      username: "oauth-upgrade",
      avatar_url: null,
      email_verified: true,
      state: "active",
      locked: false,
    };
    const configured = await ctx.rawRequest({
      path: "/__test/social-provider/profile",
      method: "POST",
      json: profile,
    });
    expect(configured.status).toBe(200);

    let cookies: string[] = [];
    const initiated = await primary.client.signIn.social(
      {
        provider: "gitlab",
        callbackURL: "/anonymous-done",
        disableRedirect: true,
        additionalData: {
          serverContext: { anonymousUserId: foreignAnonymous.data!.user.id },
          _serverContextProof: "forged",
          application: "retained",
        },
      },
      {
        onSuccess(context) {
          cookies = context.response.headers.getSetCookie();
        },
      },
    );
    expect(initiated.error).toBeNull();
    expect(cookies).toHaveLength(1);
    expect(cookies[0]).not.toContain("session_token");

    const before = await state(ctx);
    const authorization = new URL(initiated.data!.url!);
    const stateId = authorization.searchParams.get("state")!;
    const callbackPath = `${authProfilePath(primary.profile)}/callback/gitlab?code=fixture-code&state=${encodeURIComponent(stateId)}`;
    const cookie = cookies.map((value) => value.split(";")[0]).join("; ");
    expect(cookie).not.toContain(issued.data!.token);

    const response = await primary.fetch(callbackPath, { redirect: "manual", headers: { cookie } });
    const completedWire = {
      status: response.status,
      location: response.headers.get("location"),
      body: await response.text(),
      cookies: response.headers.getSetCookie(),
    };
    const completed = {
      ...completedWire,
      cookies: await observedCookies(ctx, completedWire.cookies, {
        token: (await primary.client.getSession()).data!.session.token,
      }),
    };
    expect(completed).toMatchObject({ status: 302, location: "/anonymous-done" });

    const current = await primary.client.getSession();
    const after = await state(ctx);
    expect(current.data!.user).toMatchObject({
      email: profile.email,
      name: profile.name,
      isAnonymous: false,
    });
    expect(current.data!.user.id).not.toBe(issued.data!.user.id);
    expect(current.data!.user.id).not.toBe(foreignAnonymous.data!.user.id);
    expect(after.events).toHaveLength(1);
    expect(after.events[0]).toMatchObject(
      ctx.snapshot({
        path: "/callback/gitlab",
        anonymousUser: { user: issued.data!.user, session: oldSession.data!.session },
        newUser: { user: current.data!.user, session: current.data!.session },
      }) as any,
    );
    expect(after.users.some((row) => row.id === issued.data!.user.id)).toBe(false);
    expect(after.sessions.some((row) => row.userId === issued.data!.user.id)).toBe(false);
    expect(await ctx.readUserState({ userId: foreignAnonymous.data!.user.id })).toEqual(
      foreignBefore,
    );

    const replayResponse = await primary.fetch(callbackPath, {
      redirect: "manual",
      headers: { cookie },
    });
    const replay = {
      status: replayResponse.status,
      location: replayResponse.headers.get("location"),
      body: await replayResponse.text(),
      cookies: await observedCookies(ctx, replayResponse.headers.getSetCookie()),
    };
    expect(replay.location).toContain("state_mismatch");
    expect(await state(ctx)).toEqual(after);

    return {
      foreignAnonymous,
      foreignBefore,
      issued,
      oldSession,
      configured,
      initiated,
      stateCookies: await observedCookies(ctx, cookies, { state: stateId }),
      before,
      completed,
      current,
      after,
      replay,
      final: await state(ctx),
      foreignAfter: await ctx.readUserState({ userId: foreignAnonymous.data!.user.id }),
    };
  },
  ["POST /sign-in/social", "GET /callback/{}"],
);

compatScenario(
  "anonymous issuance inherits only a real signed browser-session preference",
  async (ctx) => {
    const primary = actor(ctx, "primary");
    const foreign = actor(ctx, "foreign");
    const signup = await primary.client.signUp.email({
      email: ctx.uniqueEmail("anonymous-browser-owner"),
      name: "Browser Owner",
      password: "password123",
    });
    const foreignSignup = await foreign.client.signUp.email({
      email: ctx.uniqueEmail("anonymous-browser-foreign"),
      name: "Foreign Browser",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    expect(foreignSignup.error).toBeNull();

    const foreignBefore = await ctx.readUserState({ userId: foreignSignup.data!.user.id });
    let signedCookies: string[] = [];
    const regular = await primary.client.signIn.email(
      {
        email: ctx.uniqueEmail("anonymous-browser-owner"),
        password: "password123",
        rememberMe: false,
      },
      {
        onSuccess(context) {
          signedCookies = context.response.headers.getSetCookie();
        },
      },
    );
    expect(regular.error).toBeNull();

    const preference = signedCookies
      .map((header) => Cookie.parse(header))
      .find((cookie) => cookie?.key.endsWith(".dont_remember"));
    expect(preference).toBeDefined();
    expect(signedPayload(preference!.value)).toBe("true");

    const before = await state(ctx);
    const regularBefore = await ctx.readUserState({ userId: signup.data!.user.id });
    let issuedCookies: string[] = [];
    const issued = await primary.anonymous.signIn.anonymous(
      {},
      {
        onSuccess(context) {
          issuedCookies = context.response.headers.getSetCookie();
        },
      },
    );
    expect(issued.error).toBeNull();

    const parsed = issuedCookies.map((header) => Cookie.parse(header));
    expect(parsed.map((cookie) => cookie!.key)).toEqual([
      "better-auth.session_token",
      "better-auth.dont_remember",
    ]);

    for (const cookie of parsed) {
      expect(cookie!.maxAge ?? null).toBeNull();
      expect(cookie!.expires).toBe("Infinity");
    }

    expect(signedPayload(parsed[0]!.value)).toBe(issued.data!.token!);
    expect(signedPayload(parsed[1]!.value)).toBe("true");

    const current = await primary.client.getSession();
    const after = await state(ctx);
    expect(current.data!.session.userId).toBe(issued.data!.user.id);
    expect(current.data!.session.token).toBe(issued.data!.token);
    expect((current.data!.user as any).isAnonymous).toBe(true);
    expect(after.users).toHaveLength(before.users.length + 1);
    expect(after.sessions).toHaveLength(before.sessions.length + 1);
    expect(after.accounts).toEqual(before.accounts);
    expect(after.events).toHaveLength(0);
    expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(regularBefore);
    expect(await ctx.readUserState({ userId: foreignSignup.data!.user.id })).toEqual(foreignBefore);

    const invalid = actor(ctx, "tampered-preference");
    const decoded = decodeURIComponent(preference!.value);
    const separator = decoded.lastIndexOf(".");
    const forgedPreference = encodeURIComponent(
      `${decoded.slice(0, separator + 1)}${decoded[separator + 1] === "A" ? "B" : "A"}${decoded.slice(separator + 2)}`,
    );
    expect(forgedPreference).not.toBe(preference!.value);

    let durableCookies: string[] = [];
    const durable = await invalid.anonymous.signIn.anonymous(
      {},
      {
        headers: { cookie: `${preference!.key}=${forgedPreference}` },
        onSuccess(context) {
          durableCookies = context.response.headers.getSetCookie();
        },
      },
    );
    expect(durable.error).toBeNull();
    expect(durableCookies).toHaveLength(1);

    const durableCookie = Cookie.parse(durableCookies[0]!);
    expect(durableCookie!.key).toBe("better-auth.session_token");
    expect(durableCookie!.maxAge).toBe(604800);
    expect(signedPayload(durableCookie!.value)).toBe(durable.data!.token!);

    const durableCurrent = await invalid.client.getSession();
    const final = await state(ctx);
    expect(durableCurrent.data!.session.userId).toBe(durable.data!.user.id);
    expect(durableCurrent.data!.session.token).toBe(durable.data!.token);
    expect(final.users).toHaveLength(after.users.length + 1);
    expect(final.sessions).toHaveLength(after.sessions.length + 1);
    expect(final.accounts).toEqual(after.accounts);
    expect(final.events).toEqual(after.events);

    return {
      signup,
      foreignSignup,
      foreignBefore,
      regular,
      before,
      regularBefore,
      issued,
      cookies: await observedCookies(ctx, issuedCookies, { token: issued.data!.token! }),
      current,
      after,
      durable,
      durableCookies: await observedCookies(ctx, durableCookies, { token: durable.data!.token! }),
      durableCurrent,
      final,
      regularAfter: await ctx.readUserState({ userId: signup.data!.user.id }),
      foreignAfter: await ctx.readUserState({ userId: foreignSignup.data!.user.id }),
    };
  },
  ["POST /sign-in/anonymous"],
);
