import { expect } from "bun:test";
import { createHmac } from "node:crypto";

import { createAuthClient } from "better-auth/client";
import { multiSessionClient } from "better-auth/client/plugins";
import { z } from "zod";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

type Context = Parameters<Parameters<typeof compatScenario>[1]>[0];
type Profile = Extract<
  import("../../../support/profiles").FixtureProfile,
  `multi-session${string}`
>;

function multiClient(ctx: Context, profile: Profile = "multi-session", actor = "browser") {
  return createAuthClient({
    baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
    plugins: [multiSessionClient()],
    fetchOptions: { customFetchImpl: ctx.actor(actor, profile).fetch },
  });
}

const stateSchema = z.object({
  user: z.object({ id: z.string() }).passthrough().nullable(),
  accounts: z.array(z.unknown()),
  sessions: z.array(
    z
      .object({ id: z.string(), token: z.string(), userId: z.string(), expiresAt: z.string() })
      .passthrough(),
  ),
});

for (const profile of [
  "multi-session",
  "multi-session-cookie-alias",
  "multi-session-cookie-prefix",
] as const) {
  compatScenario(
    profile === "multi-session"
      ? "multiple browser sessions retain accounts switch active identity and revoke with fallback"
      : `${profile} retain accounts switch active identity and revoke with fallback`,
    async (ctx) => {
      const client = multiClient(ctx, profile);
      const alice = await client.signUp.email({
        email: ctx.uniqueEmail("multi-alice"),
        password: "password123",
        name: "Alice",
      });
      expect(alice.error).toBeNull();

      const bob = await client.signUp.email({
        email: ctx.uniqueEmail("multi-bob"),
        password: "password123",
        name: "Bob",
      });
      expect(bob.error).toBeNull();

      if (!alice.data || !bob.data || !alice.data.token || !bob.data.token) {
        throw new Error("two user sessions expected");
      }

      const list = await client.multiSession.listDeviceSessions();
      expect(list.error).toBeNull();
      expect(list.data).toHaveLength(2);
      expect(list.data?.map((item) => item.user.id)).toEqual([
        bob.data.user.id,
        alice.data.user.id,
      ]);

      const select = await client.multiSession.setActive({ sessionToken: alice.data.token });
      expect(select.error).toBeNull();
      expect(select.data?.session.token).toBe(alice.data.token);

      const active = await client.getSession();
      expect(active.data?.user.id).toBe(alice.data.user.id);

      const outsider = await multiClient(ctx, profile, "outsider").multiSession.setActive({
        sessionToken: alice.data.token,
      });
      expect(outsider.error?.code).toBe("INVALID_SESSION_TOKEN");

      const otherClient = multiClient(ctx, profile, "outsider");
      const other = await otherClient.signUp.email({
        email: ctx.uniqueEmail("multi-outsider"),
        password: "password123",
        name: "Other Browser",
      });
      expect(other.error).toBeNull();

      const foreignRevoke = await otherClient.multiSession.revoke({
        sessionToken: alice.data.token,
      });
      expect(foreignRevoke.error?.code).toBe("INVALID_SESSION_TOKEN");

      const unchanged = stateSchema.parse(await ctx.readUserState({ userId: alice.data.user.id }));
      expect(unchanged.sessions).toHaveLength(1);
      expect(unchanged.sessions[0]?.token).toBe(alice.data.token);
      expect((await otherClient.getSession()).data?.user.id).toBe(other.data?.user.id);

      await otherClient.signOut();
      expect(stateSchema.parse(await ctx.readUserState({ userId: alice.data.user.id }))).toEqual(
        unchanged,
      );

      const revoke = await client.multiSession.revoke({ sessionToken: alice.data.token });
      expect(revoke.data?.status).toBe(true);

      const fallback = await client.getSession();
      expect(fallback.data?.user.id).toBe(bob.data.user.id);

      const old = stateSchema.parse(await ctx.readUserState({ userId: alice.data.user.id }));
      expect(old.user?.id).toBe(alice.data.user.id);
      expect(old.sessions).toHaveLength(0);

      const replay = await client.multiSession.setActive({ sessionToken: alice.data.token });
      expect(replay.error?.code).toBe("INVALID_SESSION_TOKEN");

      const remaining = await client.multiSession.listDeviceSessions();
      expect(remaining.data).toHaveLength(1);

      const signout = await client.signOut();
      expect(signout.error).toBeNull();

      const after = await client.multiSession.listDeviceSessions();
      expect(after.data).toEqual([]);

      const bobState = stateSchema.parse(await ctx.readUserState({ userId: bob.data.user.id }));
      expect(bobState.sessions).toHaveLength(0);

      return {
        alice,
        bob,
        list,
        select,
        active,
        outsider,
        other,
        foreignRevoke,
        unchanged,
        revoke,
        fallback,
        old,
        replay,
        remaining,
        signout,
        after,
        bobState,
      };
    },
    [
      "GET /multi-session/list-device-sessions",
      "POST /multi-session/set-active",
      "POST /multi-session/revoke",
      "POST /sign-out",
    ],
  );
}

compatScenario(
  "multiple sessions rotate same-user login and honor configured browser account limit",
  async (ctx) => {
    const client = multiClient(ctx, "multi-session-limited");
    const email = ctx.uniqueEmail("multi-limit-first");
    const first = await client.signUp.email({ email, password: "password123", name: "First" });
    expect(first.error).toBeNull();

    const second = await client.signUp.email({
      email: ctx.uniqueEmail("multi-limit-second"),
      password: "password123",
      name: "Second",
    });
    expect(second.error).toBeNull();

    const third = await client.signUp.email({
      email: ctx.uniqueEmail("multi-limit-third"),
      password: "password123",
      name: "Third",
    });
    expect(third.error).toBeNull();

    if (!first.data || !second.data || !third.data) {
      throw new Error("three accounts expected");
    }

    const list = await client.multiSession.listDeviceSessions();
    expect(list.data).toHaveLength(2);
    expect(list.data?.map((item) => item.user.id)).toEqual([
      second.data.user.id,
      first.data.user.id,
    ]);

    const active = await client.getSession();
    expect(active.data?.user.id).toBe(third.data.user.id);

    const missingCookie = await client.multiSession.setActive({ sessionToken: third.data.token! });
    expect(missingCookie.error?.code).toBe("INVALID_SESSION_TOKEN");

    const rotated = await client.signIn.email({ email, password: "password123" });
    expect(rotated.error).toBeNull();
    expect(rotated.data?.token).not.toBe(first.data.token);

    const state = stateSchema.parse(await ctx.readUserState({ userId: first.data.user.id }));
    expect(state.sessions).toHaveLength(1);
    expect(state.sessions.at(0)?.token).toBe(rotated.data?.token);

    const replay = await client.multiSession.setActive({ sessionToken: first.data.token! });
    expect(replay.error?.code).toBe("INVALID_SESSION_TOKEN");

    const refreshed = await client.multiSession.listDeviceSessions();
    expect(refreshed.data).toHaveLength(2);
    expect(new Set(refreshed.data?.map((item) => item.user.id)).size).toBe(2);

    const signout = await client.signOut();
    expect(signout.error).toBeNull();

    const after = [];

    for (const [index, account] of [first, second, third].entries()) {
      const persisted = stateSchema.parse(
        await ctx.readUserState({ userId: account.data!.user.id }),
      );
      expect(persisted.user?.id).toBe(account.data!.user.id);
      expect(persisted.sessions).toHaveLength(index === 2 ? 1 : 0);

      if (index === 2) {
        expect(persisted.sessions[0]?.token).toBe(third.data.token!);
      }

      after.push(persisted);
    }

    expect((await client.multiSession.listDeviceSessions()).data).toEqual([]);
    expect((await client.getSession()).data).toBeNull();

    const foreignBefore = await ctx.readUserState({ userId: third.data.user.id });
    const invalidSignin = await ctx
      .actor("invalid-capacity", "multi-session-limited")
      .fetch(`${ctx.baseURL}${authProfilePath("multi-session-limited")}/sign-in/email`, {
        method: "POST",
        credentials: "omit",
        headers: {
          "content-type": "application/json",
          cookie: "other_multi-invalid=bad; another_multi-invalid=bad",
        },
        body: JSON.stringify({ email, password: "password123" }),
      });
    expect(invalidSignin.status).toBe(200);

    const invalidBody = await invalidSignin.json();
    const invalidCookies = invalidSignin.headers.getSetCookie();
    expect(invalidCookies.some((value) => value.includes("_multi-"))).toBeFalse();

    const signedCookie = invalidCookies
      .find((value) => value.startsWith("better-auth.session_token="))
      ?.split(";")[0];

    if (!signedCookie) {
      throw new Error("actual session cookie expected");
    }

    const signed = decodeURIComponent(signedCookie.slice(signedCookie.indexOf("=") + 1));
    const secret = ["compat", "test", "only", "key", "not", "real", "minimum", "32chars"].join("-");
    expect(signed).toBe(
      invalidBody.token +
        "." +
        createHmac("sha256", secret).update(invalidBody.token).digest("base64"),
    );

    const read = await ctx
      .actor("invalid-capacity", "multi-session-limited")
      .fetch(`${ctx.baseURL}${authProfilePath("multi-session-limited")}/get-session`, {
        credentials: "omit",
        headers: { cookie: signedCookie },
      });
    expect(read.status).toBe(200);

    const authenticated = await read.json();
    expect(authenticated.user.id).toBe(first.data.user.id);
    expect(authenticated.session.token).toBe(invalidBody.token);

    const capacityState = stateSchema.parse(
      await ctx.readUserState({ userId: first.data.user.id }),
    );
    expect(capacityState.sessions).toHaveLength(1);
    expect(capacityState.sessions[0]?.token).toBe(invalidBody.token);

    const foreignAfter = await ctx.readUserState({ userId: third.data.user.id });
    expect(foreignAfter).toEqual(foreignBefore);

    return {
      first,
      second,
      third,
      list,
      active,
      missingCookie,
      rotated,
      state,
      replay,
      refreshed,
      signout,
      after,
      invalidSignin: {
        status: invalidSignin.status,
        body: invalidBody,
        signedCookie,
        cookieNames: invalidCookies.map((value) => value.slice(0, value.indexOf("="))),
      },
      authenticated,
      capacityState,
      foreignBefore,
      foreignAfter,
    };
  },
  ["POST /sign-in/email"],
);

for (const profile of [
  "multi-session",
  "multi-session-cookie-alias",
  "multi-session-cookie-prefix",
] as const) {
  compatScenario(
    profile === "multi-session"
      ? "multiple sessions reject invalid selection bodies and expire browser proofs without retiring another owner"
      : `${profile} reject invalid selection bodies and expire proofs without retiring another owner`,
    async (ctx) => {
      const client = multiClient(ctx, profile);
      const first = await client.signUp.email({
        email: ctx.uniqueEmail("multi-expired"),
        password: "password123",
        name: "Expired Owner",
      });
      const liveEmail = ctx.uniqueEmail("multi-live");
      const secondSignup = await client.signUp.email({
        email: liveEmail,
        password: "password123",
        name: "Live Owner",
      });
      expect(secondSignup.error).toBeNull();

      const second = await client.signIn.email({
        email: liveEmail,
        password: "password123",
        rememberMe: false,
      });
      expect(first.error).toBeNull();
      expect(second.error).toBeNull();

      if (!first.data?.token || !second.data?.token) {
        throw new Error("two persisted sessions expected");
      }

      const selected = await client.multiSession.setActive({ sessionToken: first.data.token });
      expect(selected.error).toBeNull();
      expect(selected.data?.user.id).toBe(first.data.user.id);

      const original = stateSchema.parse(await ctx.readUserState({ userId: first.data.user.id }));
      const unauthenticated = await ctx
        .actor("visitor", profile)
        .fetch(`${ctx.baseURL}${authProfilePath(profile)}/multi-session/revoke`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: "{}",
        });
      expect(unauthenticated.status).toBe(400);

      const unauthenticatedBody = await unauthenticated.json();
      expect(unauthenticatedBody).toMatchObject({ code: "VALIDATION_ERROR" });

      const invalid = [];

      for (const route of ["set-active", "revoke"]) {
        for (const body of [
          {},
          { sessionToken: null },
          { sessionToken: 7 },
          { sessionToken: false },
          { sessionToken: [] },
        ]) {
          const response = await ctx
            .actor("browser", profile)
            .fetch(`${ctx.baseURL}${authProfilePath(profile)}/multi-session/${route}`, {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify(body),
            });
          const value = await response.json();
          expect(response.status).toBe(400);
          expect(value).toMatchObject({ code: "VALIDATION_ERROR" });
          expect(
            stateSchema.parse(await ctx.readUserState({ userId: first.data.user.id })),
          ).toEqual(original);

          invalid.push({ status: response.status, body: value });
        }
      }

      const expired = await ctx.rawRequest({
        path: "/__test/expire-session",
        method: "POST",
        json: { token: first.data.token, expiresAt: "2000-01-01T00:00:00.000Z" },
      });
      expect(expired.status).toBe(200);

      const list = await client.multiSession.listDeviceSessions();
      expect(list.error).toBeNull();
      expect(list.data?.map((item) => item.user.id)).toEqual([second.data.user.id]);

      const missing = await client.multiSession.setActive({ sessionToken: first.data.token });
      expect(missing.error?.code).toBe("INVALID_SESSION_TOKEN");

      const live = stateSchema.parse(await ctx.readUserState({ userId: second.data.user.id }));
      expect(live.sessions).toHaveLength(1);
      expect(live.sessions[0]?.token).toBe(second.data.token);

      const fallback = await client.multiSession.setActive({ sessionToken: second.data.token });
      expect(fallback.error).toBeNull();
      expect((await client.getSession()).data?.user.id).toBe(second.data.user.id);

      const revoke = await client.multiSession.revoke({ sessionToken: second.data.token });
      expect(revoke.error).toBeNull();
      expect((await client.getSession()).data).toBeNull();
      expect((await client.multiSession.listDeviceSessions()).data).toEqual([]);
      expect(
        stateSchema.parse(await ctx.readUserState({ userId: second.data.user.id })).sessions,
      ).toHaveLength(0);

      return {
        first,
        secondSignup,
        second,
        selected,
        original,
        unauthenticated: { status: unauthenticated.status, body: unauthenticatedBody },
        invalid,
        expired,
        list,
        missing,
        live,
        fallback,
        revoke,
      };
    },
    [
      "GET /multi-session/list-device-sessions",
      "POST /multi-session/set-active",
      "POST /multi-session/revoke",
    ],
  );
}

// Real HTTP issuance protects raw numeric admission, rather than a private predicate.
for (const [profile, admitted] of [
  ["multi-session-zero", 0],
  ["multi-session-fractional", 1],
  ["multi-session-negative", 0],
  ["multi-session-nan", 3],
  ["multi-session-infinite", 3],
  ["multi-session-negative-infinite", 0],
] as const) {
  compatScenario(
    `${profile} raw limit controls proofs without evicting stored sessions`,
    async (ctx) => {
      const client = multiClient(ctx, profile);
      const accounts = [];
      for (let index = 0; index < 3; index++) {
        const account = await client.signUp.email({
          email: ctx.uniqueEmail(`raw-limit-${index}`),
          password: "password123",
          name: `Account ${index}`,
        });
        expect(account.error).toBeNull();
        if (!account.data?.token) throw new Error("issued session required");
        accounts.push(account.data);
      }
      const list = await client.multiSession.listDeviceSessions();
      expect(list.error).toBeNull();
      expect(list.data).toHaveLength(admitted);
      const expectedOrder =
        admitted === 3 ? [accounts[1], accounts[2], accounts[0]] : accounts.slice(0, admitted);
      expect(list.data?.map((item) => item.session.token)).toEqual(
        expectedOrder.map((item) => item!.token),
      );
      const active = await client.getSession();
      expect(active.data?.session.token).toBe(accounts[2]!.token);
      const selections = [];
      for (const [index, account] of accounts.entries()) {
        const selection = await client.multiSession.setActive({ sessionToken: account.token });
        if (index < admitted) expect(selection.data?.session.token).toBe(account.token);
        else expect(selection.error?.code).toBe("INVALID_SESSION_TOKEN");
        selections.push(selection);
      }
      const before = [];
      for (const account of accounts) {
        const state = await ctx.readUserState({ userId: account.user.id });
        expect(stateSchema.parse(state).sessions.map((row) => row.token)).toEqual([account.token]);
        before.push(state);
      }
      const logout = await client.signOut();
      expect(logout.error).toBeNull();
      const after = [];
      for (const [index, account] of accounts.entries()) {
        const state = await ctx.readUserState({ userId: account.user.id });
        // Logout retires actual device proofs and the current session only.
        expect(stateSchema.parse(state).sessions).toHaveLength(
          index < admitted || (admitted === 0 && index === 2) ? 0 : 1,
        );
        after.push(state);
      }
      return { accounts, list, active, selections, before, logout, after };
    },
    ["GET /multi-session/list-device-sessions", "POST /multi-session/set-active", "POST /sign-out"],
  );
}

compatScenario(
  "multiple sessions retire repeated genuine proofs before applying fractional capacity",
  async (ctx) => {
    const profile = "multi-session-fractional";
    const path = `${ctx.baseURL}${authProfilePath(profile)}`;
    const actor = ctx.actor("repeated-proof", profile);
    const email = ctx.uniqueEmail("repeated-proof");
    const signup = await actor.fetch(`${path}/sign-up/email`, {
      method: "POST",
      credentials: "omit",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password: "password123", name: "Repeated proof owner" }),
    });
    expect(signup.status).toBe(200);
    const issued = await signup.json();
    const proof = signup.headers
      .getSetCookie()
      .find((raw) => raw.includes("_multi-"))
      ?.split(";")[0];
    if (!proof) throw new Error("genuine emitted proof required");
    const signed = proof.slice(proof.indexOf("=") + 1);
    const repeated = `another_multi-${issued.token}=${signed}`;
    const before = await ctx.readUserState({ userId: issued.user.id });
    expect(stateSchema.parse(before).sessions.map((row) => row.token)).toEqual([issued.token]);
    const signin = await actor.fetch(`${path}/sign-in/email`, {
      method: "POST",
      credentials: "omit",
      headers: { "content-type": "application/json", cookie: `${proof}; ${repeated}` },
      body: JSON.stringify({ email, password: "password123" }),
    });
    expect(signin.status).toBe(200);
    const rotated = await signin.json();
    expect(rotated.token).not.toBe(issued.token);
    const cookies = signin.headers.getSetCookie();
    const retired = cookies.filter((raw) => raw.includes("_multi-") && raw.includes("Max-Age=0"));
    expect(retired).toHaveLength(2);
    const replacement = cookies.find(
      (raw) => raw.includes("_multi-") && !raw.includes("Max-Age=0"),
    );
    expect(replacement).toBeDefined();
    const after = await ctx.readUserState({ userId: issued.user.id });
    expect(stateSchema.parse(after).sessions.map((row) => row.token)).toEqual([rotated.token]);
    const selected = await actor.fetch(`${path}/multi-session/set-active`, {
      method: "POST",
      credentials: "omit",
      headers: { "content-type": "application/json", cookie: replacement!.split(";")[0]! },
      body: JSON.stringify({ sessionToken: rotated.token }),
    });
    expect(selected.status).toBe(200);
    const selection = await selected.json();
    expect(selection.session.token).toBe(rotated.token);
    return { issued, before, rotated, after, selection };
  },
  ["POST /sign-in/email", "POST /multi-session/set-active"],
);
