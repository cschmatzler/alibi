import { expect } from "bun:test";
import { createHmac } from "node:crypto";

import { createAuthClient } from "better-auth/client";
import { anonymousClient } from "better-auth/client/plugins";

import { authProfilePath, type FixtureProfile } from "../../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../../support/scenario";

function actor(ctx: ScenarioContext, name: string, mode: string) {
  const profile = `anonymous-${mode}` as FixtureProfile;
  const transport = ctx.actor(name, profile);
  return {
    ...transport,
    client: createAuthClient({
      baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
      plugins: [anonymousClient()],
      fetchOptions: { customFetchImpl: transport.fetch },
    }),
  };
}
async function state(ctx: ScenarioContext): Promise<any> {
  const result = await ctx.rawRequest({ path: "/__test/anonymous/state" });
  expect(result.status).toBe(200);
  return result.body;
}
for (const mode of ["custom", "custom-cache"]) {
  compatScenario(
    `anonymous ${mode} transfers original physical application columns with distinct public and trusted projections`,
    async (ctx) => {
      const owner = actor(ctx, "primary", mode);
      const foreign = actor(ctx, "foreign", mode);
      const enrolled = await foreign.client.signUp.email({
        email: ctx.uniqueEmail("foreign-custom"),
        name: "Foreign",
        password: "password123",
      });
      expect(enrolled.error).toBeNull();
      const foreignBefore = await ctx.readUserState({ userId: enrolled.data!.user.id });
      const issued = await owner.client.signIn.anonymous();
      expect(issued.error).toBeNull();
      expect(issued.data!.user).toMatchObject({ cargoLabel: "Application Original" });
      expect(issued.data!.user).not.toHaveProperty("cargoHidden");
      const original = await owner.client.getSession();
      const before = await state(ctx);
      const upgrade = await owner.client.signUp.email({
        email: ctx.uniqueEmail("custom-upgrade"),
        name: "Original Owner",
        password: "password123",
      });
      expect(upgrade.error).toBeNull();
      const after = await state(ctx);
      expect(after.events).toHaveLength(1);
      const event = after.events[0];
      expect(event.anonymousUser).toEqual(ctx.snapshot(original.data));
      expect(event.newUser.user).toEqual(
        ctx.snapshot({ ...upgrade.data!.user, cargoHidden: "Application Secret" }),
      );
      expect(event.newUser.user).toMatchObject({
        name: "Original Owner",
        cargoLabel: "Application Original",
        cargoHidden: "Application Secret",
      });
      expect(after.users.find((user: any) => user.id === upgrade.data!.user.id)).toMatchObject({
        name: "Stored Hook Name",
        cargoLabel: "Transferred Application Original",
        cargoHidden: "Stored Secret",
      });
      expect(after.users.some((user: any) => user.id === issued.data!.user.id)).toBe(false);
      expect(after.sessions.some((row: any) => row.userId === issued.data!.user.id)).toBe(false);
      expect(after.accounts.some((row: any) => row.userId === issued.data!.user.id)).toBe(false);
      const current = await owner.client.getSession({ query: { disableCookieCache: true } });
      expect(current.data!.user).toMatchObject({
        name: "Stored Hook Name",
        cargoLabel: "Transferred Application Original",
      });
      expect(current.data!.user).not.toHaveProperty("cargoHidden");
      expect(await ctx.readUserState({ userId: enrolled.data!.user.id })).toEqual(foreignBefore);
      return {
        enrolled,
        foreignBefore,
        issued,
        original,
        before,
        upgrade,
        after,
        current,
        foreignAfter: await ctx.readUserState({ userId: enrolled.data!.user.id }),
      };
    },
    ["POST /sign-in/anonymous", "POST /sign-up/email"],
  );
}
compatScenario(
  "anonymous ordinary uncoded and coded link failures preserve committed login and every historical owner",
  async (ctx) => {
    const results = [];
    for (const mode of ["link-ordinary", "link-uncoded", "link-error"]) {
      const owner = actor(ctx, `primary-${mode}`, mode);
      const enrolled = actor(ctx, `enrolled-${mode}`, mode);
      const email = ctx.uniqueEmail(mode);
      const signup = await enrolled.client.signUp.email({
        email,
        name: "Existing Owner",
        password: "password123",
      });
      expect(signup.error).toBeNull();
      let originalCookies: string[] = [];
      const issued = await owner.client.signIn.anonymous(
        {},
        {
          onSuccess(context) {
            originalCookies = context.response.headers.getSetCookie();
          },
        },
      );
      expect(issued.error).toBeNull();
      const original = await owner.client.getSession();
      const before = await state(ctx);
      const denied = await owner.client.signIn.email({ email, password: "wrong-password" });
      expect(denied.error).not.toBeNull();
      expect(await state(ctx)).toEqual(before);
      const response = await owner.fetch(
        `${authProfilePath(`anonymous-${mode}` as FixtureProfile)}/sign-in/email`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ email, password: "password123" }),
        },
      );
      const wire = { status: response.status, body: await response.text() };
      expect(wire.status).toBe(mode === "link-ordinary" ? 500 : 403);
      if (mode === "link-ordinary") expect(wire.body).toBe("");
      else {
        expect(JSON.parse(wire.body)).toEqual({
          message: "Configured anonymous transfer denied",
          ...(mode === "link-error" ? { code: "APPLICATION_LINK_DENIED" } : {}),
        });
      }
      const after = await state(ctx);
      expect(after.users).toEqual(before.users);
      expect(after.accounts).toEqual(before.accounts);
      expect(after.sessions).toHaveLength(before.sessions.length + 1);
      expect(after.events).toHaveLength(before.events.length + 1);
      const event = after.events.at(-1);
      expect(event.anonymousUser).toEqual(ctx.snapshot(original.data));
      expect(event.newUser.user.id).toBe(signup.data!.user.id);
      expect(
        after.sessions.some(
          (row: any) =>
            row.token === event.newUser.session.token && row.userId === signup.data!.user.id,
        ),
      ).toBe(true);
      const current = await owner.client.getSession();
      const oldResponse = await owner.fetch(
        `${authProfilePath(`anonymous-${mode}` as FixtureProfile)}/get-session`,
        { headers: { cookie: originalCookies.map((value) => value.split(";")[0]).join("; ") } },
      );
      const oldReplay = { status: oldResponse.status, body: await oldResponse.json() };
      expect(oldReplay.body.user.id).toBe(issued.data!.user.id);
      expect(oldReplay.body.session.token).toBe(original.data!.session.token);
      const historical = await enrolled.client.getSession();
      expect(historical.data!.user.id).toBe(signup.data!.user.id);
      results.push({
        mode,
        signup,
        issued,
        original,
        before,
        denied,
        wire,
        after,
        current,
        historical,
        oldReplay,
        final: await state(ctx),
      });
    }
    return { results };
  },
  ["POST /sign-in/email"],
);
for (const [mode, expireOriginal, expireAll] of [
  ["recovery", false, false],
  ["recovery", true, false],
  ["recovery-disabled", true, false],
  ["recovery", true, true],
] as const) {
  compatScenario(
    `anonymous ${mode} cookie-less recovery selects first active physical session with originalExpired=${expireOriginal} allExpired=${expireAll}`,
    async (ctx) => {
      const owner = actor(ctx, "primary", mode);
      const foreign = actor(ctx, "foreign", mode);
      const foreignSignup = await foreign.client.signUp.email({
        email: ctx.uniqueEmail("foreign-recovery"),
        name: "Foreign",
        password: "password123",
      });
      expect(foreignSignup.error).toBeNull();
      const foreignBefore = await ctx.readUserState({ userId: foreignSignup.data!.user.id });
      let originalCookies: string[] = [];
      const issued = await owner.client.signIn.anonymous(
        {},
        {
          onSuccess(context) {
            originalCookies = context.response.headers.getSetCookie();
          },
        },
      );
      expect(issued.error).toBeNull();
      const original = await owner.client.getSession();
      const profile = {
        id: 123456,
        email: ctx.uniqueEmail("recovered-owner"),
        name: "Recovered Owner",
        username: "recovered-owner",
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
      let stateCookies: string[] = [];
      const initiated = await owner.client.signIn.social(
        { provider: "gitlab", callbackURL: "/anonymous-recovered", disableRedirect: true },
        {
          onSuccess(context) {
            stateCookies = context.response.headers.getSetCookie();
          },
        },
      );
      expect(initiated.error).toBeNull();
      const prepared = await ctx.rawRequest({
        path: "/__test/anonymous/prepare",
        method: "POST",
        json: { userId: issued.data!.user.id, expireOriginal },
      });
      expect(prepared.body).toEqual({ success: true });
      const expiredAll = expireAll
        ? await ctx.rawRequest({
            path: "/__test/anonymous/prepare",
            method: "POST",
            json: { userId: issued.data!.user.id, expireAll: true },
          })
        : null;
      const before = await state(ctx);
      const owned = before.sessions.filter((row: any) => row.userId === issued.data!.user.id);
      expect(owned).toHaveLength(4);
      expect(
        before.accounts.filter((row: any) => row.userId === issued.data!.user.id),
      ).toHaveLength(1);
      const expected = expireOriginal
        ? owned.find((row: any) => row.userAgent === "recovery-first")
        : owned.find((row: any) => row.token === original.data!.session.token);
      const stateId = new URL(initiated.data!.url!).searchParams.get("state")!;
      const callback = `${authProfilePath(`anonymous-${mode}` as FixtureProfile)}/callback/gitlab?code=fixture-code&state=${encodeURIComponent(stateId)}`;
      const cookie = stateCookies.map((value) => value.split(";")[0]).join("; ");
      expect(cookie).not.toContain("session_token");
      const rejectedResponse = await owner.fetch(
        `${callback.replace("fixture-code", "invalid-fixture-code")}`,
        { redirect: "manual", headers: { cookie: cookie.replace(/.$/, "x") } },
      );
      const rejected = {
        status: rejectedResponse.status,
        location: rejectedResponse.headers.get("location"),
        body: await rejectedResponse.text(),
      };
      expect(rejected.status).toBe(302);
      expect(await state(ctx)).toEqual(before);
      const response = await owner.fetch(callback, { redirect: "manual", headers: { cookie } });
      const completed = {
        status: response.status,
        location: response.headers.get("location"),
        body: await response.text(),
      };
      expect(completed).toEqual({ status: 302, location: "/anonymous-recovered", body: "" });
      const after = await state(ctx);
      expect(after.events).toHaveLength(expireAll ? 0 : 1);
      const event = after.events[0];
      if (event) {
        expect(event.anonymousUser.session).toEqual(expected);
        expect(event.anonymousUser.user).toEqual(
          before.users.find((row: any) => row.id === issued.data!.user.id),
        );
        expect(event.anonymousUser.user).toMatchObject({ cargoHidden: "Application Secret" });
        expect(event.newUser.user).toMatchObject({
          email: profile.email,
          cargoLabel: "Application Original",
          cargoHidden: "Application Secret",
        });
      }
      const retained = mode === "recovery-disabled" || expireAll;
      expect(after.users.some((row: any) => row.id === issued.data!.user.id)).toBe(retained);
      expect(after.sessions.filter((row: any) => row.userId === issued.data!.user.id)).toEqual(
        retained ? owned : [],
      );
      expect(after.accounts.filter((row: any) => row.userId === issued.data!.user.id)).toEqual(
        retained ? before.accounts.filter((row: any) => row.userId === issued.data!.user.id) : [],
      );
      const current = await owner.client.getSession();
      expect(current.data!.user.id).not.toBe(issued.data!.user.id);
      expect(current.data!.user.email).toBe(profile.email);
      if (event) {
        expect(current.data!.user.id).toBe(event.newUser.user.id);
        expect(current.data!.session.token).toBe(event.newUser.session.token);
        expect(current.data!.user).toHaveProperty("cargoLabel", "Transferred Application Original");
      }
      const replayResponse = await owner.fetch(callback, {
        redirect: "manual",
        headers: { cookie },
      });
      const replay = {
        status: replayResponse.status,
        location: replayResponse.headers.get("location"),
        body: await replayResponse.text(),
      };
      expect(replay.location).toContain("state_mismatch");
      expect(await state(ctx)).toEqual(after);
      const oldReplayResponse = await owner.fetch(
        `${authProfilePath(`anonymous-${mode}` as FixtureProfile)}/get-session?disableCookieCache=true`,
        { headers: { cookie: originalCookies.map((value) => value.split(";")[0]).join("; ") } },
      );
      const oldReplay = { status: oldReplayResponse.status, body: await oldReplayResponse.json() };
      expect(oldReplay.body).toBeNull();
      const historicalReplays = [];
      for (const session of owned.filter(
        (row: any) => row.token !== original.data!.session.token,
      )) {
        // These are actual server-created rows, not caller-nominated identities.
        const signature = createHmac("sha256", "compat-test-only-key-not-real-minimum-32chars")
          .update(session.token)
          .digest("base64");
        const historicalResponse = await owner.fetch(
          `${authProfilePath(`anonymous-${mode}` as FixtureProfile)}/get-session?disableCookieCache=true`,
          {
            headers: {
              cookie: `better-auth.session_token=${encodeURIComponent(`${session.token}.${signature}`)}`,
            },
          },
        );
        const historical = {
          status: historicalResponse.status,
          body: await historicalResponse.json(),
        };
        if (retained && !expireAll && session.userAgent !== "historical") {
          expect(historical.body.session.token).toBe(session.token);
          expect(historical.body.user.id).toBe(issued.data!.user.id);
        } else {
          expect(historical.body).toBeNull();
        }
        historicalReplays.push(historical);
      }
      const final = await state(ctx);
      expect(final.events).toEqual(after.events);
      expect(final.accounts).toEqual(after.accounts);
      expect(final.sessions.filter((row: any) => row.userId === issued.data!.user.id)).toEqual(
        mode === "recovery-disabled"
          ? historicalReplays
              .filter((replay) => replay.body !== null)
              .map((replay) => replay.body.session)
          : [],
      );
      expect(await ctx.readUserState({ userId: foreignSignup.data!.user.id })).toEqual(
        foreignBefore,
      );
      return {
        foreignSignup,
        foreignBefore,
        issued,
        original,
        configured,
        initiated,
        prepared,
        expiredAll,
        before,
        rejected,
        completed,
        after,
        current,
        replay,
        oldReplay,
        historicalReplays,
        final,
        foreignAfter: await ctx.readUserState({ userId: foreignSignup.data!.user.id }),
      };
    },
    ["POST /sign-in/social", "GET /callback/{}"],
  );
}
