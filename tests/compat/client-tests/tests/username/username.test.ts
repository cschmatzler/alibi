import { expect } from "bun:test";
import { compatScenario } from "../../support/scenario";

compatScenario(
  "username availability follows normalized persisted usernames",
  async (ctx) => {
    const actor = ctx.actor();
    const username = ctx.uniqueToken("username").replace(/-/g, "_");
    const before = await actor.client.isUsernameAvailable({ username: username.toUpperCase() });
    expect(before.data).toEqual({ available: true });
    const signup = await actor.client.signUp.email({
      email: ctx.uniqueEmail("admin-username"),
      password: "password123",
      name: "Username User",
      username: username.toUpperCase(),
    });
    expect(signup.error).toBeNull();
    expect(signup.data?.user.username).toBe(username);
    if (!signup.data) throw new Error("username owner must exist");
    const stateBefore = await ctx.readUserState({ userId: signup.data.user.id });
    const taken = await ctx.actor("guest").client.isUsernameAvailable({ username });
    const differentCase = await ctx
      .actor("guest")
      .client.isUsernameAvailable({ username: username.toUpperCase() });
    const unrelated = await ctx
      .actor("guest")
      .client.isUsernameAvailable({ username: "another_available_username" });
    expect(taken.data).toEqual({ available: false });
    expect(differentCase.data).toEqual({ available: false });
    expect(unrelated.data).toEqual({ available: true });
    const stateAfter = await ctx.readUserState({ userId: signup.data.user.id });
    expect(stateAfter).toEqual(stateBefore);
    const session = await actor.client.getSession();
    expect(session.data?.user.username).toBe(username);
    return {
      before: ctx.snapshot(before),
      signup: ctx.snapshot(signup),
      taken: ctx.snapshot(taken),
      differentCase: ctx.snapshot(differentCase),
      unrelated: ctx.snapshot(unrelated),
      session: ctx.snapshot(session),
    };
  },
  ["POST /sign-up/email", "POST /is-username-available"],
);

compatScenario("username availability rejects invalid names before lookup", async (ctx) => {
  const client = ctx.actor().client;
  const empty = await client.isUsernameAvailable({ username: "" });
  const tooShort = await client.isUsernameAvailable({ username: "ab" });
  const tooLong = await client.isUsernameAvailable({ username: "a".repeat(31) });
  const invalid = await client.isUsernameAvailable({ username: "bad+username" });
  expect(empty.error).toMatchObject({ status: 422, code: "INVALID_USERNAME" });
  expect(tooShort.error).toMatchObject({ status: 422, code: "USERNAME_TOO_SHORT" });
  expect(tooLong.error).toMatchObject({ status: 422, code: "USERNAME_TOO_LONG" });
  expect(invalid.error).toMatchObject({ status: 422, code: "INVALID_USERNAME" });
  return {
    empty: ctx.snapshot(empty),
    tooShort: ctx.snapshot(tooShort),
    tooLong: ctx.snapshot(tooLong),
    invalid: ctx.snapshot(invalid),
  };
});

// Configured behavior is owned at the HTTP boundary, including persistence,
// foreign-user uniqueness and sessions. Defaults above cannot catch ignored options.
for (const profile of [
  "signup-username-limits",
  "signup-username-preserve",
  "signup-username-post",
  "signup-username-immutable",
  "signup-username-display-disabled",
] as const) {
  compatScenario(
    `configured username policy ${profile} reaches signup lookup update and sign-in`,
    async (ctx) => {
      expect(
        (
          await ctx.rawRequest({
            path: "/__test/signup-policy",
            method: "POST",
            json: { operation: "mode", mode: "normal" },
          })
        ).status,
      ).toBe(200);
      const actor = ctx.actor("owner", profile);
      const raw =
        profile === "signup-username-limits"
          ? "Ab"
          : profile === "signup-username-post"
            ? " Owner-Name "
            : "Owner_Name";
      const stored =
        profile === "signup-username-preserve"
          ? raw
          : profile === "signup-username-post"
            ? "owner_name"
            : raw.toLowerCase();
      const before = await actor.client.isUsernameAvailable({ username: stored });
      expect(before.data).toEqual({ available: true });
      const signup = await actor.client.signUp.email({
        email: ctx.uniqueEmail("username-policy"),
        name: "Configured Owner",
        password: "password123",
        username: raw,
      });
      expect(signup.error).toBeNull();
      expect(signup.data?.user.username).toBe(stored);
      if (profile === "signup-username-display-disabled")
        expect(signup.data?.user).not.toHaveProperty("displayUsername");
      if (!signup.data) throw new Error("configured owner missing");
      const stateBefore = await ctx.readUserState({ userId: signup.data.user.id });
      const foreign = ctx.actor("foreign", profile);
      const taken = await foreign.client.isUsernameAvailable({ username: stored });
      expect(taken.data).toEqual({ available: false });
      const duplicate = await foreign.client.signUp.email({
        email: ctx.uniqueEmail("foreign-username"),
        name: "Foreign",
        password: "password123",
        username: profile === "signup-username-post" ? raw : stored,
      });
      expect(duplicate.error).toMatchObject({ status: 400, code: "USERNAME_IS_ALREADY_TAKEN" });
      expect(await ctx.readUserState({ userId: signup.data.user.id })).toEqual(stateBefore);
      const foreignSignup = await foreign.client.signUp.email({
        email: ctx.uniqueEmail("foreign-owner"),
        name: "Foreign Owner",
        password: "foreign-password123",
        username: profile === "signup-username-limits" ? "Ef" : "Foreign_Name",
      });
      expect(foreignSignup.error).toBeNull();
      if (!foreignSignup.data) throw new Error("foreign owner missing");
      const foreignBefore = await ctx.readUserState({ userId: foreignSignup.data.user.id });
      const foreignUpdate = await foreign.client.updateUser({ username: stored });
      expect(foreignUpdate.error).toMatchObject({
        status: 400,
        code:
          profile === "signup-username-immutable"
            ? "USERNAME_IS_IMMUTABLE"
            : "USERNAME_IS_ALREADY_TAKEN",
      });
      expect(await ctx.readUserState({ userId: foreignSignup.data.user.id })).toEqual(
        foreignBefore,
      );
      const caseLookup = await foreign.client.isUsernameAvailable({
        username: raw.toLowerCase().trim().replaceAll("-", "_"),
      });
      expect(caseLookup.data).toEqual({ available: profile === "signup-username-preserve" });
      const same = await actor.client.updateUser({ username: stored });
      expect(same.error).toBeNull();
      const changed = await actor.client.updateUser({
        username: profile === "signup-username-limits" ? "Cd" : "Other_Name",
      });
      if (profile === "signup-username-immutable")
        expect(changed.error).toMatchObject({ status: 400, code: "USERNAME_IS_IMMUTABLE" });
      else expect(changed.error).toBeNull();
      const finalUsername =
        profile === "signup-username-immutable"
          ? stored
          : profile === "signup-username-limits"
            ? "cd"
            : profile === "signup-username-preserve"
              ? "Other_Name"
              : "other_name";
      const signin = await foreign.client.signIn.username({
        username: finalUsername,
        password: "password123",
        rememberMe: false,
      });
      expect(signin.error).toBeNull();
      expect(signin.data?.user.username).toBe(finalUsername);
      const wrong = await ctx
        .actor("wrong", profile)
        .client.signIn.username({ username: finalUsername, password: "wrong-password" });
      expect(wrong.error).toMatchObject({ status: 401, code: "INVALID_USERNAME_OR_PASSWORD" });
      const session = await foreign.client.getSession();
      expect(session.data?.user.id).toBe(signup.data.user.id);
      return {
        foreignSignup: ctx.snapshot(foreignSignup),
        foreignUpdate: ctx.snapshot(foreignUpdate),
        foreignBefore,
        ownerBefore: stateBefore,
        caseLookup: ctx.snapshot(caseLookup),
        before: ctx.snapshot(before),
        signup: ctx.snapshot(signup),
        taken: ctx.snapshot(taken),
        duplicate: ctx.snapshot(duplicate),
        same: ctx.snapshot(same),
        changed: ctx.snapshot(changed),
        signin: ctx.snapshot(signin),
        wrong: ctx.snapshot(wrong),
        session: ctx.snapshot(session),
      };
    },
  );
}

type UsernameState = {
  users: Record<string, unknown>[];
  accounts: Record<string, unknown>[];
  sessions: Record<string, unknown>[];
  verifications: Record<string, unknown>[];
  events: Record<string, unknown>[];
};
async function usernameState(
  ctx: import("../../support/scenario").ScenarioContext,
  profile: import("../../support/profiles").FixtureProfile,
) {
  const response = await ctx.rawRequest({ path: `/__test/signup-policy/state?profile=${profile}` });
  expect(response.status).toBe(200);
  const state = response.body as UsernameState;
  const hash = (value: unknown) => {
    if (typeof value !== "string") return value;
    expect(value).toMatch(/^[a-f0-9]{32}:[a-f0-9]{128}$/);
    return { token: value, encoding: "scrypt-salt-key" };
  };
  return {
    ...state,
    accounts: state.accounts.map((row) => ({ ...row, password: hash(row.password) })),
    events: state.events.map(
      (row): Record<string, unknown> => ({ ...row, ...(row.hash ? { hash: hash(row.hash) } : {}) }),
    ),
  };
}
for (const profile of [
  "signup-username-pre",
  "signup-username-implicit",
  "signup-username-post",
] as const) {
  compatScenario(
    `username ${profile} retains normalization order at each real boundary`,
    async (ctx) => {
      expect(
        (
          await ctx.rawRequest({
            path: "/__test/signup-policy",
            method: "POST",
            json: { operation: "mode", mode: "normal" },
          })
        ).status,
      ).toBe(200);
      const owner = ctx.actor("owner", profile);
      const rejected = await owner.client.signUp.email({
        email: ctx.uniqueEmail("raw-name"),
        name: "Order Owner",
        password: "password123",
        username: " Owner-Name ",
      });
      if (profile === "signup-username-post") expect(rejected.error).toBeNull();
      else expect(rejected.error).toMatchObject({ status: 400, code: "INVALID_USERNAME" });
      const signup =
        profile === "signup-username-post"
          ? rejected
          : await owner.client.signUp.email({
              email: ctx.uniqueEmail("valid-name"),
              name: "Order Owner",
              password: "password123",
              username: "Owner_Name",
            });
      expect(signup.error).toBeNull();
      const state = await usernameState(ctx, profile);
      const hook = state.events.find((row) => row.stage === "username-hook");
      expect(hook?.request).toMatchObject({
        method: "POST",
        path: "/sign-up/email",
        marker: null,
        contentType: "application/json",
      });
      const calls = state.events.filter((row) => row.stage === "username");
      expect(calls.filter((row) => row.callback === "normalize")).toHaveLength(
        profile === "signup-username-post" ? 5 : 4,
      );
      const guest = ctx.actor("guest", profile);
      const signin = await guest.client.signIn.username({
        username: " Owner-Name ",
        password: "password123",
      });
      if (profile === "signup-username-pre") expect(signin.error).toBeNull();
      else expect(signin.error).toMatchObject({ status: 422, code: "INVALID_USERNAME" });
      const unavailable = await guest.client.isUsernameAvailable({ username: " Owner-Name " });
      expect(unavailable.error).toMatchObject({ status: 422, code: "INVALID_USERNAME" });
      const update = await owner.client.updateUser({ username: " New-Name " });
      if (profile === "signup-username-post") expect(update.error).toBeNull();
      else expect(update.error).toMatchObject({ status: 400, code: "INVALID_USERNAME" });
      const final = await usernameState(ctx, profile);
      expect(final.accounts).toEqual(state.accounts);
      return {
        rejected: ctx.snapshot(rejected),
        signup: ctx.snapshot(signup),
        state,
        signin: ctx.snapshot(signin),
        unavailable: ctx.snapshot(unavailable),
        update: ctx.snapshot(update),
        final,
      };
    },
  );
}
for (const profile of [
  "signup-username-unicode",
  "signup-username-display-pre",
  "signup-username-display-post",
] as const) {
  compatScenario(
    `username ${profile} applies awaited validators and configured display transforms`,
    async (ctx) => {
      expect(
        (
          await ctx.rawRequest({
            path: "/__test/signup-policy",
            method: "POST",
            json: { operation: "mode", mode: "normal" },
          })
        ).status,
      ).toBe(200);
      const owner = ctx.actor("owner", profile);
      const invalid = await owner.client.signUp.email({
        email: ctx.uniqueEmail("invalid-name"),
        name: "Invalid",
        password: "password123",
        username: profile === "signup-username-unicode" ? "😀😀😀" : "owner_name",
        ...(profile === "signup-username-unicode" ? {} : { displayUsername: " Raw Display " }),
      });
      if (profile === "signup-username-display-post") expect(invalid.error).toBeNull();
      else
        expect(invalid.error).toMatchObject({
          status: 400,
          code:
            profile === "signup-username-unicode"
              ? "USERNAME_TOO_LONG"
              : "INVALID_DISPLAY_USERNAME",
        });
      const signup =
        profile === "signup-username-display-post"
          ? invalid
          : await owner.client.signUp.email({
              email: ctx.uniqueEmail("unicode-name"),
              name: "Valid",
              password: "password123",
              username: profile === "signup-username-unicode" ? "😀😀" : "owner_name",
              ...(profile === "signup-username-unicode"
                ? {}
                : { displayUsername: "VALID DISPLAY" }),
            });
      expect(signup.error).toBeNull();
      if (profile !== "signup-username-unicode")
        expect(signup.data?.user.displayUsername).toBe(
          profile === "signup-username-display-post" ? "RAW DISPLAY" : "VALID DISPLAY",
        );
      const before = await usernameState(ctx, profile);
      expect(
        before.events.some(
          (row) =>
            row.stage === "username" &&
            row.callback ===
              (profile === "signup-username-unicode" ? "validate" : "display-validate"),
        ),
      ).toBe(true);
      const update = await owner.client.updateUser(
        profile === "signup-username-unicode"
          ? { username: "ΟΣ" }
          : { displayUsername: "NEXT DISPLAY" },
      );
      expect(update.error).toBeNull();
      const signin = await ctx.actor("guest", profile).client.signIn.username({
        username: profile === "signup-username-unicode" ? "ΟΣ" : "owner_name",
        password: "password123",
      });
      expect(signin.error).toBeNull();
      const after = await usernameState(ctx, profile);
      expect(after.accounts).toEqual(before.accounts);
      return {
        invalid: ctx.snapshot(invalid),
        signup: ctx.snapshot(signup),
        before,
        update: ctx.snapshot(update),
        signin: ctx.snapshot(signin),
        after,
      };
    },
  );
}
for (const profile of ["signup-username-throw", "signup-username-readonly"] as const) {
  compatScenario(
    `username ${profile} rejects input without creating credentials or sessions`,
    async (ctx) => {
      expect(
        (
          await ctx.rawRequest({
            path: "/__test/signup-policy",
            method: "POST",
            json: { operation: "mode", mode: "normal" },
          })
        ).status,
      ).toBe(200);
      const before = await usernameState(ctx, profile);
      const signup = await ctx.actor("owner", profile).client.signUp.email({
        email: ctx.uniqueEmail("denied-name"),
        name: "Denied",
        password: "password123",
        username: profile === "signup-username-throw" ? "explode" : "owner_name",
      });
      expect(signup.error?.status).toBe(profile === "signup-username-throw" ? 500 : 400);
      if (profile === "signup-username-readonly")
        expect(signup.error?.code).toBe("FIELD_NOT_ALLOWED");
      const after = await usernameState(ctx, profile);
      expect(after.users).toEqual(before.users);
      expect(after.accounts).toEqual(before.accounts);
      expect(after.sessions).toEqual(before.sessions);
      return { before, signup: ctx.snapshot(signup), after };
    },
  );
}
compatScenario(
  "configured username sign-in retains verification and remember-me session policy",
  async (ctx) => {
    expect(
      (
        await ctx.rawRequest({
          path: "/__test/signup-policy",
          method: "POST",
          json: { operation: "mode", mode: "normal" },
        })
      ).status,
    ).toBe(200);
    const profile = "signup-username-required" as const;
    const owner = ctx.actor("owner", profile);
    const signup = await owner.client.signUp.email({
      email: ctx.uniqueEmail("verified-name"),
      name: "Verified Owner",
      password: "password123",
      username: "Owner_Name",
    });
    expect(signup.error).toBeNull();
    expect(signup.data?.token).toBeNull();
    const before = await usernameState(ctx, profile);
    expect(before.sessions).toHaveLength(0);
    const denied = await owner.client.signIn.username({
      username: "OWNER_NAME",
      password: "password123",
    });
    expect(denied.error).toMatchObject({ status: 403, code: "EMAIL_NOT_VERIFIED" });
    const delivery = before.events.find((row) => row.stage === "verification-email");
    if (typeof delivery?.token !== "string")
      throw new Error("actual verification delivery missing");
    const verified = await owner.client.verifyEmail({ query: { token: delivery.token } });
    expect(verified.error).toBeNull();
    const signin = await owner.client.signIn.username({
      username: "OWNER_NAME",
      password: "password123",
      rememberMe: false,
    });
    expect(signin.error).toBeNull();
    const session = await owner.client.getSession();
    expect(session.data?.user.emailVerified).toBe(true);
    const after = await usernameState(ctx, profile);
    expect(after.accounts).toEqual(before.accounts);
    expect(after.sessions).toHaveLength(1);
    const duration =
      Date.parse(String(after.sessions[0]!.expiresAt)) -
      Date.parse(String(after.sessions[0]!.createdAt));
    expect(duration).toBeGreaterThan(86_399_000);
    expect(duration).toBeLessThanOrEqual(86_400_000);
    return {
      signup: ctx.snapshot(signup),
      before,
      denied: ctx.snapshot(denied),
      verified: ctx.snapshot(verified),
      signin: ctx.snapshot(signin),
      session: ctx.snapshot(session),
      after,
    };
  },
);
