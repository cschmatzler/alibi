import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "empty verification callback returns JSON on first verification and guest replay",
  async (ctx) => {
    const profile = "user-lifecycle-auto";
    const control = async (action = "state") => {
      const response = await ctx.rawRequest({
        path: "/__test/user-lifecycle/control",
        method: "POST",
        json: { profile: "auto", action },
      });
      expect(response.status).toBe(200);
      return response.body as any;
    };
    const email = ctx.uniqueEmail("empty-callback-owner");
    const owner = ctx.actor("owner", profile);
    const signup = await owner.client.signUp.email({
      email,
      password: "password123",
      name: "Owner",
    });
    expect(signup.error).toBeNull();
    const foreign = ctx.actor("foreign", profile);
    const foreignSignup = await foreign.client.signUp.email({
      email: ctx.uniqueEmail("empty-callback-foreign"),
      password: "password123",
      name: "Foreign",
    });
    expect(foreignSignup.error).toBeNull();
    expect((await owner.client.sendVerificationEmail({ email })).error).toBeNull();
    const delivered = (await control()).events
      .filter((event: any) => event.stage === "verification-mail")
      .at(-1);
    expect(delivered.token).toBeTypeOf("string");
    await control("reset");
    const before = await control();
    const guest = ctx.actor("guest", profile);
    const observations = [];
    for (const actor of [guest, ctx.actor("replay-guest", profile)]) {
      let receipt: { status: number; location: string | null; cookies: string[] } | undefined;
      const verified = await actor.client.verifyEmail({
        query: { token: delivered.token, callbackURL: "" },
        fetchOptions: {
          redirect: "manual",
          onResponse({ response }) {
            receipt = {
              status: response.status,
              location: response.headers.get("location"),
              cookies: response.headers.getSetCookie(),
            };
          },
        },
      });
      expect(verified.error).toBeNull();
      expect(verified.data as unknown).toEqual({ status: true, user: null });
      expect(receipt!.status).toBe(200);
      expect(receipt!.location).toBeNull();
      if (observations.length === 0) {
        expect(
          receipt!.cookies.some((cookie) => cookie.startsWith("better-auth.session_token=")),
        ).toBe(true);
      } else {
        expect(receipt!.cookies).toEqual([]);
      }
      observations.push({
        verified,
        receipt: {
          ...receipt!,
          cookies: receipt!.cookies.map((cookie) => cookie.split("=", 1)[0]),
        },
        state: await control(),
      });
    }
    const after = observations[0]!.state;
    expect(observations[1]!.state).toEqual(after);
    expect(after.users.find((user: any) => user.id === signup.data!.user.id)).toMatchObject({
      email,
      emailVerified: true,
    });
    expect(after.users.filter((user: any) => user.id !== signup.data!.user.id)).toEqual(
      before.users.filter((user: any) => user.id !== signup.data!.user.id),
    );
    expect(after.accounts).toEqual(before.accounts);
    expect(after.verifications).toEqual(before.verifications);
    expect(after.sessions).toHaveLength(before.sessions.length + 1);
    for (const session of before.sessions) expect(after.sessions).toContainEqual(session);
    expect(
      after.events
        .filter((event: any) => event.stage.includes("verification"))
        .map((event: any) => event.stage),
    ).toEqual(["before-verification", "after-verification"]);
    const current = await guest.client.getSession();
    expect(current.data!.user).toMatchObject({
      id: signup.data!.user.id,
      email,
      emailVerified: true,
    });
    const foreignCurrent = await foreign.client.getSession();
    expect(foreignSignup.data!.token).toBeTypeOf("string");
    expect(foreignCurrent.data!.session.token).toBe(foreignSignup.data!.token!);
    const project = (state: any) => ({
      ...state,
      accounts: state.accounts.map((account: any) => ({
        ...account,
        password: account.password ? { token: account.password } : account.password,
      })),
    });
    return ctx.snapshot({
      signup,
      foreignSignup,
      current,
      foreignCurrent,
      before: project(before),
      observations: observations.map((entry) => ({ ...entry, state: project(entry.state) })),
    });
  },
  ["GET /verify-email", "GET /get-session"],
);
