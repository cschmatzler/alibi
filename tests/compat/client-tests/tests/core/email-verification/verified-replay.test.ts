import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
compatScenario(
  "already verified guest proof replay returns no user hooks cookies or new session",
  async (ctx) => {
    const profile = "user-lifecycle-auto";
    const control = async (action = "state") => {
      const r = await ctx.rawRequest({
        path: "/__test/user-lifecycle/control",
        method: "POST",
        json: { profile: "auto", action },
      });
      expect(r.status).toBe(200);
      return r.body as any;
    };
    await control("reset");
    const owner = ctx.actor("owner", profile);
    const email = ctx.uniqueEmail("verified-replay");
    const signup = await owner.client.signUp.email({
      email,
      name: "Owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    const foreign = await ctx.actor("foreign", profile).client.signUp.email({
      email: ctx.uniqueEmail("replay-foreign"),
      name: "Foreign",
      password: "password123",
    });
    expect(foreign.error).toBeNull();
    expect((await owner.client.sendVerificationEmail({ email })).error).toBeNull();
    const delivered = (await control()).events
      .filter((e: any) => e.stage === "verification-mail")
      .at(-1);
    expect(delivered.user.email).toBe(email);
    const token = delivered.token;
    const first = await ctx.actor("first-guest", profile).client.verifyEmail({ query: { token } });
    expect(first.error).toBeNull();
    const firstSession = await ctx.actor("first-guest", profile).client.getSession();
    expect(firstSession.data!.user.id).toBe(signup.data!.user.id);
    await control("reset");
    const before = await control();
    expect(before.events).toEqual([]);
    expect(before.users.find((u: any) => u.id === signup.data!.user.id).emailVerified).toBe(true);
    const guest = ctx.actor("replay-guest", profile);
    let cookies: string[] = [];
    const replay = await guest.client.verifyEmail({
      query: { token },
      fetchOptions: {
        onResponse({ response }) {
          cookies = response.headers.getSetCookie();
        },
      },
    });
    expect(replay.error).toBeNull();
    expect(replay.data as unknown).toEqual({ status: true, user: null });
    expect(cookies).toEqual([]);
    expect(await control()).toEqual(before);
    expect((await guest.client.getSession()).data).toBeNull();
    const callback = ctx.baseURL + "/done?mode=replay#verified";
    const response = await guest.fetch(
      ctx.baseURL +
        authProfilePath(profile) +
        "/verify-email?" +
        new URLSearchParams({ token, callbackURL: callback }),
      { redirect: "manual" },
    );
    const redirected = {
      status: response.status,
      location: response.headers.get("location"),
      body: await response.text(),
      cookies: response.headers.getSetCookie(),
    };
    expect(redirected).toEqual({ status: 302, location: callback, body: "", cookies: [] });
    const after = await control();
    expect(after).toEqual(before);
    const project = (s: any) => ({
      ...s,
      accounts: s.accounts.map((a: any) => ({
        ...a,
        password: a.password ? { token: a.password } : a.password,
      })),
    });
    return ctx.snapshot({
      signup,
      foreign,
      first,
      firstSession,
      replay,
      cookies,
      redirected,
      before: project(before),
      after: project(after),
    });
  },
  ["GET /verify-email", "GET /get-session"],
);
