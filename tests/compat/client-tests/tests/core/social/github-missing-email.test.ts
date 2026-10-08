import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "github empty email list denies identity without creating or linking rows and consumes state",
  async (ctx) => {
    const owner = ctx.actor("owner");
    const signup = await owner.client.signUp.email({
      email: ctx.uniqueEmail("unrelated"),
      name: "Unrelated",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    const before = await ctx.readUserState({ userId: signup.data!.user.id });
    const allBefore = (await ctx.rawRequest({ path: "/__test/social-provider/state" })).body as any;
    const guest = ctx.actor("github");
    await ctx.setGitHubProfile({
      id: ctx.uniqueToken("missing-email-subject"),
      name: "Missing Email",
      email: null,
      emails: [],
    });
    const started = await guest.client.signIn.social({
      provider: "github",
      callbackURL: "/dashboard",
      errorCallbackURL: "/github-error",
    });
    expect(started.error).toBeNull();
    const state = new URL(started.data!.url!).searchParams.get("state")!;
    const path = `/api/auth/callback/github?code=compat-code&state=${encodeURIComponent(state)}`;
    const denied = await ctx.rawRequest({ actor: "github", path, redirect: "manual" });
    expect(denied.status).toBe(302);
    const destination = new URL(denied.location!, ctx.baseURL);
    expect(destination.pathname).toBe("/github-error");
    expect(destination.searchParams.get("error")).toBe("email_not_found");
    const session = await guest.client.getSession();
    expect(session.data).toBeNull();
    const replay = await ctx.rawRequest({ actor: "github", path, redirect: "manual" });
    expect(replay.status).toBe(302);
    expect(new URL(replay.location!, ctx.baseURL).searchParams.get("error")).toBe("state_mismatch");
    const after = (await ctx.rawRequest({ path: "/__test/social-provider/state" })).body as any;
    for (const table of ["users", "accounts", "sessions"]) {
      expect(after[table]).toEqual(allBefore[table]);
    }
    expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(before);
    // A real successful provider control proves the same callback path can issue a session.
    const email = ctx.uniqueEmail("valid-control");
    await ctx.setGitHubProfile({
      id: ctx.uniqueToken("valid-control-subject"),
      email: null,
      emails: [{ email, primary: true, verified: true, visibility: "private" }],
    });
    const control = await guest.client.signIn.social({
      provider: "github",
      callbackURL: "/dashboard",
    });
    const controlState = new URL(control.data!.url!).searchParams.get("state")!;
    const accepted = await ctx.rawRequest({
      actor: "github",
      path: `/api/auth/callback/github?code=compat-code&state=${encodeURIComponent(controlState)}`,
      redirect: "manual",
    });
    expect(new URL(accepted.location!, ctx.baseURL).pathname).toBe("/dashboard");
    const current = await guest.client.getSession();
    expect(current.data!.user.email).toBe(email);
    return ctx.snapshot({ started, denied, session, replay, before, after, accepted, current });
  },
  ["POST /sign-in/social", "GET /callback/{}", "GET /get-session"],
);
