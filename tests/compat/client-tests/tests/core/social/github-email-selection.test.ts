import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";

for (const mode of ["primary-second", "no-primary"] as const) {
  compatScenario(
    `github ${mode} selects email and matching trust from competing records`,
    async (ctx) => {
      const unrelated = ctx.actor("unrelated");
      const signup = await unrelated.client.signUp.email({
        email: ctx.uniqueEmail("unrelated"),
        name: "Unrelated",
        password: "password123",
      });
      expect(signup.error).toBeNull();
      const before = await ctx.readUserState({ userId: signup.data!.user.id });
      const first = ctx.uniqueEmail("first");
      const second = ctx.uniqueEmail("second");
      const subject = ctx.uniqueToken("github-subject");
      await ctx.setGitHubProfile({
        id: subject,
        name: "Selection User",
        email: null,
        emails: [
          { email: first, primary: false, verified: false, visibility: "private" },
          {
            email: second,
            primary: mode === "primary-second",
            verified: true,
            visibility: "private",
          },
        ],
      });
      const actor = ctx.actor("github");
      const started = await actor.client.signIn.social({
        provider: "github",
        callbackURL: "/dashboard",
      });
      expect(started.error).toBeNull();
      const state = new URL(started.data!.url!).searchParams.get("state")!;
      expect(state).toBeTruthy();
      const callback = await ctx.rawRequest({
        actor: "github",
        path: `/api/auth/callback/github?code=compat-code&state=${encodeURIComponent(state)}`,
        redirect: "manual",
      });
      expect(callback.status).toBe(302);
      expect(new URL(callback.location!, ctx.baseURL).pathname).toBe("/dashboard");
      const session = await actor.client.getSession();
      expect(session.error).toBeNull();
      expect(session.data!.user.email).toBe(mode === "primary-second" ? second : first);
      expect(session.data!.user.emailVerified).toBe(mode === "primary-second");
      const stored = (await ctx.readUserState({ userId: session.data!.user.id })) as any;
      expect(stored.user.email).toBe(session.data!.user.email);
      expect(stored.user.emailVerified).toBe(session.data!.user.emailVerified);
      expect(stored.accounts).toHaveLength(1);
      expect(stored.accounts[0]).toMatchObject({
        providerId: "github",
        accountId: subject,
        userId: session.data!.user.id,
      });
      expect(stored.sessions).toHaveLength(1);
      expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(before);
      return ctx.snapshot({ started, callback, session, stored, before });
    },
    ["POST /sign-in/social", "GET /callback/{}", "GET /get-session"],
  );
}
