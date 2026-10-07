import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";

for (const matchingRecord of [true, false]) {
  compatScenario(
    `github inline email trusts only its own record matching=${matchingRecord}`,
    async (ctx) => {
      const email = ctx.uniqueEmail("inline-owner");
      const owner = ctx.actor("owner");
      const signup = await owner.client.signUp.email({
        email,
        name: "Local Owner",
        password: "password123",
      });
      expect(signup.error).toBeNull();
      const before = await ctx.readUserState({ userId: signup.data!.user.id });
      const subject = ctx.uniqueToken("inline-subject");
      const configure = (address: string) =>
        ctx.setGitHubProfile({
          id: subject,
          email: address,
          name: "Inline User",
          emails: [
            {
              email: ctx.uniqueEmail("primary-other"),
              primary: true,
              verified: true,
              visibility: "private" as const,
            },
            ...(matchingRecord
              ? [{ email: address, primary: false, verified: false, visibility: "private" }]
              : []),
          ],
        });
      await configure(email);
      const guest = ctx.actor("github");
      const run = async () => {
        const started = await guest.client.signIn.social({
          provider: "github",
          callbackURL: "/dashboard",
          errorCallbackURL: "/github-error",
        });
        expect(started.error).toBeNull();
        const state = new URL(started.data!.url!).searchParams.get("state")!;
        return {
          started,
          callback: await ctx.rawRequest({
            actor: "github",
            path: `/api/auth/callback/github?code=compat-code&state=${encodeURIComponent(state)}`,
            redirect: "manual",
          }),
        };
      };
      const existing = await run();
      expect(existing.callback.status).toBe(302);
      expect(new URL(existing.callback.location!, ctx.baseURL).searchParams.get("error")).toBe(
        "account_not_linked",
      );
      expect((await guest.client.getSession()).data).toBeNull();
      expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(before);
      const newEmail = ctx.uniqueEmail("new-inline");
      await configure(newEmail);
      const fresh = await run();
      expect(new URL(fresh.callback.location!, ctx.baseURL).pathname).toBe("/dashboard");
      const session = await guest.client.getSession();
      expect(session.data!.user.email).toBe(newEmail);
      expect(session.data!.user.emailVerified).toBe(false);
      const stored = (await ctx.readUserState({ userId: session.data!.user.id })) as any;
      expect(stored.user.email).toBe(newEmail);
      expect(stored.user.emailVerified).toBe(false);
      expect(stored.accounts).toHaveLength(1);
      expect(stored.accounts[0]).toMatchObject({
        providerId: "github",
        accountId: subject,
        userId: session.data!.user.id,
      });
      expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(before);
      return ctx.snapshot({ existing, fresh, session, stored, before });
    },
    ["POST /sign-in/social", "GET /callback/{}", "GET /get-session"],
  );
}
