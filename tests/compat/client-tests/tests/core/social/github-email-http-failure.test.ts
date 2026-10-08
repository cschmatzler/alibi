import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "github ancillary email HTTP failure keeps usable inline email without trusting it",
  async (ctx) => {
    const observations = [];
    for (const status of [503, 200]) {
      const email = ctx.uniqueEmail(`ancillary-${status}`);
      const subject = ctx.uniqueToken(`ancillary-subject-${status}`);
      await ctx.setGitHubProfile({
        id: subject,
        name: "Inline User",
        email,
        emails: [{ email, primary: true, verified: true, visibility: "private" }],
      });
      const transport = await ctx.rawRequest({
        path: "/__test/github-email-transport",
        method: "POST",
        json: { status },
      });
      expect(transport.body).toEqual({ status });
      const actor = ctx.actor(`github-${status}`);
      const started = await actor.client.signIn.social({
        provider: "github",
        callbackURL: "/dashboard",
      });
      expect(started.error).toBeNull();
      const state = new URL(started.data!.url!).searchParams.get("state")!;
      const callback = await ctx.rawRequest({
        actor: `github-${status}`,
        path: `/api/auth/callback/github?code=compat-code&state=${encodeURIComponent(state)}`,
        redirect: "manual",
      });
      expect(callback.status).toBe(302);
      expect(new URL(callback.location!, ctx.baseURL).pathname).toBe("/dashboard");
      const requests = await ctx.rawRequest({ path: "/__test/github-email-transport" });
      expect(requests.body).toEqual(["/user", "/user/emails"]);
      const session = await actor.client.getSession();
      expect(session.data!.user.email).toBe(email);
      expect(session.data!.user.emailVerified).toBe(status === 200);
      const stored = (await ctx.readUserState({ userId: session.data!.user.id })) as any;
      expect(stored.user.email).toBe(email);
      expect(stored.user.emailVerified).toBe(status === 200);
      expect(stored.accounts).toHaveLength(1);
      expect(stored.accounts[0]).toMatchObject({
        accountId: subject,
        providerId: "github",
        userId: session.data!.user.id,
      });
      expect(stored.sessions).toHaveLength(1);
      observations.push({ started, callback, requests, session, stored });
    }
    return ctx.snapshot(observations);
  },
  ["POST /sign-in/social", "GET /callback/{}", "GET /get-session"],
);
