import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
for (const mode of ["other", "all"] as const) {
  compatScenario(
    mode === "other"
      ? "revoke-other-sessions deletes active siblings but retains expired physical rows and foreign authority"
      : "revoke-sessions deletes active and expired owner rows while preserving foreign authority",
    async (ctx) => {
      const owner = ctx.actor("owner");
      const email = ctx.uniqueEmail("physical-revoke-owner");
      const signup = await owner.client.signUp.email({
        email,
        name: "Owner",
        password: "password123",
      });
      expect(signup.error).toBeNull();
      const userId = signup.data!.user.id;
      const active = await ctx
        .actor("active")
        .client.signIn.email({ email, password: "password123" });
      expect(active.error).toBeNull();
      const expired = await ctx
        .actor("expired")
        .client.signIn.email({ email, password: "password123" });
      expect(expired.error).toBeNull();
      const other = await ctx.actor("foreign").client.signUp.email({
        email: ctx.uniqueEmail("physical-revoke-foreign"),
        name: "Foreign",
        password: "password123",
      });
      expect(other.error).toBeNull();
      const expiredAt = new Date(Date.now() - 3600000).toISOString();
      const clock = await ctx.rawRequest({
        path: "/__test/expire-session",
        method: "POST",
        json: { token: expired.data!.token, expiresAt: expiredAt },
      });
      expect(clock.body).toEqual({ updated: 1 });
      const before = (await ctx.readUserState({ userId })) as any;
      expect(before.sessions).toHaveLength(3);
      const otherBefore = await ctx.readUserState({ userId: other.data!.user.id });
      const revoked = await (mode === "other"
        ? owner.client.revokeOtherSessions()
        : owner.client.revokeSessions());
      expect(revoked.error).toBeNull();
      const after = (await ctx.readUserState({ userId })) as any;
      expect(after.sessions).toEqual(
        mode === "other" ? before.sessions.filter((s: any) => s.token !== active.data!.token) : [],
      );
      if (mode === "other") {
        expect(after.sessions.find((s: any) => s.token === expired.data!.token).expiresAt).toBe(
          expiredAt,
        );
      }
      expect(after.user).toEqual(before.user);
      expect(after.accounts).toEqual(before.accounts);
      expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(otherBefore);
      const kept = await owner.client.getSession();
      if (mode === "other") expect(kept.data!.session.token).toBe(signup.data!.token!);
      else expect(kept.data).toBeNull();
      const removed = await ctx.actor("active").client.getSession();
      expect(removed.data).toBeNull();
      const foreign = await ctx.actor("foreign").client.getSession();
      expect(foreign.data!.user.id).toBe(other.data!.user.id);
      expect(await ctx.readUserState({ userId })).toEqual(after);
      return ctx.snapshot({
        signup,
        active,
        expired,
        other,
        before,
        revoked,
        after,
        otherBefore,
        kept,
        removed,
        foreign,
      });
    },
    [
      mode === "other" ? "POST /revoke-other-sessions" : "POST /revoke-sessions",
      "GET /get-session",
    ],
  );
}
