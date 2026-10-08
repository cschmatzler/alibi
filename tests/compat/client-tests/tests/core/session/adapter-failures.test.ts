import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";

for (const operation of ["delete_session", "delete_user_sessions"] as const) {
  compatScenario(
    `session adapter failures: ${operation} preserves authority and supports retry`,
    async (ctx) => {
      const profile = "session-adapter-failure";
      async function control(mode?: string) {
        const response = await fetch(`${ctx.baseURL}/__test/session-adapter-failure`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(mode === undefined ? {} : { mode }),
        });
        expect(response.status).toBe(200);
        return response.json() as Promise<{ mode: string; events: string[] }>;
      }
      await control("");
      const owner = ctx.actor("adapter-owner", profile);
      const sibling = ctx.actor("adapter-sibling", profile);
      const foreign = ctx.actor("adapter-foreign", profile);
      const email = ctx.uniqueEmail("adapter-owner");
      const signup = await owner.client.signUp.email({
        email,
        password: "password123",
        name: "Adapter Owner",
      });
      const login = await sibling.client.signIn.email({ email, password: "password123" });
      const other = await foreign.client.signUp.email({
        email: ctx.uniqueEmail("adapter-foreign"),
        password: "password123",
        name: "Foreign Owner",
      });
      expect(signup.error).toBeNull();
      expect(login.error).toBeNull();
      expect(other.error).toBeNull();
      const current = await owner.client.getSession();
      const target = await sibling.client.getSession();
      const ownerId = signup.data!.user.id;
      const foreignId = other.data!.user.id;
      const before = (await ctx.readUserState({ userId: ownerId })) as { sessions: unknown[] };
      const foreignBefore = await ctx.readUserState({ userId: foreignId });
      expect(before.sessions).toHaveLength(2);
      await control(operation);
      const failed =
        operation === "delete_session"
          ? await owner.client.revokeSession({ token: target.data!.session.token })
          : await owner.client.revokeSessions();
      const receipts = await control();
      expect(receipts.events).toContain("get_session");
      expect(receipts.events).toContain(operation);
      expect(failed.data).toBeNull();
      expect(JSON.stringify(failed.error)).not.toContain("application-selected");
      const afterFailure = await ctx.readUserState({ userId: ownerId });
      expect(afterFailure).toEqual(before);
      expect(await ctx.readUserState({ userId: foreignId })).toEqual(foreignBefore);
      expect((await owner.client.getSession()).data?.session.token).toBe(
        current.data!.session.token,
      );
      expect((await sibling.client.getSession()).data?.session.token).toBe(
        target.data!.session.token,
      );
      expect((await foreign.client.getSession()).data?.user.id).toBe(foreignId);
      await control("");
      const retry =
        operation === "delete_session"
          ? await owner.client.revokeSession({ token: target.data!.session.token })
          : await owner.client.revokeSessions();
      expect(retry.error).toBeNull();
      expect(retry.data).toEqual({ status: true });
      expect((await sibling.client.getSession()).data).toBeNull();
      const ownerAfter = await owner.client.getSession();
      if (operation === "delete_session") {
        expect(ownerAfter.data?.session.token).toBe(current.data!.session.token);
      } else expect(ownerAfter.data).toBeNull();
      const final = (await ctx.readUserState({ userId: ownerId })) as { sessions: unknown[] };
      expect(final.sessions).toHaveLength(operation === "delete_session" ? 1 : 0);
      expect(await ctx.readUserState({ userId: foreignId })).toEqual(foreignBefore);
      expect(failed.error).toMatchObject({
        status: 500,
        code: "INTERNAL_SERVER_ERROR",
        message: "Internal Server Error",
      });
      return {
        signup: ctx.snapshot(signup),
        login: ctx.snapshot(login),
        other: ctx.snapshot(other),
        current: ctx.snapshot(current),
        target: ctx.snapshot(target),
        failed: ctx.snapshot(failed),
        afterFailure,
        retry: ctx.snapshot(retry),
        ownerAfter: ctx.snapshot(ownerAfter),
        final,
      };
    },
    [operation === "delete_session" ? "POST /revoke-session" : "POST /revoke-sessions"],
  );
}
