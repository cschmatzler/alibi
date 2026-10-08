import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import { readUserState } from "../../../support/verification";

compatScenario(
  "account allowUnlinkingAll removes the last credential provider while preserving user and sessions",
  async (ctx) => {
    const observations = [];
    for (const profile of [undefined, "account-unlink-all"] as const) {
      const owner = ctx.actor(`unlink-owner-${profile}`, profile);
      const signup = await owner.client.signUp.email({
        email: ctx.uniqueEmail(`unlink-${profile}`),
        name: "Unlink owner",
        password: "password123",
      });
      expect(signup.error).toBeNull();
      const before = await readUserState(ctx, signup.data!.user.id);
      expect(before.accounts).toHaveLength(1);
      expect(before.accounts[0]!.providerId).toBe("credential");
      const providerResponse = await owner.fetch(
        `${ctx.baseURL}${profile ? authProfilePath(profile) : "/api/auth"}/unlink-account`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ providerId: "credential" }),
        },
      );
      const providerForm = { status: providerResponse.status, body: await providerResponse.json() };
      expect(providerForm.status).toBe(400);
      expect(await readUserState(ctx, signup.data!.user.id)).toEqual(before);
      const unlinked = await owner.client.unlinkAccount({ accountId: before.accounts[0]!.id });
      const after = await readUserState(ctx, signup.data!.user.id);
      if (profile) {
        expect(unlinked.error).toBeNull();
        expect(unlinked.data).toEqual({ status: true });
        expect(after.accounts).toEqual([]);
        expect(after.user).toEqual(before.user);
        expect(after.sessions).toEqual(before.sessions);
        const session = await owner.client.getSession();
        expect(session.data?.user.id).toBe(signup.data!.user.id);
        const replay = await owner.client.unlinkAccount({ accountId: before.accounts[0]!.id });
        expect(replay.error).not.toBeNull();
        expect(await readUserState(ctx, signup.data!.user.id)).toEqual(after);
        observations.push({ session, replay });
      } else {
        expect(unlinked.error).toMatchObject({ status: 400 });
        expect(after).toEqual(before);
      }
      observations.push({
        profile: profile ?? "default",
        signup,
        before,
        providerForm,
        unlinked,
        after,
      });
    }
    return ctx.snapshot(observations);
  },
  ["POST /unlink-account"],
);
