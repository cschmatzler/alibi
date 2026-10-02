import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { adminClient } from "better-auth/client/plugins";
import { z } from "zod";

import { authProfilePath, type FixtureProfile } from "../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../support/scenario";

async function signup(ctx: ScenarioContext, profile: FixtureProfile, name: string) {
  const client = createAuthClient({
    baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
    plugins: [adminClient()],
    fetchOptions: { customFetchImpl: ctx.actor(name, profile).fetch },
  });
  const result = await client.signUp.email({
    email: ctx.uniqueEmail(name),
    name,
    password: "password123",
  });
  expect(result.error).toBeNull();

  if (!result.data) {
    throw new Error("real registered owner required");
  }

  return { client, result, id: result.data.user.id };
}

const stateSchema = z.object({
  sessions: z.array(z.object({ id: z.string(), token: z.string(), userId: z.string() })),
});

for (const mode of ["privileged", "ordinary", "legacy", "no-base"] as const) {
  compatScenario(
    `admin impersonation ${mode} uses original actor permissions for admin targets and self sessions`,
    async (ctx) => {
      const profile = `admin-impersonation-${mode}` as FixtureProfile;
      const owner = await signup(ctx, profile, "impersonation-owner");
      const target = await signup(ctx, profile, "impersonation-target");
      const foreign = await signup(ctx, "admin-impersonation-no-base", "impersonation-foreign");
      const role = await owner.client.admin.setRole({ userId: target.id, role: "admin" });
      expect(role.error).toBeNull();
      expect(role.data?.user.role).toBe("admin");

      const original = await owner.client.getSession();
      expect(original.data?.user.id).toBe(owner.id);

      const ownerBefore = await ctx.readUserState({ userId: owner.id });
      const targetBefore = await ctx.readUserState({ userId: target.id });
      const foreignBefore = await ctx.readUserState({ userId: foreign.id });
      const guest = createAuthClient({
        baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
        plugins: [adminClient()],
        fetchOptions: { customFetchImpl: ctx.actor("impersonation-guest", profile).fetch },
      });
      const unauthenticated = await guest.admin.impersonateUser({ userId: target.id });
      expect(unauthenticated.error?.status).toBe(401);

      const wrongActor = await foreign.client.$fetch("/admin/impersonate-user", {
        method: "POST",
        body: {
          userId: target.id,
          role: "operator",
          permissions: { user: ["impersonate", "impersonate-admins"] },
          allowImpersonatingAdmins: true,
        },
      });
      expect(wrongActor.error).toMatchObject({
        status: 403,
        code: "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS",
      });
      expect(await ctx.readUserState({ userId: target.id })).toEqual(targetBefore);
      expect(await ctx.readUserState({ userId: foreign.id })).toEqual(foreignBefore);

      const impersonated = await owner.client.admin.impersonateUser({ userId: target.id });
      let current: unknown = null;
      let during: unknown = null;
      let stopped: unknown = null;

      if (mode === "privileged" || mode === "legacy") {
        expect(impersonated.error).toBeNull();
        expect(impersonated.data?.user.id).toBe(target.id);
        expect(impersonated.data).toMatchObject({ session: { impersonatedBy: owner.id } });
        expect(impersonated.data?.session.token).not.toBe(original.data?.session.token);

        current = await owner.client.getSession();
        expect(current).toMatchObject({
          data: {
            user: { id: target.id },
            session: {
              id: impersonated.data!.session.id,
              token: impersonated.data!.session.token,
              impersonatedBy: owner.id,
            },
          },
        });

        during = await ctx.readUserState({ userId: target.id });
        const rows = stateSchema.parse(during).sessions;
        expect(rows).toHaveLength(stateSchema.parse(targetBefore).sessions.length + 1);
        expect(rows).toContainEqual(
          expect.objectContaining({
            id: impersonated.data!.session.id,
            token: impersonated.data!.session.token,
            userId: target.id,
          }),
        );
        expect(await ctx.readUserState({ userId: owner.id })).toEqual(ownerBefore);

        stopped = await owner.client.admin.stopImpersonating();
        expect(stopped).toMatchObject({
          error: null,
          data: {
            user: { id: owner.id },
            session: { id: original.data!.session.id, token: original.data!.session.token },
          },
        });
      } else {
        expect(impersonated.error).toMatchObject({
          status: 403,
          code:
            mode === "ordinary"
              ? "YOU_CANNOT_IMPERSONATE_ADMINS"
              : "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS",
        });
      }

      expect(await ctx.readUserState({ userId: target.id })).toEqual(targetBefore);
      expect(await ctx.readUserState({ userId: owner.id })).toEqual(ownerBefore);

      const self = await owner.client.admin.impersonateUser({ userId: owner.id });
      let selfDuring: unknown = null;
      let selfStopped: unknown = null;

      if (mode === "no-base") {
        expect(self.error).toMatchObject({
          status: 403,
          code: "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS",
        });
      } else {
        expect(self.error).toBeNull();
        expect(self.data?.user.id).toBe(owner.id);
        expect(self.data).toMatchObject({ session: { impersonatedBy: owner.id } });
        expect(self.data?.session.token).not.toBe(original.data?.session.token);

        const selected = await owner.client.getSession();
        expect(selected.data?.session.id).toBe(self.data?.session.id);
        expect(selected.data?.session.token).toBe(self.data?.session.token);

        selfDuring = await ctx.readUserState({ userId: owner.id });
        expect(stateSchema.parse(selfDuring).sessions).toHaveLength(
          stateSchema.parse(ownerBefore).sessions.length + 1,
        );

        selfStopped = await owner.client.admin.stopImpersonating();
        expect(selfStopped).toMatchObject({
          error: null,
          data: {
            user: { id: owner.id },
            session: { id: original.data!.session.id, token: original.data!.session.token },
          },
        });
      }

      const restored = await owner.client.getSession();
      expect(restored.data?.session.id).toBe(original.data?.session.id);
      expect(restored.data?.session.token).toBe(original.data?.session.token);

      const ownerAfter = await ctx.readUserState({ userId: owner.id });
      const targetAfter = await ctx.readUserState({ userId: target.id });
      const foreignAfter = await ctx.readUserState({ userId: foreign.id });
      expect(ownerAfter).toEqual(ownerBefore);
      expect(targetAfter).toEqual(targetBefore);
      expect(foreignAfter).toEqual(foreignBefore);

      return {
        mode,
        signup: owner.result,
        target: target.result,
        foreign: foreign.result,
        role,
        original,
        ownerBefore,
        targetBefore,
        foreignBefore,
        unauthenticated,
        wrongActor,
        impersonated,
        current,
        during,
        stopped,
        self,
        selfDuring,
        selfStopped,
        restored,
        ownerAfter,
        targetAfter,
        foreignAfter,
      };
    },
    ["POST /admin/impersonate-user", "POST /admin/stop-impersonating"],
  );
}
