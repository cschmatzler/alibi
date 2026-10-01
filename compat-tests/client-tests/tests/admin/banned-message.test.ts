import { expect } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { adminClient } from "better-auth/client/plugins";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { authProfilePath, type FixtureProfile } from "../../support/profiles";

function client(ctx: ScenarioContext, name: string, profile?: FixtureProfile) {
  return createAuthClient({
    baseURL: `${ctx.baseURL}${profile ? authProfilePath(profile) : "/api/auth"}`,
    plugins: [adminClient()],
    fetchOptions: { customFetchImpl: ctx.actor(name, profile).fetch },
  });
}
async function signup(
  ctx: ScenarioContext,
  name: string,
  profile?: FixtureProfile,
) {
  const current = client(ctx, name, profile),
    email = ctx.uniqueEmail(name);
  const result = await current.signUp.email({
    email,
    name,
    password: "password123",
    // The application field is not writable by clients. Its stored default must win.
    ...{ metadata: { supportCode: "forged-client-code" } },
  });
  expect(result.error).toBeNull();
  if (!result.data) throw new Error("signup required");
  expect(result.data.user).not.toHaveProperty("metadata");
  return { client: current, email, result, userId: result.data.user.id };
}
async function state(ctx: ScenarioContext, email: string) {
  const result = await ctx.rawRequest({
    path: `/__test/admin-role-state?email=${encodeURIComponent(email)}`,
    method: "GET",
  });
  expect(result.status).toBe(200);
  return result.body as {
    user: {
      id: string;
      banned: boolean;
      banReason: string | null;
      banExpires: string | null;
    };
    sessions: {
      userId: string;
      token: string;
      impersonatedBy: string | null;
    }[];
  };
}
async function events(
  ctx: ScenarioContext,
  email: string,
  profile: FixtureProfile,
) {
  const result = await ctx.rawRequest({
    path: `/__test/admin-banned-message-events?email=${encodeURIComponent(email)}&profile=${profile}`,
    method: "GET",
  });
  expect(result.status).toBe(200);
  return result.body as {
    user: { userId: string; metadata: { supportCode: string } };
    events: {
      profile: string;
      userId: string;
      email: string;
      name: string;
      role: string;
      banned: boolean;
      banReason: string;
      banExpires: string | null;
      metadata: { supportCode: string };
    }[];
  };
}
for (const profile of [
  "admin-banned-message",
  "admin-banned-message-error",
] as const) {
  compatScenario(
    `admin awaited ${profile} uses hidden stored owner data and skips unauthorized expired and unbanned requests`,
    async (ctx) => {
      const owner = await signup(ctx, `${profile}-owner`, profile),
        target = await signup(ctx, `${profile}-target`, profile),
        foreign = await signup(ctx, `${profile}-foreign`, profile);
      const foreignRole = await owner.client.admin.setRole({
        userId: foreign.userId,
        role: "user",
      });
      expect(foreignRole.error).toBeNull();
      expect(foreignRole.data?.user.role).toBe("user");
      const ownerBefore = await state(ctx, owner.email),
        foreignBefore = await state(ctx, foreign.email),
        initial = await events(ctx, target.email, profile);
      expect(initial).toEqual({
        user: {
          userId: target.userId,
          metadata: { supportCode: "private-fixture-code" },
        },
        events: [],
      });
      const unbannedSignin = await target.client.signIn.email({
        email: target.email,
        password: "password123",
      });
      expect(unbannedSignin.error).toBeNull();
      const unbannedEvents = await events(ctx, target.email, profile);
      expect(unbannedEvents).toEqual(initial);
      const ban = await owner.client.admin.banUser({
        userId: target.userId,
        banReason: "application ban",
      });
      expect(ban.error).toBeNull();
      const banned = await state(ctx, target.email);
      expect(banned.user).toMatchObject({
        id: target.userId,
        banned: true,
        banReason: "application ban",
        banExpires: null,
      });
      expect(banned.sessions).toHaveLength(0);
      const wrongPassword = await target.client.signIn.email({
        email: target.email,
        password: "wrong password",
      });
      expect(wrongPassword.error?.status).toBe(401);
      const foreignDenied = await foreign.client.admin.impersonateUser({
        userId: target.userId,
      });
      expect(foreignDenied.error?.status).toBe(403);
      const preCallback = await events(ctx, target.email, profile);
      expect(preCallback).toEqual(initial);
      const deniedSignin = await target.client.signIn.email({
        email: target.email,
        password: "password123",
      });
      const afterSignin = await events(ctx, target.email, profile);
      expect(afterSignin.events).toHaveLength(1);
      const deniedImpersonation = await owner.client.admin.impersonateUser({
        userId: target.userId,
      });
      const afterImpersonation = await events(ctx, target.email, profile);
      expect(afterImpersonation.events).toHaveLength(2);
      for (const event of afterImpersonation.events)
        expect(event).toEqual({
          profile,
          userId: target.userId,
          email: target.email,
          name: `${profile}-target`,
          role: "admin",
          banned: true,
          banReason: "application ban",
          banExpires: null,
          metadata: { supportCode: "private-fixture-code" },
        });
      for (const result of [deniedSignin, deniedImpersonation]) {
        expect(result.data).toBeNull();
        expect(result.error?.status).toBe(
          profile === "admin-banned-message" ? 403 : 400,
        );
        expect(result.error?.code).toBe(
          profile === "admin-banned-message"
            ? "BANNED_USER"
            : "APPLICATION_BAN_MESSAGE_REFUSED",
        );
        expect(result.error?.message).toBe(
          profile === "admin-banned-message"
            ? "private-fixture-code:application ban"
            : "configured message refused",
        );
      }
      const rejectedState = await state(ctx, target.email);
      expect(rejectedState).toEqual(banned);
      let expectedFinalEvents = afterImpersonation;
      let serverError;
      if (profile === "admin-banned-message-error") {
        const serverBan = await owner.client.admin.banUser({
          userId: target.userId,
          banReason: "server application ban",
        });
        expect(serverBan.error).toBeNull();
        const serverBanned = await state(ctx, target.email);
        const serverSignin = await target.client.signIn.email({
          email: target.email,
          password: "password123",
        });
        const serverImpersonation = await owner.client.admin.impersonateUser({
          userId: target.userId,
        });
        for (const errorResult of [serverSignin, serverImpersonation]) {
          expect(errorResult.data).toBeNull();
          expect(errorResult.error).toMatchObject({
            status: 500,
            code: "APPLICATION_BAN_MESSAGE_UNAVAILABLE",
            message: "configured message unavailable",
          });
        }
        const serverAfter = await state(ctx, target.email);
        expect(serverAfter).toEqual(serverBanned);
        expectedFinalEvents = await events(ctx, target.email, profile);
        expect(expectedFinalEvents.events).toHaveLength(4);
        for (const event of expectedFinalEvents.events.slice(2))
          expect(event).toMatchObject({
            userId: target.userId,
            metadata: { supportCode: "private-fixture-code" },
            banReason: "server application ban",
          });
        serverError = {
          serverBan,
          serverBanned,
          serverSignin,
          serverImpersonation,
          serverAfter,
          events: expectedFinalEvents,
        };
      }
      const expiredBan = await owner.client.admin.banUser({
        userId: target.userId,
        banReason: "expired application ban",
        banExpiresIn: -60,
      });
      expect(expiredBan.error).toBeNull();
      const expiredSignin = await target.client.signIn.email({
        email: target.email,
        password: "password123",
      });
      expect(expiredSignin.error).toBeNull();
      expect(expiredSignin.data?.user.id).toBe(target.userId);
      expect(expiredSignin.data?.user.banned).toBe(true);
      const afterExpiredSignin = await state(ctx, target.email);
      expect(afterExpiredSignin.user).toMatchObject({
        id: target.userId,
        banned: false,
        banReason: null,
        banExpires: null,
      });
      expect(afterExpiredSignin.sessions).toHaveLength(1);
      expect(afterExpiredSignin.sessions[0]).toMatchObject({
        userId: target.userId,
        token: expiredSignin.data?.token,
        impersonatedBy: null,
      });
      const secondExpiredBan = await owner.client.admin.banUser({
        userId: target.userId,
        banReason: "expired impersonation ban",
        banExpiresIn: -60,
      });
      expect(secondExpiredBan.error).toBeNull();
      const expiredImpersonation = await owner.client.admin.impersonateUser({
        userId: target.userId,
      });
      expect(expiredImpersonation.error).toBeNull();
      expect(expiredImpersonation.data?.user.id).toBe(target.userId);
      expect(expiredImpersonation.data?.user.banned).toBe(true);
      const afterExpiredImpersonation = await state(ctx, target.email);
      expect(afterExpiredImpersonation.sessions).toHaveLength(1);
      expect(afterExpiredImpersonation.sessions[0]).toMatchObject({
        userId: target.userId,
        token: expiredImpersonation.data?.session.token,
        impersonatedBy: owner.userId,
      });
      const current = await owner.client.getSession();
      expect(current.data?.user.id).toBe(target.userId);
      const finalEvents = await events(ctx, target.email, profile),
        ownerEvents = await events(ctx, owner.email, profile);
      expect(finalEvents).toEqual(expectedFinalEvents);
      expect(ownerEvents.events).toHaveLength(0);
      const ownerAfter = await state(ctx, owner.email),
        foreignAfter = await state(ctx, foreign.email);
      expect(ownerAfter).toEqual(ownerBefore);
      expect(foreignAfter).toEqual(foreignBefore);
      await ctx.resetServerState();
      const replacement = await signup(ctx, `${profile}-target`, profile);
      expect(replacement.email).toBe(target.email);
      expect(replacement.userId).not.toBe(target.userId);
      const replacementEvents = await events(ctx, replacement.email, profile);
      expect(replacementEvents).toEqual({
        user: { userId: replacement.userId, metadata: { supportCode: "private-fixture-code" } },
        events: [],
      });
      expect((await state(ctx, replacement.email)).sessions).toHaveLength(1);
      return {
        owner: owner.result,
        target: target.result,
        foreign: foreign.result,
        foreignRole,
        ownerBefore,
        foreignBefore,
        initial,
        unbannedSignin,
        unbannedEvents,
        ban,
        banned,
        wrongPassword,
        foreignDenied,
        preCallback,
        deniedSignin,
        afterSignin,
        deniedImpersonation,
        afterImpersonation,
        rejectedState,
        serverError,
        expiredBan,
        expiredSignin,
        afterExpiredSignin,
        secondExpiredBan,
        expiredImpersonation,
        afterExpiredImpersonation,
        current,
        finalEvents,
        ownerEvents,
        ownerAfter,
        foreignAfter,
        replacement: replacement.result,
        replacementEvents,
      };
    },
    ["POST /admin/ban-user", "POST /admin/set-role", "POST /admin/impersonate-user", "POST /sign-in/email"],
  );
}
