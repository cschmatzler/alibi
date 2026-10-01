import { expect } from "bun:test";
import { z } from "zod";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { adminActor, signUpAndPromoteAdmin } from "./helpers";

const persisted = z.object({
  accounts: z.array(z.object({ userId: z.string() })),
  sessions: z.array(z.object({ userId: z.string(), token: z.string() })),
});

async function expiredBanSnapshot(
  ctx: ScenarioContext,
  impersonation: boolean,
) {
  const owner = await signUpAndPromoteAdmin(
      ctx,
      "owner",
      "expired-ban-owner",
      "Ban owner",
    ),
    target = adminActor(ctx, "target"),
    foreign = adminActor(ctx, "foreign");
  expect(owner.signup.error).toBeNull();
  if (!owner.signup.data) throw new Error("issued owner required");
  const email = ctx.uniqueEmail("expired-ban-target"),
    foreignEmail = ctx.uniqueEmail("expired-ban-foreign");
  const signup = await target.client.signUp.email({
      email,
      password: "password123",
      name: "Expired ban target",
    }),
    foreignSignup = await foreign.client.signUp.email({
      email: foreignEmail,
      password: "password123",
      name: "Foreign owner",
    });
  expect(signup.error).toBeNull();
  expect(foreignSignup.error).toBeNull();
  if (!signup.data || !foreignSignup.data)
    throw new Error("issued target and foreign users required");
  const userId = signup.data.user.id,
    ownerId = owner.signup.data.user.id,
    foreignId = foreignSignup.data.user.id;
  const reader = adminActor(ctx, "owner-reader");
  const readerLogin = await reader.client.signIn.email({
    email: owner.email,
    password: "password123",
  });
  expect(readerLogin.error).toBeNull();
  const ownerBefore = await ctx.readUserState({ userId: ownerId }),
    foreignBefore = await ctx.readUserState({ userId: foreignId });
  const ban = await owner.adminClient.admin.banUser({
    userId,
    banReason: "expired application ban",
    banExpiresIn: -60,
  });
  expect(ban.error).toBeNull();
  expect(ban.data?.user.banned).toBe(true);
  const bannedUser = await owner.adminClient.admin.getUser({
    query: { id: userId },
  });
  expect(bannedUser.error).toBeNull();
  expect(bannedUser.data?.banned).toBe(true);
  const bannedState = await ctx.readUserState({ userId });
  expect(persisted.parse(bannedState).sessions).toHaveLength(0);
  const result = impersonation
    ? await owner.adminClient.admin.impersonateUser({ userId })
    : await target.client.signIn.email({ email, password: "password123" });
  expect(result.error).toBeNull();
  expect(result.data?.user).toMatchObject({
    id: userId,
    banned: true,
    banReason: "expired application ban",
    banExpires: bannedUser.data?.banExpires,
  });
  if (!result.data || !bannedUser.data)
    throw new Error("both original user observations required");
  expect(new Date(result.data.user.updatedAt).getTime()).toBe(
    new Date(bannedUser.data.updatedAt).getTime(),
  );
  const authoritative = await reader.adminClient.admin.getUser({
    query: { id: userId },
  });
  expect(authoritative.error).toBeNull();
  expect(authoritative.data).toMatchObject({
    id: userId,
    banned: false,
    banReason: null,
    banExpires: null,
  });
  const current = await (
    impersonation ? owner.client : target.client
  ).getSession();
  expect(current.error).toBeNull();
  expect(current.data?.user).toMatchObject({
    id: userId,
    banned: false,
    banReason: null,
    banExpires: null,
  });
  const after = await ctx.readUserState({ userId }),
    rows = persisted.parse(after);
  expect(rows.sessions).toHaveLength(1);
  expect(rows.sessions[0]?.userId).toBe(userId);
  expect(rows.sessions[0]?.token).toBe(current.data?.session.token);
  expect(rows.accounts.every((account) => account.userId === userId)).toBe(
    true,
  );
  const token =
    impersonation && result.data && "session" in result.data
      ? result.data.session.token
      : result.data && "token" in result.data
        ? result.data.token
        : null;
  expect(typeof token).toBe("string");
  expect(token).toBe(current.data?.session.token ?? null);
  const foreignAfter = await ctx.readUserState({ userId: foreignId });
  expect(foreignAfter).toEqual(foreignBefore);
  const ownerAfter = await ctx.readUserState({ userId: ownerId });
  expect(ownerAfter).toEqual(ownerBefore);
  const readerCurrent = await reader.client.getSession();
  expect(readerCurrent.data?.user.id).toBe(ownerId);
  expect(readerCurrent.data?.session.token).toBe(
    readerLogin.data?.token ?? undefined,
  );
  return {
    owner: owner.signup,
    signup,
    foreignSignup,
    ownerBefore,
    foreignBefore,
    ban,
    bannedUser,
    bannedState,
    result,
    authoritative,
    readerLogin,
    readerCurrent,
    current,
    after,
    ownerAfter,
    foreignAfter,
  };
}

compatScenario(
  "expired ban sign-in returns original user snapshot while persistent authorization and session state unban",
  (ctx) => expiredBanSnapshot(ctx, false),
);
compatScenario(
  "expired ban impersonation returns original target snapshot while persistent authorization and session state unban",
  (ctx) => expiredBanSnapshot(ctx, true),
);
