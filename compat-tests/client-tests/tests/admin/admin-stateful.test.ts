import { expect } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { twoFactorClient } from "better-auth/client/plugins";
import { z } from "zod";
import { compatScenario } from "../../support/scenario";
import { adminActor, signUpAndPromoteAdmin } from "../admin/helpers";

const persistedUserState = z.object({
  user: z.object({ id: z.string(), email: z.string().nullable(), emailVerified: z.boolean(), twoFactorEnabled: z.boolean() }).nullable(),
  accounts: z.array(z.object({ id: z.string(), userId: z.string(), accountId: z.string(), providerId: z.string() })),
  sessions: z.array(z.object({ id: z.string(), token: z.string(), userId: z.string(), expiresAt: z.string() })),
  twoFactorExists: z.boolean(),
});

compatScenario("admin deletion revokes target credentials and sessions while rejecting other principals", async (ctx) => {
  const admin = await signUpAndPromoteAdmin(ctx, "admin", "admin-delete-admin", "Deletion Admin");
  const target = adminActor(ctx, "target");
  const email = ctx.uniqueEmail("admin-delete-target");
  const signup = await target.client.signUp.email({ email, password: "password123", name: "Deletion Target" });
  expect(signup.error).toBeNull();
  if (!signup.data) throw new Error("deletion target must be created");
  const userId = signup.data.user.id;
  await target.client.signIn.email({ email, password: "password123" });
  await ctx.seedOAuthAccount({ email, providerId: "mock", accountId: ctx.uniqueToken("deletion-provider") });
  const factorClient = createAuthClient({ baseURL: ctx.baseURL, plugins: [twoFactorClient()], fetchOptions: { customFetchImpl: target.fetch } });
  const enrollment = await factorClient.twoFactor.enable({ password: "password123" });
  expect(enrollment.error).toBeNull();
  const before = persistedUserState.parse(await ctx.readUserState({ userId }));
  expect(before.twoFactorExists).toBe(true);
  expect(before.accounts).toHaveLength(2);
  expect(before.sessions).toHaveLength(2);
  expect(before.accounts.every(account => account.userId === userId)).toBe(true);
  const guest = adminActor(ctx, "guest");
  const unauthenticated = await guest.adminClient.admin.removeUser({ userId });
  expect(unauthenticated.error).toMatchObject({ status: 401 });
  const other = adminActor(ctx, "other");
  await other.client.signUp.email({ email: ctx.uniqueEmail("admin-delete-other"), password: "password123", name: "Other User" });
  const unauthorized = await other.adminClient.admin.removeUser({ userId });
  expect(unauthorized.error).toMatchObject({ status: 403, code: "YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS" });
  const afterRejection = persistedUserState.parse(await ctx.readUserState({ userId }));
  expect(afterRejection).toEqual(before);
  const targetSession = await target.client.getSession();
  expect(targetSession.data?.user.id).toBe(userId);
  const selfRemoval = await admin.adminClient.admin.removeUser({ userId: admin.signup.data!.user.id });
  expect(selfRemoval.error).toMatchObject({ status: 400, code: "YOU_CANNOT_REMOVE_YOURSELF" });
  expect(persistedUserState.parse(await ctx.readUserState({ userId }))).toEqual(before);
  const remove = await admin.adminClient.admin.removeUser({ userId });
  expect(remove.data).toEqual({ success: true });
  const after = persistedUserState.parse(await ctx.readUserState({ userId }));
  expect(after).toEqual({ user: null, accounts: [], sessions: [], twoFactorExists: true });
  const revoked = await target.client.getSession();
  expect(revoked.data).toBeNull();
  const credentialReuse = await target.client.signIn.email({ email, password: "password123" });
  expect(credentialReuse.error).toMatchObject({ status: 401, code: "INVALID_EMAIL_OR_PASSWORD" });
  const deleteAgain = await admin.adminClient.admin.removeUser({ userId });
  expect(deleteAgain.error).toMatchObject({ status: 404, code: "USER_NOT_FOUND" });
  const adminSession = await admin.client.getSession();
  expect(adminSession.data?.user.id).toBe(admin.signup.data?.user.id);
  return {
    signup: ctx.snapshot(signup), before, unauthenticated: ctx.snapshot(unauthenticated), unauthorized: ctx.snapshot(unauthorized),
    afterRejection, targetSession: ctx.snapshot(targetSession), selfRemoval: ctx.snapshot(selfRemoval), remove: ctx.snapshot(remove), after,
    revoked: ctx.snapshot(revoked), credentialReuse: ctx.snapshot(credentialReuse), deleteAgain: ctx.snapshot(deleteAgain), adminSession: ctx.snapshot(adminSession),
  };
}, ["POST /admin/remove-user"]);

function extractState(url: string | undefined) {
  if (!url) {
    throw new Error("missing OAuth URL");
  }
  const state = new URL(url).searchParams.get("state");
  if (!state) {
    throw new Error("missing OAuth state");
  }
  return state;
}

function summarizeLocation(location: string | null) {
  if (!location) {
    throw new Error("missing redirect location");
  }
  const url = new URL(location, "http://compat.local");
  return {
    pathname: url.pathname,
    params: Object.fromEntries(url.searchParams.entries()),
  };
}

compatScenario("admin ban, unban, and user-session routes match TS", async (ctx) => {
  const admin = await signUpAndPromoteAdmin(ctx, "admin", "admin-admin-stateful", "Admin Admin");
  const target = adminActor(ctx, "target");
  const targetEmail = ctx.uniqueEmail("admin-target");
  const signUp = await target.client.signUp.email({
    email: targetEmail,
    password: "password123",
    name: "Admin Target",
  });
  const targetId = signUp.data?.user.id ?? "";

  await target.client.signIn.email({
    email: targetEmail,
    password: "password123",
  });

  const listBeforeBan = await admin.adminClient.admin.listUserSessions({
    userId: targetId,
  });

  const banUser = await admin.adminClient.admin.banUser({
    userId: targetId,
    banReason: "admin ban",
    banExpiresIn: 60 * 60,
  });

  const listAfterBan = await admin.adminClient.admin.listUserSessions({
    userId: targetId,
  });

  const unbanUser = await admin.adminClient.admin.unbanUser({
    userId: targetId,
  });

  await target.client.signIn.email({
    email: targetEmail,
    password: "password123",
  });
  await target.client.signIn.email({
    email: targetEmail,
    password: "password123",
  });

  const listBeforeRevoke = await admin.adminClient.admin.listUserSessions({
    userId: targetId,
  });
  const revokeSingle = await admin.adminClient.admin.revokeUserSession({
    sessionToken: listBeforeRevoke.data?.sessions[0]?.token ?? "",
  });
  const listAfterSingle = await admin.adminClient.admin.listUserSessions({
    userId: targetId,
  });
  const listMissing = await admin.adminClient.admin.listUserSessions({
    userId: "missing-user",
  });
  const revokeMissing = await admin.adminClient.admin.revokeUserSessions({
    userId: "missing-user",
  });
  const revokeAll = await admin.adminClient.admin.revokeUserSessions({
    userId: targetId,
  });
  const listAfterAll = await admin.adminClient.admin.listUserSessions({
    userId: targetId,
  });

  return {
    listBeforeBan: ctx.snapshot(listBeforeBan),
    banUser: ctx.snapshot(banUser),
    listAfterBan: ctx.snapshot(listAfterBan),
    unbanUser: ctx.snapshot(unbanUser),
    listBeforeRevoke: ctx.snapshot(listBeforeRevoke),
    revokeSingle: ctx.snapshot(revokeSingle),
    listAfterSingle: ctx.snapshot(listAfterSingle),
    listMissing: ctx.snapshot(listMissing),
    revokeMissing: ctx.snapshot(revokeMissing),
    revokeAll: ctx.snapshot(revokeAll),
    listAfterAll: ctx.snapshot(listAfterAll),
  };
});

compatScenario("banned users are denied email and social session creation", async (ctx) => {
  const admin = await signUpAndPromoteAdmin(ctx, "admin", "admin-banned", "Admin Admin");
  const target = adminActor(ctx, "target");
  const targetEmail = ctx.uniqueEmail("admin-banned-user");
  const targetPassword = "password123";
  const signUp = await target.client.signUp.email({
    email: targetEmail,
    password: targetPassword,
    name: "Banned User",
  });
  const targetId = signUp.data?.user.id ?? "";

  await admin.adminClient.admin.banUser({
    userId: targetId,
    banReason: "admin banned",
  });

  const emailSignIn = await target.client.signIn.email({
    email: targetEmail,
    password: targetPassword,
  });

  await ctx.setSocialProfile({
    email: targetEmail,
    sub: ctx.uniqueToken("admin-banned-social"),
    name: "Banned Social User",
    emailVerified: true,
    idTokenValid: true,
  });

  const socialSignIn = await target.client.signIn.social({
    provider: "google",
    callbackURL: "/dashboard",
  });
  const state = extractState(socialSignIn.data?.url);
  const callback = await ctx.rawRequest({
    actor: "target",
    path: `/api/auth/callback/google?code=compat-code&state=${encodeURIComponent(state)}`,
    redirect: "manual",
  });
  const callbackLocation = summarizeLocation(callback.location);
  const session = await target.client.getSession();

  return {
    emailSignIn: ctx.snapshot(emailSignIn),
    socialSignIn: {
      redirect: socialSignIn.data?.redirect,
      hasState: Boolean(state),
    },
    callback: {
      status: callback.status,
      pathname: callbackLocation.pathname,
      params: callbackLocation.params,
    },
    session: ctx.snapshot(session),
  };
});

compatScenario("admin impersonation restores the original admin session and hides impersonated sessions", async (ctx) => {
  const admin = await signUpAndPromoteAdmin(ctx, "admin", "admin-impersonate", "Admin Admin");
  const target = adminActor(ctx, "target");
  const targetEmail = ctx.uniqueEmail("admin-impersonated-user");
  const targetPassword = "password123";
  const signUp = await target.client.signUp.email({
    email: targetEmail,
    password: targetPassword,
    name: "Impersonated User",
  });
  const targetId = signUp.data?.user.id ?? "";

  const impersonate = await admin.adminClient.admin.impersonateUser({
    userId: targetId,
  });
  const persistedImpersonation = await ctx.readUserState({ userId: targetId });
  const impersonatedSession = await admin.client.getSession();
  expect(impersonatedSession.data?.session.token).toBe(impersonate.data?.session.token);
  expect(impersonatedSession.data?.session.id).toBe(impersonate.data?.session.id);
  expect(impersonatedSession.data?.session.expiresAt.getTime()).toBe(impersonate.data?.session.expiresAt.getTime());
  const persistedAfterRead = await ctx.readUserState({ userId: targetId });
  expect(persistedAfterRead).toEqual(persistedImpersonation);

  const directSignIn = await target.client.signIn.email({
    email: targetEmail,
    password: targetPassword,
  });
  const listedSessions = await target.client.listSessions();

  const stopImpersonating = await admin.adminClient.admin.stopImpersonating({});
  const restoredSession = await admin.client.getSession();
  const adminListUsers = await admin.adminClient.admin.listUsers({
    query: {
      filterField: "role",
      filterOperator: "eq",
      filterValue: "admin",
    },
  });

  return {
    impersonate: ctx.snapshot(impersonate),
    impersonatedSession: ctx.snapshot(impersonatedSession),
    persistedImpersonation: ctx.snapshot(persistedImpersonation),
    persistedAfterRead: ctx.snapshot(persistedAfterRead),
    directSignIn: ctx.snapshot(directSignIn),
    listedSessions: ctx.snapshot(listedSessions),
    stopImpersonating: ctx.snapshot(stopImpersonating),
    restoredSession: ctx.snapshot(restoredSession),
    adminListUsers: ctx.snapshot(adminListUsers),
  };
});
