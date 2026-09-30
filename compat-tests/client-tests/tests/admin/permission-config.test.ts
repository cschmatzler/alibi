import { expect } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { adminClient } from "better-auth/client/plugins";
import { z } from "zod";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { authProfilePath, type FixtureProfile } from "../../support/profiles";

async function signup(
  ctx: ScenarioContext,
  profile: FixtureProfile,
  name: string,
) {
  const actor = ctx.actor(name, profile);
  const client = createAuthClient({
    baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
    plugins: [adminClient()],
    fetchOptions: { customFetchImpl: actor.fetch },
  });
  const result = await client.signUp.email({
    email: ctx.uniqueEmail(`${profile}-${name}`),
    password: "password123",
    name,
  });
  expect(result.error).toBeNull();
  if (!result.data) throw new Error("persisted user required");
  return { client, result, userId: result.data.user.id };
}
function permission(
  result: { data: unknown; error: unknown },
  allowed: boolean,
) {
  expect(result.error).toBeNull();
  expect(
    z.object({ success: z.boolean(), error: z.null() }).parse(result.data),
  ).toEqual({ success: allowed, error: null });
}

compatScenario(
  "admin explicit empty roles deny persisted admin reads and mutations while ordinary builtins still authorize",
  async (ctx) => {
    const owner = await signup(ctx, "admin-deny-all", "owner"),
      foreign = await signup(ctx, "admin-standard", "foreign");
    expect(owner.result.data?.user.role).toBe("admin");
    const before = await ctx.readUserState({ userId: foreign.userId });
    const check = await owner.client.admin.hasPermission({
      permissions: { user: ["get", "ban"] },
      role: "admin",
      userId: foreign.userId,
    });
    permission(check, false);
    const get = await owner.client.admin.getUser({
      query: { id: foreign.userId },
    });
    expect(get.error?.status).toBe(403);
    const ban = await owner.client.admin.banUser({
      userId: foreign.userId,
      banReason: "must remain absent",
    });
    expect(ban.error?.status).toBe(403);
    const after = await ctx.readUserState({ userId: foreign.userId });
    expect(after).toEqual(before);
    const current = await owner.client.getSession();
    expect(current.data?.user.id).toBe(owner.userId);
    const allowed = await foreign.client.admin.getUser({
      query: { id: owner.userId },
    });
    expect(allowed.error).toBeNull();
    expect(allowed.data?.id).toBe(owner.userId);
    return ctx.snapshot({
      signup: owner.result,
      foreign: foreign.result,
      check,
      get,
      ban,
      before,
      after,
      current,
      allowed,
    });
  },
);

compatScenario(
  "admin comma role tokens retain exact whitespace and cannot acquire authority through body roles or target normalization",
  async (ctx) => {
    const owner = await signup(ctx, "admin-exact-role", "owner"),
      admin = await signup(ctx, "admin-standard", "authorized");
    expect(owner.result.data?.user.role).toBe("user, admin");
    const before = await ctx.readUserState({ userId: admin.userId });
    const check = await owner.client.admin.hasPermission({
      permissions: { user: ["ban"] },
      role: "admin",
      userId: admin.userId,
    });
    permission(check, false);
    const denied = await owner.client.admin.banUser({ userId: admin.userId });
    expect(denied.error?.status).toBe(403);
    const after = await ctx.readUserState({ userId: admin.userId });
    expect(after).toEqual(before);
    const impersonation = await admin.client.admin.impersonateUser({
      userId: owner.userId,
    });
    expect(impersonation.error).toBeNull();
    expect(impersonation.data?.user.id).toBe(owner.userId);
    const current = await admin.client.getSession();
    expect(current.data?.user.id).toBe(owner.userId);
    expect(current.data?.session.impersonatedBy).toBe(admin.userId);
    const persistedState = await ctx.readUserState({ userId: owner.userId });
    const persisted = z
      .object({
        sessions: z.array(
          z.object({
            userId: z.string(),
            token: z.string(),
            impersonatedBy: z.string().nullable().optional(),
          }),
        ),
      })
      .parse(persistedState);
    expect(
      persisted.sessions.some(
        (session) =>
          session.token === current.data?.session.token &&
          session.userId === owner.userId,
      ),
    ).toBe(true);
    const stop = await admin.client.admin.stopImpersonating();
    expect(stop.error).toBeNull();
    const restored = await admin.client.getSession();
    expect(restored.data?.user.id).toBe(admin.userId);
    return ctx.snapshot({
      signup: owner.result,
      admin: admin.result,
      check,
      denied,
      before,
      after,
      impersonation,
      current,
      persisted: persistedState,
      stop,
      restored,
    });
  },
);

compatScenario(
  "admin empty persisted and configured role fall back to the actual configured user grant",
  async (ctx) => {
    const owner = await signup(ctx, "admin-empty-role", "owner"),
      foreign = await signup(ctx, "admin-standard", "foreign");
    expect(owner.result.data?.user.role).toBe("");
    const before = await ctx.readUserState({ userId: foreign.userId });
    const granted = await owner.client.admin.hasPermission({
      permissions: { user: ["get"] },
    });
    permission(granted, true);
    const read = await owner.client.admin.getUser({
      query: { id: foreign.userId },
    });
    expect(read.error).toBeNull();
    expect(read.data?.id).toBe(foreign.userId);
    const denied = await owner.client.admin.banUser({ userId: foreign.userId });
    expect(denied.error?.status).toBe(403);
    const after = await ctx.readUserState({ userId: foreign.userId });
    expect(after).toEqual(before);
    const current = await owner.client.getSession();
    expect(current.data?.user.id).toBe(owner.userId);
    return ctx.snapshot({
      signup: owner.result,
      foreign: foreign.result,
      granted,
      read,
      denied,
      before,
      after,
      current,
    });
  },
);

compatScenario(
  "admin configured grant rejects empty per-resource action requests without losing valid owned reads",
  async (ctx) => {
    const owner = await signup(ctx, "admin-standard", "owner"),
      foreign = await signup(ctx, "admin-standard", "foreign");
    const before = await ctx.readUserState({ userId: foreign.userId });
    const granted = await owner.client.admin.hasPermission({
      permissions: { user: ["get"], session: ["list"] },
    });
    permission(granted, true);
    const emptyAction = await owner.client.admin.hasPermission({
      permissions: { user: [] },
    });
    permission(emptyAction, false);
    const mixedEmpty = await owner.client.admin.hasPermission({
      permissions: { user: ["get"], session: [] },
    });
    permission(mixedEmpty, false);
    const emptyRequest = await owner.client.admin.hasPermission({
      permissions: {},
    });
    permission(emptyRequest, false);
    const deniedAction = await owner.client.admin.hasPermission({
      permissions: { user: ["get", "impersonate-admins"] },
    });
    permission(deniedAction, false);
    const read = await owner.client.admin.getUser({
      query: { id: foreign.userId },
    });
    expect(read.error).toBeNull();
    expect(read.data?.id).toBe(foreign.userId);
    const after = await ctx.readUserState({ userId: foreign.userId });
    expect(after).toEqual(before);
    return ctx.snapshot({
      signup: owner.result,
      foreign: foreign.result,
      granted,
      emptyAction,
      mixedEmpty,
      emptyRequest,
      deniedAction,
      read,
      before,
      after,
    });
  },
);
