import { expect } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { adminClient } from "better-auth/client/plugins";
import { z } from "zod";
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
  });
  expect(result.error).toBeNull();
  if (!result.data) throw new Error("issued user required");
  return { client: current, email, result, userId: result.data.user.id };
}
const row = z.object({
  user: z.object({
    id: z.string(),
    role: z.string().nullable(),
    banned: z.boolean().nullable(),
    banReason: z.string().nullable(),
    banExpires: z.string().nullable(),
    updatedAt: z.string(),
  }),
  sessions: z.array(
    z.object({
      id: z.string(),
      userId: z.string(),
      token: z.string(),
      impersonatedBy: z.string().nullable(),
      createdAt: z.string(),
      expiresAt: z.string(),
    }),
  ),
});
async function state(ctx: ScenarioContext, email: string) {
  const response = await ctx.rawRequest({
    path: `/__test/admin-role-state?email=${encodeURIComponent(email)}`,
    method: "GET",
  });
  expect(response.status).toBe(200);
  row.parse(response.body);
  return response.body;
}
function expiry(value: string, base: string, milliseconds: number) {
  const elapsed = Date.parse(value) - Date.parse(base);
  // Both dates are generated/persisted by the same server operation. No local
  // clock, sleep, or cross-runtime timestamp normalization supplies this proof.
  expect(elapsed).toBeGreaterThanOrEqual(milliseconds - 100);
  expect(elapsed).toBeLessThanOrEqual(milliseconds + 100);
}

compatScenario(
  "admin zero duration and empty reason use source defaults while owned sessions transition",
  async (ctx) => {
    const owner = await signup(ctx, "zero-owner", "admin-duration-zero"),
      target = await signup(ctx, "zero-target"),
      foreign = await signup(ctx, "zero-foreign");
    const ownerBefore = await state(ctx, owner.email),
      foreignBefore = await state(ctx, foreign.email);
    const ban = await owner.client.admin.banUser({
      userId: target.userId,
      banExpiresIn: 0,
      banReason: "",
    });
    expect(ban.error).toBeNull();
    expect(ban.data?.user.banReason).toBe("No reason");
    expect(ban.data?.user.banExpires).toBeNull();
    const banned = await state(ctx, target.email);
    expect(row.parse(banned).user).toMatchObject({
      id: target.userId,
      banned: true,
      banReason: "No reason",
      banExpires: null,
    });
    expect(row.parse(banned).sessions).toHaveLength(0);
    const denied = await target.client.signIn.email({
      email: target.email,
      password: "password123",
    });
    expect(denied.error?.status).toBe(403);
    expect(denied.error?.code).toBe("BANNED_USER");
    expect(await state(ctx, target.email)).toEqual(banned);
    const unban = await owner.client.admin.unbanUser({ userId: target.userId });
    expect(unban.error).toBeNull();
    const impersonate = await owner.client.admin.impersonateUser({
      userId: target.userId,
    });
    expect(impersonate.error).toBeNull();
    if (!impersonate.data) throw new Error("impersonation required");
    const targetAfter = await state(ctx, target.email),
      session = row
        .parse(targetAfter)
        .sessions.find(
          (item) => item.token === impersonate.data?.session.token,
        );
    if (!session) throw new Error("persisted impersonation required");
    expect(session).toMatchObject({
      userId: target.userId,
      impersonatedBy: owner.userId,
    });
    expiry(session.expiresAt, session.createdAt, 3_600_000);
    const current = await owner.client.getSession();
    expect(current.data?.user.id).toBe(target.userId);
    const ownerAfter = await state(ctx, owner.email),
      foreignAfter = await state(ctx, foreign.email);
    expect(ownerAfter).toEqual(ownerBefore);
    expect(foreignAfter).toEqual(foreignBefore);
    return {
      owner: owner.result,
      target: target.result,
      foreign: foreign.result,
      ownerBefore,
      foreignBefore,
      ban,
      banned,
      denied,
      unban,
      impersonate,
      targetAfter,
      current,
      ownerAfter,
      foreignAfter,
    };
  },
);

compatScenario(
  "admin explicit fractional and negative bans persist milliseconds and revoke only target sessions",
  async (ctx) => {
    const owner = await signup(ctx, "fraction-owner", "admin-standard"),
      target = await signup(ctx, "fraction-target"),
      foreign = await signup(ctx, "fraction-foreign");
    const ownerBefore = await state(ctx, owner.email),
      foreignBefore = await state(ctx, foreign.email);
    const observations = [];
    for (const duration of [300.875, 0, -60.25]) {
      const ban = await owner.client.admin.banUser({
        userId: target.userId,
        banExpiresIn: duration,
        banReason: "explicit reason",
      });
      expect(ban.error).toBeNull();
      const persisted = await state(ctx, target.email),
        user = row.parse(persisted).user;
      expect(user).toMatchObject({
        id: target.userId,
        banned: true,
        banReason: "explicit reason",
      });
      if (duration === 0) expect(user.banExpires).toBeNull();
      else {
        if (!user.banExpires) throw new Error("actual expiry required");
        expiry(user.banExpires, user.updatedAt, duration * 1000);
      }
      expect(row.parse(persisted).sessions).toHaveLength(0);
      const signin = await target.client.signIn.email({
        email: target.email,
        password: "password123",
      });
      const after = await state(ctx, target.email);
      if (duration >= 0) {
        expect(signin.error?.status).toBe(403);
        expect(signin.error?.code).toBe("BANNED_USER");
        expect(after).toEqual(persisted);
      } else {
        expect(signin.error).toBeNull();
        expect(signin.data?.user.id).toBe(target.userId);
        expect(row.parse(after).user).toMatchObject({
          id: target.userId,
          banned: false,
          banReason: null,
          banExpires: null,
        });
        expect(row.parse(after).sessions).toHaveLength(1);
        expect(row.parse(after).sessions[0]?.userId).toBe(target.userId);
      }
      observations.push({ duration, ban, persisted, signin, after });
    }
    const ownerAfter = await state(ctx, owner.email),
      foreignAfter = await state(ctx, foreign.email);
    expect(ownerAfter).toEqual(ownerBefore);
    expect(foreignAfter).toEqual(foreignBefore);
    return {
      owner: owner.result,
      target: target.result,
      foreign: foreign.result,
      ownerBefore,
      foreignBefore,
      observations,
      ownerAfter,
      foreignAfter,
    };
  },
);

compatScenario(
  "admin configured fractional negative and NaN defaults preserve persisted session ownership",
  async (ctx) => {
    const observations = [];
    for (const [profile, banDuration, sessionDuration, reason] of [
      ["admin-duration-fractional", 300.875, 120.75, "configured reason"],
      ["admin-duration-negative", -60.25, -10.5, "No reason"],
      ["admin-duration-nan", null, 3600, "No reason"],
    ] as const) {
      const owner = await signup(ctx, `${profile}-owner`, profile),
        target = await signup(ctx, `${profile}-target`),
        foreign = await signup(ctx, `${profile}-foreign`);
      const ownerBefore = await state(ctx, owner.email),
        foreignBefore = await state(ctx, foreign.email);
      const ban = await owner.client.admin.banUser({
        userId: target.userId,
        banReason: "",
        banExpiresIn: 0,
      });
      expect(ban.error).toBeNull();
      const banned = await state(ctx, target.email),
        user = row.parse(banned).user;
      expect(user).toMatchObject({
        id: target.userId,
        banned: true,
        banReason: reason,
      });
      expect(row.parse(banned).sessions).toHaveLength(0);
      if (banDuration === null) expect(user.banExpires).toBeNull();
      else {
        if (!user.banExpires) throw new Error("configured expiry required");
        expiry(user.banExpires, user.updatedAt, banDuration * 1000);
      }
      const unban = await owner.client.admin.unbanUser({
        userId: target.userId,
      });
      expect(unban.error).toBeNull();
      const impersonate = await owner.client.admin.impersonateUser({
        userId: target.userId,
      });
      expect(impersonate.error).toBeNull();
      if (!impersonate.data) throw new Error("issued impersonation required");
      const persisted = await state(ctx, target.email),
        sessions = row.parse(persisted).sessions;
      expect(sessions).toHaveLength(1);
      expect(sessions[0]).toMatchObject({
        userId: target.userId,
        impersonatedBy: owner.userId,
        token: impersonate.data.session.token,
      });
      if (!sessions[0]) throw new Error("stored issued session required");
      expiry(
        sessions[0].expiresAt,
        sessions[0].createdAt,
        sessionDuration * 1000,
      );
      const current = await owner.client.getSession();
      if (sessionDuration > 0)
        expect(current.data?.user.id).toBe(target.userId);
      else expect(current.data).toBeNull();
      const afterCurrent = await state(ctx, target.email),
        ownerAfter = await state(ctx, owner.email),
        foreignAfter = await state(ctx, foreign.email);
      expect(ownerAfter).toEqual(ownerBefore);
      expect(foreignAfter).toEqual(foreignBefore);
      observations.push({
        profile,
        owner: owner.result,
        target: target.result,
        foreign: foreign.result,
        ownerBefore,
        foreignBefore,
        ban,
        banned,
        unban,
        impersonate,
        persisted,
        current,
        afterCurrent,
        ownerAfter,
        foreignAfter,
      });
    }
    return { observations };
  },
);

compatScenario(
  "admin invalid configured dates fail before writes without changing issued owner or target sessions",
  async (ctx) => {
    const owner = await signup(
        ctx,
        "invalid-date-owner",
        "admin-duration-invalid",
      ),
      target = await signup(ctx, "invalid-date-target"),
      foreign = await signup(ctx, "invalid-date-foreign");
    const before = await state(ctx, target.email),
      ownerBefore = await state(ctx, owner.email),
      foreignBefore = await state(ctx, foreign.email);
    const ban = await owner.client.admin.banUser({ userId: target.userId });
    expect(ban.error?.status).toBe(500);
    expect(ban.data).toBeNull();
    const afterBan = await state(ctx, target.email);
    expect(afterBan).toEqual(before);
    const outOfRange = await owner.client.admin.banUser({
      userId: target.userId,
      banExpiresIn: 1e20,
    });
    expect(outOfRange.error?.status).toBe(500);
    expect(outOfRange.data).toBeNull();
    const afterOutOfRange = await state(ctx, target.email);
    expect(afterOutOfRange).toEqual(before);
    const impersonate = await owner.client.admin.impersonateUser({
      userId: target.userId,
    });
    expect(impersonate.error?.status).toBe(500);
    expect(impersonate.data).toBeNull();
    const afterImpersonate = await state(ctx, target.email);
    expect(afterImpersonate).toEqual(before);
    const ownerCurrent = await owner.client.getSession(),
      targetCurrent = await target.client.getSession(),
      foreignCurrent = await foreign.client.getSession();
    expect(ownerCurrent.data?.user.id).toBe(owner.userId);
    expect(ownerCurrent.data?.session.token).toBe(
      owner.result.data?.token ?? undefined,
    );
    expect(targetCurrent.data?.user.id).toBe(target.userId);
    expect(targetCurrent.data?.session.token).toBe(
      target.result.data?.token ?? undefined,
    );
    expect(foreignCurrent.data?.user.id).toBe(foreign.userId);
    expect(foreignCurrent.data?.session.token).toBe(
      foreign.result.data?.token ?? undefined,
    );
    const ownerAfter = await state(ctx, owner.email),
      foreignAfter = await state(ctx, foreign.email);
    expect(ownerAfter).toEqual(ownerBefore);
    expect(foreignAfter).toEqual(foreignBefore);
    return {
      owner: owner.result,
      target: target.result,
      foreign: foreign.result,
      before,
      ownerBefore,
      foreignBefore,
      ban,
      afterBan,
      outOfRange,
      afterOutOfRange,
      impersonate,
      afterImpersonate,
      ownerCurrent,
      targetCurrent,
      foreignCurrent,
      ownerAfter,
      foreignAfter,
    };
  },
);

compatScenario(
  "admin date mapping preserves genuine application hook API errors and unchanged owned state",
  async (ctx) => {
    const owner = await signup(
        ctx,
        "date-error-owner",
        "admin-duration-hook-error",
      ),
      target = await signup(ctx, "date-error-target"),
      foreign = await signup(ctx, "date-error-foreign");
    const before = await state(ctx, target.email),
      ownerBefore = await state(ctx, owner.email),
      foreignBefore = await state(ctx, foreign.email);
    const ban = await owner.client.admin.banUser({
      userId: target.userId,
      banExpiresIn: 300.5,
    });
    expect(ban.error).toMatchObject({
      status: 403,
      code: "APPLICATION_BAN_REFUSED",
      message: "Invalid Date",
    });
    const afterBan = await state(ctx, target.email);
    expect(afterBan).toEqual(before);
    const impersonate = await owner.client.admin.impersonateUser({
      userId: target.userId,
    });
    expect(impersonate.error).toMatchObject({
      status: 500,
      code: "APPLICATION_SESSION_REFUSED",
      message: "Invalid Date",
    });
    const afterImpersonate = await state(ctx, target.email);
    expect(afterImpersonate).toEqual(before);
    const current = await owner.client.getSession();
    expect(current.data?.user.id).toBe(owner.userId);
    const ownerAfter = await state(ctx, owner.email),
      foreignAfter = await state(ctx, foreign.email);
    expect(ownerAfter).toEqual(ownerBefore);
    expect(foreignAfter).toEqual(foreignBefore);
    return {
      owner: owner.result,
      target: target.result,
      foreign: foreign.result,
      before,
      ownerBefore,
      foreignBefore,
      ban,
      afterBan,
      impersonate,
      afterImpersonate,
      current,
      ownerAfter,
      foreignAfter,
    };
  },
);
