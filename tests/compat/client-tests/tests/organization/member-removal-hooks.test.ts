import { expect } from "bun:test";
import { z } from "zod";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { createTracingFetch, type TraceEntry } from "../../support/trace";

const row = z.object({ id: z.string() }).passthrough();
const snapshot = z.object({
  organizations: z.array(row),
  members: z.array(row),
  users: z.array(row),
  sessions: z.array(row),
  teams: z.array(row),
  teamMembers: z.array(row),
});
const member = z
  .object({
    id: z.string(),
    organizationId: z.string(),
    userId: z.string(),
    role: z.string(),
    createdAt: z.string(),
    user: z.record(z.string(), z.unknown()).optional(),
  })
  .passthrough();
const receipt = z.object({
  phase: z.string(),
  organization: z.record(z.string(), z.unknown()),
  member,
  user: z.record(z.string(), z.unknown()),
  snapshot,
});
const stateSchema = z.object({ receipts: z.array(receipt), snapshot });
async function configure(
  ctx: ScenarioContext,
  mode: string,
  guard?: { memberId: string; userId: string; organizationId: string },
) {
  expect(
    (
      await ctx.rawRequest({
        path: "/__test/organization-member-removal-hooks-configure",
        method: "POST",
        json: { mode, ...guard },
      })
    ).status,
  ).toBe(200);
}
async function state(ctx: ScenarioContext, waitFor?: string) {
  const result = await ctx.rawRequest({
    path:
      "/__test/organization-member-removal-hooks-state" + (waitFor ? `?waitFor=${waitFor}` : ""),
  });
  expect(result.status).toBe(200);
  return stateSchema.parse(result.body);
}
async function signup(ctx: ScenarioContext, name: string) {
  const actor = ctx.actor(name, "org-member-removal-hooks"),
    email = ctx.uniqueEmail(name),
    result = await actor.client.signUp.email({ name, email, password: "password123" });
  expect(result.error).toBeNull();
  return {
    ...actor,
    email,
    userId: z.object({ user: row }).parse(result.data).user.id,
    user: z.object({ user: z.record(z.string(), z.unknown()) }).parse(ctx.snapshot(result.data))
      .user,
  };
}
type Actor = Awaited<ReturnType<typeof signup>>;
async function select(actor: Actor, organizationId: string, teamId: string) {
  expect(
    (
      await actor.client.$fetch("/organization/set-active", {
        method: "POST",
        body: { organizationId },
      })
    ).error,
  ).toBeNull();
  expect(
    (
      await actor.client.$fetch("/organization/set-active-team", {
        method: "POST",
        body: { teamId },
      })
    ).error,
  ).toBeNull();
}
async function setup(ctx: ScenarioContext, name: string) {
  await configure(ctx, "record");
  const owner = await signup(ctx, `${name}-owner`),
    target = await signup(ctx, `${name}-target`),
    foreign = await signup(ctx, `${name}-foreign`);
  async function create(actor: Actor, label: string) {
    const result = await actor.client.$fetch("/organization/create", {
      method: "POST",
      body: {
        name: label,
        slug: ctx.uniqueToken(label),
        logo: "https://example.test/original.png",
        metadata: { original: true },
      },
    });
    expect(result.error).toBeNull();
    return row.parse(result.data);
  }
  const org = await create(owner, `${name}-org`),
    other = await create(foreign, `${name}-other`);
  async function invite(actor: Actor, organizationId: string) {
    const invited = await actor.client.$fetch("/organization/invite-member", {
      method: "POST",
      body: { organizationId, email: target.email, role: "member" },
    });
    expect(invited.error).toBeNull();
    const accepted = await target.client.$fetch("/organization/accept-invitation", {
      method: "POST",
      body: { invitationId: row.parse(invited.data).id },
    });
    expect(accepted.error).toBeNull();
    return member.parse(z.object({ member }).parse(ctx.snapshot(accepted.data)).member);
  }
  const original = await invite(owner, org.id);
  await invite(foreign, other.id);
  async function team(actor: Actor, organizationId: string, label: string) {
    const created = await actor.client.$fetch("/organization/create-team", {
      method: "POST",
      body: { organizationId, name: label },
    });
    expect(created.error).toBeNull();
    const team = row.parse(created.data);
    expect(
      (
        await actor.client.$fetch("/organization/add-team-member", {
          method: "POST",
          body: { organizationId, teamId: team.id, userId: target.userId },
        })
      ).error,
    ).toBeNull();
    return team;
  }
  const ownTeam = await team(owner, org.id, `${name}-team-first`),
    otherTeam = await team(foreign, other.id, `${name}-team-foreign`);
  const siblingBase = ctx.actor(`${name}-sibling`, "org-member-removal-hooks");
  expect(
    (await siblingBase.client.signIn.email({ email: target.email, password: "password123" })).error,
  ).toBeNull();
  const sibling = { ...siblingBase, email: target.email, userId: target.userId, user: target.user };
  await select(target, org.id, ownTeam.id);
  await select(sibling, org.id, ownTeam.id);
  const users = async () => {
    const values = [];
    for (const actor of [owner, target, foreign]) {
      const result = await ctx.rawRequest({
        path: `/__test/user-state?userId=${encodeURIComponent(actor.userId)}`,
      });
      expect(result.status).toBe(200);
      values.push(result.body);
    }
    return values;
  };
  const raw = await owner.client.$fetch("/organization/get-organization", {
    query: { organizationId: org.id },
  });
  expect(raw.error).toBeNull();
  return {
    owner,
    target,
    foreign,
    sibling,
    org,
    other,
    original,
    ownTeam,
    otherTeam,
    team,
    invite,
    users,
    rawOrg: z.record(z.string(), z.unknown()).parse(ctx.snapshot(raw.data)),
  };
}
function remove(actor: Actor, organizationId: string, memberIdOrEmail: string) {
  return actor.client.$fetch("/organization/remove-member", {
    method: "POST",
    body: { organizationId, memberIdOrEmail },
  });
}
function removed(
  before: z.infer<typeof snapshot>,
  memberId: string,
  userId: string,
  teamIds: string[],
) {
  const deleted = before.teamMembers.filter(
    (row) => row.userId === userId && teamIds.includes(String(row.teamId)),
  );
  return {
    ...before,
    members: before.members.filter((row) => row.id !== memberId),
    teamMembers: before.teamMembers.filter(
      (row) => !deleted.some((candidate) => candidate.id === row.id),
    ),
    teams: before.teams.map((row) => ({
      ...row,
      memberCount:
        Number(row.memberCount) - deleted.filter((candidate) => candidate.teamId === row.id).length,
    })),
  };
}
function phases(
  after: z.infer<typeof stateSchema>,
  original: z.infer<typeof member>,
  user: Record<string, unknown>,
  org: Record<string, unknown>,
  byEmail = false,
) {
  expect(after.receipts.map((row) => row.phase)).toEqual(["before-remove", "after-remove"]);
  const expected = {
    ...original,
    ...(byEmail
      ? { user: { id: user.id, name: user.name, email: user.email, image: user.image } }
      : {}),
  };
  for (const row of after.receipts) {
    expect(row.member).toEqual(expected);
    expect(row.user).toEqual(user);
    expect(row.organization).toEqual(org);
  }
  return after.receipts;
}
compatScenario(
  "organization removal callbacks preserve ID and email snapshots across committed team cleanup",
  async (ctx) => {
    const observations = [];
    for (const email of [false, true]) {
      const { owner, target, org, original, ownTeam, users, rawOrg } = await setup(
          ctx,
          email ? "remove-email" : "remove-id",
        ),
        before = await state(ctx),
        usersBefore = await users(),
        result = await remove(owner, org.id, email ? target.email.toUpperCase() : original.id);
      expect(result.error).toBeNull();
      const after = await state(ctx),
        notes = phases(after, original, target.user, rawOrg, email);
      expect(notes[0]!.snapshot).toEqual(before.snapshot);
      expect(after.snapshot).toEqual(
        removed(before.snapshot, original.id, target.userId, [ownTeam.id]),
      );
      expect(notes[1]!.snapshot).toEqual(after.snapshot);
      expect(await users()).toEqual(usersBefore);
      expect(z.object({ member }).parse(ctx.snapshot(result.data)).member).toEqual(
        notes[0]!.member,
      );
      observations.push({
        before,
        usersBefore,
        result: ctx.snapshot(result),
        after,
        usersAfter: await users(),
      });
    }
    return observations;
  },
  ["POST /organization/remove-member"],
);
compatScenario(
  "organization removal callbacks reject at the actual before and after persistence phases",
  async (ctx) => {
    const observations = [];
    for (const mode of ["reject-before-remove", "reject-after-remove"]) {
      const { owner, target, org, original, ownTeam, users, invite, rawOrg } = await setup(
        ctx,
        mode,
      );
      await configure(ctx, mode);
      const before = await state(ctx),
        usersBefore = await users(),
        result = await remove(owner, org.id, original.id);
      expect(result.error).toMatchObject({
        status: 400,
        code: "MEMBER_REMOVAL_HOOK_REJECTED",
        message: `Rejected ${mode.slice(7)}`,
      });
      const after = await state(ctx);
      expect(after.receipts.map((row) => row.phase)).toEqual(
        mode === "reject-before-remove" ? ["before-remove"] : ["before-remove", "after-remove"],
      );
      expect(after.snapshot).toEqual(
        mode === "reject-before-remove"
          ? before.snapshot
          : removed(before.snapshot, original.id, target.userId, [ownTeam.id]),
      );
      expect(after.receipts[0]!.snapshot).toEqual(before.snapshot);
      const usersAfter = await users();
      expect(usersAfter).toEqual(usersBefore);
      await configure(ctx, "record");
      let retryMember = original;
      let missing: unknown = null;
      let missingState: Awaited<ReturnType<typeof state>> | null = null;
      if (mode === "reject-after-remove") {
        const absent = await remove(owner, org.id, original.id);
        expect(absent.error).toMatchObject({ status: 400, code: "MEMBER_NOT_FOUND" });
        missing = ctx.snapshot(absent);
        missingState = await state(ctx);
        expect(missingState).toEqual({ receipts: [], snapshot: after.snapshot });
        expect(await users()).toEqual(usersBefore);
        retryMember = await invite(owner, org.id);
        expect(retryMember.id).not.toBe(original.id);
        expect(retryMember.userId).toBe(target.userId);
      }
      const retryBefore = await state(ctx);
      expect(retryBefore.receipts).toEqual([]);
      const retry = await remove(owner, org.id, retryMember.id);
      expect(retry.error).toBeNull();
      const final = await state(ctx),
        notes = phases(final, retryMember, target.user, rawOrg);
      expect(notes[0]!.snapshot).toEqual(retryBefore.snapshot);
      expect(final.snapshot).toEqual(
        removed(retryBefore.snapshot, retryMember.id, target.userId, [ownTeam.id]),
      );
      expect(notes[1]!.snapshot).toEqual(final.snapshot);
      expect(z.object({ member }).parse(ctx.snapshot(retry.data)).member).toEqual(retryMember);
      expect(await users()).toEqual(usersBefore);
      if (mode === "reject-after-remove") {
        expect(final.snapshot.teams).toEqual(after.snapshot.teams);
        expect(final.snapshot.teamMembers).toEqual(after.snapshot.teamMembers);
      }
      observations.push({
        mode,
        before,
        usersBefore,
        result: ctx.snapshot(result),
        after,
        usersAfter,
        missing,
        missingState,
        retryMember,
        retryBefore,
        retry: ctx.snapshot(retry),
        final,
        finalUsers: await users(),
      });
    }
    return observations;
  },
  ["POST /organization/remove-member"],
);
compatScenario(
  "organization removal keeps original callback snapshots after independent target mutation or member deletion",
  async (ctx) => {
    const observations = [];
    for (const mode of ["mutate-target", "delete-row"]) {
      const { owner, target, org, original, ownTeam, rawOrg, users } = await setup(ctx, mode);
      await configure(ctx, mode);
      const before = await state(ctx),
        usersBefore = await users(),
        result = await remove(owner, org.id, original.id);
      expect(result.error).toBeNull();
      const after = await state(ctx),
        notes = phases(after, original, target.user, rawOrg);
      expect(notes[0]!.snapshot).toEqual(before.snapshot);
      const expected = removed(before.snapshot, original.id, target.userId, [ownTeam.id]);
      if (mode === "mutate-target")
        expected.users = expected.users.map((row) =>
          row.id === target.userId ? { ...row, name: "Stored Removal Target" } : row,
        );
      expect(after.snapshot).toEqual(expected);
      expect(notes[1]!.snapshot).toEqual(after.snapshot);
      const usersAfter = await users();
      expect(usersAfter).toEqual(usersBefore);
      observations.push({ before, usersBefore, result: ctx.snapshot(result), after, usersAfter });
    }
    return observations;
  },
  ["POST /organization/remove-member"],
);
compatScenario(
  "organization removal guards and body validation prevent configured callbacks and permit a legitimate retry",
  async (ctx) => {
    const { owner, target, foreign, org, original, users } = await setup(ctx, "remove-guards"),
      before = await state(ctx),
      usersBefore = await users(),
      observations = [];
    const ownerMember = row.parse(
        before.snapshot.members.find(
          (row) => row.userId === owner.userId && row.organizationId === org.id,
        ),
      ),
      foreignTarget = row.parse(
        before.snapshot.members.find(
          (row) => row.userId === target.userId && row.organizationId !== org.id,
        ),
      );
    for (const [actor, selector, status, code] of [
      [target, original.id, 401, "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER"],
      [owner, ownerMember.id, 400, "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER"],
      [foreign, original.id, 400, "MEMBER_NOT_FOUND"],
      [owner, foreignTarget.id, 400, "MEMBER_NOT_FOUND"],
      [owner, "actual-missing-member", 400, "MEMBER_NOT_FOUND"],
    ] as const) {
      const result = await remove(actor, org.id, selector);
      expect(result.error).toMatchObject({ status, code });
      expect(await state(ctx)).toEqual(before);
      expect(await users()).toEqual(usersBefore);
      observations.push(ctx.snapshot(result));
    }
    const invalid = await owner.fetch(
      "/__test/profiles/org-member-removal-hooks/api/auth/organization/remove-member",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ memberIdOrEmail: null, organizationId: org.id }),
      },
    );
    expect(invalid.status).toBe(400);
    const invalidBody = await invalid.json();
    expect(invalidBody).toEqual({
      code: "VALIDATION_ERROR",
      message: "[body.memberIdOrEmail] Invalid input: expected string, received null",
    });
    expect(await state(ctx)).toEqual(before);
    const retry = await remove(owner, org.id, original.id);
    expect(retry.error).toBeNull();
    expect((await state(ctx)).receipts.map((row) => row.phase)).toEqual([
      "before-remove",
      "after-remove",
    ]);
    return {
      before,
      usersBefore,
      observations,
      invalid: { status: invalid.status, body: invalidBody },
      retry: ctx.snapshot(retry),
      after: await state(ctx),
      usersAfter: await users(),
    };
  },
  ["POST /organization/remove-member"],
);
compatScenario(
  "organization self removal clears only the current organization before after-hook rejection",
  async (ctx) => {
    const observations = [];
    for (const rejection of [false, true]) {
      const { owner, target, sibling, org, original, ownTeam, rawOrg } = await setup(
        ctx,
        rejection ? "remove-self-error" : "remove-self",
      );
      const promoted = await owner.client.$fetch("/organization/update-member-role", {
        method: "POST",
        body: { organizationId: org.id, memberId: original.id, role: "owner" },
      });
      expect(promoted.error).toBeNull();
      const current = member.parse(ctx.snapshot(promoted.data));
      await configure(ctx, rejection ? "reject-after-remove" : "record");
      const before = await state(ctx),
        currentSession = await target.client.getSession(),
        siblingSession = await sibling.client.getSession();
      expect(currentSession.error).toBeNull();
      expect(siblingSession.error).toBeNull();
      const currentId = z.object({ session: row }).parse(currentSession.data).session.id,
        siblingId = z.object({ session: row }).parse(siblingSession.data).session.id,
        result = await remove(target, org.id, original.id);
      if (rejection)
        expect(result.error).toMatchObject({ status: 400, code: "MEMBER_REMOVAL_HOOK_REJECTED" });
      else expect(result.error).toBeNull();
      const after = await state(ctx),
        notes = phases(after, current, target.user, rawOrg),
        expected = removed(before.snapshot, original.id, target.userId, [ownTeam.id]);
      expected.sessions = expected.sessions.map((row) =>
        row.id === currentId ? { ...row, activeOrganizationId: null } : row,
      );
      expect(after.snapshot).toEqual(expected);
      expect(notes[0]!.snapshot).toEqual(before.snapshot);
      expect(notes[1]!.snapshot).toEqual(after.snapshot);
      expect(after.snapshot.sessions.find((row) => row.id === currentId)).toHaveProperty(
        "activeTeamId",
        ownTeam.id,
      );
      expect(after.snapshot.sessions.find((row) => row.id === siblingId)).toMatchObject({
        activeOrganizationId: org.id,
        activeTeamId: ownTeam.id,
      });
      observations.push({
        before,
        currentSession: ctx.snapshot(currentSession),
        siblingSession: ctx.snapshot(siblingSession),
        result: ctx.snapshot(result),
        after,
      });
    }
    return observations;
  },
  ["POST /organization/remove-member"],
);
compatScenario(
  "organization removal honors disabled team cleanup and the actual default team page",
  async (ctx) => {
    const observations = [];
    for (const profile of [
      "org-member-removal-hooks-teams-disabled",
      "org-member-removal-hooks-team-page-one",
    ] as const) {
      const { owner, target, org, original, ownTeam, team, users } = await setup(ctx, profile),
        second = await team(owner, org.id, `${profile}-team-second`),
        configured = ctx.actor(`${profile}-configured`, profile);
      expect(
        (await configured.client.signIn.email({ email: owner.email, password: "password123" }))
          .error,
      ).toBeNull();
      await configure(ctx, "record");
      const before = await state(ctx),
        usersBefore = await users(),
        result = await remove({ ...owner, ...configured }, org.id, original.id);
      expect(result.error).toBeNull();
      const after = await state(ctx);
      expect(after.snapshot).toEqual(
        removed(
          before.snapshot,
          original.id,
          target.userId,
          profile.endsWith("teams-disabled") ? [] : [ownTeam.id],
        ),
      );
      expect(
        after.snapshot.teamMembers.some(
          (row) => row.teamId === second.id && row.userId === target.userId,
        ),
      ).toBe(true);
      expect(await users()).toEqual(usersBefore);
      expect(after.receipts.map((row) => row.phase)).toEqual(["before-remove", "after-remove"]);
      observations.push({
        profile,
        before,
        usersBefore,
        result: ctx.snapshot(result),
        after,
        usersAfter: await users(),
      });
    }
    return observations;
  },
  ["POST /organization/remove-member"],
);
compatScenario(
  "organization last owner checks its configured raw page before callbacks",
  async (ctx) => {
    const { owner, target, org, original, users } = await setup(ctx, "remove-owner-page");
    expect(
      (
        await owner.client.$fetch("/organization/update-member-role", {
          method: "POST",
          body: { organizationId: org.id, memberId: original.id, role: "owner" },
        })
      ).error,
    ).toBeNull();
    const configured = ctx.actor(
      "remove-owner-page-configured",
      "org-member-removal-hooks-page-one",
    );
    expect(
      (await configured.client.signIn.email({ email: owner.email, password: "password123" })).error,
    ).toBeNull();
    await configure(ctx, "record");
    const before = await state(ctx),
      usersBefore = await users(),
      result = await remove({ ...owner, ...configured }, org.id, original.id);
    expect(result.error).toMatchObject({
      status: 400,
      code: "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER",
    });
    expect(await state(ctx)).toEqual(before);
    expect(await users()).toEqual(usersBefore);
    const retry = await remove(owner, org.id, original.id);
    expect(retry.error).toBeNull();
    expect((await state(ctx)).receipts.map((row) => row.phase)).toEqual([
      "before-remove",
      "after-remove",
    ]);
    return {
      before,
      usersBefore,
      result: ctx.snapshot(result),
      retry: ctx.snapshot(retry),
      after: await state(ctx),
      usersAfter: await users(),
    };
  },
  ["POST /organization/remove-member"],
);
compatScenario(
  "organization removal awaits its actual before callback before member and team writes",
  async (ctx) => {
    const { owner, target, org, original, ownTeam } = await setup(ctx, "remove-await");
    await configure(ctx, "pause-before");
    const before = await state(ctx);
    let completed = false;
    const pending = remove(owner, org.id, original.id).then((result) => {
      completed = true;
      return result;
    });
    let during: Awaited<ReturnType<typeof state>> | undefined;
    const trace: TraceEntry[] = [];
    try {
      during = await state(ctx, "before-remove");
      expect(during.receipts.map((row) => row.phase)).toEqual(["before-remove"]);
      expect(completed).toBe(false);
      expect(during.snapshot).toEqual(before.snapshot);
    } finally {
      const release = await createTracingFetch(
        ctx.baseURL,
        "member-removal-release",
        trace,
      )("/__test/organization-member-removal-hooks-release", { method: "POST" });
      expect(release.status).toBe(200);
      expect(await release.json()).toEqual({ released: true });
    }
    const result = await pending;
    ctx.recordTransport(trace);
    expect(result.error).toBeNull();
    const after = await state(ctx);
    expect(after.receipts.map((row) => row.phase)).toEqual(["before-remove", "after-remove"]);
    expect(after.snapshot).toEqual(
      removed(before.snapshot, original.id, target.userId, [ownTeam.id]),
    );
    return { before, during, result: ctx.snapshot(result), after };
  },
  ["POST /organization/remove-member"],
);
compatScenario(
  "organization trusted header removal authenticates real cookie authority and delivers target snapshots",
  async (ctx) => {
    const { owner, target, foreign, org, original, ownTeam, rawOrg, users } = await setup(
        ctx,
        "remove-server",
      ),
      before = await state(ctx),
      usersBefore = await users(),
      guest = ctx.actor("remove-server-guest"),
      failures = [];
    for (const actor of [guest, foreign]) {
      const result = await actor.fetch("/__test/organization-member-removal-hooks-server", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          organizationId: org.id,
          memberIdOrEmail: original.id,
          userId: owner.userId,
        }),
      });
      expect(result.status).toBe(actor === guest ? 401 : 400);
      const body = await result.json();
      expect(body).toHaveProperty("code", actor === guest ? "UNAUTHORIZED" : "MEMBER_NOT_FOUND");
      expect(await state(ctx)).toEqual(before);
      expect(await users()).toEqual(usersBefore);
      failures.push({ status: result.status, body });
    }
    const response = await owner.fetch("/__test/organization-member-removal-hooks-server", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ organizationId: org.id, memberIdOrEmail: target.email.toUpperCase() }),
    });
    expect(response.status).toBe(200);
    const result = await response.json(),
      after = await state(ctx),
      notes = phases(after, original, target.user, rawOrg, true);
    expect(result).toEqual({ member: notes[0]!.member });
    expect(after.snapshot).toEqual(
      removed(before.snapshot, original.id, target.userId, [ownTeam.id]),
    );
    expect(await users()).toEqual(usersBefore);
    return { before, usersBefore, failures, result, after, usersAfter: await users() };
  },
  ["POST /organization/remove-member"],
);
compatScenario(
  "organization trusted member removal cleans an actually expired session without callbacks or sibling mutation",
  async (ctx) => {
    const { owner, target, org, original, ownTeam, users } = await setup(
        ctx,
        "remove-server-expired",
      ),
      sibling = ctx.actor("remove-server-expired-owner-sibling", "org-member-removal-hooks");
    expect(
      (await sibling.client.signIn.email({ email: owner.email, password: "password123" })).error,
    ).toBeNull();
    const session = await owner.client.getSession();
    expect(session.error).toBeNull();
    const current = z
      .object({ session: z.object({ id: z.string(), token: z.string() }) })
      .parse(session.data).session;
    expect(
      (
        await ctx.rawRequest({
          path: "/__test/expire-session",
          method: "POST",
          json: { token: current.token, expiresAt: "2000-01-01T00:00:00.000Z" },
        })
      ).status,
    ).toBe(200);
    await configure(ctx, "record");
    const before = await state(ctx),
      usersBefore = await users(),
      response = await owner.fetch("/__test/organization-member-removal-hooks-server", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ organizationId: org.id, memberIdOrEmail: original.id }),
      });
    expect(response.status).toBe(401);
    const body = await response.json();
    expect(body).toEqual({ code: "UNAUTHORIZED", message: "Unauthorized" });
    expect(response.headers.getSetCookie()).toEqual([]);
    const after = await state(ctx);
    expect(after.receipts).toEqual([]);
    expect(after.snapshot).toEqual({
      ...before.snapshot,
      sessions: before.snapshot.sessions.filter((row) => row.id !== current.id),
    });
    const usersAfter = await users();
    expect(usersAfter[1]).toEqual(usersBefore[1]);
    expect(usersAfter[2]).toEqual(usersBefore[2]);
    const userState = z
        .object({ sessions: z.array(z.object({ id: z.string() }).passthrough()) })
        .passthrough(),
      previous = userState.parse(usersBefore[0]);
    expect(userState.parse(usersAfter[0])).toEqual({
      ...previous,
      sessions: previous.sessions.filter((row) => row.id !== current.id),
    });
    const retry = await remove({ ...owner, ...sibling }, org.id, original.id);
    expect(retry.error).toBeNull();
    const final = await state(ctx);
    expect(final.receipts.map((row) => row.phase)).toEqual(["before-remove", "after-remove"]);
    expect(final.snapshot).toEqual(
      removed(after.snapshot, original.id, target.userId, [ownTeam.id]),
    );
    return {
      before,
      usersBefore,
      expired: { status: response.status, body, cookies: response.headers.getSetCookie() },
      after,
      usersAfter,
      retry: ctx.snapshot(retry),
      final,
      finalUsers: await users(),
    };
  },
  ["POST /organization/remove-member"],
);
async function rawRemove(actor: Actor, organizationId: string, memberIdOrEmail: string) {
  const response = await actor.fetch("/api/auth/organization/remove-member", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ organizationId, memberIdOrEmail }),
  });
  return {
    status: response.status,
    text: await response.text(),
    contentType: response.headers.get("content-type"),
    cookies: response.headers.getSetCookie(),
  };
}
function emptyDatabaseFailure(result: Awaited<ReturnType<typeof rawRemove>>) {
  expect(result).toEqual({ status: 500, text: "", contentType: null, cookies: [] });
}
async function withSqlGuard<T>(ctx: ScenarioContext, operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } finally {
    await configure(ctx, "record");
  }
}
compatScenario(
  "organization removal without callbacks returns real SQL veto empty 500 after permission and rolls back all scoped writes",
  async (ctx) =>
    withSqlGuard(ctx, async () => {
      const observations = [];
      for (const mode of ["sql-member-abort", "sql-team-abort"]) {
        const { owner, target, foreign, org, original, ownTeam, users } = await setup(ctx, mode),
          configured = ctx.actor(`${mode}-no-hooks`, "org-member-removal-no-hooks"),
          foreignConfigured = ctx.actor(`${mode}-foreign`, "org-member-removal-no-hooks"),
          guest = ctx.actor(`${mode}-guest`, "org-member-removal-no-hooks");
        expect(
          (await configured.client.signIn.email({ email: owner.email, password: "password123" }))
            .error,
        ).toBeNull();
        expect(
          (
            await foreignConfigured.client.signIn.email({
              email: foreign.email,
              password: "password123",
            })
          ).error,
        ).toBeNull();
        await configure(ctx, mode, {
          memberId: original.id,
          userId: target.userId,
          organizationId: org.id,
        });
        const before = await state(ctx),
          usersBefore = await users(),
          denials = [];
        for (const [actor, status, code] of [
          [guest, 401, "UNAUTHORIZED"],
          [foreignConfigured, 400, "MEMBER_NOT_FOUND"],
        ] as const) {
          const result = await remove({ ...owner, ...actor }, org.id, original.id);
          expect(result.error).toMatchObject({ status, code });
          expect(await state(ctx)).toEqual(before);
          expect(await users()).toEqual(usersBefore);
          denials.push(ctx.snapshot(result));
        }
        const result = await rawRemove({ ...owner, ...configured }, org.id, original.id);
        emptyDatabaseFailure(result);
        const after = await state(ctx);
        expect(after).toEqual(before);
        expect(await users()).toEqual(usersBefore);
        await configure(ctx, "record");
        const retry = await remove({ ...owner, ...configured }, org.id, original.id);
        expect(retry.error).toBeNull();
        const final = await state(ctx);
        expect(final.receipts).toEqual([]);
        expect(final.snapshot).toEqual(
          removed(before.snapshot, original.id, target.userId, [ownTeam.id]),
        );
        expect(await users()).toEqual(usersBefore);
        observations.push({
          mode,
          before,
          usersBefore,
          denials,
          result,
          after,
          retry: ctx.snapshot(retry),
          final,
          usersAfter: await users(),
        });
      }
      return observations;
    }),
  ["POST /organization/remove-member"],
);
compatScenario(
  "organization real SQL errors in removal callbacks retain before and self after persistence phases",
  async (ctx) =>
    withSqlGuard(ctx, async () => {
      const observations = [];
      for (const mode of ["sql-before-error", "sql-after-error"]) {
        const data = await setup(ctx, mode),
          { owner, target, sibling, org, original, ownTeam, rawOrg, users, invite } = data;
        let current = original;
        if (mode === "sql-after-error") {
          const promoted = await owner.client.$fetch("/organization/update-member-role", {
            method: "POST",
            body: { organizationId: org.id, memberId: original.id, role: "owner" },
          });
          expect(promoted.error).toBeNull();
          current = member.parse(ctx.snapshot(promoted.data));
        }
        const session = await target.client.getSession();
        expect(session.error).toBeNull();
        const currentId = z.object({ session: row }).parse(session.data).session.id;
        await configure(ctx, mode, {
          memberId: original.id,
          userId: target.userId,
          organizationId: org.id,
        });
        const before = await state(ctx),
          usersBefore = await users(),
          result = await rawRemove(
            mode === "sql-after-error" ? target : owner,
            org.id,
            original.id,
          );
        emptyDatabaseFailure(result);
        const after = await state(ctx);
        expect(after.receipts.map((row) => row.phase)).toEqual(
          mode === "sql-before-error" ? ["before-remove"] : ["before-remove", "after-remove"],
        );
        for (const row of after.receipts) {
          expect(row.member).toEqual(current);
          expect(row.user).toEqual(target.user);
          expect(row.organization).toEqual(rawOrg);
        }
        expect(after.receipts[0]!.snapshot).toEqual(before.snapshot);
        const expected =
          mode === "sql-before-error"
            ? before.snapshot
            : removed(before.snapshot, original.id, target.userId, [ownTeam.id]);
        if (mode === "sql-after-error")
          expected.sessions = expected.sessions.map((row) =>
            row.id === currentId ? { ...row, activeOrganizationId: null } : row,
          );
        expect(after.snapshot).toEqual(expected);
        const usersAfter = await users();
        if (mode === "sql-before-error") expect(usersAfter).toEqual(usersBefore);
        else {
          expect(after.receipts[1]!.snapshot).toEqual(after.snapshot);
          expect(usersAfter[0]).toEqual(usersBefore[0]);
          expect(usersAfter[2]).toEqual(usersBefore[2]);
          const shape = z.object({ sessions: z.array(row) }).passthrough(),
            previous = shape.parse(usersBefore[1]);
          expect(shape.parse(usersAfter[1])).toEqual({
            ...previous,
            sessions: previous.sessions.map((row) =>
              row.id === currentId ? { ...row, activeOrganizationId: null } : row,
            ),
          });
          const siblingSession = await sibling.client.getSession();
          expect(siblingSession.error).toBeNull();
          expect(
            z.object({ session: z.record(z.string(), z.unknown()) }).parse(siblingSession.data)
              .session,
          ).toMatchObject({ activeOrganizationId: org.id, activeTeamId: ownTeam.id });
        }
        await configure(ctx, "record");
        let restored = original;
        if (mode === "sql-after-error") {
          const missing = await remove(owner, org.id, original.id);
          expect(missing.error).toMatchObject({ status: 400, code: "MEMBER_NOT_FOUND" });
          expect((await state(ctx)).receipts).toEqual([]);
          restored = await invite(owner, org.id);
        }
        const retry = await remove(owner, org.id, restored.id);
        expect(retry.error).toBeNull();
        const final = await state(ctx);
        expect(final.receipts.map((row) => row.phase)).toEqual(["before-remove", "after-remove"]);
        expect(final.snapshot.members.some((row) => row.id === restored.id)).toBe(false);
        expect(final.snapshot.users).toEqual(before.snapshot.users);
        expect(final.snapshot.organizations).toEqual(before.snapshot.organizations);
        expect(
          final.snapshot.teamMembers.some(
            (row) => row.teamId === data.otherTeam.id && row.userId === target.userId,
          ),
        ).toBe(true);
        observations.push({
          mode,
          before,
          usersBefore,
          result,
          after,
          usersAfter,
          restored,
          retry: ctx.snapshot(retry),
          final,
          finalUsers: await users(),
        });
      }
      return observations;
    }),
  ["POST /organization/remove-member"],
);
compatScenario(
  "organization removal distinguishes actual SQL IGNORE success from database errors and retries without double releasing seats",
  async (ctx) =>
    withSqlGuard(ctx, async () => {
      const { owner, target, org, original, ownTeam, rawOrg, users } = await setup(
        ctx,
        "sql-member-ignore",
      );
      await configure(ctx, "sql-member-ignore", {
        memberId: original.id,
        userId: target.userId,
        organizationId: org.id,
      });
      const before = await state(ctx),
        usersBefore = await users(),
        result = await remove(owner, org.id, original.id);
      expect(result.error).toBeNull();
      const after = await state(ctx);
      phases(after, original, target.user, rawOrg);
      expect(after.snapshot).toEqual({
        ...removed(before.snapshot, original.id, target.userId, [ownTeam.id]),
        members: before.snapshot.members,
      });
      expect(after.receipts[0]!.snapshot).toEqual(before.snapshot);
      expect(after.receipts[1]!.snapshot).toEqual(after.snapshot);
      expect(await users()).toEqual(usersBefore);
      await configure(ctx, "record");
      const retry = await remove(owner, org.id, original.id);
      expect(retry.error).toBeNull();
      const final = await state(ctx);
      expect(final.snapshot).toEqual({
        ...after.snapshot,
        members: after.snapshot.members.filter((row) => row.id !== original.id),
      });
      expect(final.receipts.map((row) => row.phase)).toEqual(["before-remove", "after-remove"]);
      expect(await users()).toEqual(usersBefore);
      return {
        before,
        usersBefore,
        result: ctx.snapshot(result),
        after,
        retry: ctx.snapshot(retry),
        final,
        usersAfter: await users(),
      };
    }),
  ["POST /organization/remove-member"],
);
compatScenario(
  "organization removal preserves explicit public callback 500 JSON rather than classifying it as a database failure",
  async (ctx) => {
    const observations = [];
    for (const phase of ["before-remove", "after-remove"]) {
      const { owner, target, org, original, ownTeam, users } = await setup(
        ctx,
        `public-500-${phase}`,
      );
      await configure(ctx, `public-500-${phase}`);
      const before = await state(ctx),
        usersBefore = await users(),
        result = await rawRemove(owner, org.id, original.id);
      expect(result).toEqual({
        status: 500,
        text: JSON.stringify({
          code: "PUBLIC_REMOVAL_500",
          message: `Explicit public ${phase} error`,
        }),
        contentType: "application/json",
        cookies: [],
      });
      const after = await state(ctx);
      expect(after.receipts.map((row) => row.phase)).toEqual(
        phase === "before-remove" ? ["before-remove"] : ["before-remove", "after-remove"],
      );
      expect(after.snapshot).toEqual(
        phase === "before-remove"
          ? before.snapshot
          : removed(before.snapshot, original.id, target.userId, [ownTeam.id]),
      );
      expect(await users()).toEqual(usersBefore);
      observations.push({ phase, before, usersBefore, result, after, usersAfter: await users() });
    }
    return observations;
  },
  ["POST /organization/remove-member"],
);
