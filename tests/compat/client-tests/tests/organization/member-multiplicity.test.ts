import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { z } from "zod";

import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { createTracingFetch, type TraceEntry } from "../../support/trace";

const root = "/__test/organization-member-addition";

const row = z.object({ id: z.string() }).passthrough();

const member = z
  .object({
    id: z.string(),
    organizationId: z.string(),
    userId: z.string(),
    role: z.string(),
    createdAt: z.string().datetime(),
  })
  .strict();

const team = z
  .object({
    id: z.string(),
    organizationId: z.string(),
    name: z.string(),
    memberCount: z.number(),
    createdAt: z.string().datetime(),
    updatedAt: z.string().datetime().nullable(),
  })
  .strict();

const teamMember = z
  .object({
    id: z.string(),
    teamId: z.string(),
    userId: z.string(),
    membershipKey: z.string().nullable(),
    createdAt: z.string().datetime(),
  })
  .strict();

const stateSchema = z.object({
  receipts: z.array(z.record(z.string(), z.unknown())),
  snapshot: z.object({
    organizations: z.array(row),
    members: z.array(row),
    users: z.array(row),
    sessions: z.array(row),
    teams: z.array(row),
    teamMembers: z.array(row),
  }),
  full: z.object({
    members: z.array(member),
    teams: z.array(team),
    teamMembers: z.array(teamMember),
  }),
});

async function configure(ctx: ScenarioContext, mode: string, fields: Record<string, unknown> = {}) {
  const response = await ctx.rawRequest({
    path: `${root}/configure`,
    method: "POST",
    json: { mode, ...fields },
  });
  expect(response.status).toBe(200);
}

async function fullState(ctx: ScenarioContext) {
  const response = await ctx.rawRequest({ path: `${root}/state?waitFor=full` });
  expect(response.status).toBe(200);

  const value = stateSchema.parse(response.body);

  return {
    ...value,
    full: {
      ...value.full,
      teamMembers: value.full.teamMembers.map((item) => {
        if (item.membershipKey !== null) {
          expect(item.membershipKey).toBe(
            new Bun.CryptoHasher("sha256")
              .update(JSON.stringify([item.teamId, item.userId]))
              .digest("base64url"),
          );
        }
        return {
          ...item,
          membershipKey:
            item.membershipKey === null
              ? null
              : {
                  token: item.membershipKey,
                  inputs: {
                    teamId: { id: item.teamId },
                    userId: { id: item.userId },
                  },
                },
        };
      }),
    },
  };
}

async function signup(ctx: ScenarioContext, name: string) {
  const actor = ctx.actor(name, "org-member-addition");
  const email = ctx.uniqueEmail(name);
  const result = await actor.client.signUp.email({
    name,
    email,
    password: "password123",
  });
  expect(result.error).toBeNull();

  return {
    ...actor,
    email,
    user: row.parse(z.object({ user: row }).parse(ctx.snapshot(result.data)).user),
  };
}

type Actor = Awaited<ReturnType<typeof signup>>;

async function organization(ctx: ScenarioContext, actor: Actor, name: string) {
  const result = await actor.client.$fetch("/organization/create", {
    method: "POST",
    body: {
      name,
      slug: ctx.uniqueToken(name),
      logo: `https://example.test/${name}.png`,
      metadata: { name, amount: 1e20 },
    },
  });
  expect(result.error).toBeNull();
  return row.parse(result.data);
}

async function add(ctx: ScenarioContext, body: Record<string, unknown>) {
  return ctx.rawRequest({
    path: `${root}/server`,
    method: "POST",
    json: { profile: "org-member-addition", body },
  });
}

async function list(actor: { client: Pick<Actor["client"], "$fetch"> }) {
  const result = await actor.client.$fetch("/organization/list");
  expect(result.error).toBeNull();
  return z.array(row).parse(result.data);
}

async function ownStates(ctx: ScenarioContext, actors: Actor[]) {
  return Promise.all(actors.map((actor) => ctx.readUserState({ userId: actor.user.id })));
}

function peers(
  value: Awaited<ReturnType<typeof fullState>>,
  organizationId: string,
  userIds: string[],
) {
  return {
    members: value.full.members.filter((item) => item.organizationId === organizationId),
    teams: value.full.teams.filter((item) => item.organizationId === organizationId),
    teamMembers: value.full.teamMembers.filter((item) =>
      value.full.teams.some(
        (room) => room.id === item.teamId && room.organizationId === organizationId,
      ),
    ),
    users: value.snapshot.users.filter((item) => userIds.includes(item.id)),
    sessions: value.snapshot.sessions.filter((item) => userIds.includes(String(item.userId))),
    organizations: value.snapshot.organizations.filter((item) => item.id === organizationId),
  };
}

compatScenario(
  "organization trusted duplicate memberships keep first-row authority and exact-ID cleanup with foreign peers",
  async (ctx) => {
    await configure(ctx, "off");
    const owner = await signup(ctx, "duplicate-owner");
    const target = await signup(ctx, "duplicate-target");
    const candidate = await signup(ctx, "duplicate-candidate");
    const foreign = await signup(ctx, "duplicate-foreign");
    const principals = [owner, target, candidate, foreign];

    const own = await organization(ctx, owner, "duplicate-own");
    const other = await organization(ctx, foreign, "duplicate-other");

    async function room(actor: Actor, org: typeof own, name: string) {
      const result = await actor.client.$fetch("/organization/create-team", {
        method: "POST",
        body: { organizationId: org.id, name },
      });
      expect(result.error).toBeNull();
      return row.parse(result.data);
    }

    const ownTeam = await room(owner, own, "duplicate-own-team");
    const otherTeam = await room(foreign, other, "duplicate-other-team");

    const original = await add(ctx, {
      organizationId: own.id,
      userId: target.user.id,
      role: "member",
      teamId: ownTeam.id,
    });
    expect(original.status).toBe(200);

    const originalMember = member.parse(original.body);
    const foreignMembership = await add(ctx, {
      organizationId: other.id,
      userId: target.user.id,
      role: "member",
      teamId: otherTeam.id,
    });
    expect(foreignMembership.status).toBe(200);

    for (const [actor, org, teamId] of [
      [owner, own, ownTeam.id],
      [foreign, other, otherTeam.id],
    ] as const) {
      const joined = await actor.client.$fetch("/organization/add-team-member", {
        method: "POST",
        body: { organizationId: org.id, teamId, userId: actor.user.id },
      });
      expect(joined.error).toBeNull();
    }

    const activated = await target.client.$fetch("/organization/set-active", {
      method: "POST",
      body: { organizationId: own.id },
    });
    expect(activated.error).toBeNull();

    const rawOrg = await owner.client.$fetch("/organization/get-organization", {
      query: { organizationId: own.id },
    });
    expect(rawOrg.error).toBeNull();

    // The before-add hook rewrites the candidate's admission into a second, admin row for the target.
    await configure(ctx, "patch-target", {
      organizationId: own.id,
      patchUserId: target.user.id,
      patchRole: "admin",
    });
    const before = await fullState(ctx);
    const usersBefore = await ownStates(ctx, principals);

    const created = await add(ctx, {
      organizationId: own.id,
      userId: candidate.user.id,
      role: "member",
    });
    expect(created.status).toBe(200);

    const duplicate = member.parse(created.body);
    expect(duplicate).toMatchObject({
      organizationId: own.id,
      userId: target.user.id,
      role: "admin",
    });
    expect(duplicate.id).not.toBe(originalMember.id);

    const admitted = await fullState(ctx);
    expect(admitted.receipts.map((value) => value.phase)).toEqual(["before-add", "after-add"]);
    expect(admitted.receipts[0]!.member).toEqual({
      organizationId: own.id,
      userId: candidate.user.id,
      role: "member",
    });
    expect(admitted.receipts[1]!.member).toEqual(duplicate);

    for (const receipt of admitted.receipts) {
      expect(receipt.user).toEqual(candidate.user);
      expect(receipt.organization).toEqual(ctx.snapshot(rawOrg.data));
    }

    expect(
      admitted.full.members.filter(
        (item) => item.organizationId === own.id && item.userId === target.user.id,
      ),
    ).toEqual([originalMember, duplicate]);
    expect(admitted.full.members).toHaveLength(before.full.members.length + 1);
    expect(admitted.full.teams).toEqual(before.full.teams);
    expect(admitted.full.teamMembers).toEqual(before.full.teamMembers);
    expect(await ownStates(ctx, principals)).toEqual(usersBefore);

    const duplicateList = await list(target);
    expect(duplicateList.map((item) => item.id)).toEqual([own.id, other.id, own.id]);

    // Authority comes from the first membership row, not the duplicate admin row.
    const role = await target.client.$fetch("/organization/get-active-member-role", {
      query: { organizationId: own.id },
    });
    expect(role.error).toBeNull();
    expect(role.data).toEqual({ role: "member" });

    const denied = await target.client.$fetch("/organization/update-member-role", {
      method: "POST",
      body: {
        organizationId: own.id,
        memberId: duplicate.id,
        role: "member",
      },
    });
    expect(denied.error?.status).toBe(403);

    const foreignUpdate = await foreign.client.$fetch("/organization/update-member-role", {
      method: "POST",
      body: {
        organizationId: own.id,
        memberId: duplicate.id,
        role: "member",
      },
    });
    expect(foreignUpdate.error?.status).toBe(400);

    const foreignRemoval = await foreign.client.$fetch("/organization/remove-member", {
      method: "POST",
      body: { organizationId: own.id, memberIdOrEmail: duplicate.id },
    });
    expect(foreignRemoval.error?.status).toBe(400);
    expect(await fullState(ctx)).toEqual(admitted);
    expect(await ownStates(ctx, principals)).toEqual(usersBefore);

    const updated = await owner.client.$fetch("/organization/update-member-role", {
      method: "POST",
      body: { organizationId: own.id, memberId: duplicate.id, role: "owner" },
    });
    expect(updated.error).toBeNull();

    const changed = await fullState(ctx);
    expect(changed.full.members.find((item) => item.id === duplicate.id)).toEqual({
      ...duplicate,
      role: "owner",
    });
    expect(changed.full.members.find((item) => item.id === originalMember.id)).toEqual(
      originalMember,
    );
    expect(changed.full.members.filter((item) => item.id !== duplicate.id)).toEqual(
      admitted.full.members.filter((item) => item.id !== duplicate.id),
    );

    const removed = await owner.client.$fetch("/organization/remove-member", {
      method: "POST",
      body: { organizationId: own.id, memberIdOrEmail: duplicate.id },
    });
    expect(removed.error).toBeNull();

    const after = await fullState(ctx);
    expect(after.full.members).toEqual(
      admitted.full.members.filter((item) => item.id !== duplicate.id),
    );
    expect(after.full.teamMembers).toEqual(
      admitted.full.teamMembers.filter(
        (item) => item.teamId !== ownTeam.id || item.userId !== target.user.id,
      ),
    );
    expect(after.full.teams).toEqual(
      admitted.full.teams.map((item) =>
        item.id === ownTeam.id ? { ...item, memberCount: item.memberCount - 1 } : item,
      ),
    );
    expect(peers(after, other.id, [foreign.user.id, candidate.user.id])).toEqual(
      peers(before, other.id, [foreign.user.id, candidate.user.id]),
    );
    expect(await ownStates(ctx, principals)).toEqual(usersBefore);

    const retained = await target.client.$fetch("/organization/get-active-member-role", {
      query: { organizationId: own.id },
    });
    expect(retained.error).toBeNull();
    expect(retained.data).toEqual({ role: "member" });

    await configure(ctx, "record");
    const retry = await add(ctx, {
      organizationId: own.id,
      userId: target.user.id,
      role: "owner",
    });
    expect(retry.status).toBe(400);
    expect(retry.body).toHaveProperty("code", "USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION");

    const retryState = await fullState(ctx);
    expect(retryState.receipts).toEqual([]);
    expect(retryState.full).toEqual(after.full);

    return {
      before,
      usersBefore,
      created,
      admitted,
      duplicateList,
      role: ctx.snapshot(role),
      denied: ctx.snapshot(denied),
      foreignUpdate: ctx.snapshot(foreignUpdate),
      foreignRemoval: ctx.snapshot(foreignRemoval),
      updated: ctx.snapshot(updated),
      changed,
      removed: ctx.snapshot(removed),
      after,
      retained: ctx.snapshot(retained),
      retry,
      retryState,
      usersAfter: await ownStates(ctx, principals),
    };
  },
  [
    "GET /organization/list",
    "GET /organization/get-active-member-role",
    "POST /organization/update-member-role",
    "POST /organization/remove-member",
  ],
);

compatScenario(
  "organization physical membership pages preserve newer older newer rows and visible organization limits",
  async (ctx) => {
    await configure(ctx, "off");
    const owner = await signup(ctx, "page-owner");
    const target = await signup(ctx, "page-target");
    const candidate = await signup(ctx, "page-candidate");
    const foreign = await signup(ctx, "page-foreign");

    const older = await organization(ctx, owner, "membership-older");
    const newer = await organization(ctx, owner, "membership-newer");
    const other = await organization(ctx, foreign, "membership-foreign");

    const first = await add(ctx, {
      organizationId: newer.id,
      userId: target.user.id,
      role: "member",
    });
    const second = await add(ctx, {
      organizationId: older.id,
      userId: target.user.id,
      role: "member",
    });
    expect(first.status).toBe(200);
    expect(second.status).toBe(200);

    await configure(ctx, "patch-target", {
      organizationId: newer.id,
      patchUserId: target.user.id,
    });
    const third = await add(ctx, {
      organizationId: newer.id,
      userId: candidate.user.id,
      role: "member",
    });
    expect(third.status).toBe(200);

    await configure(ctx, "off");
    const full = await list(target);
    expect(full.map((item) => item.id)).toEqual([newer.id, older.id, newer.id]);
    expect(full[0]).toEqual(full[2]);

    const before = await fullState(ctx);
    const foreignBefore = await ctx.readUserState({ userId: foreign.user.id });

    const observations = [];

    for (const [profile, limit] of [
      ["org-member-multiplicity", 100],
      ["org-member-multiplicity-page-two", 2],
      ["org-member-multiplicity-page-one", 1],
      ["org-member-multiplicity-page-zero", 0],
    ] as const) {
      const actor = {
        client: createAuthClient({
          baseURL: `${ctx.baseURL}/__test/profiles/${profile}/api/auth`,
          fetchOptions: { customFetchImpl: target.fetch },
        }),
      };
      const listed = await list(actor);
      expect(listed).toEqual(full.slice(0, limit));

      const prior = await fullState(ctx);
      const creation = await actor.client.$fetch("/organization/create", {
        method: "POST",
        body: {
          name: `Visible page ${limit}`,
          slug: ctx.uniqueToken(`visible-page-${limit}`),
          metadata: { limit },
        },
      });

      let deleted: unknown = null;

      if (limit === 100) {
        expect(creation.error?.status).toBe(403);
        expect(await fullState(ctx)).toEqual(prior);
      } else {
        expect(creation.error).toBeNull();

        const created = row.parse(creation.data);
        const removal = await actor.client.$fetch("/organization/delete", {
          method: "POST",
          body: { organizationId: created.id },
        });
        expect(removal.error).toBeNull();

        deleted = ctx.snapshot(removal);
        expect((await fullState(ctx)).full).toEqual(prior.full);
      }

      observations.push({
        profile,
        limit,
        listed,
        prior,
        creation: ctx.snapshot(creation),
        deleted,
        after: await fullState(ctx),
      });
    }

    const after = await fullState(ctx);
    expect(after.full).toEqual(before.full);
    expect(peers(after, other.id, [foreign.user.id, candidate.user.id])).toEqual(
      peers(before, other.id, [foreign.user.id, candidate.user.id]),
    );
    expect(await ctx.readUserState({ userId: foreign.user.id })).toEqual(foreignBefore);

    const foreignList = await list(foreign);
    expect(foreignList.map((item) => item.id)).toEqual([other.id]);

    return {
      first,
      second,
      third,
      full,
      before,
      foreignBefore,
      observations,
      after,
      foreignAfter: await ctx.readUserState({ userId: foreign.user.id }),
      foreignList,
    };
  },
  ["GET /organization/list", "POST /organization/create", "POST /organization/delete"],
);

compatScenario(
  "organization concurrent normal admissions pass real prechecks and retain both physical members",
  async (ctx) => {
    await configure(ctx, "off");
    const owner = await signup(ctx, "race-owner");
    const target = await signup(ctx, "race-target");
    const foreign = await signup(ctx, "race-foreign");
    const principals = [owner, target, foreign];

    const own = await organization(ctx, owner, "race-own");
    const other = await organization(ctx, foreign, "race-other");

    await configure(ctx, "pause-before-pair");
    const before = await fullState(ctx);
    const usersBefore = await ownStates(ctx, principals);

    const traces: TraceEntry[] = [];

    async function call(name: string) {
      const response = await createTracingFetch(
        ctx.baseURL,
        name,
        traces,
      )(`${root}/server`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          profile: "org-member-addition",
          body: {
            organizationId: own.id,
            userId: target.user.id,
            role: "member",
          },
        }),
      });
      const text = await response.text();
      return { status: response.status, body: text ? JSON.parse(text) : null };
    }

    let first: ReturnType<typeof call> | undefined;
    let second: ReturnType<typeof call> | undefined;
    let one;
    let held;
    let firstResult;
    let secondResult;

    async function release(name: string) {
      const response = await createTracingFetch(
        ctx.baseURL,
        name,
        traces,
      )(`${root}/release`, { method: "POST" });
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ released: true });
    }

    try {
      first = call("member-race-first");
      one = await ctx.rawRequest({ path: `${root}/state?waitFor=before-add` });
      expect(one.status).toBe(200);
      expect(z.object({ receipts: z.array(z.unknown()) }).parse(one.body).receipts).toHaveLength(1);

      second = call("member-race-second");
      held = await ctx.rawRequest({
        path: `${root}/state?waitFor=before-pair`,
      });
      expect(held.status).toBe(200);

      const heldBody = z
        .object({
          receipts: z.array(z.record(z.string(), z.unknown())),
          snapshot: z.unknown(),
        })
        .parse(held.body);
      expect(heldBody.receipts.map((item) => item.phase)).toEqual(["before-add", "before-add"]);
      expect(heldBody.snapshot).toEqual(before.snapshot);

      await release("member-race-release-first");
      firstResult = await first;
      expect(firstResult.status).toBe(200);

      await release("member-race-release-second");
      secondResult = await second;
      expect(secondResult.status).toBe(200);
    } finally {
      if (!firstResult || !secondResult) {
        await configure(ctx, "off");
        await Promise.allSettled([first, second]);
      }
    }

    // Both genuine transport observations are retained in application release order,
    // independently of which network response completes first.
    for (const name of [
      "member-race-release-first",
      "member-race-first",
      "member-race-release-second",
      "member-race-second",
    ]) {
      const entries = traces.filter((item) => item.actor === name);
      expect(entries).toHaveLength(1);
      ctx.recordTransport(entries);
    }

    const firstMember = member.parse(firstResult!.body);
    const secondMember = member.parse(secondResult!.body);
    expect(firstMember.id).not.toBe(secondMember.id);

    const after = await fullState(ctx);
    expect(
      after.full.members.filter(
        (item) => item.organizationId === own.id && item.userId === target.user.id,
      ),
    ).toEqual([firstMember, secondMember]);
    expect(after.full.members).toHaveLength(before.full.members.length + 2);
    expect(after.receipts.map((item) => item.phase)).toEqual([
      "before-add",
      "before-add",
      "after-add",
      "after-add",
    ]);
    expect(after.receipts[2]!.member).toEqual(firstMember);
    expect(after.receipts[3]!.member).toEqual(secondMember);
    expect(after.full.teams).toEqual(before.full.teams);
    expect(after.full.teamMembers).toEqual(before.full.teamMembers);
    expect(await ownStates(ctx, principals)).toEqual(usersBefore);
    expect(peers(after, other.id, [foreign.user.id])).toEqual(
      peers(before, other.id, [foreign.user.id]),
    );

    const listed = await target.client.$fetch("/organization/list-members", {
      query: { organizationId: own.id, limit: 1 },
    });
    expect(listed.error).toBeNull();

    const page = z.object({ members: z.array(row), total: z.number() }).parse(listed.data);
    expect(page.total).toBe(3);
    expect(page.members).toHaveLength(1);

    const organizations = await list(target);
    expect(organizations.map((item) => item.id)).toEqual([own.id, own.id]);

    await configure(ctx, "record");
    const retry = await add(ctx, {
      organizationId: own.id,
      userId: target.user.id,
      role: "member",
    });
    expect(retry.status).toBe(400);
    expect((await fullState(ctx)).receipts).toEqual([]);
    expect((await fullState(ctx)).full).toEqual(after.full);

    return {
      before,
      usersBefore,
      one,
      held,
      firstResult,
      secondResult,
      after,
      listed: ctx.snapshot(listed),
      organizations,
      retry,
      final: await fullState(ctx),
      usersAfter: await ownStates(ctx, principals),
    };
  },
  ["GET /organization/list", "GET /organization/list-members"],
);
