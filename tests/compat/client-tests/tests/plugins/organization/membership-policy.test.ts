import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { z } from "zod";

import type { FixtureProfile } from "../../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../../support/scenario";

const root = "/__test/organization-membership-policy";

const row = z.object({ id: z.string() }).passthrough();

const stateSchema = z.object({
  receipts: z.array(z.record(z.string(), z.unknown())),
  snapshot: z.object({
    organizations: z.array(row),
    members: z.array(row),
    invitations: z.array(row),
    teams: z.array(row),
  }),
});

async function state(ctx: ScenarioContext) {
  const response = await ctx.rawRequest({ path: `${root}/state` });
  expect(response.status).toBe(200);
  return stateSchema.parse(response.body);
}

async function reset(ctx: ScenarioContext) {
  const response = await ctx.rawRequest({ path: `${root}/configure`, method: "POST", json: {} });
  expect(response.status).toBe(200);
}

async function signup(ctx: ScenarioContext, name: string) {
  const actor = ctx.actor(name, "org-membership-default");
  const email = ctx.uniqueEmail(name);
  const created = await actor.client.signUp.email({ email, name, password: "password123" });
  expect(created.error).toBeNull();

  const user = row.parse(z.object({ user: row }).parse(ctx.snapshot(created.data)).user);

  const session = await actor.client.getSession();
  expect(session.error).toBeNull();

  const issued = z
    .object({ user: row, session: row.extend({ token: z.string(), userId: z.string() }) })
    .parse(ctx.snapshot(session.data));
  expect(issued.user.id).toBe(user.id);
  expect(issued.session.userId).toBe(user.id);
  expect(issued.session.token).toBe(z.string().parse(created.data!.token));

  const stored = z
    .object({ sessions: z.array(row) })
    .parse(await ctx.readUserState({ userId: user.id }));
  expect(stored.sessions).toHaveLength(1);
  expect(stored.sessions[0]).toMatchObject({
    id: issued.session.id,
    userId: user.id,
    token: issued.session.token,
  });

  return { ...actor, user, email, created, session: ctx.snapshot(session) };
}

type Actor = Awaited<ReturnType<typeof signup>>;

function client(ctx: ScenarioContext, actor: Actor, profile: FixtureProfile) {
  return createAuthClient({
    baseURL: `${ctx.baseURL}/__test/profiles/${profile}/api/auth`,
    fetchOptions: { customFetchImpl: actor.fetch },
  });
}

async function org(ctx: ScenarioContext, actor: Actor, name: string) {
  const response = await actor.client.$fetch("/organization/create", {
    method: "POST",
    body: {
      name,
      slug: ctx.uniqueToken(name),
      logo: `https://example.test/${name}.png`,
      metadata: { amount: 1e20, original: name },
    },
  });
  expect(response.error).toBeNull();
  return row.parse(response.data);
}

async function add(
  ctx: ScenarioContext,
  profile: FixtureProfile,
  organizationId: string,
  userId: string,
  fields: Record<string, unknown> = {},
) {
  return ctx.rawRequest({
    path: `${root}/server`,
    method: "POST",
    json: { profile, body: { organizationId, userId, role: "member", ...fields } },
  });
}

async function actors(ctx: ScenarioContext, names: string[]) {
  const result = [];
  for (const name of names) {
    result.push(await signup(ctx, name));
  }
  return result;
}

async function owned(ctx: ScenarioContext, values: Actor[]) {
  return Promise.all(values.map((actor) => ctx.readUserState({ userId: actor.user.id })));
}

// Eleven real password signups per runtime exceed Bun's default five-second budget.
compatScenario(
  "organization fixed membership policies retain falsy defaults and raw Number admission without read callbacks",
  async (ctx) => {
    const [owner, existing, foreign] = await actors(ctx, [
      "fixed-owner",
      "fixed-existing",
      "fixed-foreign",
    ]);
    const own = await org(ctx, owner!, "fixed-own");
    await org(ctx, foreign!, "fixed-other");
    expect((await add(ctx, "org-membership-default", own.id, existing!.user.id)).status).toBe(200);

    const observations = [];

    for (const [suffix, allowed] of [
      ["default", true],
      ["none", true],
      ["zero", true],
      ["nan", true],
      ["one", false],
      ["fractional", false],
      ["negative", false],
      ["infinity", true],
    ] as const) {
      const candidate = await signup(ctx, `fixed-${suffix}`);
      await reset(ctx);
      const before = await state(ctx);
      const usersBefore = await owned(ctx, [owner!, existing!, foreign!, candidate]);
      const response = await add(
        ctx,
        `org-membership-${suffix}` as FixtureProfile,
        own.id,
        candidate.user.id,
      );
      const after = await state(ctx);

      if (allowed) {
        expect(response.status).toBe(200);

        const created = row.parse(response.body);
        expect(after.snapshot.members).toEqual([...before.snapshot.members, created]);
        expect(created).toMatchObject({
          organizationId: own.id,
          userId: candidate.user.id,
          role: "member",
        });
      } else {
        expect(response.status).toBe(403);
        expect(response.body).toHaveProperty("code", "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED");
        expect(after.snapshot).toEqual(before.snapshot);
      }

      const usersAfter = await owned(ctx, [owner!, existing!, foreign!, candidate]);
      expect(after.receipts).toEqual([]);
      expect(after.snapshot.organizations).toEqual(before.snapshot.organizations);
      expect(after.snapshot.invitations).toEqual(before.snapshot.invitations);
      expect(after.snapshot.teams).toEqual(before.snapshot.teams);
      expect(usersAfter).toEqual(usersBefore);

      observations.push({
        suffix,
        candidate: candidate.created,
        candidateSession: candidate.session,
        before,
        response,
        after,
        usersBefore,
        usersAfter,
      });
    }

    return {
      owner: owner!.created,
      ownerSession: owner!.session,
      existing: existing!.created,
      existingSession: existing!.session,
      foreign: foreign!.created,
      foreignSession: foreign!.session,
      observations,
    };
  },
  ["POST /organization/create"],
);

compatScenario(
  "organization fixed fractional membership admits one physical row then rejects capacity without principal writes",
  async (ctx) => {
    const [owner, foreign] = await actors(ctx, ["fractional-owner", "fractional-foreign"]);
    await org(ctx, foreign!, "fractional-foreign");
    const fractionalOrganization = await org(ctx, owner!, "fixed-fractional-boundary");
    const fractionalTarget = await signup(ctx, "fractional-first");
    const fractionalDeniedTarget = await signup(ctx, "fractional-second");
    await reset(ctx);
    const fractionalBefore = await state(ctx);
    const fractionalUsers = await owned(ctx, [
      owner!,
      foreign!,
      fractionalTarget,
      fractionalDeniedTarget,
    ]);

    const fractionalAllowed = await add(
      ctx,
      "org-membership-fractional",
      fractionalOrganization.id,
      fractionalTarget.user.id,
    );
    expect(fractionalAllowed.status).toBe(200);

    const fractionalAdmitted = await state(ctx);
    expect(fractionalAdmitted.snapshot.members).toEqual([
      ...fractionalBefore.snapshot.members,
      row.parse(fractionalAllowed.body),
    ]);

    const fractionalDenied = await add(
      ctx,
      "org-membership-fractional",
      fractionalOrganization.id,
      fractionalDeniedTarget.user.id,
    );
    expect(fractionalDenied.status).toBe(403);
    expect(await state(ctx)).toEqual(fractionalAdmitted);
    expect(await owned(ctx, [owner!, foreign!, fractionalTarget, fractionalDeniedTarget])).toEqual(
      fractionalUsers,
    );

    return {
      owner: owner!.created,
      foreign: foreign!.created,
      fractionalBefore,
      fractionalUsers,
      fractionalAllowed,
      fractionalAdmitted,
      fractionalDenied,
      fractionalAfter: await state(ctx),
    };
  },
  ["POST /organization/create"],
);

compatScenario(
  "organization asynchronous membership resolver observes target and raw organization after count and keeps raw zero NaN errors",
  async (ctx) => {
    const [owner, existing, foreign] = await actors(ctx, [
      "resolver-owner",
      "resolver-existing",
      "resolver-foreign",
    ]);
    const own = await org(ctx, owner!, "resolver-own");
    await org(ctx, foreign!, "resolver-foreign");
    expect((await add(ctx, "org-membership-default", own.id, existing!.user.id)).status).toBe(200);

    const raw = await owner!.client.$fetch("/organization/get-organization", {
      query: { organizationId: own.id },
    });
    expect(raw.error).toBeNull();

    const observations = [];

    for (const suffix of ["zero", "fractional", "error", "nan"] as const) {
      const target = await signup(ctx, `resolver-${suffix}`);
      await reset(ctx);
      const before = await state(ctx);
      const beforeUsers = await owned(ctx, [owner!, existing!, foreign!, target]);
      const response = await add(ctx, `org-membership-resolver-${suffix}`, own.id, target.user.id);
      const after = await state(ctx);

      expect(after.receipts).toHaveLength(1);
      expect(after.receipts[0]).toEqual({
        phase: "membership-limit",
        profile: `org-membership-resolver-${suffix}`,
        user: target.user,
        organization: ctx.snapshot(raw.data),
        snapshot: before.snapshot,
      });

      if (suffix === "nan") {
        expect(response.status).toBe(200);
        expect(after.snapshot.members).toEqual([
          ...before.snapshot.members,
          row.parse(response.body),
        ]);
      } else {
        expect(response.status).toBe(suffix === "error" ? 400 : 403);
        expect(response.body).toHaveProperty(
          "code",
          suffix === "error"
            ? "MEMBERSHIP_POLICY_REJECTED"
            : "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED",
        );
        expect(after.snapshot).toEqual(before.snapshot);
      }

      expect(await owned(ctx, [owner!, existing!, foreign!, target])).toEqual(beforeUsers);

      observations.push({ suffix, target: target.created, before, beforeUsers, response, after });
    }

    // On a fresh organization the fractional resolver limit admits one more member.
    const fractionalOrganization = await org(ctx, owner!, "resolver-fractional-boundary");
    const fractionalTarget = await signup(ctx, "resolver-fractional-first");
    const fractionalRaw = await owner!.client.$fetch("/organization/get-organization", {
      query: { organizationId: fractionalOrganization.id },
    });
    expect(fractionalRaw.error).toBeNull();

    await reset(ctx);
    const fractionalBefore = await state(ctx);
    const fractionalAllowed = await add(
      ctx,
      "org-membership-resolver-fractional",
      fractionalOrganization.id,
      fractionalTarget.user.id,
    );
    expect(fractionalAllowed.status).toBe(200);

    const fractionalAfter = await state(ctx);
    expect(fractionalAfter.receipts).toEqual([
      {
        phase: "membership-limit",
        profile: "org-membership-resolver-fractional",
        user: fractionalTarget.user,
        organization: ctx.snapshot(fractionalRaw.data),
        snapshot: fractionalBefore.snapshot,
      },
    ]);
    expect(fractionalAfter.snapshot.members).toEqual([
      ...fractionalBefore.snapshot.members,
      row.parse(fractionalAllowed.body),
    ]);

    // Target, organization and duplicate checks reject before the resolver runs.
    const candidate = await signup(ctx, "resolver-guard-target");
    await reset(ctx);
    const before = await state(ctx);
    const missingTarget = await add(
      ctx,
      "org-membership-resolver-nan",
      own.id,
      "missing-policy-target",
    );
    const missingOrganization = await add(
      ctx,
      "org-membership-resolver-nan",
      "missing-policy-organization",
      candidate.user.id,
    );
    const duplicate = await add(ctx, "org-membership-resolver-nan", own.id, existing!.user.id);
    expect(missingTarget.status).toBe(400);
    expect(missingTarget.body).toHaveProperty("code", "USER_NOT_FOUND");
    expect(missingOrganization.status).toBe(400);
    expect(missingOrganization.body).toHaveProperty("code", "ORGANIZATION_NOT_FOUND");
    expect(duplicate.status).toBe(400);
    expect(duplicate.body).toHaveProperty("code", "USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION");
    expect(await state(ctx)).toEqual(before);

    const room = await owner!.client.$fetch("/organization/create-team", {
      method: "POST",
      body: { organizationId: own.id, name: "Policy team" },
    });
    expect(room.error).toBeNull();

    await reset(ctx);
    const teamBefore = await state(ctx);
    const teamDenied = await add(
      ctx,
      "org-membership-resolver-zero-team-limit",
      own.id,
      candidate.user.id,
      { teamId: row.parse(room.data).id },
    );
    expect(teamDenied.status).toBe(403);

    const teamAfter = await state(ctx);
    expect(teamAfter.receipts.map((value) => value.phase)).toEqual(["membership-limit"]);
    expect(teamAfter.snapshot).toEqual(teamBefore.snapshot);

    return {
      observations,
      fractionalBefore,
      fractionalAllowed,
      fractionalAfter,
      before,
      missingTarget,
      missingOrganization,
      duplicate,
      room: ctx.snapshot(room),
      teamBefore,
      teamDenied,
      teamAfter,
    };
  },
  ["POST /organization/create", "GET /organization/get-organization"],
);

compatScenario(
  "organization invitation creation stays permitted at capacity and admission checks recipient then membership policy before writes",
  async (ctx) => {
    const [owner, existing, target, foreign] = await actors(ctx, [
      "invite-policy-owner",
      "invite-policy-existing",
      "invite-policy-target",
      "invite-policy-foreign",
    ]);
    const own = await org(ctx, owner!, "invite-policy-own");
    await org(ctx, foreign!, "invite-policy-foreign");
    expect((await add(ctx, "org-membership-default", own.id, existing!.user.id)).status).toBe(200);

    await reset(ctx);
    const before = await state(ctx);
    const beforeUsers = await owned(ctx, [owner!, existing!, target!, foreign!]);

    const invitation = await client(ctx, owner!, "org-membership-pending-one").$fetch(
      "/organization/invite-member",
      { method: "POST", body: { organizationId: own.id, email: target!.email, role: "member" } },
    );
    expect(invitation.error).toBeNull();

    const invited = row.parse(ctx.snapshot(invitation.data));
    const pending = await state(ctx);
    expect(pending.snapshot.invitations).toEqual([...before.snapshot.invitations, invited]);

    const pendingCap = await client(ctx, owner!, "org-membership-pending-one").$fetch(
      "/organization/invite-member",
      {
        method: "POST",
        body: {
          organizationId: own.id,
          email: ctx.uniqueEmail("pending-policy-other"),
          role: "member",
        },
      },
    );
    expect(pendingCap.error).toMatchObject({
      status: 403,
      code: "INVITATION_LIMIT_REACHED",
      message: "Invitation limit reached",
    });
    expect(await state(ctx)).toEqual(pending);

    const wrong = await client(ctx, foreign!, "org-membership-resolver-zero").$fetch(
      "/organization/accept-invitation",
      { method: "POST", body: { invitationId: invited.id } },
    );
    expect(wrong.error).toMatchObject({
      status: 403,
      code: "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION",
    });

    const unverified = await client(ctx, target!, "org-membership-resolver-zero").$fetch(
      "/organization/accept-invitation",
      { method: "POST", body: { invitationId: invited.id } },
    );
    expect(unverified.error?.status).toBe(403);
    expect((await state(ctx)).receipts).toEqual([]);
    expect((await state(ctx)).snapshot).toEqual(pending.snapshot);

    const sent = await target!.client.sendVerificationEmail({ email: target!.email });
    expect(sent.error).toBeNull();

    const proof = z
      .object({ token: z.string() })
      .parse(await ctx.readVerificationEmail({ email: target!.email }));
    const verified = await target!.client.verifyEmail({ query: { token: proof.token } });
    expect(verified.error).toBeNull();

    const targetSession = await target!.client.getSession();
    expect(targetSession.data?.user.emailVerified).toBe(true);

    const verifiedBefore = await state(ctx);
    const verifiedUsers = await owned(ctx, [owner!, existing!, target!, foreign!]);
    const fixed = await client(ctx, target!, "org-membership-one").$fetch(
      "/organization/accept-invitation",
      { method: "POST", body: { invitationId: invited.id } },
    );
    expect(fixed.error).toMatchObject({
      status: 403,
      code: "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED",
    });
    expect(await state(ctx)).toEqual(verifiedBefore);

    const resolved = await client(ctx, target!, "org-membership-resolver-zero").$fetch(
      "/organization/accept-invitation",
      { method: "POST", body: { invitationId: invited.id } },
    );
    expect(resolved.error).toMatchObject({
      status: 403,
      code: "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED",
    });

    const denied = await state(ctx);
    expect(denied.snapshot).toEqual(verifiedBefore.snapshot);
    expect(denied.receipts).toHaveLength(1);
    expect(denied.receipts[0]!.user).toEqual(ctx.snapshot(targetSession.data!.user));
    expect(denied.receipts[0]!.snapshot).toEqual(verifiedBefore.snapshot);
    expect(await owned(ctx, [owner!, existing!, target!, foreign!])).toEqual(verifiedUsers);

    const accepted = await client(ctx, target!, "org-membership-resolver-nan").$fetch(
      "/organization/accept-invitation",
      { method: "POST", body: { invitationId: invited.id } },
    );
    expect(accepted.error).toBeNull();

    const after = await state(ctx);
    expect(after.snapshot.invitations.find((value) => value.id === invited.id)).toMatchObject({
      status: "accepted",
    });
    expect(
      after.snapshot.members.filter(
        (value) => value.organizationId === own.id && value.userId === target!.user.id,
      ),
    ).toHaveLength(1);
    expect(await ctx.readUserState({ userId: foreign!.user.id })).toEqual(beforeUsers[3]);

    return {
      before,
      beforeUsers,
      invitation: ctx.snapshot(invitation),
      pending,
      pendingCap: ctx.snapshot(pendingCap),
      wrong: ctx.snapshot(wrong),
      unverified: ctx.snapshot(unverified),
      sent,
      verified,
      targetSession,
      verifiedBefore,
      verifiedUsers,
      fixed: ctx.snapshot(fixed),
      resolved: ctx.snapshot(resolved),
      denied,
      accepted: ctx.snapshot(accepted),
      after,
      usersAfter: await owned(ctx, [owner!, existing!, target!, foreign!]),
    };
  },
  ["POST /organization/invite-member", "POST /organization/accept-invitation"],
);

compatScenario(
  "organization read pages separate full member and user limits with Number versus parseInt and never invoke policy callbacks",
  async (ctx) => {
    const [owner, target, foreign] = await actors(ctx, [
      "page-policy-owner",
      "page-policy-target",
      "page-policy-foreign",
    ]);
    const own = await org(ctx, owner!, "page-policy-own");
    await org(ctx, foreign!, "page-policy-foreign");
    expect((await add(ctx, "org-membership-default", own.id, target!.user.id)).status).toBe(200);

    await reset(ctx);
    const before = await state(ctx);
    const beforeUsers = await owned(ctx, [owner!, target!, foreign!]);

    const guest = createAuthClient({
      baseURL: `${ctx.baseURL}/__test/profiles/org-membership-one/api/auth`,
      fetchOptions: {
        customFetchImpl: ctx.actor("page-policy-guest", "org-membership-one").fetch,
      },
    });
    const guestReads = [];

    for (const path of ["/organization/list-members", "/organization/get-full-organization"]) {
      const result = await guest.$fetch(path, { query: { organizationId: own.id } });
      expect(result.error).toMatchObject({
        status: 401,
        code: "UNAUTHORIZED",
        message: "Unauthorized",
      });
      expect(await state(ctx)).toEqual(before);
      expect(await owned(ctx, [owner!, target!, foreign!])).toEqual(beforeUsers);

      guestReads.push({ path, result: ctx.snapshot(result) });
    }

    const observations = [];

    for (const [suffix, expected] of [
      ["one", 1],
      ["zero", 2],
      ["nan", 2],
      ["resolver-zero", 2],
      ["page-one", 2],
      ["page-zero", 2],
    ] as const) {
      const selected = client(ctx, owner!, `org-membership-${suffix}` as FixtureProfile);
      const listed = await selected.$fetch("/organization/list-members", {
        query: { organizationId: own.id },
      });
      expect(listed.error).toBeNull();

      const page = z.object({ members: z.array(row), total: z.number() }).parse(listed.data);
      expect(page.members).toHaveLength(expected);
      expect(page.total).toBe(2);

      const full = await selected.$fetch("/organization/get-full-organization", {
        query: { organizationId: own.id },
      });

      if (suffix === "one") {
        expect(full.error?.status).toBe(500);
      } else {
        expect(full.error).toBeNull();
        expect(z.object({ members: z.array(row) }).parse(full.data).members).toHaveLength(
          suffix === "page-one" ? 1 : suffix === "page-zero" ? 0 : 2,
        );
      }

      observations.push({ suffix, listed: ctx.snapshot(listed), full: ctx.snapshot(full) });
    }

    const selected = client(ctx, owner!, "org-membership-one");
    const queries = [];

    for (const limit of ["0", "not-number", "0x1", "1.5", "-1", "Infinity"]) {
      const listed = await selected.$fetch("/organization/list-members", {
        query: { organizationId: own.id, limit },
      });
      if (limit === "1.5" || limit === "Infinity") {
        expect(listed.error?.status).toBe(500);
      } else {
        expect(listed.error).toBeNull();
        expect(z.object({ members: z.array(row) }).parse(listed.data).members).toHaveLength(
          limit === "-1" ? 2 : 1,
        );
      }
      queries.push({ limit, listed: ctx.snapshot(listed) });
    }

    const fullQueries = [];

    for (const membersLimit of ["1", "1.5", "1suffix", "0x1"]) {
      const full = await selected.$fetch("/organization/get-full-organization", {
        query: { organizationId: own.id, membersLimit },
      });
      expect(full.error).toBeNull();
      expect(z.object({ members: z.array(row) }).parse(full.data).members).toHaveLength(1);

      fullQueries.push({ membersLimit, full: ctx.snapshot(full) });
    }

    expect(await state(ctx)).toEqual(before);
    expect(await owned(ctx, [owner!, target!, foreign!])).toEqual(beforeUsers);

    const foreignView = await client(ctx, foreign!, "org-membership-one").$fetch(
      "/organization/get-full-organization",
      { query: { organizationId: own.id } },
    );
    expect(foreignView.error?.status).toBe(500);
    expect(await owned(ctx, [owner!, target!, foreign!])).toEqual(beforeUsers);
    expect((await state(ctx)).receipts).toEqual([]);

    const originalTarget = before.snapshot.members.find(
      (member) => member.organizationId === own.id && member.userId === target!.user.id,
    )!;
    const promoted = await owner!.client.$fetch("/organization/update-member-role", {
      method: "POST",
      body: { organizationId: own.id, memberId: originalTarget.id, role: "owner" },
    });
    expect(promoted.error).toBeNull();

    await reset(ctx);
    const removalBefore = await state(ctx);
    const pagedDenial = await selected.$fetch("/organization/remove-member", {
      method: "POST",
      body: { organizationId: own.id, memberIdOrEmail: originalTarget.id },
    });
    expect(pagedDenial.error).toMatchObject({
      status: 400,
      code: "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER",
    });
    expect(await state(ctx)).toEqual(removalBefore);

    const removed = await client(ctx, owner!, "org-membership-resolver-error").$fetch(
      "/organization/remove-member",
      { method: "POST", body: { organizationId: own.id, memberIdOrEmail: originalTarget.id } },
    );
    expect(removed.error).toBeNull();

    const removalAfter = await state(ctx);
    expect(removalAfter.receipts).toEqual([]);
    expect(removalAfter.snapshot).toEqual({
      ...removalBefore.snapshot,
      members: removalBefore.snapshot.members.filter((member) => member.id !== originalTarget.id),
    });
    expect(await owned(ctx, [owner!, target!, foreign!])).toEqual(beforeUsers);

    return {
      before,
      beforeUsers,
      guestReads,
      observations,
      queries,
      fullQueries,
      foreignView: ctx.snapshot(foreignView),
      promoted: ctx.snapshot(promoted),
      removalBefore,
      pagedDenial: ctx.snapshot(pagedDenial),
      removed: ctx.snapshot(removed),
      after: removalAfter,
      usersAfter: await owned(ctx, [owner!, target!, foreign!]),
    };
  },
  [
    "GET /organization/list-members",
    "GET /organization/get-full-organization",
    "POST /organization/update-member-role",
    "POST /organization/remove-member",
  ],
);
