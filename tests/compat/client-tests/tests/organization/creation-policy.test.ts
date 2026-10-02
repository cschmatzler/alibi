import { expect } from "bun:test";
import { z } from "zod";
import type { FixtureProfile } from "../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../support/scenario";

const member = z
  .object({ id: z.string(), userId: z.string(), organizationId: z.string(), role: z.string() })
  .passthrough();

const organization = z
  .object({ id: z.string(), name: z.string(), slug: z.string(), members: z.array(member) })
  .passthrough();

const stateSchema = z.object({
  orphanOrganizations: z.array(z.object({ id: z.string(), name: z.string(), slug: z.string() })),
  organizations: z.array(
    z.object({
      id: z.string(),
      name: z.string(),
      slug: z.string(),
      memberId: z.string(),
      userId: z.string(),
      role: z.string(),
    }),
  ),
  sessions: z.array(
    z.object({
      id: z.string(),
      token: z.string(),
      userId: z.string(),
      activeOrganizationId: z.string().nullable(),
    }),
  ),
  receipts: z.array(
    z.object({ operation: z.string(), userId: z.string(), email: z.string(), name: z.string() }),
  ),
});

const limitError = {
  status: 403,
  code: "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS",
  message: "You have reached the maximum number of organizations",
};

const allowError = {
  status: 403,
  code: "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION",
  message: "You are not allowed to create a new organization",
};

async function signup(
  ctx: ScenarioContext,
  profile: FixtureProfile,
  actorName: string,
  name: string,
) {
  const actor = ctx.actor(actorName, profile);
  const email = ctx.uniqueEmail(`${profile}-${actorName}`);
  const result = await actor.client.signUp.email({ email, name, password: "password123" });
  expect(result.error).toBeNull();
  const user = z.object({ user: z.object({ id: z.string() }) }).parse(result.data).user;
  return { ...actor, email, userId: user.id, result };
}

async function state(ctx: ScenarioContext, email: string) {
  const response = await ctx.rawRequest({
    path: `/__test/organization-creation-state?email=${encodeURIComponent(email)}`,
  });
  expect(response.status).toBe(200);
  return stateSchema.parse(response.body);
}

async function create(
  ctx: ScenarioContext,
  actor: Awaited<ReturnType<typeof signup>>,
  suffix: string,
  extra: Record<string, unknown> = {},
) {
  return actor.client.$fetch("/organization/create", {
    method: "POST",
    body: { name: suffix, slug: ctx.uniqueToken(suffix), ...extra },
  });
}

async function server(
  ctx: ScenarioContext,
  profile: FixtureProfile,
  userId: string,
  suffix: string,
) {
  return ctx.rawRequest({
    path: "/__test/organization-create",
    method: "POST",
    json: { profile, userId, name: suffix, slug: ctx.uniqueToken(suffix) },
  });
}

compatScenario(
  "organization creation static denial and negative limits preserve ownership while trusted creation bypasses only the allow policy",
  async (ctx) => {
    const observations = [];
    for (const profile of ["org-creation-denied", "org-creation-negative"] as const) {
      const owner = await signup(ctx, profile, "owner", "Owner");
      const foreign = await signup(ctx, profile, "foreign", "Foreign");
      const before = await state(ctx, owner.email);
      const foreignBefore = await state(ctx, foreign.email);

      const guest = await ctx.rawRequest({
        path: `/__test/profiles/${profile}/api/auth/organization/create`,
        method: "POST",
        json: { name: "Guest", slug: ctx.uniqueToken(`guest-${profile}`), userId: owner.userId },
      });
      expect(guest.status).toBe(401);
      expect(guest.body).toBeNull();

      const denied = await create(ctx, owner, `denied-${profile}`, { userId: foreign.userId });
      expect(denied.error).toMatchObject(
        profile === "org-creation-denied" ? allowError : limitError,
      );
      expect(await state(ctx, owner.email)).toEqual(before);
      expect(await state(ctx, foreign.email)).toEqual(foreignBefore);

      const trusted = await server(ctx, profile, foreign.userId, `trusted-${profile}`);
      if (profile === "org-creation-denied") {
        expect(trusted.status).toBe(200);
        const created = organization.parse(trusted.body);
        expect(created.members[0]).toMatchObject({ userId: foreign.userId, role: "owner" });
        const after = await state(ctx, foreign.email);
        expect(after.organizations).toHaveLength(1);
        expect(after.organizations[0]).toMatchObject({
          id: created.id,
          userId: foreign.userId,
          role: "owner",
        });
        expect(after.sessions).toEqual(foreignBefore.sessions);
      } else {
        expect(trusted.status).toBe(403);
        expect(trusted.body).toMatchObject({ code: limitError.code, message: limitError.message });
        expect(await state(ctx, foreign.email)).toEqual(foreignBefore);
      }

      const unknown = await server(
        ctx,
        profile,
        ctx.uniqueToken("missing-user"),
        `missing-${profile}`,
      );
      expect(unknown.status).toBe(401);
      expect(unknown.body).toBeNull();
      expect(await state(ctx, owner.email)).toEqual(before);

      observations.push({
        profile,
        owner: ctx.snapshot(owner.result),
        foreign: ctx.snapshot(foreign.result),
        before,
        foreignBefore,
        guest,
        denied: ctx.snapshot(denied),
        trusted,
        unknown,
        foreignAfter: await state(ctx, foreign.email),
      });
    }

    return observations;
  },
  ["POST /organization/create"],
);

compatScenario(
  "organization creation fractional limits count every membership and preserve other current-token selections",
  async (ctx) => {
    const profile = "org-creation-limit";
    const owner = await signup(ctx, profile, "owner", "Owner");
    const one = await create(ctx, owner, "fractional-one");
    expect(one.error).toBeNull();
    const first = organization.parse(one.data);

    const secondToken = ctx.actor("second-token", profile).client;
    expect(
      (await secondToken.signIn.email({ email: owner.email, password: "password123" })).error,
    ).toBeNull();

    const beforeSecond = await state(ctx, owner.email);
    const two = await create(ctx, owner, "fractional-two");
    expect(two.error).toBeNull();
    const second = organization.parse(two.data);

    const ownerBefore = await state(ctx, owner.email);
    expect(ownerBefore.organizations).toHaveLength(2);
    expect(
      ownerBefore.sessions.filter((row) => row.activeOrganizationId === second.id),
    ).toHaveLength(1);
    expect(ownerBefore.sessions.find((row) => row.activeOrganizationId === null)).toEqual(
      beforeSecond.sessions.find((row) => row.activeOrganizationId === null),
    );

    const another = await signup(ctx, profile, "joined-member", "Joined");
    const own = await create(ctx, another, "member-own");
    expect(own.error).toBeNull();

    const invitation = await owner.client.$fetch("/organization/invite-member", {
      method: "POST",
      body: { organizationId: first.id, email: another.email, role: "member" },
    });
    expect(invitation.error).toBeNull();
    const invitationId = z.object({ id: z.string() }).parse(invitation.data).id;
    const accepted = await another.client.$fetch("/organization/accept-invitation", {
      method: "POST",
      body: { invitationId },
    });
    expect(accepted.error).toBeNull();

    const anotherBefore = await state(ctx, another.email);
    expect(anotherBefore.organizations.map((row) => row.role).sort()).toEqual(["member", "owner"]);

    const denied = await create(ctx, another, "limit-before-slug-check", {
      slug: first.slug,
      userId: owner.userId,
    });
    expect(denied.error).toMatchObject(limitError);
    const deniedOwner = await create(ctx, owner, "third-owner");
    expect(deniedOwner.error).toMatchObject(limitError);
    expect(await state(ctx, another.email)).toEqual(anotherBefore);
    expect(await state(ctx, owner.email)).toEqual(ownerBefore);

    return {
      one: ctx.snapshot(one),
      two: ctx.snapshot(two),
      own: ctx.snapshot(own),
      invitation: ctx.snapshot(invitation),
      accepted: ctx.snapshot(accepted),
      ownerBefore,
      anotherBefore,
      denied: ctx.snapshot(denied),
      deniedOwner: ctx.snapshot(deniedOwner),
    };
  },
  ["POST /organization/create"],
);

compatScenario(
  "organization creation nonfinite number limits retain the pinned unlimited comparison branch",
  async (ctx) => {
    const observations = [];
    for (const profile of ["org-creation-infinity", "org-creation-nan"] as const) {
      const owner = await signup(ctx, profile, "owner", "Unlimited");
      const one = await create(ctx, owner, `${profile}-one`);
      const two = await create(ctx, owner, `${profile}-two`);
      expect(one.error).toBeNull();
      expect(two.error).toBeNull();

      const rows = await state(ctx, owner.email);
      expect(rows.organizations).toHaveLength(2);
      expect(
        rows.organizations.every((row) => row.userId === owner.userId && row.role === "owner"),
      ).toBe(true);

      observations.push({ profile, one: ctx.snapshot(one), two: ctx.snapshot(two), rows });
    }

    return observations;
  },
  ["POST /organization/create"],
);

compatScenario(
  "organization creation async policy sees the persisted principal and true limit results deny public and trusted creation",
  async (ctx) => {
    const profile = "org-creation-callback";
    const paid = await signup(ctx, profile, "paid", "Paid Current");
    const free = await signup(ctx, profile, "free", "Free Current");

    const forged = await create(ctx, free, "free-forged-principal", { userId: paid.userId });
    expect(forged.error).toMatchObject(allowError);

    const freeDenied = await state(ctx, free.email);
    expect(freeDenied.organizations).toEqual([]);
    expect(freeDenied.receipts).toEqual([
      { operation: "allow", userId: free.userId, email: free.email, name: "Free Current" },
    ]);
    expect((await state(ctx, paid.email)).receipts).toEqual([]);

    const first = await create(ctx, paid, "paid-allowed", { userId: free.userId });
    expect(first.error).toBeNull();
    const created = organization.parse(first.data);
    expect(created.members[0]?.userId).toBe(paid.userId);

    const paidBefore = await state(ctx, paid.email);
    const denied = await create(ctx, paid, "paid-at-limit");
    expect(denied.error).toMatchObject(limitError);

    const paidAfter = await state(ctx, paid.email);
    expect(paidAfter.organizations).toEqual(paidBefore.organizations);
    expect(paidAfter.sessions).toEqual(paidBefore.sessions);
    expect(paidAfter.receipts.map((row) => row.operation)).toEqual([
      "allow",
      "limit",
      "allow",
      "limit",
    ]);
    expect(
      paidAfter.receipts.every((row) => row.userId === paid.userId && row.email === paid.email),
    ).toBe(true);

    const trusted = await server(ctx, profile, free.userId, "trusted-free-allowed");
    expect(trusted.status).toBe(200);
    expect(organization.parse(trusted.body).members[0]?.userId).toBe(free.userId);

    const freeBefore = await state(ctx, free.email);
    expect(freeBefore.sessions).toEqual(freeDenied.sessions);

    const trustedDenied = await server(ctx, profile, free.userId, "trusted-free-at-limit");
    expect(trustedDenied.status).toBe(403);
    expect(trustedDenied.body).toMatchObject({
      code: limitError.code,
      message: limitError.message,
    });

    const freeAfter = await state(ctx, free.email);
    expect(freeAfter.organizations).toEqual(freeBefore.organizations);
    expect(freeAfter.sessions).toEqual(freeBefore.sessions);
    expect(freeAfter.receipts.map((row) => row.operation)).toEqual([
      "allow",
      "allow",
      "limit",
      "allow",
      "limit",
    ]);

    return {
      forged: ctx.snapshot(forged),
      freeDenied,
      first: ctx.snapshot(first),
      paidBefore,
      denied: ctx.snapshot(denied),
      paidAfter,
      trusted,
      freeBefore,
      trustedDenied,
      freeAfter,
    };
  },
  ["POST /organization/create"],
);

compatScenario(
  "organization creator role customization preserves explicit grants and prevents removing the only effective owner",
  async (ctx) => {
    const founder = await signup(ctx, "org-creation-founder", "founder", "Founder");
    const created = await create(ctx, founder, "custom-founder", {
      metadata: { policy: "creator-grants" },
    });
    expect(created.error).toBeNull();
    const org = organization.parse(created.data);
    expect(org.members[0]?.role).toBe("founder");

    const before = await state(ctx, founder.email);
    const denied = await founder.client.$fetch("/organization/update", {
      method: "POST",
      body: { organizationId: org.id, data: { name: "must-not-save" } },
    });
    expect(denied.error).toMatchObject({
      status: 403,
      code: "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION",
    });
    expect(await state(ctx, founder.email)).toEqual(before);

    const assigned = await founder.client.$fetch("/organization/update-member-role", {
      method: "POST",
      body: { organizationId: org.id, memberId: org.members[0]!.id, role: ["founder", "editor"] },
    });
    expect(assigned.error).toBeNull();

    const updated = await founder.client.$fetch("/organization/update", {
      method: "POST",
      body: { organizationId: org.id, data: { name: "explicit-grant" } },
    });
    expect(updated.error).toBeNull();
    expect((await state(ctx, founder.email)).organizations[0]).toMatchObject({
      name: "explicit-grant",
      role: "founder,editor",
    });

    const empty = await signup(ctx, "org-creation-empty-role", "empty", "Effective Owner");
    const defaulted = await create(ctx, empty, "empty-creator");
    expect(defaulted.error).toBeNull();
    const ownerOrg = organization.parse(defaulted.data);
    expect(ownerOrg.members[0]?.role).toBe("owner");

    const ownerBefore = await state(ctx, empty.email);
    const demotion = await empty.client.$fetch("/organization/update-member-role", {
      method: "POST",
      body: { organizationId: ownerOrg.id, memberId: ownerOrg.members[0]!.id, role: "member" },
    });
    expect(demotion.error).toMatchObject({
      status: 400,
      code: "YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER",
    });
    expect(await state(ctx, empty.email)).toEqual(ownerBefore);

    return {
      created: ctx.snapshot(created),
      before,
      denied: ctx.snapshot(denied),
      assigned: ctx.snapshot(assigned),
      updated: ctx.snapshot(updated),
      founderAfter: await state(ctx, founder.email),
      defaulted: ctx.snapshot(defaulted),
      ownerBefore,
      demotion: ctx.snapshot(demotion),
    };
  },
  [
    "POST /organization/create",
    "POST /organization/update",
    "POST /organization/update-member-role",
  ],
);

compatScenario(
  "organization creation callback errors propagate before writes even for trusted callers",
  async (ctx) => {
    const observations = [];
    for (const [actorName, name, code, message, operations] of [
      [
        "allow-error",
        "Reject Allow",
        "CREATION_ALLOW_REJECTED",
        "Creation allow callback rejected",
        ["allow"],
      ],
      [
        "limit-error",
        "Paid Reject Limit",
        "CREATION_LIMIT_REJECTED",
        "Creation limit callback rejected",
        ["allow", "limit"],
      ],
    ] as const) {
      const actor = await signup(ctx, "org-creation-callback", actorName, name);
      const before = await state(ctx, actor.email);

      const rejected = await create(ctx, actor, `${actorName}-public`);
      expect(rejected.error).toMatchObject({ status: 403, code, message });

      const afterPublic = await state(ctx, actor.email);
      expect(afterPublic.organizations).toEqual(before.organizations);
      expect(afterPublic.orphanOrganizations).toEqual(before.orphanOrganizations);
      expect(afterPublic.sessions).toEqual(before.sessions);
      expect(afterPublic.receipts.map((row) => row.operation)).toEqual([...operations]);

      const trusted = await server(
        ctx,
        "org-creation-callback",
        actor.userId,
        `${actorName}-trusted`,
      );
      expect(trusted.status).toBe(403);
      expect(trusted.body).toEqual({ code, message });

      const afterTrusted = await state(ctx, actor.email);
      expect(afterTrusted.organizations).toEqual(before.organizations);
      expect(afterTrusted.orphanOrganizations).toEqual(before.orphanOrganizations);
      expect(afterTrusted.sessions).toEqual(before.sessions);
      expect(afterTrusted.receipts.map((row) => row.operation)).toEqual([
        ...operations,
        ...operations,
      ]);

      observations.push({
        rejected: ctx.snapshot(rejected),
        trusted,
        before,
        afterPublic,
        afterTrusted,
      });
    }

    return observations;
  },
  ["POST /organization/create"],
);
