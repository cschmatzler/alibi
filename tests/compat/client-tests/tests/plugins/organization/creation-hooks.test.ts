import { expect } from "bun:test";

import { z } from "zod";

import { RUST_BASE_URL } from "../../../support/config";
import type { FixtureProfile } from "../../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../../support/scenario";
import { disconnectedRequest } from "./disconnect";

// Rust intentionally makes this lifecycle atomic (#473). The original physical
// snapshots remain in receipts/artifacts and are independently asserted per runtime.
// Cross-runtime comparison retains callback data, results, errors and transport;
// only the independently checked transaction visibility snapshots are projected.
function projectCreationVisibility(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(projectCreationVisibility);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([key]) => key !== "snapshot")
        .map(([key, entry]) => [key, projectCreationVisibility(entry)]),
    );
  }
  return value;
}
const creationComparison = {
  comparisonProjection: {
    reason:
      "Rust organization creation is atomic; pinned Source retains partial writes. Per-runtime state assertions cover visibility and rollback.",
    project: projectCreationVisibility,
  },
};
const isAtomic = (ctx: ScenarioContext) => ctx.baseURL === RUST_BASE_URL;

const row = z.object({ id: z.string() }).passthrough();

const snapshot = z.object({
  organizations: z.array(row),
  members: z.array(row),
  teams: z.array(row),
  teamMembers: z.array(row),
  sessions: z.array(row),
  users: z.array(row),
});

const receipt = z.object({
  phase: z.string(),
  user: z.object({ id: z.string(), email: z.string(), name: z.string() }),
  organization: z.record(z.string(), z.unknown()),
  member: z.record(z.string(), z.unknown()).optional(),
  team: z.record(z.string(), z.unknown()).optional(),
  snapshot,
});

const stateSchema = z.object({ receipts: z.array(receipt), snapshot });

const organization = z
  .object({
    id: z.string(),
    name: z.string(),
    slug: z.string(),
    logo: z.string().nullable().optional(),
    metadata: z.unknown().optional(),
    members: z.array(
      z
        .object({
          id: z.string(),
          organizationId: z.string(),
          userId: z.string(),
          role: z.string(),
        })
        .passthrough(),
    ),
  })
  .passthrough();

const phases = [
  "before-org",
  "before-member",
  "after-member",
  "before-team",
  "after-team",
  "after-org",
];

async function configure(ctx: ScenarioContext, mode: string, extra: Record<string, unknown> = {}) {
  const response = await ctx.rawRequest({
    path: "/__test/organization-hooks-configure",
    method: "POST",
    json: { mode, ...extra },
  });
  expect(response.status).toBe(200);
}

async function state(ctx: ScenarioContext, waitFor?: string) {
  const response = await ctx.rawRequest({
    path: "/__test/organization-hooks-state" + (waitFor ? `?waitFor=${waitFor}` : ""),
  });
  expect(response.status).toBe(200);
  const parsed = stateSchema.parse(response.body);
  if (isAtomic(ctx) && parsed.receipts.length) {
    for (const receipt of parsed.receipts) {
      expect(receipt.snapshot).toEqual(parsed.receipts[0]!.snapshot);
    }
  }
  return parsed;
}

async function signup(
  ctx: ScenarioContext,
  name: string,
  profile: FixtureProfile = "org-creation-hooks",
) {
  const actor = ctx.actor(name, profile);
  const email = ctx.uniqueEmail(name);
  const result = await actor.client.signUp.email({ name, email, password: "password123" });
  expect(result.error).toBeNull();

  return {
    ...actor,
    email,
    userId: z.object({ user: z.object({ id: z.string() }) }).parse(result.data).user.id,
  };
}

function create(
  ctx: ScenarioContext,
  actor: Awaited<ReturnType<typeof signup>>,
  name: string,
  extra: Record<string, unknown> = {},
) {
  return actor.client.$fetch("/organization/create", {
    method: "POST",
    body: {
      name,
      slug: ctx.uniqueToken(name),
      logo: "https://example.test/logo.png",
      metadata: { original: true },
      ...extra,
    },
  });
}

compatScenario(
  "organization creation hooks patch persisted drafts and run before selection in actual team order",
  async (ctx) => {
    const owner = await signup(ctx, "hook-owner");
    const foreign = await signup(ctx, "hook-foreign");

    await configure(ctx, "record");
    const initial = await state(ctx);

    const chosenId = ctx.uniqueToken("hook-chosen-id");
    await configure(ctx, "patch", { id: chosenId });
    const result = await create(ctx, owner, "patched", {
      userId: foreign.userId,
      mode: "reject-before-org",
      role: "admin",
    });
    expect(result.error).toBeNull();

    const org = organization.parse(result.data);
    expect(org).toMatchObject({
      id: chosenId,
      name: "Hooked Organization",
      slug: ctx.uniqueToken("patched") + "-hooked",
      logo: null,
      metadata: { guard: "hooked" },
    });
    expect(org.members[0]).toMatchObject({ userId: owner.userId, role: "member" });

    const after = await state(ctx);
    expect(after.receipts.map((r) => r.phase)).toEqual(phases);
    expect(
      after.receipts.every((r) => r.user.id === owner.userId && r.user.email === owner.email),
    ).toBe(true);
    expect(
      after.receipts.map((r) => [
        r.snapshot.organizations.length,
        r.snapshot.members.length,
        r.snapshot.teams.length,
        r.snapshot.teamMembers.length,
      ]),
    ).toEqual(
      isAtomic(ctx)
        ? phases.map(() => [0, 0, 0, 0])
        : [
            [0, 0, 0, 0],
            [1, 0, 0, 0],
            [1, 1, 0, 0],
            [1, 1, 0, 0],
            [1, 1, 1, 1],
            [1, 1, 1, 1],
          ],
    );
    expect(
      after.receipts.every(
        (r) => JSON.stringify(r.snapshot.sessions) === JSON.stringify(initial.snapshot.sessions),
      ),
    ).toBe(true);

    expect(after.snapshot.organizations[0]).toMatchObject({
      id: chosenId,
      logo: null,
      metadata: '{"guard":"hooked"}',
    });
    expect(after.snapshot.teams[0]).toMatchObject({
      organizationId: chosenId,
      name: "Hooked Organization",
    });
    expect(after.snapshot.teamMembers[0]).toMatchObject({ userId: owner.userId });
    expect(after.snapshot.sessions.find((r) => r.userId === owner.userId)).toMatchObject({
      activeOrganizationId: chosenId,
      activeTeamId: after.snapshot.teams[0]!.id,
    });
    expect(after.snapshot.sessions.find((r) => r.userId === foreign.userId)).toEqual(
      initial.snapshot.sessions.find((r) => r.userId === foreign.userId),
    );

    return { result: ctx.snapshot(result), initial, after };
  },
  ["POST /organization/create"],
  30_000,
  creationComparison,
);

compatScenario(
  "organization creation hook null empty and absent patches preserve source merge and no revalidation",
  async (ctx) => {
    const owner = await signup(ctx, "patch-owner", "org-creation-hooks-no-team");

    const observations = [];

    for (const mode of [
      "clear-metadata",
      "empty-metadata",
      "absent-metadata",
      "empty-name",
      "empty-member",
    ]) {
      await configure(ctx, mode);
      const result = await create(ctx, owner, mode);
      expect(result.error).toBeNull();

      const org = organization.parse(result.data);
      const after = await state(ctx);
      const stored = after.snapshot.organizations.find((r) => r.id === org.id)!;
      expect(after.receipts.map((r) => r.phase)).toEqual([
        "before-org",
        "before-member",
        "after-member",
        "after-org",
      ]);

      if (mode === "clear-metadata") {
        expect(result.data).not.toHaveProperty("metadata");
        expect(org.logo).toBeNull();
        expect(stored.metadata).toBeNull();
      }

      if (mode === "empty-metadata") {
        expect(org.metadata).toEqual({});
        expect(stored.metadata).toBe("{}");
      }

      if (mode === "absent-metadata") {
        expect(org.name).toBe("Patched Without Metadata");
        expect(org.metadata).toEqual({ original: true });
        expect(stored.metadata).toBe('{"original":true}');
      }

      if (mode === "empty-name") {
        expect(org.name).toBe("");
        expect(stored.name).toBe("");
      }

      if (mode === "empty-member") {
        const member = org.members[0]!;
        expect(member.role).toBe("");
        expect(member.id).not.toBe("ignored-member-id");
        expect(after.snapshot.members.find((r) => r.id === member.id)!.role).toBe("");
      }

      expect(after.snapshot.teams).toEqual([]);

      observations.push({ mode, result: ctx.snapshot(result), after });
    }

    return observations;
  },
  ["POST /organization/create"],
  30_000,
  creationComparison,
);

compatScenario(
  "organization creation rejected hooks retain exact earlier rows without selecting the current or sibling session",
  async (ctx) => {
    const owner = await signup(ctx, "reject-owner");
    await configure(ctx, "record");
    const seed = await create(ctx, owner, "prior-selection");
    expect(seed.error).toBeNull();

    const sibling = ctx.actor("reject-sibling", "org-creation-hooks");
    expect(
      (await sibling.client.signIn.email({ email: owner.email, password: "password123" })).error,
    ).toBeNull();

    const observations = [];

    for (const [phase, counts] of [
      ["before-org", [0, 0, 0, 0]],
      ["before-member", [1, 0, 0, 0]],
      ["after-member", [1, 1, 0, 0]],
      ["before-team", [1, 1, 0, 0]],
      ["after-team", [1, 1, 1, 1]],
      ["after-org", [1, 1, 1, 1]],
    ] as const) {
      await configure(ctx, `reject-${phase}`);
      const before = await state(ctx);
      const rejected = await create(ctx, owner, `failure-${phase}`);
      expect(rejected.error).toMatchObject({
        status: 400,
        code: "CREATION_HOOK_REJECTED",
        message: `Rejected ${phase}`,
      });

      const after = await state(ctx);
      expect(after.receipts.map((r) => r.phase)).toEqual(
        phases.slice(0, phases.indexOf(phase) + 1),
      );

      for (const [index, key] of (
        ["organizations", "members", "teams", "teamMembers"] as const
      ).entries()) {
        expect(after.snapshot[key].length - before.snapshot[key].length).toBe(
          isAtomic(ctx) ? 0 : counts[index]!,
        );
        for (const old of before.snapshot[key]) {
          expect(after.snapshot[key].find((r) => r.id === old.id)).toEqual(old);
        }
      }

      expect(after.snapshot.sessions).toEqual(before.snapshot.sessions);
      expect(after.snapshot.users).toEqual(before.snapshot.users);

      observations.push({ phase, before, rejected: ctx.snapshot(rejected), after });
    }

    return observations;
  },
  ["POST /organization/create"],
  30_000,
  creationComparison,
);

compatScenario(
  "organization creation policies and duplicate checks precede hooks while trusted creation has no request selection",
  async (ctx) => {
    const owner = await signup(ctx, "trusted-owner", "org-creation-hooks-denied");

    await configure(ctx, "reject-before-org");
    const before = await state(ctx);
    const denied = await create(ctx, owner, "policy-denied");
    expect(denied.error).toMatchObject({
      status: 403,
      code: "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION",
    });
    expect(await state(ctx)).toEqual(before);

    const rejected = await ctx.rawRequest({
      path: "/__test/organization-hooks-create",
      method: "POST",
      json: {
        profile: "org-creation-hooks-denied",
        userId: owner.userId,
        name: "Trusted Rejected",
        slug: ctx.uniqueToken("trusted-rejected"),
      },
    });
    expect(rejected.status).toBe(400);
    expect(rejected.body).toMatchObject({ code: "CREATION_HOOK_REJECTED" });
    expect((await state(ctx)).snapshot).toEqual(before.snapshot);

    await configure(ctx, "record");
    const trusted = await ctx.rawRequest({
      path: "/__test/organization-hooks-create",
      method: "POST",
      json: {
        profile: "org-creation-hooks-denied",
        userId: owner.userId,
        name: "Trusted",
        slug: ctx.uniqueToken("trusted"),
        metadata: { trusted: true },
      },
    });
    expect(trusted.status).toBe(200);

    const org = organization.parse(trusted.body);

    const after = await state(ctx);
    expect(after.receipts.map((r) => r.phase)).toEqual(phases);
    expect(after.snapshot.sessions).toEqual(before.snapshot.sessions);
    expect(after.snapshot.members[0]).toMatchObject({
      organizationId: org.id,
      userId: owner.userId,
    });

    const publicOwner = ctx.actor("allowed-duplicate", "org-creation-hooks");
    expect(
      (await publicOwner.client.signIn.email({ email: owner.email, password: "password123" }))
        .error,
    ).toBeNull();

    await configure(ctx, "reject-before-org");
    const duplicateBefore = await state(ctx);
    const duplicate = await publicOwner.client.$fetch("/organization/create", {
      method: "POST",
      body: { name: "Duplicate", slug: org.slug },
    });
    expect(duplicate.error).toMatchObject({
      status: 400,
      code: "ORGANIZATION_ALREADY_EXISTS",
      message: "Organization already exists",
    });
    expect(await state(ctx)).toEqual(duplicateBefore);

    return {
      denied: ctx.snapshot(denied),
      rejected,
      trusted,
      after,
      duplicate: ctx.snapshot(duplicate),
      duplicateBefore,
    };
  },
  ["POST /organization/create"],
  30_000,
  creationComparison,
);

compatScenario(
  "organization creation after hooks retain immutable member snapshots after independent database mutation",
  async (ctx) => {
    const owner = await signup(ctx, "mutation-owner");

    await configure(ctx, "stored-member");
    const result = await create(ctx, owner, "stored-member");
    expect(result.error).toBeNull();

    const org = organization.parse(result.data);
    const member = org.members[0]!;
    const after = await state(ctx);
    expect(member.role).toBe("owner");
    expect(after.receipts.find((r) => r.phase === "after-member")!.member!.role).toBe("owner");
    expect(after.receipts.find((r) => r.phase === "after-org")!.member!.role).toBe("owner");
    expect(
      after.receipts
        .find((r) => r.phase === "after-org")!
        .snapshot.members.find((r) => r.id === member.id)?.role,
    ).toBe(isAtomic(ctx) ? undefined : "admin");
    expect(after.snapshot.members.find((r) => r.id === member.id)!.role).toBe("admin");

    return { result: ctx.snapshot(result), after };
  },
  ["POST /organization/create"],
  30_000,
  creationComparison,
);

compatScenario(
  "organization creation awaits async member hooks before team writes and session selection",
  async (ctx) => {
    const owner = await signup(ctx, "await-owner");

    await configure(ctx, "pause-after-member");
    const before = await state(ctx);

    let completed = false;
    const pending = create(ctx, owner, "awaited-creation").then((result) => {
      completed = true;
      return result;
    });

    let paused: Awaited<ReturnType<typeof state>> | undefined;

    try {
      paused = await state(ctx, "after-member");
      expect(paused.receipts.some((r) => r.phase === "after-member")).toBe(true);
      expect(completed).toBe(false);
      expect(paused.receipts.map((r) => r.phase)).toEqual([
        "before-org",
        "before-member",
        "after-member",
      ]);
      expect(paused.snapshot.organizations).toHaveLength(isAtomic(ctx) ? 0 : 1);
      expect(paused.snapshot.members).toHaveLength(isAtomic(ctx) ? 0 : 1);
      expect(paused.snapshot.teams).toEqual([]);
      expect(paused.snapshot.teamMembers).toEqual([]);
      expect(paused.snapshot.sessions).toEqual(before.snapshot.sessions);
    } finally {
      const released = await ctx.rawRequest({
        path: "/__test/organization-hooks-release",
        method: "POST",
      });
      expect(released.status).toBe(200);
    }

    const result = await pending;
    expect(result.error).toBeNull();

    const after = await state(ctx);
    expect(after.receipts.map((r) => r.phase)).toEqual(phases);
    expect(after.snapshot.teams).toHaveLength(1);
    expect(after.snapshot.sessions[0]).toMatchObject({
      activeOrganizationId: organization.parse(result.data).id,
      activeTeamId: after.snapshot.teams[0]!.id,
    });

    // The private waiter observes real callback delivery; all requests remain traced.
    const abortName = "disconnected-creation";
    const marker = ctx.uniqueToken(abortName);
    await configure(ctx, "pause-after-member");
    let abortBefore!: Awaited<ReturnType<typeof state>>;
    const wire = await disconnectedRequest(
      ctx,
      "await-owner",
      "org-creation-hooks",
      owner.email,
      "/organization/create",
      {
        name: abortName,
        slug: ctx.uniqueToken(abortName),
        metadata: { disconnected: true },
      },
      marker,
      async () => {
        abortBefore = await state(ctx);
      },
    );

    let dropped: unknown;
    let abortPaused: Awaited<ReturnType<typeof state>> | undefined;

    try {
      abortPaused = await state(ctx, "after-member");
      expect(abortPaused.receipts.map((r) => r.phase)).toEqual([
        "before-org",
        "before-member",
        "after-member",
      ]);
      expect(abortPaused.snapshot.teams).toEqual(abortBefore.snapshot.teams);

      dropped = await wire.close();
    } finally {
      wire.dispose();
      const released = await ctx.rawRequest({
        path: "/__test/organization-hooks-release",
        method: "POST",
      });
      expect(released.status).toBe(200);
    }

    const completion = await ctx.rawRequest({
      path: `/__test/organization-transport-completion?marker=${encodeURIComponent(marker)}`,
    });
    expect(completion.status).toBe(200);
    expect(completion.body).toEqual({ marker, completed: true });

    const continued = await state(ctx, "after-org");
    expect(continued.receipts.map((r) => r.phase)).toEqual(phases);

    const stored = continued.snapshot.organizations.find(
      (r) => r.slug === ctx.uniqueToken(abortName),
    )!;
    expect(stored).toMatchObject({
      name: abortName,
      metadata: '{"disconnected":true}',
    });
    expect(continued.snapshot.members.find((r) => r.organizationId === stored.id)).toMatchObject({
      userId: owner.userId,
      role: "owner",
    });

    const team = continued.snapshot.teams.find((r) => r.organizationId === stored.id)!;
    expect(team).toMatchObject({ name: abortName });
    expect(continued.snapshot.teamMembers.find((r) => r.teamId === team.id)).toMatchObject({
      userId: owner.userId,
    });

    // after-org precedes selection; the genuine after-dispatch receipt precedes this single session read.
    const current = await owner.client.getSession();
    expect(current.data?.session).toMatchObject({
      userId: owner.userId,
      activeOrganizationId: stored.id,
      activeTeamId: team.id,
    });

    return {
      before,
      paused,
      result: ctx.snapshot(result),
      after,
      wire: { signin: wire.signin, request: wire.request },
      abortBefore,
      abortPaused,
      dropped,
      continued,
      completion,
      current,
    };
  },
  ["POST /organization/create"],
  30_000,
  creationComparison,
);

compatScenario(
  "organization trusted creation hook member overrides retain actor authority and original default team membership",
  async (ctx) => {
    const owner = await signup(ctx, "authority-owner");
    const foreign = await signup(ctx, "authority-foreign");

    await configure(ctx, "record");
    const prior = await create(ctx, owner, "authority-prior");
    expect(prior.error).toBeNull();

    const existing = organization.parse(prior.data);

    const before = await state(ctx);
    await configure(ctx, "member-authority", {
      organizationId: existing.id,
      userId: foreign.userId,
    });

    const result = await create(ctx, owner, "authority-new", {
      userId: foreign.userId,
      organizationId: existing.id,
    });
    expect(result.error).toBeNull();

    const org = organization.parse(result.data);

    const after = await state(ctx);
    expect(org.id).not.toBe(existing.id);
    expect(org.members[0]).toMatchObject({
      organizationId: existing.id,
      userId: foreign.userId,
      role: "member",
    });
    expect(after.receipts.every((r) => r.user.id === owner.userId)).toBe(true);
    expect(after.receipts.find((r) => r.phase === "before-member")!.member).toMatchObject({
      organizationId: org.id,
      userId: owner.userId,
      role: "owner",
    });
    expect(after.snapshot.members.filter((r) => r.organizationId === org.id)).toEqual([]);
    expect(after.snapshot.members.find((r) => r.id === org.members[0]!.id)).toMatchObject({
      organizationId: existing.id,
      userId: foreign.userId,
      role: "member",
    });

    const newTeam = after.snapshot.teams.find((r) => r.organizationId === org.id)!;
    expect(after.snapshot.teamMembers.find((r) => r.teamId === newTeam.id)).toMatchObject({
      userId: owner.userId,
    });
    expect(after.snapshot.sessions.find((r) => r.userId === owner.userId)).toMatchObject({
      activeOrganizationId: org.id,
      activeTeamId: newTeam.id,
    });
    expect(after.snapshot.sessions.find((r) => r.userId === foreign.userId)).toEqual(
      before.snapshot.sessions.find((r) => r.userId === foreign.userId),
    );

    for (const row of before.snapshot.members) {
      expect(after.snapshot.members.find((r) => r.id === row.id)).toEqual(row);
    }

    for (const row of before.snapshot.organizations) {
      expect(after.snapshot.organizations.find((r) => r.id === row.id)).toEqual(row);
    }

    return { prior: ctx.snapshot(prior), before, result: ctx.snapshot(result), after };
  },
  ["POST /organization/create"],
  30_000,
  creationComparison,
);
