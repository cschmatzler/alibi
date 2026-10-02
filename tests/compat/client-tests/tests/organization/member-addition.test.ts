import { expect } from "bun:test";
import { z } from "zod";
import type { FixtureProfile } from "../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { createTracingFetch, type TraceEntry } from "../../support/trace";

const row = z.object({ id: z.string() }).passthrough();

const snapshotSchema = z.object({
  organizations: z.array(row),
  members: z.array(row),
  users: z.array(row),
  sessions: z.array(row),
  teams: z.array(row),
  teamMembers: z.array(row),
});

const stateSchema = z.object({
  receipts: z.array(z.record(z.string(), z.unknown())),
  snapshot: snapshotSchema,
});

const root = "/__test/organization-member-addition";

async function configure(ctx: ScenarioContext, mode: string, fields: Record<string, unknown> = {}) {
  const response = await ctx.rawRequest({
    path: `${root}/configure`,
    method: "POST",
    json: { mode, ...fields },
  });
  expect(response.status).toBe(200);
}

async function state(ctx: ScenarioContext, waitFor?: string) {
  const result = await ctx.rawRequest({
    path: `${root}/state${waitFor ? `?waitFor=${waitFor}` : ""}`,
  });
  expect(result.status).toBe(200);
  return stateSchema.parse(result.body);
}

async function signup(ctx: ScenarioContext, name: string) {
  const actor = ctx.actor(name, "org-member-addition");
  const email = ctx.uniqueEmail(name);
  const result = await actor.client.signUp.email({ name, email, password: "password123" });
  expect(result.error).toBeNull();
  const user = row.parse(z.object({ user: row }).parse(ctx.snapshot(result.data)).user);
  return { ...actor, user, email };
}

type Actor = Awaited<ReturnType<typeof signup>>;

async function server(
  ctx: ScenarioContext,
  body: Record<string, unknown>,
  profile: FixtureProfile = "org-member-addition",
  actor?: Actor,
  useHeaders = false,
) {
  const input = { profile, useHeaders, body };
  if (!actor) return ctx.rawRequest({ path: `${root}/server`, method: "POST", json: input });

  const response = await actor.fetch(`${root}/server`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(input),
  });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : null };
}

async function seed(
  ctx: ScenarioContext,
  action: string,
  organizationId: string,
  userId: string,
  count?: number,
) {
  const response = await ctx.rawRequest({
    path: `${root}/seed`,
    method: "POST",
    json: { action, organizationId, userId, count },
  });
  expect(response.status).toBe(200);
}

async function setup(ctx: ScenarioContext, name: string) {
  await configure(ctx, "off");
  const owner = await signup(ctx, `${name}-owner`);
  const target = await signup(ctx, `${name}-target`);
  const foreign = await signup(ctx, `${name}-foreign`);

  async function org(actor: Actor, label: string) {
    const result = await actor.client.$fetch("/organization/create", {
      method: "POST",
      body: {
        name: label,
        slug: ctx.uniqueToken(label),
        metadata: { original: true, amount: 1e20 },
      },
    });
    expect(result.error).toBeNull();
    return row.parse(result.data);
  }

  const organization = await org(owner, `${name}-org`);
  const other = await org(foreign, `${name}-foreign-org`);
  const targetOwn = await org(target, `${name}-target-org`);

  // Second sessions for the owner and target, each with its own active organization.
  const siblingActor = ctx.actor(`${name}-owner-sibling`, "org-member-addition");
  const siblingSignIn = await siblingActor.client.signIn.email({
    email: owner.email,
    password: "password123",
  });
  expect(siblingSignIn.error).toBeNull();
  const siblingActive = await siblingActor.client.$fetch("/organization/set-active", {
    method: "POST",
    body: { organizationId: organization.id },
  });
  expect(siblingActive.error).toBeNull();

  const targetSibling = ctx.actor(`${name}-target-sibling`, "org-member-addition");
  const targetSiblingSignIn = await targetSibling.client.signIn.email({
    email: target.email,
    password: "password123",
  });
  expect(targetSiblingSignIn.error).toBeNull();
  const targetSiblingActive = await targetSibling.client.$fetch("/organization/set-active", {
    method: "POST",
    body: { organizationId: targetOwn.id },
  });
  expect(targetSiblingActive.error).toBeNull();

  async function team(actor: Actor, organizationId: string, label: string) {
    const result = await actor.client.$fetch("/organization/create-team", {
      method: "POST",
      body: { organizationId, name: label },
    });
    expect(result.error).toBeNull();
    return row.parse(result.data);
  }

  const first = await team(owner, organization.id, `${name}-first`);
  const second = await team(owner, organization.id, `${name}-second`);
  const foreignTeam = await team(foreign, other.id, `${name}-foreign-team`);
  const targetTeam = await team(target, targetOwn.id, `${name}-target-team`);

  const targetTeamMember = await target.client.$fetch("/organization/add-team-member", {
    method: "POST",
    body: { organizationId: targetOwn.id, teamId: targetTeam.id, userId: target.user.id },
  });
  expect(targetTeamMember.error).toBeNull();
  for (const actor of [target, targetSibling]) {
    const activeTeam = await actor.client.$fetch("/organization/set-active-team", {
      method: "POST",
      body: { teamId: targetTeam.id },
    });
    expect(activeTeam.error).toBeNull();
  }

  const rawOrg = await owner.client.$fetch("/organization/get-organization", {
    query: { organizationId: organization.id },
  });
  expect(rawOrg.error).toBeNull();

  const users = async () => ({
    owner: await ctx.readUserState({ userId: owner.user.id }),
    target: await ctx.readUserState({ userId: target.user.id }),
    foreign: await ctx.readUserState({ userId: foreign.user.id }),
  });

  await configure(ctx, "record");

  return {
    owner,
    target,
    foreign,
    organization,
    other,
    targetOwn,
    first,
    second,
    foreignTeam,
    rawOrg: ctx.snapshot(rawOrg.data),
    users,
    targetSibling,
    siblingActor,
  };
}

function checkNotes(
  after: Awaited<ReturnType<typeof state>>,
  target: Actor,
  rawOrg: unknown,
  draft: Record<string, unknown>,
  created: unknown,
) {
  expect(after.receipts.map((value) => value.phase)).toEqual(["before-add", "after-add"]);
  expect(after.receipts[0]!.member).toEqual(draft);
  expect(after.receipts[0]!.member).not.toHaveProperty("createdAt");

  for (const receipt of after.receipts) {
    expect(receipt.user).toEqual(target.user);
    expect(receipt.organization).toEqual(rawOrg);
  }

  expect(after.receipts[1]!.member).toEqual(created);
}

function withoutMembers(snapshot: Awaited<ReturnType<typeof state>>["snapshot"]) {
  return { ...snapshot, members: [] };
}

compatScenario(
  "organization trusted addition preserves raw role arrays and original target snapshots without selecting sessions",
  async (ctx) => {
    const s = await setup(ctx, "add-default");
    const before = await state(ctx);
    const usersBefore = await s.users();

    const role = [" member ", "member", "admin"];
    const result = await server(ctx, {
      organizationId: s.organization.id,
      userId: s.target.user.id,
      role,
    });
    expect(result.status).toBe(200);
    const created = row.parse(result.body);
    expect(created).toMatchObject({
      organizationId: s.organization.id,
      userId: s.target.user.id,
      role: " member ,member,admin",
    });

    const after = await state(ctx);
    checkNotes(
      after,
      s.target,
      s.rawOrg,
      {
        organizationId: s.organization.id,
        userId: s.target.user.id,
        role: " member ,member,admin",
      },
      created,
    );
    expect(after.snapshot.members).toHaveLength(before.snapshot.members.length + 1);
    expect(after.snapshot.members.find((value) => value.id === created.id)).toEqual({
      id: created.id,
      organizationId: s.organization.id,
      userId: s.target.user.id,
      role: " member ,member,admin",
    });
    expect(withoutMembers(after.snapshot)).toEqual(withoutMembers(before.snapshot));
    expect(await s.users()).toEqual(usersBefore);

    return { before, usersBefore, result, after, usersAfter: await s.users() };
  },
  ["POST /organization/create"],
);

compatScenario(
  "organization server addition rejects actual duplicate wrong-target and foreign-team guards before hooks then admits legitimate retry",
  async (ctx) => {
    const s = await setup(ctx, "add-guards");
    const before = await state(ctx);
    const usersBefore = await s.users();
    const failures = [];

    for (const [body, code] of [
      [
        { organizationId: s.organization.id, userId: "actual-missing-user", role: "member" },
        "USER_NOT_FOUND",
      ],
      [
        { organizationId: "actual-missing-org", userId: s.target.user.id, role: "member" },
        "ORGANIZATION_NOT_FOUND",
      ],
      [
        {
          organizationId: s.organization.id,
          userId: s.target.user.id,
          role: "member",
          teamId: s.foreignTeam.id,
        },
        "TEAM_NOT_FOUND",
      ],
      [
        { organizationId: s.organization.id, userId: s.owner.user.id, role: "member" },
        "USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION",
      ],
    ] as const) {
      const result = await server(ctx, body);
      expect(result.status).toBe(400);
      expect(result.body).toHaveProperty("code", code);
      expect(await state(ctx)).toEqual(before);
      expect(await s.users()).toEqual(usersBefore);
      failures.push(result);
    }

    const disabled = await server(
      ctx,
      {
        organizationId: s.organization.id,
        userId: "actual-missing-user",
        role: "member",
        teamId: s.first.id,
      },
      "org-member-addition-no-team",
    );
    expect(disabled.status).toBe(400);
    expect(disabled.body).toEqual({ message: "Teams are not enabled" });
    expect(await state(ctx)).toEqual(before);
    failures.push(disabled);

    // add-member is server-only: a public caller cannot reach it.
    const attempt = await s.owner.fetch(
      "/__test/profiles/org-member-addition/api/auth/organization/add-member",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          organizationId: s.organization.id,
          userId: s.target.user.id,
          role: "owner",
        }),
      },
    );
    expect(attempt.status).toBe(404);
    const publicBody = await attempt.text();
    expect(await state(ctx)).toEqual(before);

    const result = await server(ctx, {
      organizationId: s.organization.id,
      userId: s.target.user.id,
      role: "unregistered-role",
    });
    expect(result.status).toBe(200);
    expect(result.body).toHaveProperty("role", "unregistered-role");

    const after = await state(ctx);
    checkNotes(
      after,
      s.target,
      s.rawOrg,
      { organizationId: s.organization.id, userId: s.target.user.id, role: "unregistered-role" },
      result.body,
    );

    return {
      before,
      usersBefore,
      failures,
      publicAttempt: { status: attempt.status, body: publicBody },
      result,
      after,
      usersAfter: await s.users(),
    };
  },
  ["POST /organization/create"],
);

compatScenario(
  "organization server addition uses only real optional signed headers for active fallback and never grants a public caller override",
  async (ctx) => {
    const s = await setup(ctx, "add-headers");
    const before = await state(ctx);
    const usersBefore = await s.users();
    const failures = [];

    for (const actor of [undefined, s.target]) {
      const result = await server(
        ctx,
        { userId: s.target.user.id, role: "member" },
        "org-member-addition",
        actor,
        true,
      );
      expect(result.status).toBe(400);
      expect(result.body).toHaveProperty(
        "code",
        actor ? "USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION" : "NO_ACTIVE_ORGANIZATION",
      );
      expect(await state(ctx)).toEqual(before);
      failures.push(result);
    }

    const invalid = await ctx.rawRequest({
      path: `${root}/server`,
      method: "POST",
      headers: { cookie: "better-auth.session_token=invalid-signature" },
      json: { useHeaders: true, body: { userId: s.target.user.id, role: "member" } },
    });
    expect(invalid.status).toBe(400);
    expect(invalid.body).toHaveProperty("code", "NO_ACTIVE_ORGANIZATION");
    expect(await state(ctx)).toEqual(before);

    const result = await server(
      ctx,
      { organizationId: "", userId: s.target.user.id, role: "member" },
      "org-member-addition",
      s.owner,
      true,
    );
    expect(result.status).toBe(200);
    expect(result.body).toMatchObject({
      organizationId: s.organization.id,
      userId: s.target.user.id,
    });
    expect(await s.users()).toEqual(usersBefore);

    const after = await state(ctx);
    return { before, usersBefore, failures, invalid, result, after, usersAfter: await s.users() };
  },
  ["POST /organization/create"],
);

compatScenario(
  "organization server addition enforces all-row default and integer limits with zero and None falling back to100",
  async (ctx) => {
    const s = await setup(ctx, "add-cap");
    const extra = await signup(ctx, "add-cap-extra");

    await configure(ctx, "off");
    await seed(ctx, "padding", s.organization.id, s.owner.user.id, 98);
    await configure(ctx, "record");
    const before = await state(ctx);
    const usersBefore = await s.users();

    const one = await server(
      ctx,
      { organizationId: s.organization.id, userId: s.target.user.id, role: "member" },
      "org-member-addition-limit-one",
    );
    expect(one.status).toBe(403);
    expect(one.body).toHaveProperty("code", "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED");
    expect(await state(ctx)).toEqual(before);

    const admitted = await server(
      ctx,
      { organizationId: s.organization.id, userId: s.target.user.id, role: [] },
      "org-member-addition-zero",
    );
    expect(admitted.status).toBe(200);
    expect(admitted.body).toHaveProperty("role", "");

    await configure(ctx, "record");
    const full = await state(ctx);
    const failures = [];
    expect(
      full.snapshot.members.filter((value) => value.organizationId === s.organization.id),
    ).toHaveLength(100);

    for (const profile of [
      "org-member-addition",
      "org-member-addition-zero",
      "org-member-addition-none",
      "org-member-addition-team-page-one",
    ] as const) {
      const result = await server(
        ctx,
        { organizationId: s.organization.id, userId: extra.user.id, role: "member" },
        profile,
      );
      expect(result.status).toBe(403);
      expect(result.body).toHaveProperty("code", "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED");
      expect(await state(ctx)).toEqual(full);
      failures.push({ profile, result });
    }
    expect(await s.users()).toEqual(usersBefore);

    return {
      before,
      usersBefore,
      one,
      admitted,
      full,
      failures,
      after: await state(ctx),
      usersAfter: await s.users(),
    };
  },
  ["POST /organization/create"],
);

compatScenario(
  "organization addition awaits before hooks and preserves original user snapshots across independent mutation",
  async (ctx) => {
    const s = await setup(ctx, "add-await");

    await configure(ctx, "pause-before");
    const before = await state(ctx);

    let finished = false;
    const pending = server(ctx, {
      organizationId: s.organization.id,
      userId: s.target.user.id,
      role: "member",
    }).then((result) => {
      finished = true;
      return result;
    });

    const traces: TraceEntry[] = [];
    let during: Awaited<ReturnType<typeof state>> | undefined;
    try {
      during = await state(ctx, "before-add");
      expect(during.receipts.map((value) => value.phase)).toEqual(["before-add"]);
      expect(finished).toBe(false);
      expect(during.snapshot).toEqual(before.snapshot);
    } finally {
      const release = await createTracingFetch(
        ctx.baseURL,
        "addition-release",
        traces,
      )(`${root}/release`, { method: "POST" });
      expect(release.status).toBe(200);
      expect(await release.json()).toEqual({ released: true });
    }

    const result = await pending;
    ctx.recordTransport(traces);
    expect(result.status).toBe(200);

    const after = await state(ctx);
    checkNotes(
      after,
      s.target,
      s.rawOrg,
      { organizationId: s.organization.id, userId: s.target.user.id, role: "member" },
      result.body,
    );

    const second = await signup(ctx, "add-await-second");
    await configure(ctx, "mutate-target");
    const mutation = await server(ctx, {
      organizationId: s.organization.id,
      userId: second.user.id,
      role: "member",
    });
    expect(mutation.status).toBe(200);

    const mutated = await state(ctx);
    checkNotes(
      mutated,
      second,
      s.rawOrg,
      { organizationId: s.organization.id, userId: second.user.id, role: "member" },
      mutation.body,
    );
    expect(mutated.snapshot.users.find((value) => value.id === second.user.id)).toHaveProperty(
      "name",
      "Stored Addition Target",
    );

    return { before, during, result, after, mutation, mutated };
  },
  ["POST /organization/create"],
);

compatScenario(
  "organization addition trusted role patches are unvalidated and before versus after errors retain exact writes",
  async (ctx) => {
    const observations = [];

    for (const mode of [
      "reject-before-add",
      "reject-after-add",
      "public500-before-add",
      "public500-after-add",
      "patch-role",
      "patch-empty",
    ]) {
      const s = await setup(ctx, `add-${mode}`);

      await configure(ctx, mode);
      const before = await state(ctx);
      const usersBefore = await s.users();
      const withTeam = mode.endsWith("after-add");

      const result = await server(ctx, {
        organizationId: s.organization.id,
        userId: s.target.user.id,
        role: "member",
        ...(withTeam ? { teamId: s.first.id } : {}),
      });
      const after = await state(ctx);

      if (mode.startsWith("reject-") || mode.startsWith("public500-")) {
        expect(result.status).toBe(mode.startsWith("public500") ? 500 : 400);
        expect(result.body).toHaveProperty(
          "code",
          mode.startsWith("public500") ? "PUBLIC_ADDITION_500" : "ADDITION_HOOK_REJECTED",
        );
        const beforeOnly = mode.endsWith("before-add");
        expect(after.receipts.map((value) => value.phase)).toEqual(
          beforeOnly ? ["before-add"] : ["before-add", "after-add"],
        );
        expect(after.snapshot.members.length - before.snapshot.members.length).toBe(
          beforeOnly ? 0 : 1,
        );
        if (beforeOnly) expect(after.snapshot).toEqual(before.snapshot);
      } else {
        expect(result.status).toBe(200);
        expect(result.body).toHaveProperty(
          "role",
          mode === "patch-empty" ? "" : "hook-unregistered-role",
        );
        checkNotes(
          after,
          s.target,
          s.rawOrg,
          { organizationId: s.organization.id, userId: s.target.user.id, role: "member" },
          result.body,
        );
      }

      if (withTeam) {
        expect(after.snapshot.teamMembers).toHaveLength(before.snapshot.teamMembers.length + 1);
        expect(
          after.snapshot.teamMembers.find(
            (value) => value.teamId === s.first.id && value.userId === s.target.user.id,
          ),
        ).toBeDefined();
        expect(after.snapshot.teams).toEqual(
          before.snapshot.teams.map((value) =>
            value.id === s.first.id ? { ...value, memberCount: 1 } : value,
          ),
        );
        expect(after.snapshot.sessions).toEqual(before.snapshot.sessions);
        expect(after.snapshot.users).toEqual(before.snapshot.users);
        expect(after.snapshot.organizations).toEqual(before.snapshot.organizations);
      } else {
        expect(withoutMembers(after.snapshot)).toEqual(withoutMembers(before.snapshot));
      }
      expect(await s.users()).toEqual(usersBefore);

      observations.push({ mode, before, usersBefore, result, after, usersAfter: await s.users() });
    }

    return observations;
  },
  ["POST /organization/create"],
  15000,
);

compatScenario(
  "organization addition genuine SQL failures retain source before member team and after phases with successful retries",
  async (ctx) => {
    const observations = [];

    for (const mode of [
      "sql-before-error",
      "sql-member-abort",
      "sql-team-abort",
      "sql-after-error",
    ]) {
      const s = await setup(ctx, `add-${mode}`);

      await configure(ctx, mode, {
        organizationId: s.organization.id,
        userId: s.target.user.id,
        teamId: s.first.id,
      });
      const before = await state(ctx);
      const usersBefore = await s.users();
      const body = {
        organizationId: s.organization.id,
        userId: s.target.user.id,
        role: "member",
        ...(["sql-team-abort", "sql-after-error"].includes(mode) ? { teamId: s.first.id } : {}),
      };

      const result = await server(ctx, body);
      const after = await state(ctx);
      expect(result.status).toBe(500);
      expect(result.body).toBeNull();
      expect(after.receipts.map((value) => value.phase)).toEqual(
        mode === "sql-after-error" ? ["before-add", "after-add"] : ["before-add"],
      );
      expect(after.snapshot.members.length - before.snapshot.members.length).toBe(
        mode === "sql-after-error" ? 1 : 0,
      );

      if (mode === "sql-after-error") {
        expect(after.snapshot.teamMembers).toHaveLength(before.snapshot.teamMembers.length + 1);
        expect(
          after.snapshot.teamMembers.find(
            (value) => value.teamId === s.first.id && value.userId === s.target.user.id,
          ),
        ).toBeDefined();
        expect(after.snapshot.teams).toEqual(
          before.snapshot.teams.map((value) =>
            value.id === s.first.id ? { ...value, memberCount: 1 } : value,
          ),
        );
        expect(after.snapshot.sessions).toEqual(before.snapshot.sessions);
        expect(after.snapshot.users).toEqual(before.snapshot.users);
        expect(after.snapshot.organizations).toEqual(before.snapshot.organizations);
      } else {
        expect(withoutMembers(after.snapshot)).toEqual(withoutMembers(before.snapshot));
      }
      expect(await s.users()).toEqual(usersBefore);

      await configure(ctx, "record");
      if (mode === "sql-after-error") {
        await seed(ctx, "detach", s.organization.id, s.target.user.id);
      }
      const retry = await server(ctx, body);
      expect(retry.status).toBe(200);
      const repaired = await state(ctx);
      checkNotes(
        repaired,
        s.target,
        s.rawOrg,
        {
          organizationId: s.organization.id,
          userId: s.target.user.id,
          role: "member",
          ...(["sql-team-abort", "sql-after-error"].includes(mode) ? { teamId: s.first.id } : {}),
        },
        retry.body,
      );

      observations.push({
        mode,
        before,
        usersBefore,
        result,
        after,
        retry,
        repaired,
        usersAfter: await s.users(),
      });
    }

    return observations;
  },
  ["POST /organization/create"],
);

compatScenario(
  "organization addition team limits require actual headers and clean the original target page while preserving foreign sessions",
  async (ctx) => {
    const observations = [];

    for (const profile of [
      "org-member-addition-team-callback",
      "org-member-addition-team-page-one",
      "org-member-addition-team-page-zero",
    ] as const) {
      const s = await setup(ctx, `add-${profile}`);

      // Give the target memberships in both teams, then detach the org membership only.
      await configure(ctx, "off");
      for (const teamId of [s.first.id, s.second.id]) {
        const added = await server(ctx, {
          organizationId: s.organization.id,
          userId: s.target.user.id,
          role: "member",
          teamId,
        });
        expect(added.status).toBe(200);
        await seed(ctx, "detach", s.organization.id, s.target.user.id);
      }

      await configure(ctx, "record");
      const before = await state(ctx);
      const usersBefore = await s.users();

      const result = await server(
        ctx,
        {
          organizationId: s.organization.id,
          userId: s.target.user.id,
          role: "member",
          teamId: s.first.id,
        },
        profile,
      );
      expect(result.status).toBe(401);
      expect(result.body).toBeNull();

      const after = await state(ctx);
      expect(after.receipts.map((value) => value.phase)).toEqual(["before-add"]);
      expect(after.snapshot.members).toEqual(before.snapshot.members);
      const removedIds = profile.endsWith("zero")
        ? []
        : profile.endsWith("one")
          ? [s.first.id]
          : [s.first.id, s.second.id];
      expect(after.snapshot.teamMembers).toEqual(
        before.snapshot.teamMembers.filter(
          (value) =>
            !removedIds.includes(String(value.teamId)) || value.userId !== s.target.user.id,
        ),
      );
      expect(after.snapshot.teams).toEqual(
        before.snapshot.teams.map((value) =>
          removedIds.includes(value.id) ? { ...value, memberCount: 0 } : value,
        ),
      );
      expect(after.snapshot.sessions).toEqual(before.snapshot.sessions);
      expect(after.snapshot.users).toEqual(before.snapshot.users);
      expect(after.snapshot.organizations).toEqual(before.snapshot.organizations);
      expect(await s.users()).toEqual(usersBefore);

      await configure(ctx, "record");
      const retry = await server(
        ctx,
        {
          organizationId: s.organization.id,
          userId: s.target.user.id,
          role: "member",
          teamId: s.first.id,
        },
        profile,
        s.foreign,
        true,
      );
      expect(retry.status).toBe(200);

      const repaired = await state(ctx);
      expect(repaired.receipts.map((value) => value.phase)).toEqual([
        "before-add",
        "team-limit",
        "after-add",
      ]);
      expect(repaired.receipts[1]!.context).toMatchObject({
        organizationId: s.organization.id,
        teamId: s.first.id,
        session: {
          user: { id: s.foreign.user.id },
          session: { userId: s.foreign.user.id, activeOrganizationId: s.other.id },
        },
      });
      expect(await s.users()).toEqual(usersBefore);

      observations.push({
        profile,
        before,
        usersBefore,
        result,
        after,
        retry,
        repaired,
        usersAfter: await s.users(),
      });
    }

    return observations;
  },
  ["POST /organization/create"],
);

compatScenario(
  "organization addition retargeted trusted patches still roll back with captured original scope and cleanup SQL errors retain the new member",
  async (ctx) => {
    const s = await setup(ctx, "add-retarget");
    const patched = await signup(ctx, "add-retarget-patched");
    const targetOriginal = await server(ctx, {
      organizationId: s.organization.id,
      userId: s.target.user.id,
      role: "member",
      teamId: s.first.id,
    });
    expect(targetOriginal.status).toBe(200);
    await seed(ctx, "detach", s.organization.id, s.target.user.id);

    await configure(ctx, "patch-target-reject-team-limit", {
      organizationId: s.other.id,
      patchUserId: patched.user.id,
    });
    const before = await state(ctx);
    const usersBefore = await s.users();

    const result = await server(
      ctx,
      {
        organizationId: s.organization.id,
        userId: s.target.user.id,
        role: "member",
        teamId: s.second.id,
      },
      "org-member-addition-team-callback",
      s.owner,
      true,
    );
    expect(result.status).toBe(403);
    expect(result.body).toHaveProperty("code", "TEAM_LIMIT_POLICY_REJECTED");

    const after = await state(ctx);
    expect(after.receipts.map((value) => value.phase)).toEqual(["before-add", "team-limit"]);

    // The team-limit callback observed the patched member staged under the other organization.
    const staged = snapshotSchema.parse(after.receipts[1]!.snapshot);
    expect(staged.members).toHaveLength(before.snapshot.members.length + 1);
    expect(
      staged.members.find(
        (value) => value.organizationId === s.other.id && value.userId === patched.user.id,
      ),
    ).toMatchObject({ organizationId: s.other.id, userId: patched.user.id, role: "member" });

    expect(after.receipts[1]!.context).toMatchObject({
      organizationId: s.organization.id,
      teamId: s.second.id,
      session: { user: { id: s.owner.user.id }, session: { userId: s.owner.user.id } },
    });
    expect(after.receipts[0]!.organization).toEqual(s.rawOrg);
    expect(after.receipts[0]!.user).toEqual(s.target.user);
    expect(after.snapshot.members).toEqual(before.snapshot.members);
    expect(after.snapshot.teamMembers).toEqual(
      before.snapshot.teamMembers.filter(
        (value) => value.teamId !== s.first.id || value.userId !== s.target.user.id,
      ),
    );
    expect(after.snapshot.sessions).toEqual(before.snapshot.sessions);
    expect(await s.users()).toEqual(usersBefore);

    await configure(ctx, "sql-cleanup-abort", {
      organizationId: s.organization.id,
      userId: s.target.user.id,
    });
    const vetoBefore = await state(ctx);
    const veto = await server(
      ctx,
      {
        organizationId: s.organization.id,
        userId: s.target.user.id,
        role: "member",
        teamId: s.second.id,
      },
      "org-member-addition-team-limit",
    );
    expect(veto.status).toBe(500);
    expect(veto.body).toBeNull();

    const vetoAfter = await state(ctx);
    expect(vetoAfter.receipts.map((value) => value.phase)).toEqual(["before-add"]);
    expect(vetoAfter.snapshot.members.length).toBe(vetoBefore.snapshot.members.length + 1);
    expect(withoutMembers(vetoAfter.snapshot)).toEqual(withoutMembers(vetoBefore.snapshot));
    expect(await s.users()).toEqual(usersBefore);

    await configure(ctx, "record");
    const duplicate = await server(ctx, {
      organizationId: s.organization.id,
      userId: s.target.user.id,
      role: "member",
    });
    expect(duplicate.status).toBe(400);
    expect(duplicate.body).toHaveProperty("code", "USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION");
    expect((await state(ctx)).receipts).toEqual([]);

    return {
      targetOriginal,
      before,
      usersBefore,
      result,
      after,
      staged,
      vetoBefore,
      veto,
      vetoAfter,
      duplicate,
      final: await state(ctx),
      usersAfter: await s.users(),
    };
  },
  ["POST /organization/create"],
);
