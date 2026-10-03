import { expect } from "bun:test";

import type { FixtureProfile } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import { data, serverOperation, signUp, state } from "./helpers";

const modes = ["zero", "fraction", "negative", "nan", "infinity", "negative-infinity"] as const;
for (const kind of ["fixed", "async"] as const) {
  for (const mode of kind === "fixed" ? ([...modes, "unset"] as const) : modes) {
    compatScenario(
      `organization raw limits ${kind} ${mode} preserve quotas and durable seats`,
      async (ctx) => {
        const profile: FixtureProfile =
          mode === "unset" ? "org-numeric-fixed-unset" : `org-numeric-${kind}-${mode}`;
        const owner = await signUp(ctx, "owner", profile);
        const created = await owner.client.organization.create({
          name: "Numeric budget",
          slug: ctx.uniqueToken("numeric"),
        });
        const org = data(created);
        const foreign = data(
          await owner.client.organization.create({
            name: "Foreign budget",
            slug: ctx.uniqueToken("foreign"),
          }),
        );
        const foreignBefore = await state(ctx, foreign.id, profile);
        const teams = [];
        const roles = [];
        const teamBudget =
          mode === "negative" || mode === "negative-infinity" ? 0 : mode === "fraction" ? 2 : 3;
        const roleBudget =
          mode === "zero" || mode === "negative" || mode === "negative-infinity"
            ? 0
            : mode === "fraction"
              ? 2
              : 3;
        for (let i = 0; i < 3; i++) {
          const team = await owner.client.organization.createTeam(
            { organizationId: org.id, name: `Team ${i}` },
            { headers: { "x-numeric-policy": "observed" } },
          );
          const role = await owner.client.organization.createRole({
            organizationId: org.id,
            role: `numeric${i}`,
            permission: { team: ["create"] },
          });
          if (i < teamBudget) data(team);
          else {
            expect(team.error).toMatchObject({
              status: 400,
              code: "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS",
            });
          }
          if (i < roleBudget) data(role);
          else expect(role.error).toMatchObject({ status: 400, code: "TOO_MANY_ROLES" });
          teams.push(team);
          roles.push(role);
        }
        const roomResult = await serverOperation(ctx, {
          operation: "create-team",
          organizationId: org.id,
          name: "Seat room",
        });
        expect(roomResult.status).toBe(200);
        const room = (roomResult.body as { id: string }).id;
        const targets = [];
        for (let i = 0; i < 3; i++) {
          const seeded = await serverOperation(
            ctx,
            {
              operation: "seed-member",
              organizationId: org.id,
              id: ctx.uniqueToken(`seat-${i}`),
              email: ctx.uniqueEmail(`seat-${i}`),
              name: `Seat ${i}`,
            },
            profile,
          );
          expect(seeded.status).toBe(200);
          targets.push((seeded.body as { userId: string }).userId);
        }
        const outsider = await signUp(ctx, "outsider", profile);
        const eventsBeforeWrong = await serverOperation(
          ctx,
          { operation: "numeric-events", organizationId: org.id },
          profile,
        );
        const wrongOwnerTeam = await outsider.client.organization.createTeam({
          organizationId: org.id,
          name: "Denied owner",
        });
        expect(wrongOwnerTeam.error).toMatchObject({
          status: 403,
          code: "YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION",
        });
        const wrongOwnerRole = await outsider.client.organization.createRole({
          organizationId: org.id,
          role: "denied",
          permission: { team: ["create"] },
        });
        expect(wrongOwnerRole.error).toMatchObject({
          status: 403,
          code: "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
        });
        const wrongTeam = await owner.client.organization.addTeamMember({
          organizationId: foreign.id,
          teamId: room,
          userId: owner.user.id,
        });
        expect(wrongTeam.error).toMatchObject({ status: 400, code: "TEAM_NOT_FOUND" });
        const eventsAfterWrong = await serverOperation(
          ctx,
          { operation: "numeric-events", organizationId: org.id },
          profile,
        );
        expect(eventsAfterWrong.body).toEqual(eventsBeforeWrong.body);
        const memberBudget =
          mode === "fraction" ? 2 : mode === "infinity" || mode === "unset" ? 3 : 0;
        const admissions = [];
        for (let i = 0; i < 3; i++) {
          const response = await owner.client.organization.addTeamMember({
            organizationId: org.id,
            teamId: room,
            userId: targets[i]!,
          });
          if (i < memberBudget) data(response);
          else {
            expect(response.error).toMatchObject({
              status: 403,
              code: "TEAM_MEMBER_LIMIT_REACHED",
            });
          }
          admissions.push(response);
        }
        const retry = await owner.client.organization.addTeamMember({
          organizationId: org.id,
          teamId: room,
          userId: targets[0]!,
        });
        if (memberBudget) expect(data(retry).id).toBe(data(admissions[0]!).id);
        else expect(retry.error).toMatchObject({ status: 403, code: "TEAM_MEMBER_LIMIT_REACHED" });
        const events = await serverOperation(
          ctx,
          { operation: "numeric-events", organizationId: org.id },
          profile,
        );
        const observations = events.body as Record<string, unknown>[];
        if (kind === "async") {
          expect(observations.filter((e) => e.event === "maximumTeams")).toEqual(
            Array.from({ length: 3 }, () => ({
              event: "maximumTeams",
              organizationId: org.id,
              userId: owner.user.id,
              session: { userId: owner.user.id },
              activeOrganizationId: foreign.id,
              organizationName: "Numeric budget",
              header: "observed",
              requestMethod: "POST",
            })),
          );
          expect(observations.filter((e) => e.event === "maximumRolesPerOrganization")).toEqual(
            Array.from({ length: 3 }, () => ({
              event: "maximumRolesPerOrganization",
              organizationId: org.id,
              organizationName: "Numeric budget",
            })),
          );
          expect(observations.filter((e) => e.event === "maximumMembersPerTeam")).toEqual(
            Array.from({ length: 4 }, () => ({
              event: "maximumMembersPerTeam",
              organizationId: org.id,
              teamId: room,
              userId: owner.user.id,
              session: { userId: owner.user.id },
              activeOrganizationId: foreign.id,
            })),
          );
        }
        const ordered: string[] = [];
        for (let i = 0; i < 3; i++) {
          if (kind === "async") ordered.push("maximumTeams");
          if (i < teamBudget) ordered.push("beforeCreateTeam");
          if (kind === "async") ordered.push("maximumRolesPerOrganization");
        }
        for (let i = 0; i < 4; i++) {
          ordered.push("beforeAddTeamMember");
          if (kind === "async") ordered.push("maximumMembersPerTeam");
          if (i < memberBudget || (i === 3 && memberBudget > 0)) ordered.push("afterAddTeamMember");
        }
        expect(observations.map((e) => e.event)).toEqual(ordered);
        const after = await state(ctx, org.id, profile);
        expect(after.parsed.teams).toHaveLength(teamBudget + 1);
        expect(after.parsed.roles).toHaveLength(roleBudget);
        expect(after.parsed.teamMembers).toHaveLength(memberBudget);
        expect(after.parsed.members).toHaveLength(4);
        const foreignAfter = await state(ctx, foreign.id, profile);
        expect(foreignAfter.raw).toEqual(foreignBefore.raw);
        return {
          created,
          foreign,
          foreignBefore: foreignBefore.raw,
          teams,
          roles,
          roomResult,
          admissions,
          retry,
          wrongOwnerTeam,
          wrongOwnerRole,
          wrongTeam,
          eventsBeforeWrong,
          eventsAfterWrong,
          events,
          after: after.raw,
          foreignAfter: foreignAfter.raw,
        };
      },
      [
        "POST /organization/create-team",
        "POST /organization/add-team-member",
        "POST /organization/create-role",
      ],
    );
  }
}

compatScenario(
  "organization fractional seats survive concurrent retries and release",
  async (ctx) => {
    const profile: FixtureProfile = "org-numeric-fixed-fraction";
    const owner = await signUp(ctx, "owner", profile);
    const org = data(
      await owner.client.organization.create({
        name: "Concurrent seats",
        slug: ctx.uniqueToken("seats"),
      }),
    );
    const foreign = data(
      await owner.client.organization.create({
        name: "Untouched seats",
        slug: ctx.uniqueToken("foreign-seats"),
      }),
    );
    const foreignBefore = await state(ctx, foreign.id, profile);
    const room = data(
      await owner.client.organization.createTeam({
        organizationId: org.id,
        name: "Concurrent room",
      }),
    );
    const seeded = [];
    for (let i = 0; i < 3; i++) {
      const row = await serverOperation(
        ctx,
        {
          operation: "seed-member",
          organizationId: org.id,
          id: ctx.uniqueToken(`concurrent-${i}`),
          email: ctx.uniqueEmail(`concurrent-${i}`),
          name: `Concurrent ${i}`,
        },
        profile,
      );
      expect(row.status).toBe(200);
      seeded.push(row);
    }
    const targets = seeded.map((row) => (row.body as { userId: string }).userId);
    const add = (i: number) =>
      owner.client.organization.addTeamMember({
        organizationId: org.id,
        teamId: room.id,
        userId: targets[i]!,
      });
    const first = await Promise.all([add(0), add(0)]);
    expect(data(first[0]!).id).toBe(data(first[1]!).id);
    const second = await Promise.all([add(1), add(1)]);
    expect(data(second[0]!).id).toBe(data(second[1]!).id);
    const full = await state(ctx, org.id, profile);
    expect(full.parsed.teamMembers).toHaveLength(2);
    const denied = await add(2);
    expect(denied.error).toMatchObject({ status: 403, code: "TEAM_MEMBER_LIMIT_REACHED" });
    const removed = await owner.client.organization.removeTeamMember({
      organizationId: org.id,
      teamId: room.id,
      userId: targets[0]!,
    });
    data(removed);
    const replacement = await Promise.all([add(2), add(2)]);
    expect(data(replacement[0]!).id).toBe(data(replacement[1]!).id);
    const after = await state(ctx, org.id, profile);
    expect(after.parsed.teamMembers.map((row) => row.userId).sort()).toEqual(
      [targets[1]!, targets[2]!].sort(),
    );
    expect(after.parsed.teams[0]!.memberCount).toBe(2);
    const foreignAfter = await state(ctx, foreign.id, profile);
    expect(foreignAfter.raw).toEqual(foreignBefore.raw);
    return {
      org,
      foreign,
      foreignBefore: foreignBefore.raw,
      room,
      seeded,
      first,
      second,
      full: full.raw,
      denied,
      removed,
      replacement,
      after: after.raw,
      foreignAfter: foreignAfter.raw,
    };
  },
  ["POST /organization/add-team-member", "POST /organization/remove-team-member"],
);

compatScenario(
  "organization async quota callbacks use team snapshots before and role counts after policy writes",
  async (ctx) => {
    const profile: FixtureProfile = "org-numeric-async-fraction";
    const owner = await signUp(ctx, "owner", profile);
    const org = data(
      await owner.client.organization.create({
        name: "Callback writes roles",
        slug: ctx.uniqueToken("policy-writes"),
      }),
    );
    const before = await state(ctx, org.id, profile);
    expect(before.parsed.teams).toEqual([]);
    expect(before.parsed.roles).toEqual([]);
    const created = await owner.client.organization.createTeam(
      { organizationId: org.id, name: "Endpoint team" },
      { headers: { "x-numeric-policy": "insert" } },
    );
    data(created);
    const denied = await owner.client.organization.createRole({
      organizationId: org.id,
      role: "endpointrole",
      permission: { team: ["create"] },
    });
    expect(denied.error).toMatchObject({ status: 400, code: "TOO_MANY_ROLES" });
    const after = await state(ctx, org.id, profile);
    expect(after.parsed.teams.map((team) => team.name)).toEqual([
      "Callback team 0",
      "Callback team 1",
      "Endpoint team",
    ]);
    expect(after.parsed.roles.map((role) => role.role)).toEqual(["callback0", "callback1"]);
    expect(after.parsed.teamMembers).toEqual([]);
    const events = await serverOperation(
      ctx,
      { operation: "numeric-events", organizationId: org.id },
      profile,
    );
    expect((events.body as { event: string }[]).map((row) => row.event)).toEqual([
      "maximumTeams",
      "beforeCreateTeam",
      "maximumRolesPerOrganization",
    ]);
    const serverOrg = data(
      await owner.client.organization.create({
        name: "Server budget",
        slug: ctx.uniqueToken("server-policy"),
      }),
    );
    const serverCreated = await serverOperation(
      ctx,
      { operation: "create-team", organizationId: serverOrg.id, name: "Server team" },
      profile,
    );
    expect(serverCreated.status).toBe(200);
    const serverEvents = await serverOperation(
      ctx,
      { operation: "numeric-events", organizationId: serverOrg.id },
      profile,
    );
    expect(serverEvents.body).toEqual([
      {
        organizationId: serverOrg.id,
        event: "maximumTeams",
        userId: null,
        session: { userId: null },
        activeOrganizationId: null,
        organizationName: "Server budget",
        header: null,
        requestMethod: null,
      },
      { organizationId: serverOrg.id, event: "beforeCreateTeam" },
    ]);
    const session = await ctx.readUserState({ userId: owner.user.id });
    return {
      org,
      before: before.raw,
      created,
      denied,
      after: after.raw,
      events,
      serverOrg,
      serverCreated,
      serverEvents,
      session,
    };
  },
  ["POST /organization/create-team", "POST /organization/create-role"],
);

compatScenario(
  "organization raw seat predicate preserves a high legacy durable counter",
  async (ctx) => {
    const profile: FixtureProfile = "org-numeric-fixed-fraction";
    const owner = await signUp(ctx, "owner", profile);
    const org = data(
      await owner.client.organization.create({
        name: "Legacy seats",
        slug: ctx.uniqueToken("legacy"),
      }),
    );
    const room = data(
      await owner.client.organization.createTeam({ organizationId: org.id, name: "Legacy room" }),
    );
    const seeded = await serverOperation(
      ctx,
      {
        operation: "seed-member",
        organizationId: org.id,
        id: ctx.uniqueToken("legacy-seat"),
        email: ctx.uniqueEmail("legacy-seat"),
        name: "Legacy seat",
      },
      profile,
    );
    expect(seeded.status).toBe(200);
    const foreign = data(
      await owner.client.organization.create({
        name: "Foreign seats",
        slug: ctx.uniqueToken("legacy-foreign"),
      }),
    );
    const foreignBefore = await state(ctx, foreign.id, profile);
    const rejected = [];
    for (let i = 0; i < 2; i++) {
      const result = await owner.client.organization.addTeamMember({
        organizationId: org.id,
        teamId: room.id,
        userId: (seeded.body as { userId: string }).userId,
      });
      expect(result.error).toMatchObject({ status: 403, code: "TEAM_MEMBER_LIMIT_REACHED" });
      rejected.push(result);
    }
    // Keep the complete physical state, including its deliberately high counter.
    // The ordinary state helper additionally requires synchronized counters.
    const response = await fetch(
      new URL(
        `/__test/organization-state?organizationId=${org.id}&profile=${profile}`,
        ctx.baseURL,
      ),
    );
    expect(response.status).toBe(200);
    const raw = (await response.json()) as {
      teams: { memberCount: number }[];
      teamMembers: unknown[];
      members: unknown[];
    };
    expect(raw.teams).toHaveLength(1);
    expect(raw.teams[0]!.memberCount).toBe(5);
    expect(raw.teamMembers).toEqual([]);
    expect(raw.members).toHaveLength(2);
    const foreignAfter = await state(ctx, foreign.id, profile);
    expect(foreignAfter.raw).toEqual(foreignBefore.raw);
    return {
      org,
      room,
      seeded,
      foreign,
      foreignBefore: foreignBefore.raw,
      rejected,
      raw,
      foreignAfter: foreignAfter.raw,
    };
  },
  ["POST /organization/add-team-member"],
);
