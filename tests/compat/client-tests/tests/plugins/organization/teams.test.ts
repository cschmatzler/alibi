import { expect } from "bun:test";

import { z } from "zod";

import { compatScenario } from "../../../support/scenario";
import { data, orgActor, serverOperation, signUp, state } from "./helpers";

compatScenario(
  "organization teams persist membership identity and active-team session changes",
  async (ctx) => {
    const owner = await signUp(ctx, "owner");
    const invitee = await signUp(ctx, "invitee");
    const guest = orgActor(ctx, "guest");
    const unauthenticated = await guest.organization.listTeams({
      query: { organizationId: "missing" },
    });
    expect(unauthenticated.error).toMatchObject({ status: 401 });

    const created = await owner.client.organization.create({
      name: "Team Org",
      slug: ctx.uniqueToken("team-org"),
    });
    const org = data(created);
    expect(org).not.toHaveProperty("teams");

    const initial = await state(ctx, org.id);
    expect(initial.parsed.teams).toHaveLength(1);

    const defaultTeam = initial.parsed.teams[0];

    if (!defaultTeam) {
      throw new Error("Organization must create its default team");
    }

    expect(defaultTeam).toMatchObject({ name: "Team Org", updatedAt: null, memberCount: 1 });
    expect(initial.parsed.teamMembers[0]).toMatchObject({
      teamId: defaultTeam.id,
      userId: owner.user.id,
    });

    const ownerSession = await owner.client.getSession();
    expect(data(ownerSession).session).toMatchObject({
      activeOrganizationId: org.id,
      activeTeamId: defaultTeam.id,
    });

    const engineering = await owner.client.organization.createTeam({ name: "Engineering" });
    const team = data(engineering);
    expect(team.organizationId).toBe(org.id);
    expect(new Date(team.createdAt).toISOString()).toBe(
      new Date(team.updatedAt ?? 0).toISOString(),
    );
    expect(team).not.toHaveProperty("memberCount");

    const renamed = await owner.client.organization.updateTeam({
      teamId: team.id,
      data: { name: "Platform" },
    });
    expect(data(renamed).name).toBe("Platform");

    const invitation = await owner.client.organization.inviteMember({
      organizationId: org.id,
      email: invitee.email,
      role: "member",
      teamId: team.id,
    });
    expect(data(invitation).teamId).toBe(team.id);

    const accepted = await invitee.client.organization.acceptInvitation({
      invitationId: data(invitation).id,
    });
    expect(data(accepted).member).toMatchObject({
      organizationId: org.id,
      userId: invitee.user.id,
      role: "member",
    });

    const current = await invitee.client.getSession();
    const currentSession = data(current).session;
    expect(currentSession).toMatchObject({ activeOrganizationId: org.id, activeTeamId: team.id });

    const members = await invitee.client.organization.listTeamMembers();
    const listedMembers = data(members);
    expect(listedMembers).toHaveLength(1);
    expect(listedMembers[0]).toMatchObject({ teamId: team.id, userId: invitee.user.id });
    expect(listedMembers[0]).not.toHaveProperty("membershipKey");

    const unauthenticatedMembers = await guest.organization.listTeamMembers({
      query: { teamId: team.id },
    });
    expect(unauthenticatedMembers.error).toMatchObject({ status: 401 });

    const forbiddenUpdate = await invitee.client.organization.updateTeam({
      teamId: team.id,
      data: { name: "Denied update" },
    });
    expect(forbiddenUpdate.error).toMatchObject({
      status: 403,
      code: "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM",
    });

    const repeated = await owner.client.organization.addTeamMember({
      teamId: team.id,
      userId: invitee.user.id,
    });
    const firstMember = listedMembers[0];

    if (!firstMember) {
      throw new Error("Accepted team invitation must persist a member");
    }

    expect(data(repeated).id).toBe(firstMember.id);

    const own = await invitee.client.organization.listUserTeams();
    expect(data(own).map((team) => team.id)).toEqual([team.id]);

    const other = await owner.client.organization.listUserTeams({
      query: { userId: invitee.user.id, organizationId: org.id },
    });
    expect(data(other).map((team) => team.id)).toEqual([team.id]);

    const restricted = await invitee.client.organization.listUserTeams({
      query: { userId: owner.user.id, organizationId: org.id },
    });
    expect(restricted.error).toMatchObject({
      status: 403,
      code: "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER",
    });

    const forbiddenCreate = await invitee.client.organization.createTeam({ name: "Denied" });
    expect(forbiddenCreate.error).toMatchObject({
      status: 403,
      code: "YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION",
    });

    const clear = await invitee.client.organization.setActiveTeam({ teamId: null });
    expect(clear.error).toBeNull();

    const clearedSession = await invitee.client.getSession();
    expect(data(clearedSession).session.activeTeamId).toBeNull();
    expect(data(clearedSession).session.token).toBe(currentSession.token);

    const select = await invitee.client.organization.setActiveTeam({ teamId: team.id });
    expect(data(select).id).toBe(team.id);

    const beforeRemoval = await state(ctx, org.id);
    expect(beforeRemoval.parsed.teams.find((candidate) => candidate.id === team.id)?.name).toBe(
      "Platform",
    );

    const removeMember = await owner.client.organization.removeTeamMember({
      teamId: team.id,
      userId: invitee.user.id,
    });
    data(removeMember);
    const afterRemoval = await state(ctx, org.id);
    expect(afterRemoval.parsed.teamMembers.filter((member) => member.teamId === team.id)).toEqual(
      [],
    );

    const wrongTeam = await invitee.client.organization.setActiveTeam({ teamId: defaultTeam.id });
    expect(wrongTeam.error).toMatchObject({
      status: 403,
      code: "USER_IS_NOT_A_MEMBER_OF_THE_TEAM",
    });

    const removeTeam = await owner.client.organization.removeTeam({ teamId: team.id });
    data(removeTeam);
    const list = await owner.client.organization.listTeams();
    expect(data(list).map((team) => team.id)).toEqual([defaultTeam.id]);

    const cannotRemoveActive = await owner.client.organization.removeTeam({
      teamId: defaultTeam.id,
    });
    expect(cannotRemoveActive.error).toMatchObject({
      status: 403,
      code: "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_TEAM",
    });

    await owner.client.organization.setActiveTeam({ teamId: null });
    const cannotRemoveLast = await owner.client.organization.removeTeam({ teamId: defaultTeam.id });
    expect(cannotRemoveLast.error).toMatchObject({
      status: 400,
      code: "UNABLE_TO_REMOVE_LAST_TEAM",
    });

    return {
      owner: owner.signup,
      invitee: invitee.signup,
      unauthenticated,
      created,
      initial: initial.raw,
      ownerSession,
      engineering,
      renamed,
      invitation,
      accepted,
      current,
      members,
      unauthenticatedMembers,
      forbiddenUpdate,
      repeated,
      own,
      other,
      restricted,
      forbiddenCreate,
      clear,
      clearedSession,
      select,
      beforeRemoval: beforeRemoval.raw,
      removeMember,
      afterRemoval: afterRemoval.raw,
      wrongTeam,
      removeTeam,
      list,
      cannotRemoveActive,
      cannotRemoveLast,
    };
  },
  [
    "POST /organization/create-team",
    "POST /organization/update-team",
    "POST /organization/remove-team",
    "POST /organization/set-active-team",
    "POST /organization/add-team-member",
    "POST /organization/remove-team-member",
    "GET /organization/list-teams",
    "GET /organization/list-user-teams",
    "GET /organization/list-team-members",
  ],
);

compatScenario(
  "organization multi-team invitations reject another user and prune deleted-team pending links",
  async (ctx) => {
    const owner = await signUp(ctx, "invitation-owner");
    const invitee = await signUp(ctx, "invitation-target");
    const wrong = await signUp(ctx, "wrong-target");

    const created = await owner.client.organization.create({
      name: "Compound Org",
      slug: ctx.uniqueToken("compound-org"),
    });
    const org = data(created);
    const first = data(await owner.client.organization.createTeam({ name: "First" }));
    const second = data(await owner.client.organization.createTeam({ name: "Second" }));

    const invitation = await owner.client.organization.inviteMember({
      email: invitee.email,
      role: "member",
      teamId: [first.id, second.id],
    });
    expect(data(invitation).teamId).toBe(`${first.id},${second.id}`);

    const invitationId = data(invitation).id;
    const nonRecipient = await owner.client.organization.getInvitation({
      query: { id: invitationId },
    });
    expect(nonRecipient.error).toMatchObject({
      status: 403,
      code: "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION",
    });

    const unauthenticated = await orgActor(ctx, "invitation-guest").organization.getInvitation({
      query: { id: invitationId },
    });
    expect(unauthenticated.error).toMatchObject({ status: 401, message: "Not authenticated" });

    const wrongUser = await wrong.client.organization.acceptInvitation({
      invitationId,
    });
    expect(wrongUser.error).toMatchObject({
      status: 403,
      code: "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION",
    });

    const pending = await state(ctx, org.id);
    expect(pending.parsed.invitations[0]?.status).toBe("pending");
    expect(
      pending.parsed.teamMembers.filter((member) => member.userId === invitee.user.id),
    ).toEqual([]);

    const accepted = await invitee.client.organization.acceptInvitation({
      invitationId,
    });
    data(accepted);
    const acceptedState = await state(ctx, org.id);
    const acceptedTeams = acceptedState.parsed.teamMembers
      .filter((member) => member.userId === invitee.user.id)
      .map((member) => member.teamId);
    expect(acceptedTeams).toHaveLength(2);
    expect(acceptedTeams).toContain(first.id);
    expect(acceptedTeams).toContain(second.id);

    const current = await invitee.client.getSession();
    expect(data(current).session.activeOrganizationId).toBe(org.id);
    expect(data(current).session.activeTeamId).toBeNull();

    const repeated = await invitee.client.organization.acceptInvitation({
      invitationId,
    });
    expect(repeated.error).toMatchObject({ status: 400, code: "INVITATION_NOT_FOUND" });

    const processedLookup = await invitee.client.organization.getInvitation({
      query: { id: invitationId },
    });
    expect(processedLookup.error).toMatchObject({ status: 400, message: "Invitation not found!" });

    // Deleting a team prunes it from pending invitations but not from accepted ones.
    const pruning = await owner.client.organization.inviteMember({
      email: wrong.email,
      role: "member",
      teamId: [first.id, second.id],
    });
    const pruningId = data(pruning).id;
    const removed = await owner.client.organization.removeTeam({ teamId: first.id });
    data(removed);
    const pruned = await wrong.client.organization.getInvitation({
      query: { id: pruningId },
    });
    expect(data(pruned).teamId).toBe(second.id);

    const prunedState = await state(ctx, org.id);
    expect(
      prunedState.parsed.invitations.find((candidate) => candidate.id === pruningId)?.teamId,
    ).toBe(second.id);
    expect(
      prunedState.parsed.invitations.find((candidate) => candidate.id === invitationId)?.teamId,
    ).toBe(`${first.id},${second.id}`);
    expect(prunedState.parsed.teamMembers.some((member) => member.teamId === first.id)).toBe(false);

    const acceptedPruned = await wrong.client.organization.acceptInvitation({
      invitationId: pruningId,
    });
    data(acceptedPruned);
    const wrongSession = await wrong.client.getSession();
    expect(data(wrongSession).session.activeTeamId).toBe(second.id);

    const leave = await invitee.client.organization.leave({ organizationId: org.id });
    data(leave);
    const afterLeave = await state(ctx, org.id);
    expect(afterLeave.parsed.teamMembers.some((member) => member.userId === invitee.user.id)).toBe(
      false,
    );
    expect(afterLeave.parsed.members.some((member) => member.userId === invitee.user.id)).toBe(
      false,
    );

    return {
      created,
      first,
      second,
      invitation,
      wrongUser,
      pending: pending.raw,
      accepted,
      acceptedState: acceptedState.raw,
      current,
      repeated,
      processedLookup,
      pruning,
      nonRecipient,
      unauthenticated,
      removed,
      pruned,
      prunedState: prunedState.raw,
      acceptedPruned,
      wrongSession,
      leave,
      afterLeave: afterLeave.raw,
    };
  },
  [
    "POST /organization/accept-invitation",
    "GET /organization/get-invitation",
    "POST /organization/remove-team",
    "POST /organization/leave",
  ],
);

compatScenario(
  "organization disabled default team leaves nullable session state until membership is selected",
  async (ctx) => {
    const profile = "org-teams-no-default";
    const owner = await signUp(ctx, "no-default-owner", profile);

    const created = await owner.client.organization.create({
      name: "No Default",
      slug: ctx.uniqueToken("no-default-team"),
    });
    const org = data(created);

    const initial = await state(ctx, org.id, profile);
    expect(initial.parsed.teams).toEqual([]);
    expect(initial.parsed.teamMembers).toEqual([]);

    const current = await owner.client.getSession();
    expect(data(current).session.activeOrganizationId).toBe(org.id);
    expect(data(current).session.activeTeamId).toBeNull();

    const team = await owner.client.organization.createTeam({ name: "Explicit" });
    const teamData = data(team);
    const other = await owner.client.organization.createTeam({ name: "Joined First" });
    const otherData = data(other);

    const notMember = await owner.client.organization.setActiveTeam({ teamId: teamData.id });
    expect(notMember.error).toMatchObject({
      status: 403,
      code: "USER_IS_NOT_A_MEMBER_OF_THE_TEAM",
    });

    const joinedFirst = await owner.client.organization.addTeamMember({
      teamId: otherData.id,
      userId: owner.user.id,
    });
    data(joinedFirst);
    const added = await owner.client.organization.addTeamMember({
      teamId: teamData.id,
      userId: owner.user.id,
    });
    data(added);

    const membershipOrder = await owner.client.organization.listUserTeams();
    expect(data(membershipOrder).map((team) => team.id)).toEqual([otherData.id, teamData.id]);

    const selected = await owner.client.organization.setActiveTeam({ teamId: teamData.id });
    data(selected);
    const active = await owner.client.getSession();
    expect(data(active).session.activeTeamId).toBe(teamData.id);

    const full = await owner.client.organization.getFullOrganization();
    expect(data(full).teams.map((team) => team.id)).toEqual([teamData.id, otherData.id]);

    return {
      created,
      initial: initial.raw,
      current,
      team,
      other,
      notMember,
      joinedFirst,
      added,
      membershipOrder,
      selected,
      active,
      full,
    };
  },
  [
    "POST /organization/create",
    "POST /organization/create-team",
    "POST /organization/add-team-member",
    "POST /organization/set-active-team",
  ],
);

compatScenario(
  "organization server-only teams persist numeric-ID membership and enforce tenant and final-team policies",
  async (ctx) => {
    const owner = await signUp(ctx, "server-team-owner");
    const member = await signUp(ctx, "server-team-member");

    const created = await owner.client.organization.create({
      name: "Server Teams",
      slug: ctx.uniqueToken("server-team-org"),
    });
    const organization = data(created);

    const initial = await state(ctx, organization.id);
    const defaultTeam = initial.parsed.teams[0];

    if (!defaultTeam) {
      throw new Error("Server team flow requires the real default team");
    }

    const serverCreated = await serverOperation(ctx, {
      operation: "create-team",
      organizationId: organization.id,
      name: "Server Created",
    });
    expect(serverCreated.status).toBe(200);

    const team = z
      .object({ id: z.string(), organizationId: z.string(), name: z.literal("Server Created") })
      .parse(serverCreated.body);
    expect(team.organizationId).toBe(organization.id);

    const seed = await serverOperation(ctx, {
      operation: "seed-member",
      organizationId: organization.id,
      id: "42",
      name: "Legacy Numeric",
      email: ctx.uniqueEmail("numeric-member"),
    });
    expect(seed.status).toBe(200);
    expect(seed.body).toMatchObject({ userId: "42" });

    const invited = await owner.client.organization.inviteMember({
      email: member.email,
      role: "member",
    });
    const accepted = await member.client.organization.acceptInvitation({
      invitationId: data(invited).id,
    });
    data(accepted);

    const request = { organizationId: organization.id, teamId: team.id, userId: 42 };
    const raw = async (actor: string, path: string, body: unknown) => {
      const response = await ctx.actor(actor, "org-teams").fetch(`/api/auth/organization/${path}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });
      const value: unknown = await response.json();
      return { status: response.status, body: value };
    };

    const unauthorized = await raw("server-team-guest", "add-team-member", request);
    expect(unauthorized.status).toBe(401);

    const forbidden = await raw("server-team-member", "add-team-member", request);
    expect(forbidden).toMatchObject({
      status: 403,
      body: { code: "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM_MEMBER" },
    });

    const added = await raw("server-team-owner", "add-team-member", request);
    expect(added.status).toBe(200);

    const membership = z
      .object({ id: z.string(), teamId: z.string(), userId: z.literal("42") })
      .parse(added.body);

    const afterAdd = await state(ctx, organization.id);
    expect(afterAdd.parsed.teamMembers.find((member) => member.teamId === team.id)).toMatchObject(
      membership,
    );

    const unauthorizedRemoval = await raw("server-team-guest", "remove-team-member", request);
    expect(unauthorizedRemoval.status).toBe(401);

    const forbiddenRemoval = await raw("server-team-member", "remove-team-member", request);
    expect(forbiddenRemoval).toMatchObject({
      status: 403,
      body: { code: "YOU_ARE_NOT_ALLOWED_TO_REMOVE_A_TEAM_MEMBER" },
    });

    const rejectedRemovalState = await state(ctx, organization.id);
    expect(
      rejectedRemovalState.parsed.teamMembers.filter((member) => member.teamId === team.id),
    ).toEqual(afterAdd.parsed.teamMembers.filter((member) => member.teamId === team.id));

    const repeated = await raw("server-team-owner", "add-team-member", request);
    expect(repeated).toMatchObject({ status: 200, body: { id: membership.id } });

    // Neither the endpoint nor the server API accept a team from another tenant.
    const other = data(
      await owner.client.organization.create({
        name: "Other Server Tenant",
        slug: ctx.uniqueToken("server-team-other"),
      }),
    );
    const otherState = await state(ctx, other.id);
    const foreignTeam = otherState.parsed.teams[0];

    if (!foreignTeam) {
      throw new Error("Wrong-tenant control requires a persisted foreign team");
    }

    const wrongTenant = await raw("server-team-owner", "add-team-member", {
      ...request,
      teamId: foreignTeam.id,
    });
    expect(wrongTenant).toMatchObject({ status: 400, body: { code: "TEAM_NOT_FOUND" } });

    const wrongServerTenant = await serverOperation(ctx, {
      operation: "remove-team",
      organizationId: other.id,
      teamId: team.id,
    });
    expect(wrongServerTenant).toMatchObject({ status: 400, body: { code: "TEAM_NOT_FOUND" } });

    const removedMember = await raw("server-team-owner", "remove-team-member", request);
    expect(removedMember.status).toBe(200);

    const afterRemove = await state(ctx, organization.id);
    expect(afterRemove.parsed.teamMembers.some((member) => member.userId === "42")).toBe(false);

    const ownerAdded = await owner.client.organization.addTeamMember({
      organizationId: organization.id,
      teamId: team.id,
      userId: owner.user.id,
    });
    data(ownerAdded);
    const activatedOrganization = await owner.client.organization.setActive({
      organizationId: organization.id,
    });
    data(activatedOrganization);
    const selected = await owner.client.organization.setActiveTeam({ teamId: team.id });
    data(selected);
    const active = await owner.client.getSession();
    expect(data(active).session.activeTeamId).toBe(team.id);

    const serverRemoved = await serverOperation(ctx, {
      operation: "remove-team",
      organizationId: organization.id,
      teamId: team.id,
    });
    expect(serverRemoved).toEqual({ status: 200, body: { message: "Team removed successfully." } });

    const remaining = await state(ctx, organization.id);
    expect(remaining.parsed.teams.map((team) => team.id)).toEqual([defaultTeam.id]);
    expect(remaining.parsed.teamMembers.some((member) => member.teamId === team.id)).toBe(false);

    const afterDeletion = await owner.client.getSession();

    // Upstream deletion retains this historical session selection until explicit clearing.
    expect(data(afterDeletion).session.activeTeamId).toBe(team.id);
    expect(data(afterDeletion).session.token).toBe(data(active).session.token);

    const deletedSelection = await owner.client.organization.listTeamMembers();
    expect(deletedSelection.error).toMatchObject({ status: 400, code: "TEAM_NOT_FOUND" });

    const explicitClear = await owner.client.organization.setActiveTeam({ teamId: null });
    expect(explicitClear.error).toBeNull();

    const cleared = await owner.client.getSession();
    expect(data(cleared).session.activeTeamId).toBeNull();
    expect(data(cleared).session.token).toBe(data(active).session.token);

    const lastTeam = await serverOperation(ctx, {
      operation: "remove-team",
      organizationId: organization.id,
      teamId: defaultTeam.id,
    });
    expect(lastTeam).toMatchObject({ status: 400, body: { code: "UNABLE_TO_REMOVE_LAST_TEAM" } });

    const final = await state(ctx, organization.id);
    expect(final.parsed.teams).toHaveLength(1);

    return {
      created,
      initial: initial.raw,
      serverCreated,
      seed,
      invited,
      accepted,
      unauthorized,
      forbidden,
      added,
      afterAdd: afterAdd.raw,
      unauthorizedRemoval,
      forbiddenRemoval,
      rejectedRemovalState: rejectedRemovalState.raw,
      repeated,
      other,
      otherState: otherState.raw,
      wrongTenant,
      wrongServerTenant,
      removedMember,
      afterRemove: afterRemove.raw,
      ownerAdded,
      activatedOrganization,
      selected,
      active,
      serverRemoved,
      remaining: remaining.raw,
      afterDeletion,
      deletedSelection,
      explicitClear,
      cleared,
      lastTeam,
      final: final.raw,
    };
  },
  [
    "POST /organization/add-team-member",
    "POST /organization/remove-team-member",
    "POST /organization/set-active-team",
  ],
);

compatScenario(
  "organization asynchronous team limits use the request header and authenticated caller",
  async (ctx) => {
    const profile = "org-teams-limited";
    const owner = await signUp(ctx, "limit-owner", profile);
    const first = await signUp(ctx, "limit-first", profile);
    const second = await signUp(ctx, "limit-second", profile);

    const created = await owner.client.organization.create({
      name: "Configured Limits",
      slug: ctx.uniqueToken("configured-team-limit"),
    });
    const organization = data(created);

    const initial = await state(ctx, organization.id, profile);
    expect(initial.parsed.teams).toHaveLength(1);

    const denied = await owner.client.organization.createTeam({ name: "Default Policy" });
    expect(denied.error).toMatchObject({
      status: 400,
      code: "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS",
    });

    const expanded = { headers: { "x-team-policy": "expanded" } };
    const allowed = await owner.client.organization.createTeam({ name: "Allowed" }, expanded);
    const team = data(allowed);
    const allowedSecond = await owner.client.organization.createTeam(
      { name: "Allowed Second" },
      expanded,
    );
    data(allowedSecond);
    const full = await owner.client.organization.createTeam({ name: "Full" }, expanded);
    expect(full.error).toMatchObject({
      status: 400,
      code: "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS",
    });

    const serverDenied = await serverOperation(
      ctx,
      {
        operation: "create-team",
        organizationId: organization.id,
        name: "Server Missing Principal",
      },
      profile,
    );
    expect(serverDenied).toMatchObject({
      status: 400,
      body: { code: "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS" },
    });

    const invitations = [];
    const acceptances = [];

    for (const member of [first, second]) {
      const invitation = await owner.client.organization.inviteMember({
        email: member.email,
        role: "member",
      });
      invitations.push(invitation);
      const accepted = await member.client.organization.acceptInvitation({
        invitationId: data(invitation).id,
      });
      data(accepted);
      acceptances.push(accepted);
    }

    const added = await owner.client.organization.addTeamMember({
      teamId: team.id,
      userId: first.user.id,
    });
    data(added);
    const memberLimit = await owner.client.organization.addTeamMember({
      teamId: team.id,
      userId: second.user.id,
    });
    expect(memberLimit.error).toMatchObject({ status: 403, code: "TEAM_MEMBER_LIMIT_REACHED" });

    const persisted = await state(ctx, organization.id, profile);
    expect(persisted.parsed.teams.map((team) => team.name)).toEqual([
      "Configured Limits",
      "Allowed",
      "Allowed Second",
    ]);

    const members = persisted.parsed.teamMembers.filter((member) => member.teamId === team.id);
    expect(members).toHaveLength(1);
    expect(members[0]?.userId).toBe(first.user.id);

    return {
      created,
      initial: initial.raw,
      denied,
      allowed,
      allowedSecond,
      full,
      serverDenied,
      invitations,
      acceptances,
      added,
      memberLimit,
      persisted: persisted.raw,
    };
  },
  ["POST /organization/create-team", "POST /organization/add-team-member"],
);

compatScenario(
  "organization keeps the selected team during creation and can remove its final team when configured",
  async (ctx) => {
    const profile = "org-teams-removable";
    const owner = await signUp(ctx, "removable-owner", profile);

    const created = await owner.client.organization.create({
      name: "Original Selection",
      slug: ctx.uniqueToken("removable-first"),
    });
    const organization = data(created);

    const initial = await state(ctx, organization.id, profile);
    const selected = initial.parsed.teams[0];

    if (!selected) {
      throw new Error("A created default team must have a persisted selection");
    }

    const before = await owner.client.getSession();
    expect(data(before).session).toMatchObject({
      activeOrganizationId: organization.id,
      activeTeamId: selected.id,
    });

    const kept = await owner.client.organization.create({
      name: "Separate Created Team",
      slug: ctx.uniqueToken("removable-kept"),
      keepCurrentActiveOrganization: true,
    });
    const other = data(kept);
    const otherState = await state(ctx, other.id, profile);
    expect(otherState.parsed.teams).toHaveLength(1);
    expect(otherState.parsed.teamMembers[0]?.userId).toBe(owner.user.id);

    const preserved = await owner.client.getSession();
    expect(data(preserved).session).toMatchObject({
      activeOrganizationId: organization.id,
      activeTeamId: selected.id,
      token: data(before).session.token,
    });

    const protectedSelection = await owner.client.organization.removeTeam({ teamId: selected.id });
    expect(protectedSelection.error).toMatchObject({
      status: 403,
      code: "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_TEAM",
    });

    const clear = await owner.client.organization.setActiveTeam({ teamId: null });
    expect(clear.error).toBeNull();

    const removed = await owner.client.organization.removeTeam({ teamId: selected.id });
    data(removed);

    const after = await state(ctx, organization.id, profile);
    expect(after.parsed.teams).toEqual([]);
    expect(after.parsed.teamMembers).toEqual([]);
    expect(after.parsed.members.map((member) => member.userId)).toEqual([owner.user.id]);

    const teams = await owner.client.organization.listTeams();
    expect(data(teams)).toEqual([]);

    const full = await owner.client.organization.getFullOrganization();
    expect(data(full).teams).toEqual([]);

    const current = await owner.client.getSession();
    expect(data(current).session).toMatchObject({
      activeOrganizationId: organization.id,
      activeTeamId: null,
      token: data(before).session.token,
    });

    const untouched = await state(ctx, other.id, profile);
    expect(untouched.parsed.teams.map((team) => team.id)).toEqual(
      otherState.parsed.teams.map((team) => team.id),
    );
    expect(untouched.parsed.teamMembers).toEqual(otherState.parsed.teamMembers);

    return {
      created,
      initial: initial.raw,
      before,
      kept,
      otherState: otherState.raw,
      preserved,
      protectedSelection,
      clear,
      removed,
      after: after.raw,
      teams,
      full,
      current,
      untouched: untouched.raw,
    };
  },
  [
    "POST /organization/create",
    "POST /organization/remove-team",
    "POST /organization/set-active-team",
  ],
);

compatScenario(
  "team-member listing denies a persisted stray member without organization membership",
  async (ctx) => {
    const owner = await signUp(ctx, "stray-team-owner");
    const member = await signUp(ctx, "actual-team-member");
    const outsider = await signUp(ctx, "stray-team-outsider");
    const tenant = data(
      await owner.client.organization.create({
        name: "Team Tenant",
        slug: ctx.uniqueToken("team-tenant"),
      }),
    );
    const otherTenant = data(
      await outsider.client.organization.create({
        name: "Other Tenant",
        slug: ctx.uniqueToken("other-team-tenant"),
      }),
    );
    const initial = await state(ctx, tenant.id);
    const team = initial.parsed.teams[0]!;
    const invitation = data(
      await owner.client.organization.inviteMember({
        organizationId: tenant.id,
        email: member.email,
        role: "member",
        teamId: team.id,
      }),
    );
    expect(
      (await member.client.organization.acceptInvitation({ invitationId: invitation.id })).error,
    ).toBeNull();
    const seeded = await serverOperation(ctx, {
      operation: "seed-stray-team-member",
      teamId: team.id,
      userId: outsider.user.id,
    });
    expect(seeded.status).toBe(200);
    expect(seeded.body).toEqual({ inserted: true });
    const before = await state(ctx, tenant.id);
    expect(before.parsed.teamMembers).toContainEqual(
      expect.objectContaining({ teamId: team.id, userId: outsider.user.id }),
    );
    expect(before.parsed.members.some((row) => row.userId === outsider.user.id)).toBe(false);
    const otherBefore = await state(ctx, otherTenant.id);
    const sessionsBefore = await Promise.all(
      [owner, member, outsider].map((actor) => ctx.readUserState({ userId: actor.user.id })),
    );
    const denied = await outsider.client.organization.listTeamMembers({
      query: { teamId: team.id },
    });
    expect(denied.data).toBeNull();
    expect(await state(ctx, tenant.id)).toEqual(before);
    expect(await state(ctx, otherTenant.id)).toEqual(otherBefore);
    expect(
      await Promise.all(
        [owner, member, outsider].map((actor) => ctx.readUserState({ userId: actor.user.id })),
      ),
    ).toEqual(sessionsBefore);
    const allowed = await owner.client.organization.listTeamMembers({ query: { teamId: team.id } });
    expect(allowed.error).toBeNull();
    expect(allowed.data?.map((row) => row.userId).sort()).toEqual(
      [owner.user.id, member.user.id, outsider.user.id].sort(),
    );
    expect((await outsider.client.getSession()).data?.user.id).toBe(outsider.user.id);
    expect(denied.error).toMatchObject({
      status: 400,
      code: "USER_IS_NOT_A_MEMBER_OF_THE_TEAM",
      message: "User is not a member of the team",
    });
    return {
      seeded,
      denied: ctx.snapshot(denied),
      allowed: ctx.snapshot(allowed),
      before: before.raw,
      otherBefore: otherBefore.raw,
    };
  },
  ["GET /organization/list-team-members"],
);

for (const mode of ["missing", "moved"] as const) {
  compatScenario(
    `invitation acceptance restores pending invitation for ${mode} referenced team`,
    async (ctx) => {
      const owner = await signUp(ctx, "broken-team-owner");
      const recipient = await signUp(ctx, "broken-team-recipient");
      const foreign = await signUp(ctx, "broken-team-foreign");
      const tenant = data(
        await owner.client.organization.create({
          name: "Invitation Tenant",
          slug: ctx.uniqueToken("invitation-tenant"),
        }),
      );
      const otherTenant = data(
        await foreign.client.organization.create({
          name: "Foreign Tenant",
          slug: ctx.uniqueToken("foreign-invitation-tenant"),
        }),
      );
      const room = data(
        await owner.client.organization.createTeam({
          organizationId: tenant.id,
          name: "Referenced Empty Team",
        }),
      );
      const invitation = data(
        await owner.client.organization.inviteMember({
          organizationId: tenant.id,
          email: recipient.email,
          role: "member",
          teamId: room.id,
        }),
      );
      expect(invitation.teamId).toBe(room.id);
      const altered = await serverOperation(ctx, {
        operation: "set-team-storage",
        teamId: room.id,
        ...(mode === "moved" ? { organizationId: otherTenant.id } : {}),
      });
      expect(altered.status).toBe(200);
      expect(altered.body).toEqual({ changed: true });
      const before = await state(ctx, tenant.id);
      const foreignBefore = await state(ctx, otherTenant.id);
      expect(before.parsed.teams.some((team) => team.id === room.id)).toBe(false);
      if (mode === "moved") {
        expect(foreignBefore.parsed.teams).toContainEqual(
          expect.objectContaining({ id: room.id, organizationId: otherTenant.id }),
        );
      }
      const sessions = await Promise.all(
        [owner, recipient, foreign].map((actor) => ctx.readUserState({ userId: actor.user.id })),
      );
      const rejected = await recipient.client.organization.acceptInvitation({
        invitationId: invitation.id,
      });
      expect(rejected.data).toBeNull();
      const after = await state(ctx, tenant.id);
      expect(after).toEqual(before);
      expect(after.parsed.invitations.find((row) => row.id === invitation.id)?.status).toBe(
        "pending",
      );
      expect(after.parsed.members.some((row) => row.userId === recipient.user.id)).toBe(false);
      expect(await state(ctx, otherTenant.id)).toEqual(foreignBefore);
      expect(
        await Promise.all(
          [owner, recipient, foreign].map((actor) => ctx.readUserState({ userId: actor.user.id })),
        ),
      ).toEqual(sessions);
      const repaired = await serverOperation(ctx, {
        operation: "set-team-storage",
        teamId: room.id,
        restore: true,
      });
      expect(repaired.status).toBe(200);
      const restored = await state(ctx, tenant.id);
      expect(restored.parsed.teams).toContainEqual(
        expect.objectContaining({ id: room.id, organizationId: tenant.id, name: room.name }),
      );
      const accepted = await recipient.client.organization.acceptInvitation({
        invitationId: invitation.id,
      });
      expect(accepted.error).toBeNull();
      expect(accepted.data?.invitation.status).toBe("accepted");
      const committed = await state(ctx, tenant.id);
      expect(committed.parsed.teamMembers).toContainEqual(
        expect.objectContaining({ teamId: room.id, userId: recipient.user.id }),
      );
      expect((await recipient.client.getSession()).data?.session).toMatchObject({
        activeOrganizationId: tenant.id,
        activeTeamId: room.id,
      });
      expect((await foreign.client.getSession()).data?.user.id).toBe(foreign.user.id);
      expect(rejected.error).toMatchObject({ status: 400, code: "TEAM_NOT_FOUND" });
      return {
        altered,
        rejected: ctx.snapshot(rejected),
        repaired,
        accepted: ctx.snapshot(accepted),
        before: before.raw,
        committed: committed.raw,
      };
    },
    ["POST /organization/accept-invitation"],
  );
}
