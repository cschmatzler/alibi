import { expect } from "bun:test";

import { z } from "zod";

import { compatScenario, type ScenarioContext } from "../../../support/scenario";
import { signUpUser } from "./helpers";

async function removalSetup(ctx: ScenarioContext, name: string) {
  const configured = await ctx.rawRequest({
    path: "/__test/organization-member-role-hooks-configure",
    method: "POST",
    json: { mode: "record" },
  });
  expect(configured.status).toBe(200);

  const owner = await signUpUser(ctx, `${name}-owner`, `${name}-owner`, "Owner");
  const target = await signUpUser(ctx, `${name}-target`, `${name}-target`, "Target");
  const foreign = await signUpUser(ctx, `${name}-foreign`, `${name}-foreign`, "Foreign");

  for (const actor of [owner, target, foreign]) {
    expect(actor.signup.error).toBeNull();
  }

  const created = await owner.orgClient.organization.create({
    name: "Removal",
    slug: ctx.uniqueToken(`${name}-org`),
    metadata: { owned: true },
  });
  const other = await foreign.orgClient.organization.create({
    name: "Foreign",
    slug: ctx.uniqueToken(`${name}-foreign-org`),
    metadata: { foreign: true },
  });
  expect(created.error).toBeNull();
  expect(other.error).toBeNull();

  const organizationId = z.string().parse(created.data?.id);
  const invited = await owner.orgClient.organization.inviteMember({
    organizationId,
    email: target.email,
    role: "member",
  });
  expect(invited.error).toBeNull();

  const accepted = await target.orgClient.organization.acceptInvitation({
    invitationId: z.string().parse(invited.data?.id),
  });
  expect(accepted.error).toBeNull();

  const memberId = z.string().parse(accepted.data?.member.id);
  expect((await target.orgClient.organization.setActive({ organizationId })).error).toBeNull();

  const actors = [owner, target, foreign];

  async function state() {
    const response = await ctx.rawRequest({ path: "/__test/organization-member-role-hooks-state" });
    expect(response.status).toBe(200);

    const users = [];

    for (const actor of actors) {
      const observed = await ctx.rawRequest({
        path: `/__test/user-state?userId=${encodeURIComponent(z.string().parse(actor.signup.data?.user.id))}`,
      });
      expect(observed.status).toBe(200);
      users.push(observed.body);
    }

    return {
      hooks: z
        .object({
          receipts: z.array(z.unknown()),
          snapshot: z.object({
            organizations: z.array(z.record(z.string(), z.unknown())),
            members: z.array(z.record(z.string(), z.unknown())),
            users: z.array(z.record(z.string(), z.unknown())),
            sessions: z.array(z.record(z.string(), z.unknown())),
          }),
        })
        .parse(response.body),
      users,
    };
  }

  return { owner, target, foreign, created, other, organizationId, memberId, state };
}

compatScenario(
  "organization ID removal omits the email join and preserves the target and foreign selected sessions",
  async (ctx) => {
    const { owner, target, organizationId, memberId, state } = await removalSetup(ctx, "remove-id");
    const before = await state();

    const result = await owner.orgClient.organization.removeMember({
      organizationId,
      memberIdOrEmail: memberId,
    });
    expect(result.error).toBeNull();
    expect(result.data?.member).toHaveProperty("id", memberId);
    expect(result.data?.member).toHaveProperty("userId", target.signup.data?.user.id);
    expect(result.data?.member).not.toHaveProperty("user");

    const after = await state();
    expect(after.hooks.receipts).toEqual([]);
    expect(after.hooks.snapshot).toEqual({
      ...before.hooks.snapshot,
      members: before.hooks.snapshot.members.filter((member) => member.id !== memberId),
    });
    expect(after.users).toEqual(before.users);

    return { before, result: ctx.snapshot(result), after };
  },
  ["POST /organization/remove-member"],
);

compatScenario(
  "organization removal permission and last-owner guards reject without mutation and preserve foreign authority",
  async (ctx) => {
    const { owner, target, foreign, organizationId, memberId, state } = await removalSetup(
      ctx,
      "remove-guards",
    );
    const before = await state();
    const ownerMember = z
      .record(z.string(), z.unknown())
      .parse(
        before.hooks.snapshot.members.find(
          (member) =>
            member.userId === owner.signup.data?.user.id &&
            member.organizationId === organizationId,
        ),
      );
    const foreignMember = z
      .record(z.string(), z.unknown())
      .parse(
        before.hooks.snapshot.members.find(
          (member) => member.userId === foreign.signup.data?.user.id,
        ),
      );

    const observations = [];

    for (const [actor, selector, status, code] of [
      [target, memberId, 401, "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER"],
      [
        owner,
        z.string().parse(ownerMember.id),
        400,
        "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER",
      ],
      [
        owner,
        z.string().parse(foreignMember.id),
        400,
        "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER",
      ],
      [foreign, memberId, 400, "MEMBER_NOT_FOUND"],
      [owner, ` ${target.email} `, 400, "MEMBER_NOT_FOUND"],
    ] as const) {
      const result = await actor.orgClient.organization.removeMember({
        organizationId,
        memberIdOrEmail: selector,
      });
      expect(result.error).toMatchObject({ status, code });
      expect(await state()).toEqual(before);

      observations.push(ctx.snapshot(result));
    }

    const retry = await owner.orgClient.organization.removeMember({
      organizationId,
      memberIdOrEmail: target.email.toUpperCase(),
    });
    expect(retry.error).toBeNull();
    expect(retry.data?.member).toHaveProperty("user", {
      id: target.signup.data?.user.id,
      name: "Target",
      email: target.email,
      image: null,
    });

    const after = await state();
    expect(after.hooks.snapshot).toEqual({
      ...before.hooks.snapshot,
      members: before.hooks.snapshot.members.filter((member) => member.id !== memberId),
    });
    expect(after.users).toEqual(before.users);
    expect(after.hooks.receipts).toEqual([]);

    return { before, observations, retry: ctx.snapshot(retry), after };
  },
  ["POST /organization/remove-member"],
);

compatScenario(
  "organization removal validates ordered string fields and media before guest authentication",
  async (ctx) => {
    const { owner, organizationId, memberId, state } = await removalSetup(ctx, "remove-input");
    const before = await state();
    const guest = ctx.actor("remove-input-guest");

    const observations = [];

    for (const [body, media, status, error] of [
      [
        "{}",
        "application/json",
        400,
        {
          code: "VALIDATION_ERROR",
          message: "[body.memberIdOrEmail] Invalid input: expected string, received undefined",
        },
      ],
      [
        JSON.stringify({ memberIdOrEmail: null, organizationId: 1 }),
        "application/json",
        400,
        {
          code: "VALIDATION_ERROR",
          message:
            "[body.memberIdOrEmail] Invalid input: expected string, received null; [body.organizationId] Invalid input: expected string, received number",
        },
      ],
      [
        "{",
        "application/json",
        400,
        { code: "BAD_REQUEST", message: "Invalid JSON in request body" },
      ],
      [
        JSON.stringify({ organizationId, memberIdOrEmail: memberId }),
        "text/plain",
        415,
        {
          code: "UNSUPPORTED_MEDIA_TYPE",
          message: 'Content-Type "text/plain" is not allowed. Allowed types: application/json',
        },
      ],
      [
        JSON.stringify({ organizationId, memberIdOrEmail: "", userId: owner.signup.data?.user.id }),
        "application/json",
        401,
        { code: "UNAUTHORIZED", message: "Unauthorized" },
      ],
    ] as const) {
      const response = await guest.fetch("/api/auth/organization/remove-member", {
        method: "POST",
        headers: { "content-type": media },
        body,
      });
      const value = await response.json();
      expect(response.status).toBe(status);
      expect(value).toEqual(error);
      expect(await state()).toEqual(before);

      observations.push({ status: response.status, body: value });
    }

    for (const [organization, selector] of [
      [organizationId, ""],
      [" ", memberId],
    ] as const) {
      const result = await owner.orgClient.organization.removeMember({
        organizationId: organization,
        memberIdOrEmail: selector,
      });
      expect(result.error).toMatchObject({ status: 400, code: "MEMBER_NOT_FOUND" });
      expect(await state()).toEqual(before);

      observations.push(ctx.snapshot(result));
    }

    const retry = await owner.orgClient.organization.removeMember({
      organizationId: "",
      memberIdOrEmail: memberId,
    });
    expect(retry.error).toBeNull();

    const after = await state();
    expect(after.hooks.snapshot).toEqual({
      ...before.hooks.snapshot,
      members: before.hooks.snapshot.members.filter((member) => member.id !== memberId),
    });
    expect(after.users).toEqual(before.users);

    return { before, observations, retry: ctx.snapshot(retry), after };
  },
  ["POST /organization/remove-member"],
);

compatScenario(
  "organization member queries reflect non-public add-member and active member endpoints",
  async (ctx) => {
    const owner = await signUpUser(ctx, "owner", "organization-members-owner", "Owner");
    const member = await signUpUser(ctx, "member", "organization-members-user", "Member");
    const multiRoleMember = await signUpUser(
      ctx,
      "multi-role",
      "organization-members-multi-role",
      "Multi Role Member",
    );
    const slug = ctx.uniqueToken("organization-members-org");

    const organization = await owner.orgClient.organization.create({
      name: "Members Org",
      slug,
    });
    const organizationId = organization.data?.id;

    const addMember = await ctx.rawRequest({
      actor: "owner",
      path: "/api/auth/organization/add-member",
      method: "POST",
      json: {
        organizationId,
        userId: member.signup.data?.user.id,
        role: "member",
      },
    });
    const addMultiRoleMember = await ctx.rawRequest({
      actor: "owner",
      path: "/api/auth/organization/add-member",
      method: "POST",
      json: {
        organizationId,
        userId: multiRoleMember.signup.data?.user.id,
        role: ["admin", "member"],
      },
    });

    const invitedMember = await owner.orgClient.organization.inviteMember({
      organizationId: organizationId ?? "",
      email: member.email,
      role: "member",
    });
    const acceptedMember = await member.orgClient.organization.acceptInvitation({
      invitationId: invitedMember.data?.id ?? "",
    });
    const invitedMultiRoleMember = await owner.orgClient.organization.inviteMember({
      organizationId: organizationId ?? "",
      email: multiRoleMember.email,
      role: ["admin", "member"] as never,
    });
    const acceptedMultiRoleMember = await multiRoleMember.orgClient.organization.acceptInvitation({
      invitationId: invitedMultiRoleMember.data?.id ?? "",
    });

    const listMembers = await owner.orgClient.organization.listMembers({
      query: {
        organizationId,
        limit: 1,
        offset: 1,
      },
    });
    const getActiveMember = await owner.orgClient.organization.getActiveMember();
    const getActiveMemberRole = await owner.orgClient.organization.getActiveMemberRole();
    const getOtherMemberRole = await owner.orgClient.organization.getActiveMemberRole({
      query: {
        organizationId,
        userId: member.signup.data?.user.id,
      },
    });

    return {
      organization: ctx.snapshot(organization),
      addMember: ctx.snapshot(addMember),
      addMultiRoleMember: ctx.snapshot(addMultiRoleMember),
      invitedMember: ctx.snapshot(invitedMember),
      acceptedMember: ctx.snapshot(acceptedMember),
      invitedMultiRoleMember: ctx.snapshot(invitedMultiRoleMember),
      acceptedMultiRoleMember: ctx.snapshot(acceptedMultiRoleMember),
      listMembers: ctx.snapshot(listMembers),
      getActiveMember: ctx.snapshot(getActiveMember),
      getActiveMemberRole: ctx.snapshot(getActiveMemberRole),
      getOtherMemberRole: ctx.snapshot(getOtherMemberRole),
    };
  },
);

compatScenario("organization list members supports sort and filter queries", async (ctx) => {
  const owner = await signUpUser(ctx, "owner", "organization-list-owner", "Owner");
  const member = await signUpUser(ctx, "member", "organization-list-member", "Member");
  const admin = await signUpUser(ctx, "admin", "organization-list-admin", "Admin");
  const slug = ctx.uniqueToken("organization-list-org");

  const organization = await owner.orgClient.organization.create({
    name: "List Org",
    slug,
  });
  const organizationId = organization.data?.id;

  const invitedMember = await owner.orgClient.organization.inviteMember({
    organizationId: organizationId ?? "",
    email: member.email,
    role: "member",
  });
  await member.orgClient.organization.acceptInvitation({
    invitationId: invitedMember.data?.id ?? "",
  });

  const invitedAdmin = await owner.orgClient.organization.inviteMember({
    organizationId: organizationId ?? "",
    email: admin.email,
    role: "admin",
  });
  await admin.orgClient.organization.acceptInvitation({
    invitationId: invitedAdmin.data?.id ?? "",
  });

  const filteredMembers = await owner.orgClient.organization.listMembers({
    query: {
      organizationId,
      filterField: "role",
      filterOperator: "ne",
      filterValue: "owner",
    },
  });
  const sortedMembers = await owner.orgClient.organization.listMembers({
    query: {
      organizationId,
      sortBy: "createdAt",
      sortDirection: "desc",
    },
  });

  return {
    organization: ctx.snapshot(organization),
    filteredMembers: ctx.snapshot(filteredMembers),
    sortedMembers: ctx.snapshot(sortedMembers),
  };
});

compatScenario(
  "organization membership mutations cover permissions, role updates, removal, and leave",
  async (ctx) => {
    const owner = await signUpUser(ctx, "owner", "organization-mutations-owner", "Owner");
    const member = await signUpUser(ctx, "member", "organization-mutations-member", "Member");
    const removable = await signUpUser(
      ctx,
      "removable",
      "organization-mutations-removable",
      "Removable",
    );
    const slug = ctx.uniqueToken("organization-mutations-org");

    const organization = await owner.orgClient.organization.create({
      name: "Mutation Org",
      slug,
    });
    const organizationId = organization.data?.id;

    const invitedMember = await owner.orgClient.organization.inviteMember({
      organizationId: organizationId ?? "",
      email: member.email,
      role: "member",
    });
    const acceptedMember = await member.orgClient.organization.acceptInvitation({
      invitationId: invitedMember.data?.id ?? "",
    });
    const invitedRemovable = await owner.orgClient.organization.inviteMember({
      organizationId: organizationId ?? "",
      email: removable.email,
      role: "member",
    });
    const acceptedRemovable = await removable.orgClient.organization.acceptInvitation({
      invitationId: invitedRemovable.data?.id ?? "",
    });

    const ownerPermissions = await owner.orgClient.organization.hasPermission({
      organizationId,
      permissions: {
        invitation: ["create"],
        member: ["update"],
      },
    });

    const memberSetActive = await member.orgClient.organization.setActive({
      organizationId: organizationId ?? "",
    });
    const memberPermissionsBeforeRoleUpdate = await member.orgClient.organization.hasPermission({
      permissions: {
        member: ["delete"],
      },
    });

    const updateMemberRole = await owner.orgClient.organization.updateMemberRole({
      organizationId: organizationId ?? "",
      memberId: acceptedMember.data?.member.id ?? "",
      role: ["admin", "member"],
    });
    const removeMember = await owner.orgClient.organization.removeMember({
      organizationId: organizationId ?? "",
      memberIdOrEmail: removable.email,
    });
    const leaveOrganization = await member.orgClient.organization.leave({
      organizationId: organizationId ?? "",
    });

    return {
      organization: ctx.snapshot(organization),
      invitedMember: ctx.snapshot(invitedMember),
      acceptedMember: ctx.snapshot(acceptedMember),
      invitedRemovable: ctx.snapshot(invitedRemovable),
      acceptedRemovable: ctx.snapshot(acceptedRemovable),
      ownerPermissions: ctx.snapshot(ownerPermissions),
      memberSetActive: ctx.snapshot(memberSetActive),
      memberPermissionsBeforeRoleUpdate: ctx.snapshot(memberPermissionsBeforeRoleUpdate),
      updateMemberRole: ctx.snapshot(updateMemberRole),
      removeMember: ctx.snapshot(removeMember),
      leaveOrganization: ctx.snapshot(leaveOrganization),
    };
  },
);

compatScenario(
  "organization member role updates normalize string and array input without deduplicating roles",
  async (ctx) => {
    const owner = await signUpUser(ctx, "normalize-owner", "role-normalize-owner", "Owner");
    const target = await signUpUser(ctx, "normalize-target", "role-normalize-target", "Target");
    const created = await owner.orgClient.organization.create({
      name: "Normalize",
      slug: ctx.uniqueToken("normalize"),
    });
    expect(created.error).toBeNull();

    const organizationId = z.object({ id: z.string() }).parse(created.data).id;

    const invited = await owner.orgClient.organization.inviteMember({
      organizationId,
      email: target.email,
      role: "member",
    });
    expect(invited.error).toBeNull();

    const invitationId = z.object({ id: z.string() }).parse(invited.data).id;
    const accepted = await target.orgClient.organization.acceptInvitation({ invitationId });
    expect(accepted.error).toBeNull();

    const memberId = z.object({ member: z.object({ id: z.string() }) }).parse(accepted.data)
      .member.id;

    const observations = [];

    for (const [role, expected] of [
      ["  admin , member, ,admin  ", "admin,member,admin"],
      [[" admin ,member ", "", " admin"], "admin,member,admin"],
      [" member ", "member"],
    ] as const) {
      const result = await owner.orgClient.organization.updateMemberRole({
        organizationId,
        memberId,
        role: role as never,
      });
      expect(result.error).toBeNull();
      expect(result.data).toHaveProperty("role", expected);

      const stored = await ctx.rawRequest({
        path: `/__test/organization-creation-state?email=${encodeURIComponent(target.email)}`,
      });
      expect(stored.status).toBe(200);
      expect(
        z
          .object({
            organizations: z.array(z.object({ id: z.string(), role: z.string() }).passthrough()),
          })
          .parse(stored.body)
          .organizations.find((row) => row.id === organizationId),
      ).toHaveProperty("role", expected);

      observations.push({ result: ctx.snapshot(result), stored });
    }

    return {
      created: ctx.snapshot(created),
      invited: ctx.snapshot(invited),
      accepted: ctx.snapshot(accepted),
      observations,
    };
  },
  ["POST /organization/update-member-role"],
);
