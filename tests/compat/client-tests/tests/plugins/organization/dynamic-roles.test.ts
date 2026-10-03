import { expect } from "bun:test";

import { apiKeyClient } from "@better-auth/api-key/client";
import { createAuthClient } from "better-auth/client";
import { z } from "zod";

import type { FixtureProfile } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import {
  data,
  orgActor,
  serverOperation,
  signUp as teamSignUp,
  state as teamState,
} from "./helpers";

type Context = Parameters<Parameters<typeof compatScenario>[1]>[0];

const profile = "org-teams-dynamic";

async function raw(
  ctx: Context,
  actor: string,
  selected: FixtureProfile,
  path: string,
  json?: unknown,
  method = "POST",
  rawBody?: string,
) {
  const response = await ctx.actor(actor, selected).fetch(`/api/auth${path}`, {
    method,
    ...(json === undefined && rawBody === undefined
      ? {}
      : { headers: { "content-type": "application/json" }, body: rawBody ?? JSON.stringify(json) }),
  });
  const text = await response.text();
  let body: unknown = null;

  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
  }

  return { status: response.status, body };
}

const seededRole = z.object({ roleId: z.string(), organizationId: z.string(), role: z.string() });

const signUp: typeof teamSignUp = (ctx, name) => teamSignUp(ctx, name, "org-teams-dynamic");
const state: typeof teamState = (ctx, id) => teamState(ctx, id, "org-teams-dynamic");

compatScenario(
  "organization dynamic roles persist ordered permissions and revoke assigned authority on update",
  async (ctx) => {
    const owner = await signUp(ctx, "role-owner");
    const member = await signUp(ctx, "role-member");
    const foreign = await signUp(ctx, "foreign-owner");

    const created = await owner.client.organization.create({
      name: "Role Org",
      slug: ctx.uniqueToken("role-org"),
    });
    const org = data(created);
    const foreignCreated = await foreign.client.organization.create({
      name: "Other Org",
      slug: ctx.uniqueToken("other-role-org"),
    });
    const foreignOrg = data(foreignCreated);

    const invitation = await owner.client.organization.inviteMember({
      email: member.email,
      role: "member",
    });
    const accepted = await member.client.organization.acceptInvitation({
      invitationId: data(invitation).id,
    });
    const memberId = data(accepted).member.id;

    const denied = await member.client.organization.createRole({
      role: "denied",
      permission: { team: ["create"] },
    });
    expect(denied.error).toMatchObject({
      status: 403,
      code: "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE",
    });

    const permission = { team: ["create", "update"], member: ["update"] };
    const role = await owner.client.organization.createRole({ role: "TeamEditor", permission });
    const roleData = data(role).roleData;
    expect(roleData).toMatchObject({
      role: "teameditor",
      organizationId: org.id,
      permission,
      updatedAt: null,
    });

    const persisted = await state(ctx, org.id);
    expect(persisted.parsed.roles[0]?.permission).toBe(JSON.stringify(permission));

    const wrongScope = await foreign.client.organization.getRole({
      query: { roleId: roleData.id, organizationId: foreignOrg.id },
    });
    expect(wrongScope.error).toMatchObject({ status: 400, code: "ROLE_NOT_FOUND" });

    const invalidResource = await owner.client.organization.createRole({
      role: "invalid-resource",
      permission: { invented: ["read"] },
    });
    expect(invalidResource.error).toMatchObject({ status: 400, code: "INVALID_RESOURCE" });

    const predefined = await owner.client.organization.createRole({
      role: "OWNER",
      permission: {},
    });
    expect(predefined.error).toMatchObject({ status: 400, code: "ROLE_NAME_IS_ALREADY_TAKEN" });

    const assigned = await owner.client.organization.updateMemberRole({
      memberId,
      role: "teameditor",
    });
    data(assigned);
    const hasPermission = await member.client.organization.hasPermission({
      permissions: { team: ["create"], member: ["update"] },
    });
    expect(data(hasPermission).success).toBe(true);

    const team = await member.client.organization.createTeam({ name: "Delegated" });
    data(team);

    const assignedDelete = await owner.client.organization.deleteRole({ roleId: roleData.id });
    expect(assignedDelete.error).toMatchObject({
      status: 400,
      code: "ROLE_IS_ASSIGNED_TO_MEMBERS",
    });

    const unknownRole = await owner.client.organization.updateMemberRole({
      memberId,
      role: "missing",
    });
    expect(unknownRole.error).toMatchObject({
      status: 400,
      code: "ROLE_NOT_FOUND",
      message: "ROLE_NOT_FOUND: missing",
    });

    const updated = await owner.client.organization.updateRole({
      roleId: roleData.id,
      data: { permission: { team: ["update"] } },
    });
    expect(data(updated).roleData.updatedAt).toBeNull();

    const read = await owner.client.organization.getRole({ query: { roleName: "teameditor" } });
    expect(data(read).updatedAt).not.toBeNull();
    expect(data(read).permission).toEqual({ team: ["update"] });

    const revoked = await member.client.organization.createTeam({ name: "Revoked" });
    expect(revoked.error).toMatchObject({
      status: 403,
      code: "YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION",
    });

    const list = await owner.client.organization.listRoles();
    expect(data(list)).toHaveLength(1);

    const reset = await owner.client.organization.updateMemberRole({ memberId, role: "member" });
    data(reset);
    const deleted = await owner.client.organization.deleteRole({ roleName: "teameditor" });
    expect(data(deleted).success).toBe(true);

    const afterDelete = await state(ctx, org.id);
    expect(afterDelete.parsed.roles).toEqual([]);

    return {
      created,
      foreignCreated,
      invitation,
      accepted,
      denied,
      role,
      persisted: persisted.raw,
      wrongScope,
      invalidResource,
      predefined,
      assigned,
      hasPermission,
      team,
      assignedDelete,
      unknownRole,
      updated,
      read,
      revoked,
      list,
      reset,
      deleted,
      afterDelete: afterDelete.raw,
    };
  },
  [
    "POST /organization/create-role",
    "POST /organization/update-role",
    "POST /organization/delete-role",
    "GET /organization/get-role",
    "GET /organization/list-roles",
  ],
);

compatScenario(
  "organization role configuration preserves static quotas and missing access-control behavior",
  async (ctx) => {
    const disabled = [];

    for (const [method, path, json] of [
      ["POST", "/organization/create-role", { role: "unavailable", permission: {} }],
      ["POST", "/organization/update-role", { roleId: "unavailable", data: {} }],
      ["POST", "/organization/delete-role", { roleId: "unavailable" }],
      ["GET", "/organization/get-role?roleId=unavailable", undefined],
      ["GET", "/organization/list-roles", undefined],
    ] as const) {
      const response = await raw(ctx, "disabled-role-actor", "org-teams", path, json, method);
      expect(response.status).toBe(404);
      disabled.push(response);
    }

    const limited = await teamSignUp(ctx, "limited-role-owner", "org-roles-limited");
    const created = await limited.client.organization.create({
      name: "Limited roles",
      slug: ctx.uniqueToken("limited-roles"),
    });
    const organizationId = data(created).id;

    const first = await limited.client.organization.createRole({
      role: "First",
      permission: { team: ["create"] },
    });
    const roleId = data(first).roleData.id;
    const overflow = await limited.client.organization.createRole({
      role: "overflow",
      permission: { invented: ["read"] },
    });
    expect(overflow.error).toMatchObject({ status: 400, code: "TOO_MANY_ROLES" });

    const before = await teamState(ctx, organizationId, "org-roles-limited");
    expect(before.parsed.roles).toHaveLength(1);
    expect(before.parsed.roles[0]?.id).toBe(roleId);

    const deleted = await limited.client.organization.deleteRole({ roleId });
    data(deleted);
    const replacement = await limited.client.organization.createRole({
      role: "replacement",
      permission: {},
    });
    data(replacement);
    const after = await teamState(ctx, organizationId, "org-roles-limited");
    expect(after.parsed.roles.map((role) => role.role)).toEqual(["replacement"]);

    const noAc = await teamSignUp(ctx, "no-ac-role-owner", "org-roles-no-ac");
    const missingBeforeOrganization = await noAc.client.organization.createRole({
      role: "missing",
      permission: {},
    });
    expect(missingBeforeOrganization.error).toMatchObject({
      status: 501,
      code: "MISSING_AC_INSTANCE",
    });

    const noAcCreated = await noAc.client.organization.create({
      name: "Missing access control",
      slug: ctx.uniqueToken("missing-ac"),
    });
    const noAcId = data(noAcCreated).id;

    const seed = await serverOperation(
      ctx,
      {
        operation: "seed-role",
        organizationId: noAcId,
        role: "legacy",
        permission: { team: ["create"] },
      },
      "org-roles-no-ac",
    );
    expect(seed.status).toBe(200);

    const legacy = seededRole.parse(seed.body);

    const read = await noAc.client.organization.getRole({ query: { roleId: legacy.roleId } });
    expect(data(read).permission).toEqual({ team: ["create"] });

    const update = await noAc.client.organization.updateRole({
      roleId: legacy.roleId,
      data: { permission: {} },
    });
    expect(update.error).toMatchObject({ status: 501, code: "MISSING_AC_INSTANCE" });

    const unchanged = await teamState(ctx, noAcId, "org-roles-no-ac");
    expect(unchanged.parsed.roles[0]?.permission).toBe('{"team":["create"]}');
    expect(unchanged.parsed.roles[0]?.updatedAt).toBeNull();

    const list = await noAc.client.organization.listRoles();
    expect(data(list)).toHaveLength(1);

    const removed = await noAc.client.organization.deleteRole({ roleId: legacy.roleId });
    data(removed);
    const removedState = await teamState(ctx, noAcId, "org-roles-no-ac");
    expect(removedState.parsed.roles).toEqual([]);

    return {
      disabled,
      created,
      first,
      overflow,
      before: before.raw,
      deleted,
      replacement,
      after: after.raw,
      missingBeforeOrganization,
      noAcCreated,
      seed,
      read,
      update,
      unchanged: unchanged.raw,
      list,
      removed,
      removedState: removedState.raw,
    };
  },
  [],
  30_000,
  { oracle: { unroutedRequests: "asserts role routes are absent without dynamic access control" } },
);

compatScenario(
  "organization callback role quotas count every persisted row while role lists retain the configured adapter page",
  async (ctx) => {
    const selected = "org-roles-callback";
    const owner = await teamSignUp(ctx, "callback-role-owner", selected);

    const one = await owner.client.organization.create({
      name: "One role budget",
      slug: ctx.uniqueToken("one-role-budget"),
    });
    const two = await owner.client.organization.create({
      name: "Two role budget",
      slug: ctx.uniqueToken("two-role-budget"),
    });
    const oneId = data(one).id;
    const twoId = data(two).id;

    const created = [];

    for (const [organizationId, names] of [
      [oneId, ["one"]],
      [twoId, ["one", "two"]],
    ] as const) {
      for (const role of names) {
        const response = await owner.client.organization.createRole({
          organizationId,
          role,
          permission: {},
        });
        data(response);
        created.push(response);
      }
    }

    const lists = [];
    const rejected = [];

    for (const organizationId of [oneId, twoId]) {
      const response = await owner.client.organization.listRoles({ query: { organizationId } });
      expect(data(response)).toHaveLength(1);

      lists.push(response);
      const overflow = await owner.client.organization.createRole({
        organizationId,
        role: "overflow",
        permission: {},
      });
      expect(overflow.error).toMatchObject({ status: 400, code: "TOO_MANY_ROLES" });

      rejected.push(overflow);
    }

    const oneState = await teamState(ctx, oneId, selected);
    const twoState = await teamState(ctx, twoId, selected);
    expect(oneState.parsed.roles).toHaveLength(1);
    expect(twoState.parsed.roles).toHaveLength(2);

    const deleted = await owner.client.organization.deleteRole({
      organizationId: twoId,
      roleName: "two",
    });
    data(deleted);
    const replacement = await owner.client.organization.createRole({
      organizationId: twoId,
      role: "replacement",
      permission: {},
    });
    data(replacement);
    const after = await teamState(ctx, twoId, selected);
    expect(after.parsed.roles.map((role) => role.role)).toEqual(["one", "replacement"]);

    return {
      one,
      two,
      created,
      lists,
      rejected,
      oneState: oneState.raw,
      twoState: twoState.raw,
      deleted,
      replacement,
      after: after.raw,
    };
  },
);

compatScenario(
  "organization delegated grants follow overlapping permission cache reloads by organization and configured profile",
  async (ctx) => {
    const selected = "org-roles-callback";
    const owner = await teamSignUp(ctx, "cache-owner", selected);
    const member = await teamSignUp(ctx, "cache-member", selected);

    const created = await owner.client.organization.create({
      name: "Two role budget",
      slug: ctx.uniqueToken("pending-role-cache"),
    });
    const other = await owner.client.organization.create({
      name: "One role budget",
      slug: ctx.uniqueToken("other-role-cache"),
    });
    const organizationId = data(created).id;
    const otherId = data(other).id;

    const manager = await owner.client.organization.createRole({
      organizationId,
      role: "manager",
      permission: { ac: ["create"], team: ["create"] },
    });
    const managerId = data(manager).roleData.id;

    const invitation = await owner.client.organization.inviteMember({
      organizationId,
      email: member.email,
      role: "member",
    });
    const accepted = await member.client.organization.acceptInvitation({
      invitationId: data(invitation).id,
    });
    const assignment = await owner.client.organization.updateMemberRole({
      organizationId,
      memberId: data(accepted).member.id,
      role: "manager",
    });
    data(assignment);

    const alternate = orgActor(ctx, "cache-alternate-owner", "org-roles-no-ac");
    const signedIn = await alternate.signIn.email({ email: owner.email, password: "password123" });
    expect(data(signedIn).user.id).toBe(owner.user.id);

    const rounds = [];

    for (const mode of ["none", "other", "same", "other-profile", "other", "same"] as const) {
      const restored = await owner.client.organization.updateRole({
        organizationId,
        roleId: managerId,
        data: { permission: { ac: ["create"], team: ["create"] } },
      });
      data(restored);

      const arm = await serverOperation(
        ctx,
        { operation: "role-policy", organizationId, stage: "arm" },
        selected,
      );
      expect(arm).toEqual({ status: 200, body: { organizationId, stage: "arm" } });

      // Deliberately not awaited: the armed barrier holds this request inside the
      // role-limit callback until the release stage below.
      const pending = member.client.organization.createRole({
        organizationId,
        role: "delegated",
        permission: { team: ["create"] },
      });
      const entered = await serverOperation(
        ctx,
        { operation: "role-policy", organizationId, stage: "wait" },
        selected,
      );
      expect(entered).toEqual({ status: 200, body: { organizationId, stage: "wait" } });

      const revoked = await owner.client.organization.updateRole({
        organizationId,
        roleId: managerId,
        data: { permission: { ac: ["create"] } },
      });
      data(revoked);

      // Optionally reload the permission cache mid-flight: for another
      // organization, for this one, or for this one through another profile.
      const reloadClient = mode === "other-profile" ? alternate : owner.client;
      const reload =
        mode === "none"
          ? null
          : await reloadClient.organization.hasPermission({
              organizationId: mode === "other" ? otherId : organizationId,
              permissions: { team: ["create"] },
            });

      if (reload) {
        expect(data(reload).success).toBe(true);
      }

      const released = await serverOperation(
        ctx,
        { operation: "role-policy", organizationId, stage: "release" },
        selected,
      );
      expect(released).toEqual({ status: 200, body: { organizationId, stage: "release" } });

      const result = await pending;
      const rejected = mode === "same" || mode === "other-profile";

      if (rejected) {
        expect(result.error).toMatchObject({
          status: 403,
          code: "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE",
          missingPermissions: ["team:create"],
        });
      } else {
        expect(data(result).statements).toEqual({ team: ["create"] });
      }

      const persisted = await teamState(ctx, organizationId, selected);
      expect(persisted.parsed.roles.map((role) => role.role)).toEqual(
        rejected ? ["manager"] : ["manager", "delegated"],
      );
      expect(persisted.parsed.roles[0]?.permission).toBe('{"ac":["create"]}');

      const cleanup = rejected
        ? null
        : await owner.client.organization.deleteRole({ organizationId, roleName: "delegated" });

      if (cleanup) {
        expect(data(cleanup).success).toBe(true);
      }

      rounds.push({
        mode,
        restored,
        arm,
        entered,
        revoked,
        reload,
        released,
        result,
        persisted: persisted.raw,
        cleanup,
      });
    }

    const unchanged = await teamState(ctx, otherId, selected);
    expect(unchanged.parsed.roles).toEqual([]);

    return {
      created,
      other,
      manager,
      invitation,
      accepted,
      assignment,
      signedIn,
      rounds,
      unchanged: unchanged.raw,
    };
  },
);

compatScenario(
  "organization delegated roles enforce grant subsets and revoke organization API-key authority",
  async (ctx) => {
    const selected = "org-roles-delegated";
    const owner = await teamSignUp(ctx, "delegating-owner", selected);
    const member = await teamSignUp(ctx, "delegating-member", selected);
    await teamSignUp(ctx, "delegating-outsider", selected);

    const created = await owner.client.organization.create({
      name: "Delegation",
      slug: ctx.uniqueToken("delegation"),
    });
    const organizationId = data(created).id;

    const invitation = await owner.client.organization.inviteMember({
      email: member.email,
      role: ["delegator", "auditor"],
    });
    const accepted = await member.client.organization.acceptInvitation({
      invitationId: data(invitation).id,
    });
    const memberId = data(accepted).member.id;

    const combinedPermission = await member.client.organization.hasPermission({
      permissions: { team: ["create"], member: ["update"] },
    });
    expect(data(combinedPermission).success).toBe(false);

    const teamPermission = await member.client.organization.hasPermission({
      permissions: { team: ["create"] },
    });
    const memberPermission = await member.client.organization.hasPermission({
      permissions: { member: ["update"] },
    });
    expect(data(teamPermission).success).toBe(true);
    expect(data(memberPermission).success).toBe(true);

    const denied = await member.client.organization.createRole({
      role: "escalated",
      permission: { team: ["delete", "delete"], apiKey: ["create"] },
    });
    expect(denied.error).toMatchObject({
      status: 403,
      code: "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE",
      missingPermissions: ["team:delete", "team:delete", "apiKey:create"],
    });

    const delegated = await member.client.organization.createRole({
      role: "combined",
      permission: { team: ["create"], member: ["update"] },
    });
    expect(data(delegated).statements).toEqual({ team: ["create"], member: ["update"] });

    const keyRole = await owner.client.organization.createRole({
      role: "key-editor",
      permission: { apiKey: ["create", "read"] },
    });
    const keyRoleId = data(keyRole).roleData.id;
    const assigned = await owner.client.organization.updateMemberRole({
      memberId,
      role: "key-editor",
    });
    data(assigned);

    const keys = (actor: string) =>
      createAuthClient({
        baseURL: ctx.baseURL,
        plugins: [apiKeyClient()],
        fetchOptions: { customFetchImpl: ctx.actor(actor, selected).fetch },
      });
    const ownerKeys = keys("delegating-owner");
    const memberKeys = keys("delegating-member");
    const outsiderKeys = keys("delegating-outsider");

    const key = await memberKeys.apiKey.create({
      configId: "organization",
      organizationId,
      name: "delegated-key",
    });
    const keyData = data(key);
    expect(keyData.referenceId).toBe(organizationId);

    const read = await memberKeys.apiKey.get({
      query: { configId: "organization", id: keyData.id },
    });
    expect(data(read).id).toBe(keyData.id);

    const deleteDenied = await memberKeys.apiKey.delete({
      configId: "organization",
      keyId: keyData.id,
    });
    expect(deleteDenied.error).toMatchObject({
      status: 403,
      code: "INSUFFICIENT_API_KEY_PERMISSIONS",
    });

    const outsiderDenied = await outsiderKeys.apiKey.get({
      query: { configId: "organization", id: keyData.id },
    });
    expect(outsiderDenied.error).toMatchObject({ status: 403 });

    const revoked = await owner.client.organization.updateRole({
      roleId: keyRoleId,
      data: { permission: { apiKey: [] } },
    });
    data(revoked);

    const readRevoked = await memberKeys.apiKey.get({
      query: { configId: "organization", id: keyData.id },
    });
    const createRevoked = await memberKeys.apiKey.create({
      configId: "organization",
      organizationId,
      name: "revoked-key",
    });
    expect(readRevoked.error).toMatchObject({
      status: 403,
      code: "INSUFFICIENT_API_KEY_PERMISSIONS",
    });
    expect(createRevoked.error).toMatchObject({
      status: 403,
      code: "INSUFFICIENT_API_KEY_PERMISSIONS",
    });

    const retained = await ownerKeys.apiKey.get({
      query: { configId: "organization", id: keyData.id },
    });
    expect(data(retained).id).toBe(keyData.id);

    const deleted = await ownerKeys.apiKey.delete({ configId: "organization", keyId: keyData.id });
    expect(data(deleted).success).toBe(true);

    const finalState = await teamState(ctx, organizationId, selected);
    expect(finalState.parsed.roles.map((role) => role.role)).toEqual(["combined", "key-editor"]);
    expect(finalState.parsed.roles[1]?.permission).toBe('{"apiKey":[]}');

    return {
      created,
      invitation,
      accepted,
      combinedPermission,
      teamPermission,
      memberPermission,
      denied,
      delegated,
      keyRole,
      assigned,
      key,
      read,
      deleteDenied,
      outsiderDenied,
      revoked,
      readRevoked,
      createRevoked,
      retained,
      deleted,
      finalState: finalState.raw,
    };
  },
);

compatScenario(
  "organization role name selectors update and delete every legacy duplicate within the selected tenant",
  async (ctx) => {
    const owner = await signUp(ctx, "legacy-role-owner");
    const foreign = await signUp(ctx, "legacy-role-foreign");

    const created = await owner.client.organization.create({
      name: "Legacy roles",
      slug: ctx.uniqueToken("legacy-roles"),
    });
    const other = await foreign.client.organization.create({
      name: "Foreign legacy roles",
      slug: ctx.uniqueToken("foreign-legacy-roles"),
    });
    const organizationId = data(created).id;
    const otherId = data(other).id;

    const seeds = [];

    const permissionJsons = [
      '{ "team" : ["create", "create"], "member" : ["update"] }',
      '{ "member" : ["update"], "team" : ["delete"] }',
      '{ "team" : ["create"] }',
    ];
    for (const [index, orgId] of [organizationId, organizationId, otherId].entries()) {
      const seed = await serverOperation(
        ctx,
        {
          operation: "seed-role",
          organizationId: orgId,
          role: "legacy-editor",
          permission: JSON.parse(permissionJsons[index]!),
          permissionJson: permissionJsons[index],
        },
        profile,
      );
      expect(seed.status).toBe(200);
      seeds.push(seed);
    }

    const first = seededRole.parse(seeds[0]?.body);
    const second = seededRole.parse(seeds[1]?.body);

    const wrongScope = await foreign.client.organization.updateRole({
      organizationId,
      roleId: first.roleId,
      data: { permission: { team: ["delete"] } },
    });
    expect(wrongScope.error).toMatchObject({
      status: 403,
      code: "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
    });

    const beforeUpdates = await state(ctx, organizationId);
    expect(beforeUpdates.parsed.roles.map((role) => role.permission)).toEqual(
      permissionJsons.slice(0, 2),
    );

    const noOp = await owner.client.organization.updateRole({
      roleName: "legacy-editor",
      data: {},
    });
    expect(data(noOp).roleData.permission).toEqual(JSON.parse(permissionJsons[0]!));
    const afterNoOp = await state(ctx, organizationId);
    expect(afterNoOp.parsed.roles.map((role) => role.permission)).toEqual(
      permissionJsons.slice(0, 2),
    );

    const renamed = await owner.client.organization.updateRole({
      roleName: "legacy-editor",
      data: { roleName: "Renamed-Editor" },
    });
    expect(data(renamed).roleData.role).toBe("renamed-editor");
    const afterRename = await state(ctx, organizationId);
    expect(afterRename.parsed.roles.map((role) => role.role)).toEqual([
      "renamed-editor",
      "renamed-editor",
    ]);
    expect(afterRename.parsed.roles.map((role) => role.permission)).toEqual(
      permissionJsons.slice(0, 2),
    );

    const byId = await owner.client.organization.updateRole({
      roleId: first.roleId,
      data: { permission: { team: ["update"] } },
    });
    expect(new Date(data(byId).roleData.updatedAt!).toISOString()).toBe(
      afterRename.parsed.roles[0]?.updatedAt,
    );

    const afterId = await state(ctx, organizationId);
    expect(afterId.parsed.roles.map((role) => role.permission)).toEqual([
      '{"team":["update"]}',
      permissionJsons[1],
    ]);

    const byName = await owner.client.organization.updateRole({
      roleName: "renamed-editor",
      data: { permission: { member: ["update"] } },
    });
    expect(data(byName).roleData.id).toBe(first.roleId);

    const afterName = await state(ctx, organizationId);
    expect(afterName.parsed.roles.map((role) => role.permission)).toEqual([
      '{"member":["update"]}',
      '{"member":["update"]}',
    ]);
    expect(afterName.parsed.roles[0]?.updatedAt).not.toBeNull();
    expect(afterName.parsed.roles[0]?.updatedAt).toBe(afterName.parsed.roles[1]?.updatedAt);

    const foreignState = await state(ctx, otherId);
    expect(foreignState.parsed.roles[0]?.permission).toBe(permissionJsons[2]);
    expect(foreignState.parsed.roles[0]?.updatedAt).toBeNull();

    const removed = await owner.client.organization.deleteRole({ roleName: "renamed-editor" });
    data(removed);
    const removedState = await state(ctx, organizationId);
    expect(removedState.parsed.roles).toEqual([]);

    const replay = await owner.client.organization.deleteRole({ roleId: second.roleId });
    expect(replay.error).toMatchObject({ status: 400, code: "ROLE_NOT_FOUND" });

    const foreignAfter = await state(ctx, otherId);
    expect(foreignAfter.parsed.roles).toHaveLength(1);

    return {
      created,
      other,
      seeds,
      wrongScope,
      beforeUpdates: beforeUpdates.raw,
      noOp,
      afterNoOp: afterNoOp.raw,
      renamed,
      afterRename: afterRename.raw,
      byId,
      afterId: afterId.raw,
      byName,
      afterName: afterName.raw,
      foreignState: foreignState.raw,
      removed,
      removedState: removedState.raw,
      replay,
      foreignAfter: foreignAfter.raw,
    };
  },
);

compatScenario(
  "organization role validation and permission request unions retain authentication precedence and persisted state",
  async (ctx) => {
    const owner = await signUp(ctx, "role-validation-owner");
    const outsider = await signUp(ctx, "role-validation-outsider");

    const created = await owner.client.organization.create({
      name: "Validation",
      slug: ctx.uniqueToken("role-validation"),
    });
    const organizationId = data(created).id;

    const role = await owner.client.organization.createRole({
      role: "editor",
      permission: { team: ["create"] },
    });
    const roleId = data(role).roleData.id;

    const invalid = [];

    for (const [json, message] of [
      [
        { roleName: "", data: {} },
        "[body.roleName] Too small: expected string to have >=1 characters",
      ],
      [{ roleId: "", data: {} }, "[body.roleId] Too small: expected string to have >=1 characters"],
      [{ roleName: "", roleId: "", data: {} }, "[body] Invalid input"],
      [{ roleName: 123, data: {} }, "[body] Invalid input"],
      [
        { roleId, data: { permission: null } },
        "[body.data.permission] Invalid input: expected record, received null",
      ],
      [
        { roleId, data: { roleName: null } },
        "[body.data.roleName] Invalid input: expected string, received null",
      ],
      [
        { organizationId: null, roleId, data: {} },
        "[body.organizationId] Invalid input: expected string, received null",
      ],
      [
        { organizationId: 1, roleName: "", data: { permission: null, roleName: 1 } },
        "[body.organizationId] Invalid input: expected string, received number; [body.data.permission] Invalid input: expected record, received null; [body.data.roleName] Invalid input: expected string, received number; [body.roleName] Too small: expected string to have >=1 characters",
      ],
    ] as const) {
      const response = await raw(
        ctx,
        "role-validation-owner",
        profile,
        "/organization/update-role",
        json,
      );
      expect(response).toMatchObject({ status: 400, body: { code: "VALIDATION_ERROR", message } });
      invalid.push(response);
    }

    const invalidCreates = [];

    for (const text of ["", "{malformed"]) {
      const response = await raw(
        ctx,
        "role-validation-owner",
        profile,
        "/organization/create-role",
        undefined,
        "POST",
        text,
      );
      expect(response).toMatchObject({
        status: 400,
        body:
          text === ""
            ? {
                code: "VALIDATION_ERROR",
                message: "[body] Invalid input: expected object, received null",
              }
            : { code: "BAD_REQUEST", message: "Invalid JSON in request body" },
      });
      invalidCreates.push(response);
    }

    const noBody = await raw(ctx, "role-validation-owner", profile, "/organization/create-role");
    expect(noBody.status).toBe(400);

    invalidCreates.push(noBody);

    const integerResources = await raw(
      ctx,
      "role-validation-owner",
      profile,
      "/organization/create-role",
      undefined,
      "POST",
      '{"role":"extra","permission":{"2":[null],"1":[false],"team":[1]}}',
    );
    expect(integerResources).toMatchObject({
      status: 400,
      body: {
        code: "VALIDATION_ERROR",
        message:
          "[body.permission.1.0] Invalid input: expected string, received boolean; [body.permission.2.0] Invalid input: expected string, received null; [body.permission.team.0] Invalid input: expected string, received number",
      },
    });

    invalidCreates.push(integerResources);

    for (const [json, message] of [
      [
        { role: "extra", permission: {}, additionalFields: null },
        "[body.additionalFields] Invalid input: expected object, received null",
      ],
      [
        { role: "extra", permission: {}, additionalFields: 1 },
        "[body.additionalFields] Invalid input: expected object, received number",
      ],
      [
        { role: "extra", permission: {}, additionalFields: [] },
        "[body.additionalFields] Invalid input: expected object, received array",
      ],
      [
        { organizationId: null, role: 1, permission: null, additionalFields: 1 },
        "[body.organizationId] Invalid input: expected string, received null; [body.role] Invalid input: expected string, received number; [body.permission] Invalid input: expected record, received null; [body.additionalFields] Invalid input: expected object, received number",
      ],
      [
        { role: "extra", permission: { team: [null, 1], member: 1 } },
        "[body.permission.team.0] Invalid input: expected string, received null; [body.permission.team.1] Invalid input: expected string, received number; [body.permission.member] Invalid input: expected array, received number",
      ],
    ] as const) {
      const response = await raw(
        ctx,
        "role-validation-owner",
        profile,
        "/organization/create-role",
        json,
      );
      expect(response).toMatchObject({ status: 400, body: { code: "VALIDATION_ERROR", message } });
      invalidCreates.push(response);
    }

    const unchanged = await state(ctx, organizationId);
    expect(unchanged.parsed.roles[0]?.permission).toBe('{"team":["create"]}');
    expect(unchanged.parsed.roles[0]?.updatedAt).toBeNull();

    const selected = await raw(ctx, "role-validation-owner", profile, "/organization/update-role", {
      roleName: null,
      roleId,
      data: { permission: { team: ["update"] } },
    });
    expect(selected.status).toBe(200);

    const permissions = [];

    for (const [json, success] of [
      [{ permissions: {} }, false],
      [{ permissions: { team: [] } }, false],
      [{ permissions: { invented: [] } }, false],
      [{ permission: { team: ["create"] } }, false],
      [{ permissions: { team: ["create"] }, permission: null }, true],
      [{ permissions: null, permission: { team: ["create"] } }, false],
      [{ organizationId: "", permissions: { team: ["create"] } }, true],
    ] as const) {
      const response = await raw(
        ctx,
        "role-validation-owner",
        profile,
        "/organization/has-permission",
        json,
      );
      expect(response).toEqual({ status: 200, body: { error: null, success } });
      permissions.push(response);
    }

    const both = await raw(ctx, "role-validation-owner", profile, "/organization/has-permission", {
      permissions: { team: ["create"] },
      permission: { team: ["create"] },
    });
    expect(both).toMatchObject({
      status: 400,
      body: {
        code: "VALIDATION_ERROR",
        message: "[body] Invalid input: more than one option matched",
      },
    });

    const allInvalidPermissions = await raw(
      ctx,
      "role-validation-owner",
      profile,
      "/organization/has-permission",
      { organizationId: null, permissions: null, permission: null },
    );
    expect(allInvalidPermissions).toMatchObject({
      status: 400,
      body: {
        code: "VALIDATION_ERROR",
        message:
          "[body.organizationId] Invalid input: expected string, received null; [body] Invalid input",
      },
    });

    const outsiderDenied = await raw(
      ctx,
      "role-validation-outsider",
      profile,
      "/organization/has-permission",
      { organizationId, permissions: { team: ["create"] } },
    );
    expect(outsiderDenied).toMatchObject({
      status: 401,
      body: { code: "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION" },
    });

    const malformedWithoutSession = await raw(
      ctx,
      "unsigned-role-actor",
      profile,
      "/organization/create-role",
      { role: 123, permission: {} },
    );
    expect(malformedWithoutSession).toMatchObject({
      status: 400,
      body: {
        code: "VALIDATION_ERROR",
        message: "[body.role] Invalid input: expected string, received number",
      },
    });

    const unauthorized = await raw(
      ctx,
      "unsigned-role-actor",
      profile,
      "/organization/create-role",
      { role: "unsigned", permission: {} },
    );
    expect(unauthorized).toMatchObject({ status: 401, body: { code: "UNAUTHORIZED" } });

    const unsigned = orgActor(ctx, "unsigned-role-actor", profile);
    const unsignedRead = await unsigned.organization.getRole({ query: { organizationId, roleId } });
    const unsignedList = await unsigned.organization.listRoles({ query: { organizationId } });
    const unsignedUpdate = await unsigned.organization.updateRole({
      organizationId,
      roleId,
      data: { permission: { team: ["delete"] } },
    });
    const unsignedDelete = await unsigned.organization.deleteRole({ organizationId, roleId });

    for (const response of [unsignedRead, unsignedList, unsignedUpdate, unsignedDelete]) {
      expect(response.error).toMatchObject({ status: 401, code: "UNAUTHORIZED" });
    }

    const outsiderRead = await outsider.client.organization.getRole({
      query: { organizationId, roleId },
    });
    const outsiderList = await outsider.client.organization.listRoles({
      query: { organizationId },
    });

    for (const response of [outsiderRead, outsiderList]) {
      expect(response.error).toMatchObject({
        status: 403,
        code: "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
      });
    }

    const outsiderExisting = await outsider.client.organization.createRole({
      organizationId,
      role: "editor",
      permission: {},
    });
    expect(outsiderExisting.error).toMatchObject({
      status: 403,
      code: "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
    });

    const outsiderPredefined = await outsider.client.organization.createRole({
      organizationId,
      role: "OWNER",
      permission: {},
    });
    expect(outsiderPredefined.error).toMatchObject({
      status: 400,
      code: "ROLE_NAME_IS_ALREADY_TAKEN",
    });

    const invalidExisting = await owner.client.organization.createRole({
      role: "editor",
      permission: { invented: ["read"] },
    });
    expect(invalidExisting.error).toMatchObject({ status: 400, code: "INVALID_RESOURCE" });

    const unicodeRole = await raw(
      ctx,
      "role-validation-owner",
      profile,
      "/organization/create-role",
      { role: "ΟΣ", permission: {}, additionalFields: { ignored: "value" } },
    );
    expect(unicodeRole).toMatchObject({
      status: 200,
      body: { roleData: { role: "ος", permission: {} } },
    });

    const unicodeDuplicate = await owner.client.organization.createRole({
      role: "ος",
      permission: {},
    });
    expect(unicodeDuplicate.error).toMatchObject({
      status: 400,
      code: "ROLE_NAME_IS_ALREADY_TAKEN",
    });

    const unicodeRemoved = await owner.client.organization.deleteRole({ roleName: "ος" });
    data(unicodeRemoved);

    const finalState = await state(ctx, organizationId);
    expect(finalState.parsed.roles).toHaveLength(1);
    expect(finalState.parsed.roles[0]?.permission).toBe('{"team":["update"]}');

    return {
      created,
      role,
      invalid,
      invalidCreates,
      unchanged: unchanged.raw,
      selected,
      permissions,
      both,
      allInvalidPermissions,
      outsiderDenied,
      malformedWithoutSession,
      unauthorized,
      unsignedRead,
      unsignedList,
      unsignedUpdate,
      unsignedDelete,
      outsiderRead,
      outsiderList,
      outsiderExisting,
      outsiderPredefined,
      invalidExisting,
      unicodeRole,
      unicodeDuplicate,
      unicodeRemoved,
      finalState: finalState.raw,
    };
  },
);

compatScenario(
  "organization assigned-role deletion applies the configured adapter page and removes the deleted grant",
  async (ctx) => {
    const selected = "org-roles-callback";
    const owner = await teamSignUp(ctx, "page-role-owner", selected);
    const prefix = await teamSignUp(ctx, "page-role-prefix", selected);
    const assigned = await teamSignUp(ctx, "page-role-assigned", selected);

    const created = await owner.client.organization.create({
      name: "Two role budget",
      slug: ctx.uniqueToken("page-role-budget"),
    });
    const organizationId = data(created).id;

    const editor = await owner.client.organization.createRole({
      role: "editor",
      permission: { team: ["create"] },
    });
    const prefixRole = await owner.client.organization.createRole({
      role: "prefixeditor",
      permission: {},
    });
    const editorId = data(editor).roleData.id;
    data(prefixRole);

    const prefixInvitation = await owner.client.organization.inviteMember({
      email: prefix.email,
      role: "member",
    });
    const prefixAccepted = await prefix.client.organization.acceptInvitation({
      invitationId: data(prefixInvitation).id,
    });
    const prefixMemberId = data(prefixAccepted).member.id;

    // Reproduce a stored legacy assignment beyond the configured role lookup page.
    const legacyPrefix = await serverOperation(
      ctx,
      {
        operation: "set-member-role",
        organizationId,
        memberId: prefixMemberId,
        role: "prefixeditor",
      },
      selected,
    );
    expect(legacyPrefix).toEqual({
      status: 200,
      body: { memberId: prefixMemberId, organizationId, role: "prefixeditor" },
    });

    const assignedInvitation = await owner.client.organization.inviteMember({
      email: assigned.email,
      role: "editor",
    });
    const assignedAccepted = await assigned.client.organization.acceptInvitation({
      invitationId: data(assignedInvitation).id,
    });
    data(assignedAccepted);

    const before = await teamState(ctx, organizationId, selected);
    expect(before.parsed.members.map((member) => member.role)).toEqual([
      "owner",
      "prefixeditor",
      "editor",
    ]);

    const beforePermission = await assigned.client.organization.hasPermission({
      permissions: { team: ["create"] },
    });
    expect(data(beforePermission).success).toBe(true);

    const deleted = await owner.client.organization.deleteRole({ roleId: editorId });
    expect(data(deleted).success).toBe(true);

    const after = await teamState(ctx, organizationId, selected);
    expect(after.parsed.roles.map((role) => role.role)).toEqual(["prefixeditor"]);
    expect(after.parsed.members.map((member) => member.role)).toEqual([
      "owner",
      "prefixeditor",
      "editor",
    ]);

    const revoked = await assigned.client.organization.createTeam({ name: "Deleted role grant" });
    expect(revoked.error).toMatchObject({
      status: 403,
      code: "YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION",
    });

    const finalState = await teamState(ctx, organizationId, selected);
    expect(finalState.parsed.teams).toHaveLength(1);

    return {
      created,
      editor,
      prefixRole,
      prefixInvitation,
      prefixAccepted,
      legacyPrefix,
      assignedInvitation,
      assignedAccepted,
      before: before.raw,
      beforePermission,
      deleted,
      after: after.raw,
      revoked,
      finalState: finalState.raw,
    };
  },
);
