import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

compatScenario(
  "canonical organization role reads, listing and deletion preserve member authority and stored lifecycle",
  async (ctx) => {
    const profile = "org-teams-dynamic";
    async function signup(name: string) {
      let cookie = "";
      const actor = ctx.actor(name, profile);
      const user = await actor.client.signUp.email({
        name,
        email: ctx.uniqueEmail(name),
        password: "Password123!",
        fetchOptions: {
          onSuccess({ response }) {
            cookie = response.headers
              .getSetCookie()
              .map((raw) => raw.split(";")[0])
              .join("; ");
          },
        },
      });
      expect(user.error).toBeNull();
      return { actor, user, headers: { cookie } };
    }
    const owner = await signup("role-read-owner");
    const member = await signup("role-read-member");
    const outsider = await signup("role-read-outsider");
    async function http(actor: typeof owner, path: string, body: Record<string, unknown>) {
      const response = await actor.actor.fetch(ctx.baseURL + authProfilePath(profile) + path, {
        method: "POST",
        headers: { "content-type": "application/json", ...actor.headers },
        body: JSON.stringify(body),
      });
      expect(response.status).toBe(200);
      return response.json();
    }
    const first = await http(owner, "/organization/create", {
      name: "First role organization",
      slug: ctx.uniqueToken("first-read-org"),
    });
    const firstRole = await http(owner, "/organization/create-role", {
      role: "FirstReader",
      permission: { ac: ["read"] },
    });
    const invitation = await http(owner, "/organization/invite-member", {
      email: member.user.data!.user.email,
      role: "member",
    });
    const accepted = await http(member, "/organization/accept-invitation", {
      invitationId: invitation.id,
    });
    const teamOnly = await http(owner, "/organization/create-role", {
      role: "TeamOnly",
      permission: { team: ["create"] },
    });
    await http(owner, "/organization/update-member-role", {
      memberId: accepted.member.id,
      role: "teamonly",
    });
    const second = await http(owner, "/organization/create", {
      name: "Second role organization",
      slug: ctx.uniqueToken("second-read-org"),
    });
    const secondRole = await http(owner, "/organization/create-role", {
      role: "SecondReader",
      permission: { team: ["create"] },
    });
    const emptyOrganization = await http(owner, "/organization/create", {
      name: "Empty role organization",
      slug: ctx.uniqueToken("empty-role-org"),
    });
    await http(owner, "/organization/set-active", { organizationId: second.id });
    async function state(id: string) {
      const response = await ctx.rawRequest({
        path: `/__test/organization-state?${new URLSearchParams({ profile, organizationId: id })}`,
      });
      expect(response.status).toBe(200);
      return response.body;
    }
    const before = [
      await state(first.id),
      await state(second.id),
      await state(emptyOrganization.id),
    ];
    async function invoke(input: Record<string, unknown>) {
      return ctx.rawRequest({
        path: "/__test/organization-api",
        method: "POST",
        json: { profile, operation: "server-get-role", ...input },
      });
    }
    const reads = [];
    for (const [query, role] of [
      [{ organizationId: first.id, roleId: firstRole.roleData.id }, firstRole.roleData],
      [{ organizationId: first.id, roleName: "firstreader" }, firstRole.roleData],
      [{ roleName: "secondreader" }, secondRole.roleData],
      [
        { organizationId: first.id, roleName: "firstreader", roleId: "wrong-id" },
        firstRole.roleData,
      ],
      [
        { organizationId: first.id, roleName: "", roleId: firstRole.roleData.id },
        firstRole.roleData,
      ],
    ] as const) {
      const response = await invoke({ query, headers: owner.headers });
      expect(response.status).toBe(200);
      expect(response.body).toEqual(role);
      reads.push(response);
    }
    const denials = [];
    for (const [input, status, code] of [
      [{ query: { roleId: firstRole.roleData.id } }, 400, "VALIDATION_ERROR"],
      [{ query: { roleId: firstRole.roleData.id }, headers: {} }, 401, "UNAUTHORIZED"],
      [
        {
          query: { organizationId: first.id, roleId: firstRole.roleData.id },
          headers: outsider.headers,
        },
        403,
        "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
      ],
      [
        {
          query: { organizationId: first.id, roleId: firstRole.roleData.id },
          headers: member.headers,
        },
        403,
        "YOU_ARE_NOT_ALLOWED_TO_READ_A_ROLE",
      ],
      [
        {
          query: { organizationId: second.id, roleId: firstRole.roleData.id },
          headers: owner.headers,
        },
        400,
        "ROLE_NOT_FOUND",
      ],
      [{ query: { roleName: "missing-role" }, headers: owner.headers }, 400, "ROLE_NOT_FOUND"],
      [{ query: { roleName: "SecondReader" }, headers: owner.headers }, 400, "ROLE_NOT_FOUND"],
      [
        {
          query: {
            organizationId: first.id,
            roleName: "missing-role",
            roleId: firstRole.roleData.id,
          },
          headers: owner.headers,
        },
        400,
        "ROLE_NOT_FOUND",
      ],
    ] as const) {
      const response = await invoke(input);
      expect(response.status).toBe(status);
      expect((response.body as { code: string }).code).toBe(code);
      denials.push(response);
    }
    const lists = [];
    for (const [input, expected] of [
      [
        { query: { organizationId: first.id, roleName: 7, roleId: ["ignored"] } },
        [firstRole.roleData, teamOnly.roleData],
      ],
      [{}, [secondRole.roleData]],
      [{ query: {} }, [secondRole.roleData]],
      [{ query: { organizationId: emptyOrganization.id } }, []],
    ] as const) {
      const response = await invoke({
        operation: "server-list-roles",
        ...input,
        headers: owner.headers,
      });
      expect(response.status).toBe(200);
      expect(response.body).toEqual(expected);
      lists.push(response);
    }
    const listDenials = [];
    for (const [input, status, code] of [
      [{ query: { organizationId: first.id } }, 400, "VALIDATION_ERROR"],
      [{ headers: {} }, 401, "UNAUTHORIZED"],
      [{ headers: outsider.headers }, 400, "NO_ACTIVE_ORGANIZATION"],
      [
        { query: { organizationId: first.id }, headers: outsider.headers },
        403,
        "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
      ],
      [
        { query: { organizationId: first.id }, headers: member.headers },
        403,
        "YOU_ARE_NOT_ALLOWED_TO_LIST_A_ROLE",
      ],
      [{ query: { organizationId: "" }, headers: owner.headers }, 400, "NO_ACTIVE_ORGANIZATION"],
    ] as const) {
      const response = await invoke({ operation: "server-list-roles", ...input });
      expect(response.status).toBe(status);
      expect((response.body as { code: string }).code).toBe(code);
      listDenials.push(response);
    }
    const after = [
      await state(first.id),
      await state(second.id),
      await state(emptyOrganization.id),
    ];
    expect(after).toEqual(before);
    const updateDenials = [];
    for (const [input, status, code] of [
      [{ body: { roleId: firstRole.roleData.id, data: {} } }, 400, "VALIDATION_ERROR"],
      [{ body: { roleId: firstRole.roleData.id, data: {} }, headers: {} }, 401, "UNAUTHORIZED"],
      [
        {
          body: { organizationId: first.id, roleId: firstRole.roleData.id, data: {} },
          headers: outsider.headers,
        },
        403,
        "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
      ],
      [
        {
          body: { organizationId: first.id, roleId: firstRole.roleData.id, data: {} },
          headers: member.headers,
        },
        403,
        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE",
      ],
      [
        {
          body: { organizationId: second.id, roleId: firstRole.roleData.id, data: {} },
          headers: owner.headers,
        },
        400,
        "ROLE_NOT_FOUND",
      ],
      [
        {
          body: {
            organizationId: first.id,
            roleId: firstRole.roleData.id,
            data: { roleName: "owner" },
          },
          headers: owner.headers,
        },
        400,
        "ROLE_NAME_IS_ALREADY_TAKEN",
      ],
      [
        {
          body: {
            organizationId: first.id,
            roleId: firstRole.roleData.id,
            data: { roleName: "teamonly" },
          },
          headers: owner.headers,
        },
        400,
        "ROLE_NAME_IS_ALREADY_TAKEN",
      ],
      [
        {
          body: {
            organizationId: first.id,
            roleId: firstRole.roleData.id,
            data: { permission: { invented: ["read"] } },
          },
          headers: owner.headers,
        },
        400,
        "INVALID_RESOURCE",
      ],
    ] as const) {
      const response = await invoke({ operation: "server-update-role", ...input });
      expect(response.status).toBe(status);
      expect((response.body as { code: string }).code).toBe(code);
      updateDenials.push(response);
    }
    expect([
      await state(first.id),
      await state(second.id),
      await state(emptyOrganization.id),
    ]).toEqual(before);
    const updatedById = await invoke({
      operation: "server-update-role",
      body: {
        organizationId: first.id,
        roleId: firstRole.roleData.id,
        data: { roleName: "FirstRenamed", permission: { team: ["create"] }, id: "forged" },
      },
      headers: owner.headers,
    });
    expect(updatedById.status).toBe(200);
    expect(updatedById.body).toMatchObject({
      success: true,
      roleData: {
        id: firstRole.roleData.id,
        organizationId: first.id,
        role: "firstrenamed",
        permission: { team: ["create"] },
      },
    });
    const updatedRead = await invoke({
      query: { organizationId: first.id, roleId: firstRole.roleData.id },
      headers: owner.headers,
    });
    expect(updatedRead.status).toBe(200);
    expect(updatedRead.body).toMatchObject({
      id: firstRole.roleData.id,
      role: "firstrenamed",
      permission: { team: ["create"] },
    });
    const updatedByName = await invoke({
      operation: "server-update-role",
      body: { roleName: "secondreader", data: { roleName: "SecondRenamed" } },
      headers: owner.headers,
    });
    expect(updatedByName.status).toBe(200);
    expect(updatedByName.body).toMatchObject({
      success: true,
      roleData: {
        id: secondRole.roleData.id,
        organizationId: second.id,
        role: "secondrenamed",
        permission: { team: ["create"] },
      },
    });
    const beforeDeletion = [
      await state(first.id),
      await state(second.id),
      await state(emptyOrganization.id),
    ];
    const deleteDenials = [];
    for (const [input, status, code] of [
      [{ body: { roleId: firstRole.roleData.id } }, 400, "VALIDATION_ERROR"],
      [{ body: { roleId: firstRole.roleData.id }, headers: {} }, 401, "UNAUTHORIZED"],
      [
        {
          body: { organizationId: first.id, roleId: firstRole.roleData.id },
          headers: outsider.headers,
        },
        403,
        "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
      ],
      [
        {
          body: { organizationId: first.id, roleId: firstRole.roleData.id },
          headers: member.headers,
        },
        403,
        "YOU_ARE_NOT_ALLOWED_TO_DELETE_A_ROLE",
      ],
      [
        {
          body: { organizationId: first.id, roleId: teamOnly.roleData.id },
          headers: owner.headers,
        },
        400,
        "ROLE_IS_ASSIGNED_TO_MEMBERS",
      ],
      [
        { body: { roleName: "owner" }, headers: owner.headers },
        400,
        "CANNOT_DELETE_A_PRE_DEFINED_ROLE",
      ],
      [
        {
          body: { organizationId: second.id, roleId: firstRole.roleData.id },
          headers: owner.headers,
        },
        400,
        "ROLE_NOT_FOUND",
      ],
      [
        {
          body: {
            organizationId: first.id,
            roleName: "missing-role",
            roleId: firstRole.roleData.id,
          },
          headers: owner.headers,
        },
        400,
        "ROLE_NOT_FOUND",
      ],
    ] as const) {
      const response = await invoke({ operation: "server-delete-role", ...input });
      expect(response.status).toBe(status);
      expect((response.body as { code: string }).code).toBe(code);
      deleteDenials.push(response);
    }
    expect([
      await state(first.id),
      await state(second.id),
      await state(emptyOrganization.id),
    ]).toEqual(beforeDeletion);
    const deletedById = await invoke({
      operation: "server-delete-role",
      body: { organizationId: first.id, roleId: firstRole.roleData.id, id: "forged" },
      headers: owner.headers,
    });
    expect(deletedById.status).toBe(200);
    expect(deletedById.body).toEqual({ success: true });
    const missing = await invoke({
      query: { organizationId: first.id, roleId: firstRole.roleData.id },
      headers: owner.headers,
    });
    expect(missing.status).toBe(400);
    expect((missing.body as { code: string }).code).toBe("ROLE_NOT_FOUND");
    const deletedByName = await invoke({
      operation: "server-delete-role",
      body: { roleName: "secondrenamed" },
      headers: owner.headers,
    });
    expect(deletedByName.status).toBe(200);
    expect(deletedByName.body).toEqual({ success: true });
    const repeated = await invoke({
      operation: "server-delete-role",
      body: { roleName: "secondrenamed" },
      headers: owner.headers,
    });
    expect(repeated.status).toBe(400);
    expect((repeated.body as { code: string }).code).toBe("ROLE_NOT_FOUND");
    const final = [
      await state(first.id),
      await state(second.id),
      await state(emptyOrganization.id),
    ] as { roles: { id: string }[] }[];
    expect(final[0]!.roles.map((role) => role.id)).toEqual([teamOnly.roleData.id]);
    expect(final[1]!.roles).toEqual([]);
    expect(final[2] as unknown).toEqual(before[2]);
    for (const index of [0, 1]) {
      const { roles: _roles, ...remaining } = final[index]!;
      const { roles: _beforeRoles, ...prior } = before[index] as Record<string, unknown>;
      expect(remaining).toEqual(prior);
    }
    return ctx.snapshot({
      owner: owner.user,
      member: member.user,
      outsider: outsider.user,
      first,
      firstRole,
      second,
      secondRole,
      before,
      reads,
      denials,
      teamOnly,
      emptyOrganization,
      lists,
      listDenials,
      after,
      updateDenials,
      updatedById,
      updatedRead,
      updatedByName,
      beforeDeletion,
      deleteDenials,
      deletedById,
      missing,
      deletedByName,
      repeated,
      final,
    });
  },
);
