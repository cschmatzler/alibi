import { expect } from "vitest";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

compatScenario(
  "canonical createOrgRole persists normalized permissions through a logical server call",
  async (ctx) => {
    const profile = "org-teams-dynamic";
    async function signup(name: string) {
      let cookie = "";
      const actor = ctx.actor(name, profile);
      const result = await actor.client.signUp.email({
        email: ctx.uniqueEmail(name),
        name,
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
      expect(result.error).toBeNull();
      return { actor, result, headers: { cookie } };
    }
    const owner = await signup("role-server-owner");
    const outsider = await signup("role-server-outsider");
    const created = await owner.actor.fetch(
      ctx.baseURL + authProfilePath(profile) + "/organization/create",
      {
        method: "POST",
        headers: { "content-type": "application/json", ...owner.headers },
        body: JSON.stringify({
          name: "Server role organization",
          slug: ctx.uniqueToken("server-role-org"),
        }),
      },
    );
    expect(created.status).toBe(200);
    const organization = await created.json();
    async function state() {
      const response = await ctx.rawRequest({
        path: `/__test/organization-state?${new URLSearchParams({ profile, organizationId: organization.id })}`,
      });
      expect(response.status).toBe(200);
      return response.body;
    }
    const before = await state();
    async function invoke(input: Record<string, unknown>) {
      return ctx.rawRequest({
        path: "/__test/organization-api",
        method: "POST",
        json: { operation: "server-create-role", profile, ...input },
      });
    }
    const permission = { team: ["create", "update"], member: ["update"] };
    const role = await invoke({
      body: {
        organizationId: organization.id,
        role: "TeamEditor",
        permission,
        id: "forged-role",
        createdAt: "2000-01-01",
      },
      headers: owner.headers,
    });
    expect(role.status).toBe(200);
    const result = role.body as {
      success: boolean;
      roleData: { id: string; role: string; organizationId: string; permission: unknown };
    };
    expect(result.success).toBe(true);
    expect(result.roleData).toMatchObject({
      role: "teameditor",
      organizationId: organization.id,
      permission,
    });
    expect(result.roleData.id).not.toBe("forged-role");
    const stored = await ctx.rawRequest({
      path: "/__test/organization-api",
      method: "POST",
      json: {
        operation: "stored-role",
        profile,
        organizationId: organization.id,
        roleId: result.roleData.id,
      },
    });
    expect(stored.status).toBe(200);
    expect(stored.body).toMatchObject({
      role: "teameditor",
      permission: JSON.stringify(permission),
    });
    const afterCreation = await state();
    const denials = [];
    for (const [input, status, code] of [
      [{ body: { role: "missing-headers", permission } }, 400, "VALIDATION_ERROR"],
      [{ body: { role: "empty-headers", permission }, headers: {} }, 401, "UNAUTHORIZED"],
      [
        {
          body: { organizationId: organization.id, role: "outside", permission },
          headers: outsider.headers,
        },
        403,
        "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
      ],
      [
        { body: { role: "TeamEditor", permission }, headers: owner.headers },
        400,
        "ROLE_NAME_IS_ALREADY_TAKEN",
      ],
      [
        { body: { role: "OWNER", permission: {} }, headers: owner.headers },
        400,
        "ROLE_NAME_IS_ALREADY_TAKEN",
      ],
      [
        {
          body: { role: "invalid-resource", permission: { invented: ["read"] } },
          headers: owner.headers,
        },
        400,
        "INVALID_RESOURCE",
      ],
    ] as const) {
      const denied = await invoke(input);
      expect(denied.status).toBe(status);
      expect((denied.body as { code: string }).code).toBe(code);
      denials.push(denied);
    }
    expect(await state()).toEqual(afterCreation);
    const active = await invoke({
      body: { role: "ActiveReader", permission: { ac: ["read"] } },
      headers: owner.headers,
    });
    expect(active.status).toBe(200);
    expect((active.body as { roleData: unknown }).roleData).toMatchObject({
      organizationId: organization.id,
      role: "activereader",
      permission: { ac: ["read"] },
    });
    const final = await state();
    return ctx.snapshot({
      owner: owner.result,
      outsider: outsider.result,
      organization,
      before,
      role,
      stored,
      afterCreation,
      denials,
      active,
      final,
    });
  },
);
