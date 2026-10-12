import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

compatScenario(
  "server listUserTeams preserves cross-organization membership and authority",
  async (ctx) => {
    const profile = "org-teams-no-default";
    async function signup(name: string) {
      const actor = ctx.actor(name, profile);
      let cookie = "";
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
    const owner = await signup("user-teams-owner");
    const outsider = await signup("user-teams-outsider");
    const userId = owner.result.data!.user.id;
    async function http(path: string, body: Record<string, unknown>) {
      const response = await owner.actor.fetch(ctx.baseURL + authProfilePath(profile) + path, {
        method: "POST",
        headers: { "content-type": "application/json", ...owner.headers },
        body: JSON.stringify(body),
      });
      expect(response.status).toBe(200);
      return response.json();
    }
    const organizations: Array<{ id: string }> = [];
    const teams = [];
    for (const name of ["first", "second"]) {
      const organization = await http("/organization/create", {
        name,
        slug: ctx.uniqueToken(name),
      });
      const team = await http("/organization/create-team", {
        name,
        organizationId: organization.id,
      });
      await http("/organization/add-team-member", {
        teamId: team.id,
        userId,
        organizationId: organization.id,
      });
      organizations.push(organization);
      teams.push(team);
    }
    async function invoke(query?: Record<string, unknown>, headers?: Record<string, string>) {
      return ctx.rawRequest({
        path: "/__test/organization-api",
        method: "POST",
        json: {
          profile,
          operation: "server-list-user-teams",
          ...(query ? { query } : {}),
          ...(headers ? { headers } : {}),
        },
      });
    }
    async function state() {
      return Promise.all(
        organizations.map(
          async (organization) =>
            (
              await ctx.rawRequest({
                path: `/__test/organization-state?profile=${profile}&organizationId=${organization.id}`,
              })
            ).body,
        ),
      );
    }
    const before = await state();
    const denied = [];
    for (const [query, headers, status, code] of [
      [undefined, undefined, 400, "VALIDATION_ERROR"],
      [undefined, {}, 401, "UNAUTHORIZED"],
      [
        { organizationId: organizations[0]!.id },
        outsider.headers,
        403,
        "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
      ],
      [
        { userId: outsider.result.data!.user.id, organizationId: organizations[0]!.id },
        owner.headers,
        400,
        "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
      ],
      [
        { userId, organizationId: organizations[0]!.id },
        outsider.headers,
        403,
        "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
      ],
      [{ userId }, outsider.headers, 400, "NO_ACTIVE_ORGANIZATION"],
    ] as const) {
      const result = await invoke(query, headers);
      expect(result.status).toBe(status);
      expect((result.body as { code: string }).code).toBe(code);
      denied.push(result);
    }
    const all = [];
    for (const query of [
      undefined,
      {},
      { organizationId: "", userId: "" },
      { teamId: 42, ignored: { nested: true } },
    ]) {
      const result = await invoke(query, owner.headers);
      expect(result.status).toBe(200);
      expect(result.body).toEqual(teams);
      all.push(result);
    }
    const scoped = await invoke({ organizationId: organizations[0]!.id }, owner.headers);
    expect(scoped.status).toBe(200);
    expect(scoped.body).toEqual([teams[0]]);
    const empty = await invoke(undefined, outsider.headers);
    expect(empty.status).toBe(200);
    expect(empty.body).toEqual([]);
    const after = await state();
    expect(after).toEqual(before);
    return ctx.snapshot({
      owner: owner.result,
      outsider: outsider.result,
      organizations,
      teams,
      before,
      denied,
      all,
      scoped,
      empty,
      after,
    });
  },
);
