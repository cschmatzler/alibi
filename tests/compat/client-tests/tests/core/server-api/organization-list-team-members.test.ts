import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

compatScenario(
  "server listTeamMembers preserves active selection and requires an actual team seat",
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
    const owner = await signup("team-read-owner");
    const outsider = await signup("team-read-outsider");
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
    const teams: Array<{ id: string }> = [];
    for (const name of ["first", "second"]) {
      const organization = await http("/organization/create", {
        name,
        slug: ctx.uniqueToken(name),
      });
      organizations.push(organization);
      teams.push(
        await http("/organization/create-team", { name, organizationId: organization.id }),
      );
    }
    const admitted = await http("/organization/add-team-member", {
      teamId: teams[0]!.id,
      userId,
      organizationId: organizations[0]!.id,
    });
    await http("/organization/set-active", { organizationId: organizations[0]!.id });
    await http("/organization/set-active-team", { teamId: teams[0]!.id });
    async function invoke(query?: Record<string, unknown>, headers?: Record<string, string>) {
      return ctx.rawRequest({
        path: "/__test/organization-api",
        method: "POST",
        json: {
          profile,
          operation: "server-list-team-members",
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
      [{ teamId: teams[0]!.id }, outsider.headers, 400, "USER_IS_NOT_A_MEMBER_OF_THE_TEAM"],
      [{ teamId: teams[1]!.id }, owner.headers, 400, "USER_IS_NOT_A_MEMBER_OF_THE_TEAM"],
      [{ teamId: "missing-team" }, owner.headers, 400, "TEAM_NOT_FOUND"],
      [undefined, outsider.headers, 400, "YOU_DO_NOT_HAVE_AN_ACTIVE_TEAM"],
    ] as const) {
      const result = await invoke(query, headers);
      expect(result.status).toBe(status);
      expect((result.body as { code: string }).code).toBe(code);
      denied.push(result);
    }
    const active = [];
    for (const query of [
      undefined,
      {},
      { teamId: "" },
      { organizationId: 42, userId: {}, ignored: true },
    ]) {
      const result = await invoke(query, owner.headers);
      expect(result.status).toBe(200);
      expect(result.body).toEqual([admitted]);
      active.push(result);
    }
    const explicit = await invoke({ teamId: teams[0]!.id }, owner.headers);
    expect(explicit.status).toBe(200);
    expect(explicit.body).toEqual([admitted]);
    const after = await state();
    expect(after).toEqual(before);
    return ctx.snapshot({
      owner: owner.result,
      outsider: outsider.result,
      organizations,
      teams,
      admitted,
      before,
      denied,
      active,
      explicit,
      after,
    });
  },
);
