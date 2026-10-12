import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

compatScenario(
  "server updateTeam requires headers and preserves explicit and active organization scope",
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
    const owner = await signup("team-update-owner");
    const outsider = await signup("team-update-outsider");
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
    const teams: Array<{ id: string; createdAt: string }> = [];
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
    async function invoke(body: Record<string, unknown>, headers?: Record<string, string>) {
      return ctx.rawRequest({
        path: "/__test/organization-api",
        method: "POST",
        json: { profile, operation: "server-update-team", body, ...(headers ? { headers } : {}) },
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
            ).body as { teams: unknown[]; members: unknown; teamMembers: unknown },
        ),
      );
    }
    const before = await state();
    const rejected = {
      teamId: teams[0]!.id,
      data: { name: "Rejected", organizationId: organizations[0]!.id },
    };
    const denied = [];
    for (const [body, headers, status, code] of [
      [rejected, undefined, 400, "VALIDATION_ERROR"],
      [rejected, {}, 401, "UNAUTHORIZED"],
      [rejected, outsider.headers, 403, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM"],
      [
        { teamId: teams[0]!.id, data: { name: "Rejected", organizationId: organizations[1]!.id } },
        owner.headers,
        400,
        "TEAM_NOT_FOUND",
      ],
      [
        { teamId: teams[0]!.id, data: { name: "", organizationId: organizations[0]!.id } },
        owner.headers,
        400,
        "VALIDATION_ERROR",
      ],
    ] as const) {
      const result = await invoke(body, headers);
      expect(result.status).toBe(status);
      expect((result.body as { code: string }).code).toBe(code);
      denied.push(result);
    }
    expect(await state()).toEqual(before);
    const updated = [];
    for (const index of [0, 1]) {
      const result = await invoke(
        {
          teamId: teams[index]!.id,
          data: {
            name: `Updated ${index}`,
            ...(index === 0 ? { organizationId: organizations[index]!.id } : {}),
          },
        },
        owner.headers,
      );
      expect(result.status).toBe(200);
      expect(result.body).toMatchObject({
        id: teams[index]!.id,
        name: `Updated ${index}`,
        organizationId: organizations[index]!.id,
        createdAt: teams[index]!.createdAt,
      });
      updated.push(result);
    }
    const after = await state();
    for (const index of [0, 1]) {
      expect(after[index]!.teams).toHaveLength(1);
      expect(after[index]!.teams[0]).toMatchObject(updated[index]!.body as Record<string, unknown>);
      expect(after[index]!.members).toEqual(before[index]!.members);
      expect(after[index]!.teamMembers).toEqual(before[index]!.teamMembers);
    }
    return ctx.snapshot({
      owner: owner.result,
      outsider: outsider.result,
      organizations,
      teams,
      before,
      denied,
      updated,
      after,
    });
  },
);
