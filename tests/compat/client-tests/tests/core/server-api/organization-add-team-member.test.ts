import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

compatScenario(
  "server addTeamMember requires headers and persists idempotent admission",
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
    const owner = await signup("team-admission-owner");
    const outsider = await signup("team-admission-outsider");
    async function http(path: string, body: Record<string, unknown>) {
      const response = await owner.actor.fetch(ctx.baseURL + authProfilePath(profile) + path, {
        method: "POST",
        headers: { "content-type": "application/json", ...owner.headers },
        body: JSON.stringify(body),
      });
      expect(response.status).toBe(200);
      return response.json();
    }
    const organization = await http("/organization/create", {
      name: "Team admission",
      slug: ctx.uniqueToken("team-admission"),
    });
    const team = await http("/organization/create-team", {
      name: "Admission",
      organizationId: organization.id,
    });
    const userId = owner.result.data!.user.id;
    async function invoke(body: Record<string, unknown>, headers?: Record<string, string>) {
      return ctx.rawRequest({
        path: "/__test/organization-api",
        method: "POST",
        json: {
          profile,
          operation: "server-add-team-member",
          body,
          ...(headers ? { headers } : {}),
        },
      });
    }
    async function state() {
      return (
        await ctx.rawRequest({
          path: `/__test/organization-state?profile=${profile}&organizationId=${organization.id}`,
        })
      ).body as { members: unknown; teamMembers: unknown[] };
    }
    const before = await state();
    const input = { teamId: team.id, userId, organizationId: organization.id };
    const denied = [];
    for (const [body, headers, status, code] of [
      [input, undefined, 400, "VALIDATION_ERROR"],
      [input, {}, 401, "UNAUTHORIZED"],
      [input, outsider.headers, 400, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION"],
      [
        { ...input, userId: outsider.result.data!.user.id },
        owner.headers,
        400,
        "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
      ],
      [{ ...input, teamId: "missing-team" }, owner.headers, 400, "TEAM_NOT_FOUND"],
    ] as const) {
      const result = await invoke(body, headers);
      expect(result.status).toBe(status);
      expect((result.body as { code: string }).code).toBe(code);
      denied.push(result);
    }
    expect(await state()).toEqual(before);
    const admitted = await invoke({ teamId: team.id, userId }, owner.headers);
    expect(admitted.status).toBe(200);
    expect(admitted.body).toMatchObject({ teamId: team.id, userId });
    const after = await state();
    expect(after.members).toEqual(before.members);
    expect(after.teamMembers).toEqual([admitted.body]);
    const repeated = await invoke({ teamId: team.id, userId }, owner.headers);
    expect(repeated.status).toBe(200);
    expect(repeated.body).toEqual(admitted.body);
    expect(await state()).toEqual(after);
    return ctx.snapshot({
      owner: owner.result,
      outsider: outsider.result,
      organization,
      team,
      before,
      denied,
      admitted,
      after,
      repeated,
    });
  },
);
