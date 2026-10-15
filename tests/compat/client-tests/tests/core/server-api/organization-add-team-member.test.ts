import { expect } from "vitest";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

compatScenario(
  "server team membership lifecycle requires headers and persists admission and removal",
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
    async function invoke(
      body: Record<string, unknown>,
      headers?: Record<string, string>,
      operation = "server-add-team-member",
    ) {
      return ctx.rawRequest({
        path: "/__test/organization-api",
        method: "POST",
        json: {
          profile,
          operation,
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
    for (const operation of ["server-add-team-member", "server-remove-team-member"]) {
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
        const result = await invoke(body, headers, operation);
        expect(result.status).toBe(status);
        expect((result.body as { code: string }).code).toBe(code);
        denied.push(result);
      }
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
    const removed = await invoke(
      { teamId: team.id, userId },
      owner.headers,
      "server-remove-team-member",
    );
    expect(removed.status).toBe(200);
    expect(removed.body).toEqual({ message: "Team member removed successfully." });
    const cleared = await state();
    expect(cleared).toEqual(before);
    const replay = await invoke(
      { teamId: team.id, userId },
      owner.headers,
      "server-remove-team-member",
    );
    expect(replay.status).toBe(400);
    expect((replay.body as { code: string }).code).toBe("USER_IS_NOT_A_MEMBER_OF_THE_TEAM");
    expect(await state()).toEqual(cleared);
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
      removed,
      cleared,
      replay,
    });
  },
);
