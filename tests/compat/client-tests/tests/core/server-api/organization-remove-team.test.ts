import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

compatScenario(
  "trusted removeTeam without a request prunes links and preserves the last team",
  async (ctx) => {
    const profile = "org-teams-no-default";
    const owner = ctx.actor("trusted-removal-owner", profile);
    let cookie = "";
    const signup = await owner.client.signUp.email({
      email: ctx.uniqueEmail("trusted-removal-owner"),
      name: "Trusted owner",
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
    expect(signup.error).toBeNull();
    async function http(path: string, body: Record<string, unknown>) {
      const response = await owner.fetch(ctx.baseURL + authProfilePath(profile) + path, {
        method: "POST",
        headers: { "content-type": "application/json", cookie },
        body: JSON.stringify(body),
      });
      expect(response.status).toBe(200);
      return response.json();
    }
    const organization = await http("/organization/create", {
      name: "Trusted removal",
      slug: ctx.uniqueToken("trusted-removal"),
    });
    const alpha = await http("/organization/create-team", {
      organizationId: organization.id,
      name: "Alpha",
    });
    const beta = await http("/organization/create-team", {
      organizationId: organization.id,
      name: "Beta",
    });
    const membership = await http("/organization/add-team-member", {
      teamId: alpha.id,
      userId: signup.data!.user.id,
    });
    const invitation = await http("/organization/invite-member", {
      organizationId: organization.id,
      email: ctx.uniqueEmail("trusted-removal-invitee"),
      role: "member",
      teamId: [alpha.id, beta.id],
    });
    async function invoke(body: Record<string, unknown>) {
      return ctx.rawRequest({
        path: "/__test/organization-api",
        method: "POST",
        json: { profile, operation: "server-remove-team", body },
      });
    }
    async function state() {
      return (
        await ctx.rawRequest({
          path: `/__test/organization-state?profile=${profile}&organizationId=${organization.id}`,
        })
      ).body as {
        teams: Array<{ id: string }>;
        members: unknown;
        teamMembers: unknown[];
        invitations: Array<{ teamId: string; status: string }>;
      };
    }
    const before = await state();
    const denied = [];
    for (const [body, code] of [
      [{ teamId: alpha.id }, "NO_ACTIVE_ORGANIZATION"],
      [{ teamId: alpha.id, organizationId: "" }, "NO_ACTIVE_ORGANIZATION"],
      [{ teamId: alpha.id, organizationId: "missing-organization" }, "TEAM_NOT_FOUND"],
      [{ teamId: "missing-team", organizationId: organization.id }, "TEAM_NOT_FOUND"],
    ] as const) {
      const result = await invoke(body);
      expect(result.status).toBe(400);
      expect((result.body as { code: string }).code).toBe(code);
      denied.push(result);
    }
    expect(await state()).toEqual(before);
    const removed = await invoke({ teamId: alpha.id, organizationId: organization.id });
    expect(removed.status).toBe(200);
    expect(removed.body).toEqual({ message: "Team removed successfully." });
    const after = await state();
    expect(after.teams.map((team) => team.id)).toEqual([beta.id]);
    expect(after.members).toEqual(before.members);
    expect(after.teamMembers).toEqual([]);
    expect(after.invitations).toHaveLength(1);
    expect(after.invitations[0]).toMatchObject({ teamId: beta.id, status: "pending" });
    const replay = [];
    for (const [teamId, code] of [
      [alpha.id, "TEAM_NOT_FOUND"],
      [beta.id, "UNABLE_TO_REMOVE_LAST_TEAM"],
    ]) {
      const result = await invoke({ teamId, organizationId: organization.id });
      expect(result.status).toBe(400);
      expect((result.body as { code: string }).code).toBe(code);
      replay.push(result);
    }
    expect(await state()).toEqual(after);
    return ctx.snapshot({
      signup,
      organization,
      alpha,
      beta,
      membership,
      invitation,
      before,
      denied,
      removed,
      after,
      replay,
    });
  },
);
