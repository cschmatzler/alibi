import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

compatScenario(
  "trusted createTeam without a request preserves storage and configured limits",
  async (ctx) => {
    const profile = "org-numeric-fixed-fraction";
    const owner = ctx.actor("trusted-team-owner", profile);
    let cookie = "";
    const signup = await owner.client.signUp.email({
      email: ctx.uniqueEmail("trusted-team-owner"),
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
    const response = await owner.fetch(
      ctx.baseURL + authProfilePath(profile) + "/organization/create",
      {
        method: "POST",
        headers: { "content-type": "application/json", cookie },
        body: JSON.stringify({ name: "Trusted teams", slug: ctx.uniqueToken("trusted-teams") }),
      },
    );
    expect(response.status).toBe(200);
    const organization = await response.json();
    async function invoke(body: Record<string, unknown>) {
      return ctx.rawRequest({
        path: "/__test/organization-api",
        method: "POST",
        json: { profile, operation: "server-create-team", body },
      });
    }
    async function state() {
      return (
        await ctx.rawRequest({
          path: `/__test/organization-state?profile=${profile}&organizationId=${organization.id}`,
        })
      ).body as {
        teams: Array<{ id: string; name: string }>;
        members: unknown;
        teamMembers: unknown;
      };
    }
    const before = await state();
    const denied = [];
    for (const [body, code] of [
      [{ name: "Rejected" }, "NO_ACTIVE_ORGANIZATION"],
      [{ name: "Rejected", organizationId: "" }, "NO_ACTIVE_ORGANIZATION"],
      [{ name: "Rejected", organizationId: "missing-organization" }, "ORGANIZATION_NOT_FOUND"],
    ] as const) {
      const result = await invoke(body);
      expect(result.status).toBe(400);
      expect((result.body as { code: string }).code).toBe(code);
      denied.push(result);
    }
    expect(await state()).toEqual(before);
    const created = [];
    for (const name of ["Alpha", "Beta"]) {
      const result = await invoke({ name, organizationId: organization.id });
      expect(result.status).toBe(200);
      expect(result.body).toMatchObject({ name, organizationId: organization.id });
      created.push(result);
    }
    const stored = await state();
    expect(stored.teams).toHaveLength(2);
    expect(stored.teams.map((team) => team.id).sort()).toEqual(
      created.map((result) => (result.body as { id: string }).id).sort(),
    );
    expect(stored.members).toEqual(before.members);
    expect(stored.teamMembers).toEqual(before.teamMembers);
    const limited = await invoke({ name: "Over limit", organizationId: organization.id });
    expect(limited.status).toBe(400);
    expect((limited.body as { code: string }).code).toBe(
      "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS",
    );
    expect(await state()).toEqual(stored);
    return ctx.snapshot({ signup, organization, before, denied, created, stored, limited });
  },
);
