import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario("organization disabled features omit server operations", async (ctx) => {
  const actor = ctx.actor();
  for (const [profile, teams, roles] of [
    ["org-teams-disabled", false, false],
    ["org-teams-no-default", true, false],
    ["org-roles-without-teams", false, true],
    ["org-teams-dynamic", true, true],
  ] as const) {
    const response = await actor.fetch(
      `${ctx.baseURL}/__test/server-api/organization-feature-surface`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ profile }),
      },
    );
    expect(response.status).toBe(200);
    const result = (await response.json()) as any;
    for (const operation of [
      "createTeam",
      "updateTeam",
      "removeTeam",
      "listOrganizationTeams",
      "listUserTeams",
      "listTeamMembers",
      "setActiveTeam",
      "addTeamMember",
      "removeTeamMember",
    ]) {
      expect(result.operations[operation]).toBe(teams);
    }
    for (const operation of [
      "createOrgRole",
      "getOrgRole",
      "listOrgRoles",
      "deleteOrgRole",
      "updateOrgRole",
    ]) {
      expect(result.operations[operation]).toBe(roles);
    }
  }
  return { conditionalSurface: true };
});
