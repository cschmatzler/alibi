import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

compatScenario(
  "server setActiveTeam preserves selection and publishes usable session cookies",
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
    const owner = await signup("team-selection-owner");
    const outsider = await signup("team-selection-outsider");
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
      name: "Team selection",
      slug: ctx.uniqueToken("team-selection"),
    });
    const teams = [];
    for (const name of ["Alpha", "No seat"]) {
      teams.push(
        await http("/organization/create-team", { name, organizationId: organization.id }),
      );
    }
    await http("/organization/add-team-member", {
      teamId: teams[0].id,
      userId: owner.result.data!.user.id,
    });
    async function invoke(body: Record<string, unknown>, headers?: Record<string, string>) {
      const response = await owner.actor.fetch(
        ctx.baseURL + "/__test/server-api/organization-set-active-team",
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ profile, body, ...(headers ? { headers } : {}) }),
        },
      );
      return { response, status: response.status, body: await response.json() };
    }
    async function state() {
      return (
        await ctx.rawRequest({
          path: `/__test/organization-state?profile=${profile}&organizationId=${organization.id}`,
        })
      ).body;
    }
    const before = await state();
    const denied = [];
    for (const [body, headers, status, code] of [
      [{ teamId: teams[0].id }, undefined, 400, "VALIDATION_ERROR"],
      [{ teamId: teams[0].id }, {}, 401, "UNAUTHORIZED"],
      [{ teamId: teams[0].id }, outsider.headers, 400, "NO_ACTIVE_ORGANIZATION"],
      [{ teamId: "missing-team" }, owner.headers, 400, "TEAM_NOT_FOUND"],
      [{ teamId: teams[1].id }, owner.headers, 403, "USER_IS_NOT_A_MEMBER_OF_THE_TEAM"],
    ] as const) {
      const result = await invoke(body, headers);
      expect(result.status).toBe(status);
      expect(result.body.code).toBe(code);
      expect(result.response.headers.getSetCookie()).toEqual([]);
      denied.push({ status: result.status, body: result.body });
    }
    expect(await state()).toEqual(before);
    let cookie = owner.headers.cookie;
    const selections = [];
    for (const [body, active, emitsCookie] of [
      [{}, false, false],
      [{ teamId: null }, false, false],
      [{ teamId: teams[0].id }, true, true],
      [{}, true, true],
      [{ teamId: "" }, true, true],
      [{ teamId: null }, false, true],
      [{ teamId: null }, false, false],
    ] as const) {
      const result = await invoke(body, { cookie });
      expect(result.status).toBe(200);
      expect(result.body).toEqual(active ? teams[0] : null);
      const published = result.response.headers.getSetCookie();
      expect(published).toHaveLength(emitsCookie ? 1 : 0);
      if (emitsCookie) {
        expect(published[0]).toContain("better-auth.session_token=");
        expect(published[0]).toContain("HttpOnly");
        cookie = published.map((raw) => raw.split(";")[0]).join("; ");
      }
      const sessionResponse = await owner.actor.fetch(
        ctx.baseURL + authProfilePath(profile) + "/get-session",
        { headers: { cookie } },
      );
      expect(sessionResponse.status).toBe(200);
      const session = await sessionResponse.json();
      expect(session.user.id).toBe(owner.result.data!.user.id);
      expect(session.session.activeTeamId ?? null).toBe(active ? teams[0].id : null);
      expect(await state()).toEqual(before);
      selections.push({ status: result.status, body: result.body, session });
    }
    return ctx.snapshot({
      owner: owner.result,
      outsider: outsider.result,
      organization,
      teams,
      before,
      denied,
      selections,
    });
  },
);
