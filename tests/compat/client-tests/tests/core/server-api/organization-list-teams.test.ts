import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

compatScenario(
  "canonical listOrganizationTeams reads owned teams and uses the active organization without a request",
  async (ctx) => {
    const profile = "org-invite-limit-none";
    async function signup(name: string) {
      let cookie = "";
      const actor = ctx.actor(name, profile);
      const user = await actor.client.signUp.email({
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
      expect(user.error).toBeNull();
      return { actor, user, headers: { cookie } };
    }
    const owner = await signup("team-list-owner");
    const outsider = await signup("team-list-outsider");
    async function http(path: string, body: Record<string, unknown>) {
      const response = await owner.actor.fetch(ctx.baseURL + authProfilePath(profile) + path, {
        method: "POST",
        headers: { "content-type": "application/json", ...owner.headers },
        body: JSON.stringify(body),
      });
      expect(response.status).toBe(200);
      return await response.json();
    }
    const first = await http("/organization/create", {
      name: "First team organization",
      slug: ctx.uniqueToken("first-team-org"),
    });
    const alpha = await http("/organization/create-team", {
      organizationId: first.id,
      name: "Alpha",
    });
    const beta = await http("/organization/create-team", {
      organizationId: first.id,
      name: "Beta",
    });
    const second = await http("/organization/create", {
      name: "Second team organization",
      slug: ctx.uniqueToken("second-team-org"),
    });
    const gamma = await http("/organization/create-team", {
      organizationId: second.id,
      name: "Gamma",
    });
    async function state() {
      return (await ctx.rawRequest({ path: "/__test/organization-invitation-life/state" })).body;
    }
    const before = await state();
    async function invoke(input: Record<string, unknown>) {
      return ctx.rawRequest({
        path: "/__test/organization-invitation-life/server",
        method: "POST",
        json: { operation: "listOrganizationTeams", ...input },
      });
    }
    const explicit = await invoke({ query: { organizationId: first.id }, headers: owner.headers });
    expect(explicit.status).toBe(200);
    expect(explicit.body).toEqual([alpha, beta]);
    const active = await invoke({ headers: owner.headers });
    expect(active.status).toBe(200);
    expect(active.body).toEqual([gamma]);
    const empty = await invoke({ query: { organizationId: "" }, headers: owner.headers });
    expect(empty.status).toBe(200);
    expect(empty.body).toEqual([gamma]);
    const denied = [];
    for (const [input, status, code] of [
      [{ query: { organizationId: first.id } }, 400, "VALIDATION_ERROR"],
      [{ query: { organizationId: first.id }, headers: {} }, 401, "UNAUTHORIZED"],
      [
        { query: { organizationId: first.id }, headers: outsider.headers },
        403,
        "YOU_ARE_NOT_ALLOWED_TO_ACCESS_THIS_ORGANIZATION",
      ],
      [{ headers: outsider.headers }, 400, "NO_ACTIVE_ORGANIZATION"],
      [
        { query: { organizationId: "not-an-organization" }, headers: owner.headers },
        403,
        "YOU_ARE_NOT_ALLOWED_TO_ACCESS_THIS_ORGANIZATION",
      ],
    ] as const) {
      const response = await invoke(input);
      expect(response.status).toBe(status);
      expect((response.body as { code: string }).code).toBe(code);
      denied.push(response);
    }
    const after = await state();
    expect(after).toEqual(before);
    return ctx.snapshot({
      owner: owner.user,
      outsider: outsider.user,
      first,
      alpha,
      beta,
      second,
      gamma,
      before,
      explicit,
      active,
      empty,
      denied,
      after,
    });
  },
);
