import { expect } from "bun:test";

import { apiKeyClient } from "@better-auth/api-key/client";
import { createAuthClient } from "better-auth/client";
import { organizationClient } from "better-auth/client/plugins";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
compatScenario(
  "static organization create grant permits nonowner admin but denies read-only member",
  async (ctx) => {
    const profile = "api-key-org-static";
    const client = (name: string) =>
      createAuthClient({
        baseURL: ctx.baseURL + authProfilePath(profile),
        plugins: [organizationClient(), apiKeyClient()],
        fetchOptions: { customFetchImpl: ctx.actor(name, profile).fetch },
      });
    const owner = client("owner");
    expect(
      (
        await owner.signUp.email({
          email: ctx.uniqueEmail("static-create-owner"),
          name: "Owner",
          password: "password123",
        })
      ).error,
    ).toBeNull();
    const org = await owner.organization.create({
      name: "Create grants",
      slug: ctx.uniqueToken("static-create"),
    });
    expect(org.error).toBeNull();
    const organizationId = org.data!.id;
    const members = [];
    for (const role of ["admin", "member"] as const) {
      const actor = client(role);
      const email = ctx.uniqueEmail("static-create-" + role);
      const signup = await actor.signUp.email({ email, name: role, password: "password123" });
      expect(signup.error).toBeNull();
      const invited = await owner.organization.inviteMember({ organizationId, email, role });
      expect(invited.error).toBeNull();
      const accepted = await actor.organization.acceptInvitation({
        invitationId: invited.data!.id,
      });
      expect(accepted.error).toBeNull();
      expect(accepted.data!.member.role).toBe(role);
      members.push({ actor, role, signup, invited, accepted });
    }
    const before = await owner.apiKey.list({ query: { configId: "organization", organizationId } });
    expect(before.error).toBeNull();
    const denied = await members[1]!.actor.apiKey.create({
      configId: "organization",
      organizationId,
      name: "Denied member key",
    });
    expect(denied.error).toMatchObject({ status: 403, code: "INSUFFICIENT_API_KEY_PERMISSIONS" });
    expect(
      await owner.apiKey.list({ query: { configId: "organization", organizationId } }),
    ).toEqual(before);
    const created = await members[0]!.actor.apiKey.create({
      configId: "organization",
      organizationId,
      name: "Granted admin key",
    });
    expect(created.error).toBeNull();
    expect(created.data!.referenceId).toBe(organizationId);
    const after = await owner.apiKey.list({ query: { configId: "organization", organizationId } });
    expect(after.error).toBeNull();
    expect(after.data!.total).toBe(before.data!.total + 1);
    expect(after.data!.apiKeys).toContainEqual(
      expect.objectContaining({ id: created.data!.id, referenceId: organizationId }),
    );
    const checked = await ctx.rawRequest({
      path: "/__test/api-key/verify",
      method: "POST",
      json: { key: created.data!.key, configId: "organization" },
    });
    expect(checked.status).toBe(200);
    expect(checked.body).toMatchObject({ valid: true, key: { referenceId: organizationId } });
    return ctx.snapshot({
      org,
      members: members.map(({ actor, ...rest }) => rest),
      before,
      denied,
      created,
      after,
      checked,
    });
  },
  ["POST /api-key/create", "GET /api-key/list"],
);
