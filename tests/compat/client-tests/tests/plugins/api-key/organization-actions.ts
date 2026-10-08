import { expect } from "bun:test";

import { apiKeyClient } from "@better-auth/api-key/client";
import { createAuthClient } from "better-auth/client";
import { organizationClient } from "better-auth/client/plugins";

import { authProfilePath } from "../../../support/profiles";
import type { ScenarioContext } from "../../../support/scenario";
export async function organizationActions(ctx: ScenarioContext, label: string) {
  const profile = "api-key-org-static";
  const client = (name: string) =>
    createAuthClient({
      baseURL: ctx.baseURL + authProfilePath(profile),
      plugins: [organizationClient(), apiKeyClient()],
      fetchOptions: { customFetchImpl: ctx.actor(name, profile).fetch },
    });
  const owner = client("owner");
  const signup = await owner.signUp.email({
    email: ctx.uniqueEmail(label + "-owner"),
    name: "Owner",
    password: "password123",
  });
  expect(signup.error).toBeNull();
  const org = await owner.organization.create({
    name: "Action grants",
    slug: ctx.uniqueToken(label + "-org"),
  });
  expect(org.error).toBeNull();
  const organizationId = org.data!.id;
  const member = async (role: "member" | "updater" | "deleter") => {
    const actor = client(role);
    const email = ctx.uniqueEmail(label + "-" + role);
    const signup = await actor.signUp.email({ email, name: role, password: "password123" });
    expect(signup.error).toBeNull();
    const response = await ctx
      .actor("owner", profile)
      .fetch(ctx.baseURL + authProfilePath(profile) + "/organization/invite-member", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ organizationId, email, role }),
      });
    expect(response.status).toBe(200);
    const invitation = (await response.json()) as { id: string };
    const accepted = await actor.organization.acceptInvitation({ invitationId: invitation.id });
    expect(accepted.error).toBeNull();
    expect(accepted.data!.member.role).toBe(role);
    return { actor, signup, invitation, accepted };
  };
  const create = async (name: string) => {
    const result = await owner.apiKey.create({ configId: "organization", organizationId, name });
    expect(result.error).toBeNull();
    return result;
  };
  const verify = async (key: string) => {
    const r = await ctx.rawRequest({
      path: "/__test/api-key/verify",
      method: "POST",
      json: { key, configId: "organization" },
    });
    expect(r.status).toBe(200);
    return r.body as any;
  };
  return { owner, signup, org, organizationId, member, create, verify };
}
