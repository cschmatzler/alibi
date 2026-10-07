import { expect } from "bun:test";

import { apiKeyClient } from "@better-auth/api-key/client";
import { createAuthClient } from "better-auth/client";
import { organizationClient } from "better-auth/client/plugins";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
compatScenario(
  "static read-only organization member lists exactly organization keys without dynamic access or secret exposure",
  async (ctx) => {
    const profile = "api-key-org-static";
    const client = (name: string) =>
      createAuthClient({
        baseURL: ctx.baseURL + authProfilePath(profile),
        plugins: [organizationClient(), apiKeyClient()],
        fetchOptions: { customFetchImpl: ctx.actor(name, profile).fetch },
      });
    const owner = client("owner");
    const reader = client("reader");
    const signup = await owner.signUp.email({
      email: ctx.uniqueEmail("org-static-owner"),
      name: "Owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    const email = ctx.uniqueEmail("org-static-reader");
    expect(
      (await reader.signUp.email({ email, name: "Reader", password: "password123" })).error,
    ).toBeNull();
    const org = await owner.organization.create({
      name: "Readable",
      slug: ctx.uniqueToken("static-org"),
    });
    expect(org.error).toBeNull();
    const organizationId = org.data!.id;
    const foreign = await owner.organization.create({
      name: "Foreign",
      slug: ctx.uniqueToken("static-foreign"),
    });
    expect(foreign.error).toBeNull();
    const invite = await owner.organization.inviteMember({ organizationId, email, role: "member" });
    expect(invite.error).toBeNull();
    const accepted = await reader.organization.acceptInvitation({ invitationId: invite.data!.id });
    expect(accepted.error).toBeNull();
    expect(accepted.data!.member.role).toBe("member");
    const keys = [];
    for (const name of ["First", "Second"]) {
      const key = await owner.apiKey.create({ configId: "organization", organizationId, name });
      expect(key.error).toBeNull();
      keys.push(key.data!);
    }
    const personal = await owner.apiKey.create({ name: "Personal" });
    expect(personal.error).toBeNull();
    const foreignKey = await owner.apiKey.create({
      configId: "organization",
      organizationId: foreign.data!.id,
      name: "Foreign",
    });
    expect(foreignKey.error).toBeNull();
    const observations = [];
    for (const configId of [undefined, "organization"]) {
      const listed = await reader.apiKey.list({
        query: { organizationId, ...(configId ? { configId } : {}) },
      });
      expect(listed.error).toBeNull();
      expect(listed.data!.total).toBe(2);
      expect(listed.data!.apiKeys.map((k) => k.id).sort()).toEqual(keys.map((k) => k.id).sort());
      for (const key of listed.data!.apiKeys) {
        expect(key.referenceId).toBe(organizationId);
        expect(key).not.toHaveProperty("key");
      }
      observations.push(listed);
    }
    const page = await reader.apiKey.list({
      query: {
        organizationId,
        configId: "organization",
        limit: 1,
        offset: 1,
        sortBy: "name",
        sortDirection: "asc",
      },
    });
    expect(page.error).toBeNull();
    expect(page.data!.total).toBe(2);
    expect(page.data!.apiKeys).toHaveLength(1);
    expect(page.data!.apiKeys[0]!.id).toBe(keys[1]!.id);
    expect(page.data!.apiKeys[0]).not.toHaveProperty("key");
    const denied = await reader.apiKey.list({
      query: { configId: "organization", organizationId: foreign.data!.id },
    });
    expect(denied.error).toMatchObject({ status: 403, code: "USER_NOT_MEMBER_OF_ORGANIZATION" });
    const after = await owner.apiKey.list({ query: { configId: "organization", organizationId } });
    expect(after.data!.total).toBe(2);
    return ctx.snapshot({
      signup,
      org,
      foreign,
      invite,
      accepted,
      keys,
      personal,
      foreignKey,
      observations,
      page,
      denied,
      after,
    });
  },
  ["GET /api-key/list"],
);
