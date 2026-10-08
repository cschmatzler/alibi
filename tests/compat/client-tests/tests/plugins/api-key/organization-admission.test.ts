import { expect } from "bun:test";

import { apiKeyClient } from "@better-auth/api-key/client";
import { createAuthClient } from "better-auth/client";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

compatScenario(
  "organization API-key admission rejects missing organization missing plugin and foreign membership without storing keys",
  async (ctx) => {
    const owner = ctx.actor("owner");
    expect(
      (
        await owner.client.signUp.email({
          email: ctx.uniqueEmail("org-key-owner"),
          name: "Owner",
          password: "password123",
        })
      ).error,
    ).toBeNull();
    const organization = await ctx.rawRequest({
      actor: "owner",
      path: "/api/auth/organization/create",
      method: "POST",
      json: {
        name: "Key Organization",
        slug: ctx.uniqueToken("key-org"),
      },
    });
    expect(organization.status).toBe(200);
    const orgId = (organization.body as { id: string }).id;
    const client = (actor: string, profile?: "api-key-options") =>
      createAuthClient({
        baseURL: ctx.baseURL + (profile ? authProfilePath(profile) : "/api/auth"),
        plugins: [apiKeyClient()],
        fetchOptions: { customFetchImpl: ctx.actor(actor, profile).fetch },
      });
    const ownerKeys = client("owner");
    const before = await ownerKeys.apiKey.list({
      query: { configId: "organization", organizationId: orgId },
    });
    expect(before.error).toBeNull();
    const missingId = await ownerKeys.apiKey.create({
      configId: "organization",
      name: "Missing organization",
    });
    expect(missingId.error).toMatchObject({ status: 400, code: "ORGANIZATION_ID_REQUIRED" });
    const outsider = ctx.actor("outsider");
    expect(
      (
        await outsider.client.signUp.email({
          email: ctx.uniqueEmail("org-key-outsider"),
          name: "Outsider",
          password: "password123",
        })
      ).error,
    ).toBeNull();
    const foreign = await client("outsider").apiKey.create({
      configId: "organization",
      organizationId: orgId,
      name: "Foreign key",
    });
    expect(foreign.error).toMatchObject({ status: 403, code: "USER_NOT_MEMBER_OF_ORGANIZATION" });
    expect(
      await ownerKeys.apiKey.list({ query: { configId: "organization", organizationId: orgId } }),
    ).toEqual(before);
    const missingPluginClient = client("no-plugin", "api-key-options");
    expect(
      (
        await missingPluginClient.signUp.email({
          email: ctx.uniqueEmail("org-key-no-plugin"),
          name: "Plugin absent",
          password: "password123",
        })
      ).error,
    ).toBeNull();
    const read = async () => (await ctx.rawRequest({ path: "/__test/api-key-options/state" })).body;
    const storedBefore = await read();
    const missingPlugin = await missingPluginClient.apiKey.create({
      configId: "organization",
      organizationId: orgId,
      name: "Missing plugin",
    });
    expect(missingPlugin.error).toMatchObject({
      status: 500,
      code: "ORGANIZATION_PLUGIN_REQUIRED",
    });
    expect(await read()).toEqual(storedBefore);
    const accepted = await ownerKeys.apiKey.create({
      configId: "organization",
      organizationId: orgId,
      name: "Member key",
    });
    expect(accepted.error).toBeNull();
    expect(accepted.data!.referenceId).toBe(orgId);
    const after = await ownerKeys.apiKey.list({
      query: { configId: "organization", organizationId: orgId },
    });
    expect(after.error).toBeNull();
    expect(after.data!.total).toBe(before.data!.total + 1);
    expect(after.data!.apiKeys).toContainEqual(
      expect.objectContaining({ id: accepted.data!.id, referenceId: orgId }),
    );
    return ctx.snapshot({
      organization,
      before,
      missingId,
      foreign,
      missingPlugin,
      accepted,
      after,
    });
  },
  ["POST /api-key/create", "GET /api-key/list"],
);
