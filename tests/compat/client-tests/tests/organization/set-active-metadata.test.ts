import { expect } from "bun:test";
import { z } from "zod";
import { compatScenario, type ScenarioContext } from "../../support/scenario";

const stateSchema = z.object({
  organizations: z.array(
    z.object({
      id: z.string(),
      name: z.string(),
      slug: z.string(),
      memberId: z.string(),
      userId: z.string(),
      role: z.string(),
      logo: z.string().nullable(),
      metadata: z.string().nullable(),
    }),
  ),
  sessions: z.array(
    z.object({
      id: z.string(),
      token: z.string(),
      userId: z.string(),
      activeOrganizationId: z.string().nullable(),
    }),
  ),
  orphanOrganizations: z.array(z.object({ id: z.string(), name: z.string(), slug: z.string() })),
  receipts: z.array(
    z.object({ operation: z.string(), userId: z.string(), email: z.string(), name: z.string() }),
  ),
});
async function state(ctx: ScenarioContext, email: string) {
  const response = await ctx.rawRequest({
    path: `/__test/organization-creation-state?email=${encodeURIComponent(email)}&includeMetadata=true&includeLogo=true`,
  });
  expect(response.status).toBe(200);
  return stateSchema.parse(response.body);
}
async function signup(ctx: ScenarioContext) {
  const owner = ctx.actor("metadata-owner", "org-creation-empty-role");
  const email = ctx.uniqueEmail("set-active-metadata");
  const response = await owner.client.signUp.email({
    name: "Metadata Owner",
    email,
    password: "password123",
  });
  expect(response.error).toBeNull();
  const result = z
    .object({ token: z.string(), user: z.object({ id: z.string() }) })
    .parse(response.data);
  return { ...owner, email, userId: result.user.id, token: result.token };
}
const responseSchema = z.object({
  id: z.string(),
  name: z.string(),
  slug: z.string(),
  logo: z.string().nullable(),
  metadata: z.string().nullable(),
});

compatScenario(
  "organization set-active returns exact stored metadata text and changes only the current token selection",
  async (ctx) => {
    const owner = await signup(ctx);
    const metadata = {
      "2": "second",
      "1": "first",
      nested: { fixed: 1e20, tiny: 1e-19, array: [null, true, "literal"] },
      "$serde_json::private::RawValue": "application-key",
    };
    const slug = ctx.uniqueToken("record-metadata");
    const created = await owner.client.$fetch("/organization/create", {
      method: "POST",
      body: { name: "Record Metadata", slug, logo: "https://fixture.test/record.png", metadata },
    });
    expect(created.error).toBeNull();
    const firstId = z.object({ id: z.string() }).parse(created.data).id;
    const other = ctx.actor("other-metadata-token", "org-creation-empty-role");
    const signedIn = await other.client.signIn.email({
      email: owner.email,
      password: "password123",
    });
    expect(signedIn.error).toBeNull();
    const otherToken = z.object({ token: z.string() }).parse(signedIn.data).token;
    const emptyCreated = await other.client.$fetch("/organization/create", {
      method: "POST",
      body: { name: "Empty Metadata", slug: ctx.uniqueToken("empty-metadata"), metadata: {} },
    });
    expect(emptyCreated.error).toBeNull();
    const secondId = z.object({ id: z.string() }).parse(emptyCreated.data).id;
    const before = await state(ctx, owner.email);
    expect(before.organizations.find((row) => row.id === firstId)?.metadata).toBe(
      JSON.stringify(metadata),
    );
    expect(before.organizations.find((row) => row.id === secondId)?.metadata).toBe("{}");
    expect(before.sessions.find((row) => row.token === owner.token)?.activeOrganizationId).toBe(
      firstId,
    );
    expect(before.sessions.find((row) => row.token === otherToken)?.activeOrganizationId).toBe(
      secondId,
    );
    const selectedEmpty = await owner.client.$fetch("/organization/set-active", {
      method: "POST",
      body: { organizationId: secondId },
    });
    expect(selectedEmpty.error).toBeNull();
    expect(responseSchema.parse(selectedEmpty.data)).toMatchObject({
      id: secondId,
      metadata: "{}",
    });
    expect(selectedEmpty.data).not.toHaveProperty("members");
    expect(selectedEmpty.data).not.toHaveProperty("invitations");
    const afterEmpty = await state(ctx, owner.email);
    expect(afterEmpty.organizations).toEqual(before.organizations);
    expect(afterEmpty.sessions.find((row) => row.token === owner.token)?.activeOrganizationId).toBe(
      secondId,
    );
    expect(afterEmpty.sessions.find((row) => row.token === otherToken)).toEqual(
      before.sessions.find((row) => row.token === otherToken),
    );
    const selectedRecord = await owner.client.$fetch("/organization/set-active", {
      method: "POST",
      body: { organizationSlug: slug },
    });
    expect(selectedRecord.error).toBeNull();
    expect(responseSchema.parse(selectedRecord.data)).toMatchObject({
      id: firstId,
      metadata: JSON.stringify(metadata),
    });
    const afterRecord = await state(ctx, owner.email);
    expect(afterRecord).toEqual(before);
    const changed = { guard: "fresh-row", nested: [null, { fixed: 1e20 }], "1": "first" };
    const updated = await owner.client.$fetch("/organization/update", {
      method: "POST",
      body: { organizationId: firstId, data: { metadata: changed } },
    });
    expect(updated.error).toBeNull();
    expect(z.object({ metadata: z.unknown() }).parse(updated.data).metadata).toEqual(changed);
    const selectedChanged = await owner.client.$fetch("/organization/set-active", {
      method: "POST",
      body: { organizationId: firstId },
    });
    expect(selectedChanged.error).toBeNull();
    expect(responseSchema.parse(selectedChanged.data)).toMatchObject({
      id: firstId,
      metadata: JSON.stringify(changed),
      logo: "https://fixture.test/record.png",
    });
    const afterChanged = await state(ctx, owner.email);
    expect(afterChanged.organizations.find((row) => row.id === firstId)).toEqual({
      ...before.organizations.find((row) => row.id === firstId)!,
      metadata: JSON.stringify(changed),
    });
    expect(afterChanged.organizations.find((row) => row.id === secondId)).toEqual(
      before.organizations.find((row) => row.id === secondId),
    );
    expect(afterChanged.sessions).toEqual(before.sessions);
    expect(afterChanged.receipts).toEqual(before.receipts);
    expect(afterChanged.orphanOrganizations).toEqual(before.orphanOrganizations);
    return {
      created: ctx.snapshot(created),
      emptyCreated: ctx.snapshot(emptyCreated),
      before,
      selectedEmpty: ctx.snapshot(selectedEmpty),
      afterEmpty,
      selectedRecord: ctx.snapshot(selectedRecord),
      afterRecord,
      updated: ctx.snapshot(updated),
      selectedChanged: ctx.snapshot(selectedChanged),
      afterChanged,
    };
  },
  ["POST /organization/set-active", "POST /organization/update"],
);

compatScenario(
  "organization set-active emits null for absent metadata and retains real membership and session scope",
  async (ctx) => {
    const owner = await signup(ctx);
    const created = await owner.client.$fetch("/organization/create", {
      method: "POST",
      body: { name: "Absent Metadata", slug: ctx.uniqueToken("absent-metadata") },
    });
    expect(created.error).toBeNull();
    expect(created.data).not.toHaveProperty("metadata");
    const id = z.object({ id: z.string() }).parse(created.data).id;
    const before = await state(ctx, owner.email);
    expect(before.organizations[0]?.metadata).toBeNull();
    const fetched = [];
    for (const path of ["get-organization", "get-full-organization"]) {
      const result = await owner.client.$fetch(`/organization/${path}`, {
        query: { organizationId: id },
      });
      expect(result.error).toBeNull();
      expect(z.object({ id: z.string(), metadata: z.null() }).parse(result.data)).toEqual({
        id,
        metadata: null,
      });
      fetched.push(ctx.snapshot(result));
    }
    const listed = await owner.client.$fetch("/organization/list");
    expect(listed.error).toBeNull();
    expect(z.array(z.object({ id: z.string(), metadata: z.null() })).parse(listed.data)).toEqual([
      { id, metadata: null },
    ]);
    const renamed = await owner.client.$fetch("/organization/update", {
      method: "POST",
      body: { organizationId: id, data: { name: "Renamed Without Metadata" } },
    });
    expect(renamed.error).toBeNull();
    expect(renamed.data).not.toHaveProperty("metadata");
    const renamedState = await state(ctx, owner.email);
    expect(renamedState.organizations).toEqual(
      before.organizations.map((row) => ({ ...row, name: "Renamed Without Metadata" })),
    );
    expect(renamedState.sessions).toEqual(before.sessions);
    const selected = await owner.client.$fetch("/organization/set-active", {
      method: "POST",
      body: { organizationId: id },
    });
    expect(selected.error).toBeNull();
    expect(responseSchema.parse(selected.data)).toMatchObject({ id, metadata: null });
    const after = await state(ctx, owner.email);
    expect(after).toEqual(renamedState);
    expect(after.organizations[0]).toMatchObject({ id, userId: owner.userId, role: "owner" });
    expect(after.sessions.find((row) => row.token === owner.token)?.activeOrganizationId).toBe(id);
    return {
      created: ctx.snapshot(created),
      before,
      fetched,
      listed: ctx.snapshot(listed),
      renamed: ctx.snapshot(renamed),
      renamedState,
      selected: ctx.snapshot(selected),
      after,
    };
  },
  ["POST /organization/set-active", "POST /organization/update"],
);

compatScenario(
  "organization legacy literal JSON null stays distinct from SQL null through owner endpoints",
  async (ctx) => {
    const owner = await signup(ctx);
    const created = await owner.client.$fetch("/organization/create", {
      method: "POST",
      body: { name: "Legacy Literal Null", slug: ctx.uniqueToken("legacy-null") },
    });
    expect(created.error).toBeNull();
    const id = z.object({ id: z.string() }).parse(created.data).id;
    const otherMetadata = {
      guard: "unchanged",
      fixed: 1e20,
      tiny: 1e-19,
      "2": "second",
      "1": "first",
    };
    const otherCreated = await owner.client.$fetch("/organization/create", {
      method: "POST",
      body: {
        name: "Unchanged Organization",
        slug: ctx.uniqueToken("unchanged-null"),
        metadata: otherMetadata,
      },
    });
    expect(otherCreated.error).toBeNull();
    const otherId = z.object({ id: z.string() }).parse(otherCreated.data).id;
    const sibling = ctx.actor("legacy-sibling", "org-creation-empty-role");
    expect(
      (await sibling.client.signIn.email({ email: owner.email, password: "password123" })).error,
    ).toBeNull();
    expect(
      (
        await sibling.client.$fetch("/organization/set-active", {
          method: "POST",
          body: { organizationId: otherId },
        })
      ).error,
    ).toBeNull();
    const before = await state(ctx, owner.email);
    expect(before.organizations.find((row) => row.id === id)?.metadata).toBeNull();
    const seeded = await ctx.rawRequest({
      path: "/__test/organization-metadata-legacy",
      method: "POST",
      json: { organizationId: id },
    });
    expect(seeded).toMatchObject({ status: 200, body: { id } });
    const stored = await state(ctx, owner.email);
    expect(stored.organizations).toEqual(
      before.organizations.map((row) => (row.id === id ? { ...row, metadata: "null" } : row)),
    );
    expect(stored.sessions).toEqual(before.sessions);
    const fetched = [];
    for (const path of ["get-organization", "get-full-organization"]) {
      const result = await owner.client.$fetch(`/organization/${path}`, {
        query: { organizationId: id },
      });
      expect(result.error).toBeNull();
      expect(z.object({ id: z.string(), metadata: z.string() }).parse(result.data)).toEqual({
        id,
        metadata: "null",
      });
      fetched.push(ctx.snapshot(result));
    }
    const listed = await owner.client.$fetch("/organization/list");
    expect(listed.error).toBeNull();
    const listRows = z.array(z.object({ id: z.string(), metadata: z.string() })).parse(listed.data);
    expect(listRows.find((row) => row.id === id)?.metadata).toBe("null");
    expect(listRows.find((row) => row.id === otherId)?.metadata).toBe(
      JSON.stringify(otherMetadata),
    );
    const renamed = await owner.client.$fetch("/organization/update", {
      method: "POST",
      body: { organizationId: id, data: { name: "Renamed Literal Null" } },
    });
    expect(renamed.error).toBeNull();
    expect(renamed.data).toHaveProperty("metadata", null);
    const selected = await owner.client.$fetch("/organization/set-active", {
      method: "POST",
      body: { organizationId: id },
    });
    expect(selected.error).toBeNull();
    expect(responseSchema.parse(selected.data)).toMatchObject({ id, metadata: "null" });
    const final = await state(ctx, owner.email);
    expect(final.organizations).toEqual(
      stored.organizations.map((row) =>
        row.id === id ? { ...row, name: "Renamed Literal Null" } : row,
      ),
    );
    expect(final.sessions).toEqual(
      stored.sessions.map((row) =>
        row.token === owner.token ? { ...row, activeOrganizationId: id } : row,
      ),
    );
    const foreign = ctx.actor("legacy-foreign", "org-creation-empty-role");
    const foreignEmail = ctx.uniqueEmail("legacy-foreign");
    expect(
      (
        await foreign.client.signUp.email({
          name: "Foreign Owner",
          email: foreignEmail,
          password: "password123",
        })
      ).error,
    ).toBeNull();
    const foreignCreated = await foreign.client.$fetch("/organization/create", {
      method: "POST",
      body: {
        name: "Foreign Organization",
        slug: ctx.uniqueToken("foreign-legacy"),
        metadata: { private: "foreign" },
      },
    });
    expect(foreignCreated.error).toBeNull();
    const foreignBefore = await state(ctx, foreignEmail);
    const denied = await foreign.client.$fetch("/organization/get-organization", {
      query: { organizationId: id },
    });
    expect(denied.error).toMatchObject({
      status: 403,
      code: "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
    });
    expect(denied.data).toBeNull();
    const foreignAfter = await state(ctx, foreignEmail);
    expect(foreignAfter.organizations).toEqual(foreignBefore.organizations);
    expect(foreignAfter.sessions).toEqual(
      foreignBefore.sessions.map((row) => ({ ...row, activeOrganizationId: null })),
    );
    expect(await state(ctx, owner.email)).toEqual(final);
    return {
      created: ctx.snapshot(created),
      otherCreated: ctx.snapshot(otherCreated),
      before,
      seeded,
      stored,
      fetched,
      listed: ctx.snapshot(listed),
      renamed: ctx.snapshot(renamed),
      selected: ctx.snapshot(selected),
      final,
      foreignBefore,
      denied: ctx.snapshot(denied),
      foreignAfter,
    };
  },
  [
    "POST /organization/set-active",
    "POST /organization/update",
    "GET /organization/get-organization",
  ],
);
