import { expect } from "bun:test";
import { z } from "zod";
import { compatScenario, type ScenarioContext } from "../../support/scenario";

const storedSchema = z.object({
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
  return storedSchema.parse(response.body);
}
async function signup(ctx: ScenarioContext, name: string) {
  const actor = ctx.actor(name, "org-creation-empty-role");
  const email = ctx.uniqueEmail(name);
  const response = await actor.client.signUp.email({ name, email, password: "password123" });
  expect(response.error).toBeNull();
  const userId = z.object({ user: z.object({ id: z.string() }) }).parse(response.data).user.id;
  return { ...actor, email, userId };
}
async function create(
  ctx: ScenarioContext,
  actor: Awaited<ReturnType<typeof signup>>,
  name: string,
) {
  const logo = `https://fixture.test/${name}.png`;
  const metadata = { guard: name, payload: [null, "literal", true] };
  const response = await actor.client.$fetch("/organization/create", {
    method: "POST",
    body: { name, slug: ctx.uniqueToken(name), logo, metadata },
  });
  expect(response.error).toBeNull();
  const id = z.object({ id: z.string() }).parse(response.data).id;
  return { id, logo, metadata };
}
async function setup(ctx: ScenarioContext) {
  const owner = await signup(ctx, "patch-owner");
  const second = await create(ctx, owner, "second");
  const otherToken = ctx.actor("other-owner-token", "org-creation-empty-role");
  expect(
    (await otherToken.client.signIn.email({ email: owner.email, password: "password123" })).error,
  ).toBeNull();
  const first = await create(
    ctx,
    { ...otherToken, email: owner.email, userId: owner.userId },
    "first",
  );
  const foreign = await signup(ctx, "foreign-owner");
  const foreignOrganization = await create(ctx, foreign, "foreign");
  const before = await state(ctx, owner.email);
  const foreignBefore = await state(ctx, foreign.email);
  expect(before.sessions.map((row) => row.activeOrganizationId).sort()).toEqual(
    [first.id, second.id].sort(),
  );
  expect(before.organizations.map((row) => row.userId)).toEqual([owner.userId, owner.userId]);
  return { owner, first, second, otherToken, foreign, foreignOrganization, before, foreignBefore };
}

compatScenario(
  "organization logo patches preserve omitted fields, clear SQL null, and enforce authenticated ownership",
  async (ctx) => {
    const data = await setup(ctx);
    const { owner, first, second, foreign, before, foreignBefore } = data;
    const omitted = await owner.client.$fetch("/organization/update", {
      method: "POST",
      body: { organizationId: first.id, data: { name: "Omitted Logo" } },
    });
    expect(omitted.error).toBeNull();
    expect(z.object({ logo: z.string() }).parse(omitted.data).logo).toBe(first.logo);
    const afterOmitted = await state(ctx, owner.email);
    expect(afterOmitted.organizations.find((row) => row.id === first.id)).toMatchObject({
      name: "Omitted Logo",
      logo: first.logo,
      metadata: JSON.stringify(first.metadata),
    });
    expect(afterOmitted.organizations.find((row) => row.id === second.id)).toEqual(
      before.organizations.find((row) => row.id === second.id),
    );
    expect(afterOmitted.sessions).toEqual(before.sessions);
    const cleared = await owner.client.$fetch("/organization/update", {
      method: "POST",
      body: { organizationId: first.id, data: { logo: null } },
    });
    expect(cleared.error).toBeNull();
    expect(z.object({ logo: z.null(), metadata: z.unknown() }).parse(cleared.data)).toMatchObject({
      logo: null,
      metadata: first.metadata,
    });
    const afterClear = await state(ctx, owner.email);
    expect(afterClear.organizations.find((row) => row.id === first.id)).toMatchObject({
      logo: null,
      metadata: JSON.stringify(first.metadata),
    });
    expect(afterClear.sessions).toEqual(before.sessions);
    const blank = await owner.client.$fetch("/organization/update", {
      method: "POST",
      body: { organizationId: first.id, data: { logo: "" } },
    });
    expect(blank.error).toBeNull();
    expect(z.object({ logo: z.string() }).parse(blank.data).logo).toBe("");
    expect(
      (await state(ctx, owner.email)).organizations.find((row) => row.id === first.id)?.logo,
    ).toBe("");
    const replaced = await owner.client.$fetch("/organization/update", {
      method: "POST",
      body: { organizationId: first.id, data: { logo: "https://fixture.test/replaced.png" } },
    });
    expect(replaced.error).toBeNull();
    const protectedState = await state(ctx, owner.email);
    const denied = await foreign.client.$fetch("/organization/update", {
      method: "POST",
      body: { organizationId: first.id, data: { logo: null } },
    });
    expect(denied.error).toMatchObject({
      status: 400,
      code: "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
      message: "User is not a member of the organization",
    });
    const guest = await ctx.rawRequest({
      path: "/__test/profiles/org-creation-empty-role/api/auth/organization/update",
      method: "POST",
      json: { organizationId: first.id, data: { logo: null } },
    });
    expect(guest.status).toBe(401);
    expect(guest.body).toEqual({ message: "User not found" });
    expect(await state(ctx, owner.email)).toEqual(protectedState);
    expect(await state(ctx, foreign.email)).toEqual(foreignBefore);
    const retry = await owner.client.$fetch("/organization/update", {
      method: "POST",
      body: { organizationId: first.id, data: { logo: null } },
    });
    expect(retry.error).toBeNull();
    const final = await state(ctx, owner.email);
    expect(final.organizations.find((row) => row.id === first.id)?.logo).toBeNull();
    expect(final.organizations.find((row) => row.id === second.id)).toEqual(
      before.organizations.find((row) => row.id === second.id),
    );
    expect(final.sessions).toEqual(before.sessions);
    return {
      before,
      foreignBefore,
      omitted: ctx.snapshot(omitted),
      afterOmitted,
      cleared: ctx.snapshot(cleared),
      afterClear,
      blank: ctx.snapshot(blank),
      replaced: ctx.snapshot(replaced),
      protectedState,
      denied: ctx.snapshot(denied),
      guest,
      retry: ctx.snapshot(retry),
      final,
    };
  },
  ["POST /organization/update"],
);

compatScenario(
  "organization blank update selectors use only the current token selection and preserve other organizations",
  async (ctx) => {
    const {
      owner,
      first,
      second,
      otherToken,
      foreign,
      foreignOrganization,
      before,
      foreignBefore,
    } = await setup(ctx);
    const selected = await owner.client.$fetch("/organization/update", {
      method: "POST",
      body: { organizationId: "", data: { name: "Current Token Selected", logo: null } },
    });
    expect(selected.error).toBeNull();
    expect(
      z.object({ id: z.string(), name: z.string(), logo: z.null() }).parse(selected.data),
    ).toMatchObject({ id: second.id, name: "Current Token Selected", logo: null });
    const afterCurrent = await state(ctx, owner.email);
    expect(afterCurrent.organizations.find((row) => row.id === first.id)).toEqual(
      before.organizations.find((row) => row.id === first.id),
    );
    expect(afterCurrent.organizations.find((row) => row.id === second.id)).toMatchObject({
      name: "Current Token Selected",
      logo: null,
      metadata: JSON.stringify(second.metadata),
    });
    expect(afterCurrent.sessions).toEqual(before.sessions);
    const other = await otherToken.client.$fetch("/organization/update", {
      method: "POST",
      body: { organizationId: "", data: { name: "Other Token Selected" } },
    });
    expect(other.error).toBeNull();
    expect(z.object({ id: z.string() }).parse(other.data).id).toBe(first.id);
    const afterOther = await state(ctx, owner.email);
    expect(afterOther.organizations.find((row) => row.id === first.id)).toMatchObject({
      name: "Other Token Selected",
      logo: first.logo,
      metadata: JSON.stringify(first.metadata),
    });
    expect(afterOther.organizations.find((row) => row.id === second.id)).toEqual(
      afterCurrent.organizations.find((row) => row.id === second.id),
    );
    expect(afterOther.sessions).toEqual(before.sessions);
    const noSelection = ctx.actor("foreign-unselected", "org-creation-empty-role");
    expect(
      (await noSelection.client.signIn.email({ email: foreign.email, password: "password123" }))
        .error,
    ).toBeNull();
    const foreignWithOtherToken = await state(ctx, foreign.email);
    const absent = await noSelection.client.$fetch("/organization/update", {
      method: "POST",
      body: { organizationId: "", data: { name: "Must Not Persist" } },
    });
    expect(absent.error).toMatchObject({
      status: 400,
      code: "ORGANIZATION_NOT_FOUND",
      message: "Organization not found",
    });
    expect(await state(ctx, foreign.email)).toEqual(foreignWithOtherToken);
    const foreignSelected = await foreign.client.$fetch("/organization/update", {
      method: "POST",
      body: { organizationId: "", data: { name: "Foreign Selected", logo: null } },
    });
    expect(foreignSelected.error).toBeNull();
    expect(z.object({ id: z.string() }).parse(foreignSelected.data).id).toBe(
      foreignOrganization.id,
    );
    expect(await state(ctx, owner.email)).toEqual(afterOther);
    const foreignAfter = await state(ctx, foreign.email);
    expect(foreignAfter.organizations[0]).toMatchObject({
      name: "Foreign Selected",
      logo: null,
      metadata: JSON.stringify(foreignOrganization.metadata),
    });
    expect(foreignAfter.sessions).toEqual(foreignWithOtherToken.sessions);
    return {
      before,
      foreignBefore,
      selected: ctx.snapshot(selected),
      afterCurrent,
      other: ctx.snapshot(other),
      afterOther,
      foreignWithOtherToken,
      absent: ctx.snapshot(absent),
      foreignSelected: ctx.snapshot(foreignSelected),
      foreignAfter,
    };
  },
  ["POST /organization/update"],
);
