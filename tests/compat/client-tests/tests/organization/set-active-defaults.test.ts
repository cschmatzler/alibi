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
async function setup(ctx: ScenarioContext) {
  const owner = ctx.actor("selector-owner", "org-creation-empty-role");
  const email = ctx.uniqueEmail("selector-owner");
  const signedUp = await owner.client.signUp.email({
    name: "Selector Owner",
    email,
    password: "password123",
  });
  expect(signedUp.error).toBeNull();
  const { token, user } = z
    .object({ token: z.string(), user: z.object({ id: z.string() }) })
    .parse(signedUp.data);
  const firstSlug = ctx.uniqueToken("selector-first");
  const firstCreated = await owner.client.$fetch("/organization/create", {
    method: "POST",
    body: { name: "First Selection", slug: firstSlug, metadata: { guard: "first" } },
  });
  expect(firstCreated.error).toBeNull();
  const firstId = z.object({ id: z.string() }).parse(firstCreated.data).id;
  const other = ctx.actor("selector-other-token", "org-creation-empty-role");
  const signedIn = await other.client.signIn.email({ email, password: "password123" });
  expect(signedIn.error).toBeNull();
  const otherToken = z.object({ token: z.string() }).parse(signedIn.data).token;
  const secondSlug = ctx.uniqueToken("selector-second");
  const secondCreated = await other.client.$fetch("/organization/create", {
    method: "POST",
    body: { name: "Second Selection", slug: secondSlug, metadata: { guard: "second" } },
  });
  expect(secondCreated.error).toBeNull();
  const secondId = z.object({ id: z.string() }).parse(secondCreated.data).id;
  const before = await state(ctx, email);
  expect(before.sessions.find((row) => row.token === token)?.activeOrganizationId).toBe(firstId);
  expect(before.sessions.find((row) => row.token === otherToken)?.activeOrganizationId).toBe(
    secondId,
  );
  return {
    owner,
    email,
    token,
    userId: user.id,
    firstId,
    firstSlug,
    secondId,
    secondSlug,
    otherToken,
    before,
  };
}
async function set(
  ctx: ScenarioContext,
  actor: ReturnType<ScenarioContext["actor"]>,
  body: unknown,
  media = "application/json",
) {
  const response = await actor.fetch(
    `${ctx.baseURL}/__test/profiles/org-creation-empty-role/api/auth/organization/set-active`,
    {
      method: "POST",
      headers: { "content-type": media },
      body: typeof body === "string" ? body : JSON.stringify(body),
    },
  );
  const text = await response.text();
  return {
    status: response.status,
    body: text ? JSON.parse(text) : null,
    hasCookie: response.headers.has("set-cookie"),
  };
}

compatScenario(
  "organization set-active respects blank selector precedence and writes cookies only for actual selection updates",
  async (ctx) => {
    const { owner, email, token, firstId, firstSlug, secondId, secondSlug, otherToken, before } =
      await setup(ctx);
    const blank = await set(ctx, owner, { organizationId: "", organizationSlug: "" });
    expect(blank.status).toBe(200);
    expect(blank.hasCookie).toBeTrue();
    expect(z.object({ id: z.string() }).parse(blank.body).id).toBe(firstId);
    expect(await state(ctx, email)).toEqual(before);
    const slug = await set(ctx, owner, { organizationId: "", organizationSlug: secondSlug });
    expect(slug.status).toBe(200);
    expect(z.object({ id: z.string() }).parse(slug.body).id).toBe(secondId);
    const afterSlug = await state(ctx, email);
    expect(afterSlug.organizations).toEqual(before.organizations);
    expect(afterSlug.sessions.find((row) => row.token === token)?.activeOrganizationId).toBe(
      secondId,
    );
    expect(afterSlug.sessions.find((row) => row.token === otherToken)).toEqual(
      before.sessions.find((row) => row.token === otherToken),
    );
    const idWins = await set(ctx, owner, { organizationId: firstId, organizationSlug: secondSlug });
    expect(idWins.status).toBe(200);
    expect(z.object({ id: z.string() }).parse(idWins.body).id).toBe(firstId);
    expect(await state(ctx, email)).toEqual(before);
    const missingSlug = await set(ctx, owner, {
      organizationSlug: ctx.uniqueToken("missing-slug"),
    });
    expect(missingSlug).toEqual({
      status: 400,
      body: { code: "ORGANIZATION_NOT_FOUND", message: "Organization not found" },
      hasCookie: false,
    });
    expect(await state(ctx, email)).toEqual(before);
    const nullWins = await set(ctx, owner, { organizationId: null, organizationSlug: secondSlug });
    expect(nullWins).toEqual({ status: 200, body: null, hasCookie: true });
    const cleared = await state(ctx, email);
    expect(cleared.sessions).toEqual(
      before.sessions.map((row) =>
        row.token === token ? { ...row, activeOrganizationId: null } : row,
      ),
    );
    expect(cleared.organizations).toEqual(before.organizations);
    const unselected = [];
    for (const body of [
      { organizationId: null },
      {},
      { organizationId: "", organizationSlug: "" },
    ]) {
      const result = await set(ctx, owner, body);
      expect(result).toEqual({ status: 200, body: null, hasCookie: false });
      expect(await state(ctx, email)).toEqual(cleared);
      unselected.push(result);
    }
    const retried = await set(ctx, owner, { organizationSlug: firstSlug });
    expect(retried.status).toBe(200);
    expect(retried.hasCookie).toBeTrue();
    expect(z.object({ id: z.string() }).parse(retried.body).id).toBe(firstId);
    expect(await state(ctx, email)).toEqual(before);
    return {
      before,
      blank,
      slug,
      afterSlug,
      idWins,
      missingSlug,
      nullWins,
      cleared,
      unselected,
      retried,
    };
  },
  ["POST /organization/set-active"],
);

compatScenario(
  "organization set-active clears only the denied current token and validates guest bodies before authentication",
  async (ctx) => {
    const { owner, email, token, firstId, firstSlug, otherToken, before } = await setup(ctx);
    const foreign = ctx.actor("selector-foreign-owner", "org-creation-empty-role");
    const foreignEmail = ctx.uniqueEmail("selector-foreign");
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
        name: "Foreign Selection",
        slug: ctx.uniqueToken("foreign-selection"),
        metadata: { guard: "foreign" },
      },
    });
    expect(foreignCreated.error).toBeNull();
    const foreignId = z.object({ id: z.string() }).parse(foreignCreated.data).id;
    const foreignBefore = await state(ctx, foreignEmail);
    const denied = await set(ctx, owner, {
      organizationId: foreignId,
      organizationSlug: firstSlug,
    });
    expect(denied).toEqual({
      status: 403,
      body: {
        code: "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
        message: "User is not a member of the organization",
      },
      hasCookie: false,
    });
    const cleared = await state(ctx, email);
    expect(cleared.sessions).toEqual(
      before.sessions.map((row) =>
        row.token === token ? { ...row, activeOrganizationId: null } : row,
      ),
    );
    expect(cleared.sessions.find((row) => row.token === otherToken)).toEqual(
      before.sessions.find((row) => row.token === otherToken),
    );
    expect(cleared.organizations).toEqual(before.organizations);
    expect(await state(ctx, foreignEmail)).toEqual(foreignBefore);
    const guest = ctx.actor("selector-guest", "org-creation-empty-role");
    const invalid = await set(ctx, guest, { organizationId: 1, organizationSlug: null });
    expect(invalid).toEqual({
      status: 400,
      body: {
        code: "VALIDATION_ERROR",
        message:
          "[body.organizationId] Invalid input: expected string, received number; [body.organizationSlug] Invalid input: expected string, received null",
      },
      hasCookie: false,
    });
    const validGuest = await set(ctx, guest, {});
    expect(validGuest).toEqual({
      status: 401,
      body: { code: "UNAUTHORIZED", message: "Unauthorized" },
      hasCookie: false,
    });
    const badMedia = await set(ctx, guest, "{invalid", "text/plain");
    expect(badMedia).toEqual({
      status: 415,
      body: {
        code: "UNSUPPORTED_MEDIA_TYPE",
        message: 'Content-Type "text/plain" is not allowed. Allowed types: application/json',
      },
      hasCookie: false,
    });
    expect(await state(ctx, email)).toEqual(cleared);
    expect(await state(ctx, foreignEmail)).toEqual(foreignBefore);
    const retry = await set(ctx, owner, { organizationId: firstId });
    expect(retry.status).toBe(200);
    expect(retry.hasCookie).toBeTrue();
    expect(await state(ctx, email)).toEqual(before);
    const missingId = await set(ctx, owner, {
      organizationId: ctx.uniqueToken("missing-organization"),
    });
    expect(missingId).toEqual({
      status: 403,
      body: {
        code: "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
        message: "User is not a member of the organization",
      },
      hasCookie: false,
    });
    expect(await state(ctx, email)).toEqual(cleared);
    expect(await state(ctx, foreignEmail)).toEqual(foreignBefore);
    return {
      before,
      foreignBefore,
      denied,
      cleared,
      invalid,
      validGuest,
      badMedia,
      retry,
      missingId,
    };
  },
  ["POST /organization/set-active"],
);
