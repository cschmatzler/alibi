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
    path: `/__test/organization-creation-state?email=${encodeURIComponent(email)}&includeMetadata=true`,
  });
  expect(response.status).toBe(200);
  return storedSchema.parse(response.body);
}

/** Signs up the owner and creates a sentinel organization whose stored row must never change. */
async function owner(ctx: ScenarioContext) {
  const actor = ctx.actor("owner", "org-creation-callback");
  const email = ctx.uniqueEmail("input-owner");
  const signup = await actor.client.signUp.email({
    name: "Paid Validation",
    email,
    password: "password123",
  });
  expect(signup.error).toBeNull();

  const created = await actor.client.$fetch("/organization/create", {
    method: "POST",
    body: {
      name: "Input Sentinel",
      slug: ctx.uniqueToken("sentinel"),
      metadata: { guard: "persisted" },
    },
  });
  expect(created.error).toBeNull();

  const id = z.object({ id: z.string() }).parse(created.data).id;
  return { ...actor, email, id, signup, created };
}

async function authenticatedRaw(
  ctx: ScenarioContext,
  actor: ReturnType<ScenarioContext["actor"]>,
  route: string,
  body: string,
  media: string,
) {
  const response = await actor.fetch(
    `${ctx.baseURL}/__test/profiles/org-creation-callback/api/auth/organization/${route}`,
    {
      method: "POST",
      headers: { "content-type": media },
      body,
    },
  );
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : null };
}

function expected(path: string, kind: string) {
  return {
    status: 400,
    code: "VALIDATION_ERROR",
    message: `[${path}] Invalid input: expected record, received ${kind}`,
  };
}

compatScenario(
  "organization metadata record validation precedes policy callbacks and preserves stored rows and selections",
  async (ctx) => {
    const actor = await owner(ctx);
    const before = await state(ctx, actor.email);
    expect(before.organizations[0]?.metadata).toBe('{"guard":"persisted"}');

    const observations = [];

    for (const [kind, metadata] of [
      ["null", null],
      ["array", []],
      ["string", "record"],
      ["number", 1],
      ["boolean", true],
    ] as const) {
      const created = await actor.client.$fetch("/organization/create", {
        method: "POST",
        body: { name: "Invalid", slug: ctx.uniqueToken(`invalid-${kind}`), metadata },
      });
      expect(created.error).toMatchObject(expected("body.metadata", kind));

      const updated = await actor.client.$fetch("/organization/update", {
        method: "POST",
        body: { organizationId: actor.id, data: { name: "must-not-persist", metadata } },
      });
      expect(updated.error).toMatchObject(expected("body.data.metadata", kind));
      expect(await state(ctx, actor.email)).toEqual(before);

      observations.push({ kind, created: ctx.snapshot(created), updated: ctx.snapshot(updated) });
    }

    // 1e400 overflows to Infinity, so it has to be sent as raw JSON text.
    for (const route of ["create", "update"] as const) {
      const body =
        route === "create"
          ? `{"name":"Overflow","slug":"${ctx.uniqueToken("overflow")}","metadata":1e400}`
          : `{"organizationId":"${actor.id}","data":{"metadata":1e400}}`;
      const rejected = await authenticatedRaw(ctx, actor, route, body, "application/json");
      expect(rejected.status).toBe(400);

      const error = expected(
        route === "create" ? "body.metadata" : "body.data.metadata",
        "Infinity",
      );
      expect(rejected.body).toEqual({ code: error.code, message: error.message });
      expect(await state(ctx, actor.email)).toEqual(before);

      observations.push({ route, rejected });
    }

    const record = { guard: "updated", nested: [null, true, { type: "application-value" }] };
    const valid = await actor.client.$fetch("/organization/update", {
      method: "POST",
      body: { organizationId: actor.id, data: { metadata: record } },
    });
    expect(valid.error).toBeNull();
    expect(z.object({ metadata: z.unknown() }).parse(valid.data).metadata).toEqual(record);

    const after = await state(ctx, actor.email);
    expect(after.organizations[0]?.metadata).toBe(JSON.stringify(record));
    expect(after.receipts).toEqual(before.receipts);
    expect(after.sessions).toEqual(before.sessions);

    const empty = await actor.client.$fetch("/organization/update", {
      method: "POST",
      body: { organizationId: actor.id, data: { metadata: {} } },
    });
    expect(empty.error).toBeNull();
    expect(z.object({ metadata: z.unknown() }).parse(empty.data).metadata).toEqual({});
    expect((await state(ctx, actor.email)).organizations[0]?.metadata).toBe("{}");

    return {
      signup: ctx.snapshot(actor.signup),
      created: ctx.snapshot(actor.created),
      before,
      observations,
      valid: ctx.snapshot(valid),
      after,
      empty: ctx.snapshot(empty),
      final: await state(ctx, actor.email),
    };
  },
  ["POST /organization/create", "POST /organization/update"],
);

compatScenario(
  "organization input schemas reject ordered invalid fields before guest authentication and persist no mutations",
  async (ctx) => {
    const actor = await owner(ctx);
    const before = await state(ctx, actor.email);
    const observations = [];

    for (const [path, body, message] of [
      [
        "create",
        {},
        "[body.name] Invalid input: expected string, received undefined; [body.slug] Invalid input: expected string, received undefined",
      ],
      [
        "create",
        { name: "", slug: "" },
        "[body.name] Too small: expected string to have >=1 characters; [body.slug] Too small: expected string to have >=1 characters",
      ],
      [
        "create",
        { name: "Valid", slug: "valid", metadata: null },
        "[body.metadata] Invalid input: expected record, received null",
      ],
      ["update", {}, "[body.data] Invalid input: expected object, received undefined"],
      [
        "update",
        { data: { name: "", slug: null, metadata: [] }, organizationId: 1 },
        "[body.data.name] Too small: expected string to have >=1 characters; [body.data.slug] Invalid input: expected string, received null; [body.data.metadata] Invalid input: expected record, received array; [body.organizationId] Invalid input: expected string, received number",
      ],
    ] as const) {
      const rejected = await ctx.rawRequest({
        path: `/__test/profiles/org-creation-callback/api/auth/organization/${path}`,
        method: "POST",
        json: body,
      });
      expect(rejected.status).toBe(400);
      expect(rejected.body).toEqual({ code: "VALIDATION_ERROR", message });
      expect(await state(ctx, actor.email)).toEqual(before);

      observations.push({ path, rejected });
    }

    for (const data of [{ name: "" }, { slug: "" }, { name: null }, { slug: null }] as const) {
      const rejected = await actor.client.$fetch("/organization/update", {
        method: "POST",
        body: { organizationId: actor.id, data },
      });
      expect(rejected.error).toMatchObject({ status: 400, code: "VALIDATION_ERROR" });
      expect(await state(ctx, actor.email)).toEqual(before);

      observations.push({ data, rejected: ctx.snapshot(rejected) });
    }

    for (const route of ["create", "update"] as const) {
      const malformed = await ctx.rawRequest({
        path: `/__test/profiles/org-creation-callback/api/auth/organization/${route}`,
        method: "POST",
        body: "{invalid",
        headers: { "content-type": "application/json" },
      });
      expect(malformed.status).toBe(400);
      expect(malformed.body).toEqual({
        code: "BAD_REQUEST",
        message: "Invalid JSON in request body",
      });

      observations.push({ route, malformed });
    }

    // A schema-valid body without a session is only then rejected by authentication.
    const validGuest = await ctx.rawRequest({
      path: "/__test/profiles/org-creation-callback/api/auth/organization/update",
      method: "POST",
      json: { organizationId: actor.id, data: { name: "guest-must-not-write" } },
    });
    expect(validGuest.status).toBe(401);
    expect(validGuest.body).toEqual({ message: "User not found" });
    expect(await state(ctx, actor.email)).toEqual(before);

    const corrected = await actor.client.$fetch("/organization/update", {
      method: "POST",
      body: {
        organizationId: actor.id,
        data: { name: "Corrected Name", slug: ctx.uniqueToken("corrected") },
      },
    });
    expect(corrected.error).toBeNull();

    const after = await state(ctx, actor.email);
    expect(after.organizations[0]?.name).toBe("Corrected Name");
    expect(after.organizations[0]?.metadata).toBe(before.organizations[0]?.metadata);
    expect(after.sessions).toEqual(before.sessions);

    return { before, observations, validGuest, corrected: ctx.snapshot(corrected), after };
  },
  ["POST /organization/create", "POST /organization/update"],
);

compatScenario(
  "organization JSON media checks reject before parsing or policies and permit uppercase retries and long slugs",
  async (ctx) => {
    const actor = await owner(ctx);
    const before = await state(ctx, actor.email);
    const observations = [];

    for (const media of ["text/plain", "application/x-www-form-urlencoded"]) {
      for (const route of ["create", "update"] as const) {
        const rejected = await authenticatedRaw(ctx, actor, route, "{invalid", media);
        expect(rejected.status).toBe(415);
        expect(rejected.body).toEqual({
          code: "UNSUPPORTED_MEDIA_TYPE",
          message: `Content-Type "${media}" is not allowed. Allowed types: application/json`,
        });
        expect(await state(ctx, actor.email)).toEqual(before);

        observations.push({ media, route, rejected });
      }
    }

    const retried = await authenticatedRaw(
      ctx,
      actor,
      "update",
      JSON.stringify({ organizationId: actor.id, data: { name: "Uppercase JSON" } }),
      "APPLICATION/JSON; charset=utf-8",
    );
    expect(retried.status).toBe(200);
    expect(z.object({ name: z.string() }).parse(retried.body).name).toBe("Uppercase JSON");

    const afterRetry = await state(ctx, actor.email);
    expect(afterRetry.organizations[0]?.name).toBe("Uppercase JSON");
    expect(afterRetry.receipts).toEqual(before.receipts);

    const longActor = ctx.actor("long-owner", "org-creation-empty-role");
    const email = ctx.uniqueEmail("long-slug");
    expect(
      (await longActor.client.signUp.email({ name: "Long Slug", email, password: "password123" }))
        .error,
    ).toBeNull();

    const slug = `${ctx.uniqueToken("long")}-${"a".repeat(101)}`;
    const longCreated = await longActor.client.$fetch("/organization/create", {
      method: "POST",
      body: { name: "Long Slug", slug, metadata: { length: "unbounded" } },
    });
    expect(longCreated.error).toBeNull();
    expect(z.object({ slug: z.string() }).parse(longCreated.data).slug).toBe(slug);

    const longAfter = await state(ctx, email);
    expect(longAfter.organizations[0]?.slug).toBe(slug);

    return {
      before,
      observations,
      retried,
      afterRetry,
      longCreated: ctx.snapshot(longCreated),
      longAfter,
    };
  },
  ["POST /organization/create", "POST /organization/update"],
);

compatScenario(
  "trusted organization creation validates typed input before user lookup and allow-policy evaluation",
  async (ctx) => {
    const actor = ctx.actor("trusted-owner", "org-creation-denied");
    const email = ctx.uniqueEmail("trusted-validation");
    const signup = await actor.client.signUp.email({
      name: "Trusted Validation",
      email,
      password: "password123",
    });
    expect(signup.error).toBeNull();

    const userId = z.object({ user: z.object({ id: z.string() }) }).parse(signup.data).user.id;
    const before = await state(ctx, email);

    // Input validation fires before the (nonexistent) user is looked up.
    const missing = ctx.uniqueToken("missing-user");
    const invalid = await ctx.rawRequest({
      path: "/__test/organization-create",
      method: "POST",
      json: { profile: "org-creation-denied", userId: missing, name: "", slug: "" },
    });
    expect(invalid.status).toBe(400);
    expect(invalid.body).toEqual({
      code: "VALIDATION_ERROR",
      message:
        "[body.name] Too small: expected string to have >=1 characters; [body.slug] Too small: expected string to have >=1 characters",
    });

    const observations = [];

    for (const [kind, metadata] of [
      ["null", null],
      ["array", []],
      ["string", "wrong"],
    ] as const) {
      const rejected = await ctx.rawRequest({
        path: "/__test/organization-create",
        method: "POST",
        json: {
          profile: "org-creation-denied",
          userId,
          name: "Rejected",
          slug: ctx.uniqueToken(`typed-${kind}`),
          metadata,
        },
      });
      const error = expected("body.metadata", kind);
      expect(rejected.status).toBe(400);
      expect(rejected.body).toEqual({ code: error.code, message: error.message });
      expect(await state(ctx, email)).toEqual(before);

      observations.push({ kind, rejected });
    }

    // The trusted server path bypasses the profile's deny policy once input is valid.
    const valid = await ctx.rawRequest({
      path: "/__test/organization-create",
      method: "POST",
      json: {
        profile: "org-creation-denied",
        userId,
        name: "Trusted Success",
        slug: ctx.uniqueToken("trusted-success"),
        metadata: { trusted: "record" },
      },
    });
    expect(valid.status).toBe(200);

    const organization = z
      .object({
        id: z.string(),
        metadata: z.unknown(),
        members: z.array(z.object({ userId: z.string(), role: z.string() })),
      })
      .parse(valid.body);
    expect(organization.members[0]).toMatchObject({ userId, role: "owner" });
    expect(organization.metadata).toEqual({ trusted: "record" });

    const after = await state(ctx, email);
    expect(after.organizations).toHaveLength(1);
    expect(after.organizations[0]).toMatchObject({
      id: organization.id,
      userId,
      metadata: '{"trusted":"record"}',
    });
    expect(after.orphanOrganizations).toEqual(before.orphanOrganizations);
    expect(after.sessions).toEqual(before.sessions);

    return { signup: ctx.snapshot(signup), before, invalid, observations, valid, after };
  },
);
