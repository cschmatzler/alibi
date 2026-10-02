import { expect } from "bun:test";
import { z } from "zod";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { createTracingFetch, type TraceEntry } from "../../support/trace";

const row = z.object({ id: z.string() }).passthrough();
const snapshot = z.object({
  organizations: z.array(row),
  members: z.array(row),
  users: z.array(row),
  sessions: z.array(row),
});
const receipt = z.object({
  phase: z.string(),
  organization: z.record(z.string(), z.unknown()).nullable(),
  user: z.object({ id: z.string(), email: z.string(), name: z.string() }),
  member: z.object({
    id: z.string(),
    organizationId: z.string(),
    userId: z.string(),
    role: z.string(),
  }),
  snapshot,
});
const stateSchema = z.object({ receipts: z.array(receipt), snapshot });
const organization = z
  .object({
    id: z.string(),
    name: z.string(),
    slug: z.string(),
    logo: z.string().nullable(),
    metadata: z.unknown().optional(),
  })
  .passthrough();
async function configure(ctx: ScenarioContext, mode: string) {
  expect(
    (
      await ctx.rawRequest({
        path: "/__test/organization-update-hooks-configure",
        method: "POST",
        json: { mode },
      })
    ).status,
  ).toBe(200);
}
async function state(ctx: ScenarioContext, waitFor?: string) {
  const result = await ctx.rawRequest({
    path: "/__test/organization-update-hooks-state" + (waitFor ? `?waitFor=${waitFor}` : ""),
  });
  expect(result.status).toBe(200);
  return stateSchema.parse(result.body);
}
async function signup(ctx: ScenarioContext, name: string) {
  const actor = ctx.actor(name, "org-update-hooks"),
    email = ctx.uniqueEmail(name);
  const result = await actor.client.signUp.email({
    name,
    email,
    password: "password123",
  });
  expect(result.error).toBeNull();
  return {
    ...actor,
    email,
    userId: z.object({ user: z.object({ id: z.string() }) }).parse(result.data).user.id,
  };
}
type Actor = Awaited<ReturnType<typeof signup>>;
async function create(ctx: ScenarioContext, actor: Actor, name: string) {
  const result = await actor.client.$fetch("/organization/create", {
    method: "POST",
    body: {
      name,
      slug: ctx.uniqueToken(name),
      logo: "https://example.test/original.png",
      metadata: { original: true },
    },
  });
  expect(result.error).toBeNull();
  return organization.parse(result.data);
}
function update(actor: Actor, organizationId: string, data: Record<string, unknown>) {
  return actor.client.$fetch("/organization/update", {
    method: "POST",
    body: { organizationId, data },
  });
}
function unchanged(
  before: z.infer<typeof stateSchema>,
  after: z.infer<typeof stateSchema>,
  target: string,
) {
  expect(after.snapshot.organizations.filter((r) => r.id !== target)).toEqual(
    before.snapshot.organizations.filter((r) => r.id !== target),
  );
  for (const key of ["members", "users", "sessions"] as const)
    expect(after.snapshot[key]).toEqual(before.snapshot[key]);
}
async function setup(ctx: ScenarioContext, name: string) {
  const owner = await signup(ctx, `${name}-owner`),
    foreign = await signup(ctx, `${name}-foreign`),
    target = await create(ctx, owner, `${name}-target`),
    other = await create(ctx, foreign, `${name}-other`);
  return { owner, foreign, target, other };
}

compatScenario(
  "organization update hooks merge null empty and absent patches with parsed adapter output",
  async (ctx) => {
    const { owner, target } = await setup(ctx, "update-patch"),
      observations = [];
    for (const mode of [
      "patch",
      "null-metadata",
      "empty-metadata",
      "absent-metadata",
      "empty-name",
    ]) {
      await configure(ctx, mode);
      const before = await state(ctx),
        input = {
          name: "HTTP Update",
          logo: "https://example.test/http.png",
          metadata: { supplied: mode },
        },
        result = await update(owner, target.id, input);
      expect(result.error).toBeNull();
      const parsed = organization.parse(result.data),
        after = await state(ctx);
      expect(after.receipts.map((r) => r.phase)).toEqual(["before-update", "after-update"]);
      expect(after.receipts[0]!.organization).toEqual(input);
      expect(after.receipts[0]!.organization).not.toHaveProperty("id");
      expect(after.receipts[0]!.member).toMatchObject({
        organizationId: target.id,
        userId: owner.userId,
        role: "owner",
      });
      expect(after.receipts[0]!.user).toEqual({
        id: owner.userId,
        email: owner.email,
        name: "update-patch-owner",
      });
      expect(after.receipts[0]!.snapshot).toEqual(before.snapshot);
      expect(after.receipts[1]!.organization).toEqual(organization.parse(ctx.snapshot(parsed)));
      expect(after.receipts[1]!.snapshot).toEqual(after.snapshot);
      const stored = after.snapshot.organizations.find((r) => r.id === target.id)!;
      if (mode === "patch") {
        expect(parsed).toMatchObject({
          name: "Hooked Update",
          logo: null,
          metadata: { guard: "hooked-update" },
        });
        expect(stored.metadata).toBe('{"guard":"hooked-update"}');
      }
      if (mode === "null-metadata") {
        expect(parsed.metadata).toBeNull();
        expect(parsed.logo).toBeNull();
        expect(stored.metadata).toBe("null");
      }
      if (mode === "empty-metadata") {
        expect(parsed.metadata).toEqual({});
        expect(stored.metadata).toBe("{}");
      }
      if (mode === "absent-metadata") {
        expect(parsed.name).toBe("Patched Without Metadata");
        expect(parsed.metadata).toEqual(input.metadata);
        expect(stored.metadata).toBe(JSON.stringify(input.metadata));
      }
      if (mode === "empty-name") {
        expect(parsed.name).toBe("");
        expect(stored.name).toBe("");
      }
      unchanged(before, after, target.id);
      observations.push({ mode, before, result: ctx.snapshot(result), after });
    }
    return observations;
  },
  ["POST /organization/update"],
);

compatScenario(
  "organization update hook rejection retains source before and after persistence ordering",
  async (ctx) => {
    const { owner, target } = await setup(ctx, "update-error");
    expect(
      (
        await ctx
          .actor("update-error-sibling", "org-update-hooks")
          .client.signIn.email({ email: owner.email, password: "password123" })
      ).error,
    ).toBeNull();
    const observations = [];
    for (const mode of ["reject-before-update", "reject-after-update"]) {
      await configure(ctx, mode);
      const before = await state(ctx),
        data = { name: mode, metadata: { rejection: mode } },
        result = await update(owner, target.id, data);
      expect(result.error).toMatchObject({
        status: 400,
        code: "UPDATE_HOOK_REJECTED",
        message: `Rejected ${mode.slice(7)}`,
      });
      const after = await state(ctx);
      expect(after.receipts.map((r) => r.phase)).toEqual(
        mode === "reject-before-update" ? ["before-update"] : ["before-update", "after-update"],
      );
      if (mode === "reject-before-update") expect(after.snapshot).toEqual(before.snapshot);
      else {
        expect(after.snapshot.organizations.find((r) => r.id === target.id)).toMatchObject({
          name: mode,
          metadata: JSON.stringify(data.metadata),
        });
        unchanged(before, after, target.id);
      }
      observations.push({ mode, before, result: ctx.snapshot(result), after });
    }
    return observations;
  },
  ["POST /organization/update"],
);

compatScenario(
  "organization update validation authority and duplicate guards run before application hooks",
  async (ctx) => {
    const { owner, foreign, target, other } = await setup(ctx, "update-guards");
    await configure(ctx, "reject-before-update");
    const before = await state(ctx);
    const wrongOwner = await update(foreign, target.id, { name: "Forbidden" });
    expect(wrongOwner.error).toMatchObject({
      status: 400,
      code: "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
    });
    const duplicate = await update(owner, target.id, { slug: other.slug });
    expect(duplicate.error).toMatchObject({
      status: 400,
      code: "ORGANIZATION_SLUG_ALREADY_TAKEN",
      message: "Organization slug already taken",
    });
    const invalid = await update(owner, target.id, { name: 42 });
    expect(invalid.error).toMatchObject({
      status: 400,
      code: "VALIDATION_ERROR",
    });
    const unauthenticated = await ctx
      .actor("update-guards-guest", "org-update-hooks")
      .client.$fetch("/organization/update", {
        method: "POST",
        body: { organizationId: target.id, data: { name: "Guest" } },
      });
    expect(unauthenticated.error).toMatchObject({
      status: 401,
      message: "User not found",
    });
    const after = await state(ctx);
    expect(after).toEqual(before);
    return {
      before,
      wrongOwner: ctx.snapshot(wrongOwner),
      duplicate: ctx.snapshot(duplicate),
      invalid: ctx.snapshot(invalid),
      unauthenticated: ctx.snapshot(unauthenticated),
      after,
    };
  },
  ["POST /organization/update"],
);

compatScenario(
  "organization update callbacks retain original actor and membership despite independent writes",
  async (ctx) => {
    const { owner, target } = await setup(ctx, "update-authority");
    await configure(ctx, "mutate-authority");
    const before = await state(ctx),
      result = await update(owner, target.id, {
        name: "Authorized Before Hook",
      });
    expect(result.error).toBeNull();
    const after = await state(ctx);
    expect(after.receipts.map((r) => r.phase)).toEqual(["before-update", "after-update"]);
    expect(after.receipts[1]!.user).toEqual(after.receipts[0]!.user);
    expect(after.receipts[1]!.member).toEqual(after.receipts[0]!.member);
    expect(after.receipts[1]!.user.name).toBe("update-authority-owner");
    expect(after.receipts[1]!.member.role).toBe("owner");
    expect(after.snapshot.users.find((r) => r.id === owner.userId)).toMatchObject({
      name: "Stored New Name",
    });
    expect(after.snapshot.members.find((r) => r.id === after.receipts[0]!.member.id)).toMatchObject(
      { role: "member" },
    );
    expect(after.snapshot.sessions).toEqual(before.snapshot.sessions);
    expect(after.snapshot.organizations.filter((r) => r.id !== target.id)).toEqual(
      before.snapshot.organizations.filter((r) => r.id !== target.id),
    );
    await configure(ctx, "reject-before-update");
    const denied = await update(owner, target.id, {
      name: "Must Recheck Current Membership",
    });
    expect(denied.error).toMatchObject({
      status: 403,
      code: "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION",
    });
    const deniedState = await state(ctx);
    expect(deniedState.receipts).toEqual([]);
    expect(deniedState.snapshot).toEqual(after.snapshot);
    return {
      before,
      result: ctx.snapshot(result),
      after,
      denied: ctx.snapshot(denied),
      deniedState,
    };
  },
  ["POST /organization/update"],
);

compatScenario(
  "organization update after hook receives null when before hook actually deletes its row",
  async (ctx) => {
    const { owner, target } = await setup(ctx, "update-missing");
    expect(
      (
        await ctx
          .actor("update-missing-sibling", "org-update-hooks")
          .client.signIn.email({ email: owner.email, password: "password123" })
      ).error,
    ).toBeNull();
    await configure(ctx, "delete-row");
    const before = await state(ctx),
      result = await update(owner, target.id, { name: "Missing At Write" });
    expect(result.error).toBeNull();
    expect(result.data).toBeNull();
    const after = await state(ctx);
    expect(after.receipts.map((r) => r.phase)).toEqual(["before-update", "after-update"]);
    expect(after.receipts[1]!.organization).toBeNull();
    expect(after.receipts[1]!.member).toEqual(after.receipts[0]!.member);
    expect(after.snapshot.organizations).toEqual(
      before.snapshot.organizations.filter((r) => r.id !== target.id),
    );
    expect(after.snapshot.members).toEqual(
      before.snapshot.members.filter((r) => r.organizationId !== target.id),
    );
    expect(after.snapshot.sessions).toEqual(before.snapshot.sessions);
    expect(after.snapshot.users).toEqual(before.snapshot.users);
    return { before, result: ctx.snapshot(result), after };
  },
  ["POST /organization/update"],
);

compatScenario(
  "organization update awaits its real async before hook before executing the adapter",
  async (ctx) => {
    const owner = await signup(ctx, "update-await-owner"),
      target = await create(ctx, owner, "update-await-target");
    await configure(ctx, "pause-before");
    const before = await state(ctx);
    let completed = false;
    const pending = update(owner, target.id, {
      name: "Awaited Adapter Write",
    }).then((result) => {
      completed = true;
      return result;
    });
    let paused: Awaited<ReturnType<typeof state>> | undefined;
    const releaseTrace: TraceEntry[] = [];
    try {
      paused = await state(ctx, "before-update");
      expect(paused.receipts.map((r) => r.phase)).toEqual(["before-update"]);
      expect(completed).toBe(false);
      expect(paused.snapshot).toEqual(before.snapshot);
    } finally {
      const released = await createTracingFetch(
        ctx.baseURL,
        "update-hook-release",
        releaseTrace,
      )("/__test/organization-update-hooks-release", { method: "POST" });
      expect(released.status).toBe(200);
      expect(await released.json()).toEqual({ released: true });
    }
    const result = await pending;
    ctx.recordTransport(releaseTrace);
    expect(result.error).toBeNull();
    const after = await state(ctx);
    expect(after.receipts.map((r) => r.phase)).toEqual(["before-update", "after-update"]);
    expect(after.snapshot.organizations.find((r) => r.id === target.id)).toMatchObject({
      name: "Awaited Adapter Write",
    });
    expect(after.snapshot.sessions).toEqual(before.snapshot.sessions);
    return { before, paused, result: ctx.snapshot(result), after };
  },
  ["POST /organization/update"],
);

compatScenario(
  "organization update hooks observe raw nonfinite and signed-zero metadata before adapter JSON normalization",
  async (ctx) => {
    const { owner, target } = await setup(ctx, "update-raw-metadata");
    const observations = [];
    for (const [raw, numberClass, serialized, negativeZero] of [
      ["1e999", "positive-infinity", "null", false],
      ["-1e999", "negative-infinity", "null", false],
      ["-0", "negative-zero", "0", true],
    ] as const) {
      await configure(ctx, "raw-metadata");
      const before = await state(ctx);
      const result = await owner.client.$fetch("/organization/update", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: `{"organizationId":${JSON.stringify(target.id)},"data":{"name":"Raw Metadata","metadata":{"n":${raw}}}}`,
      });
      expect(result.error).toBeNull();
      const parsed = organization.parse(result.data);
      expect(parsed.name).toBe(numberClass);
      expect(parsed.metadata).toEqual({
        original: serialized === "null" ? null : 0,
        patched: serialized === "null" ? null : 0,
        negativeZero,
      });
      const after = await state(ctx);
      expect(after.receipts.map((r) => r.phase)).toEqual(["before-update", "after-update"]);
      expect(after.receipts[1]!.organization).toEqual(organization.parse(ctx.snapshot(parsed)));
      expect(after.snapshot.organizations.find((r) => r.id === target.id)).toMatchObject({
        name: numberClass,
        metadata: `{"original":${serialized},"patched":${serialized},"negativeZero":${negativeZero}}`,
      });
      unchanged(before, after, target.id);
      observations.push({ raw, before, result: ctx.snapshot(result), after });
    }
    return observations;
  },
  ["POST /organization/update"],
);
