import { expect } from "bun:test";

import { z } from "zod";

import { compatScenario, type ScenarioContext } from "../../../support/scenario";

const row = z.object({ id: z.string() }).passthrough();

const snapshot = z.object({
  organizations: z.array(row),
  members: z.array(row),
  users: z.array(row),
  sessions: z.array(row),
});

async function state(ctx: ScenarioContext) {
  const response = await ctx.rawRequest({ path: "/__test/organization-update-hooks-state" });
  expect(response.status).toBe(200);
  return snapshot.parse(z.object({ snapshot }).parse(response.body).snapshot);
}

async function storage(ctx: ScenarioContext, organizationId: string, mode: string) {
  const response = await ctx.rawRequest({
    path: "/__test/organization-update-storage",
    method: "POST",
    json: { organizationId, mode },
  });
  expect(response.status).toBe(200);
}

async function setup(ctx: ScenarioContext) {
  const owner = ctx.actor("owner");
  const foreign = ctx.actor("foreign");
  const sibling = ctx.actor("sibling");
  const email = ctx.uniqueEmail("owner");

  // The sibling actor is a second session for the owner's user.
  expect(
    (await owner.client.signUp.email({ name: "Owner", email, password: "password123" })).error,
  ).toBeNull();
  expect((await sibling.client.signIn.email({ email, password: "password123" })).error).toBeNull();
  expect(
    (
      await foreign.client.signUp.email({
        name: "Foreign",
        email: ctx.uniqueEmail("foreign"),
        password: "password123",
      })
    ).error,
  ).toBeNull();

  async function create(actor: typeof owner, label: string) {
    const result = await actor.client.$fetch("/organization/create", {
      method: "POST",
      body: {
        name: label,
        slug: ctx.uniqueToken(label),
        logo: "https://example.test/logo.png",
        metadata: { private: label, nested: [true, null] },
      },
    });
    expect(result.error).toBeNull();
    return z.object({ id: z.string(), slug: z.string() }).parse(result.data);
  }

  const target = await create(owner, "target");
  const other = await create(owner, "sibling");
  const foreignOrg = await create(foreign, "foreign");

  expect(
    (
      await sibling.client.$fetch("/organization/set-active", {
        method: "POST",
        body: { organizationId: target.id },
      })
    ).error,
  ).toBeNull();

  return { owner, sibling, foreign, target, other, foreignOrg };
}

type Wire = { status?: number; body?: string; contentType?: string | null };

function update(
  actor: ReturnType<ScenarioContext["actor"]>,
  organizationId: string,
  data: Record<string, unknown>,
  wire?: Wire,
) {
  return actor.client.$fetch("/organization/update", {
    method: "POST",
    body: { organizationId, data },
    onResponse: async ({ response }) => {
      if (wire) {
        Object.assign(wire, {
          status: response.status,
          body: await response.clone().text(),
          contentType: response.headers.get("content-type"),
        });
      }
    },
  });
}

function preserved(
  before: z.infer<typeof snapshot>,
  after: z.infer<typeof snapshot>,
  target: string,
) {
  expect(after.organizations.filter((row) => row.id !== target)).toEqual(
    before.organizations.filter((row) => row.id !== target),
  );
  for (const key of ["members", "users", "sessions"] as const) {
    expect(after[key]).toEqual(before[key]);
  }
}

compatScenario(
  "default organization update empty SQL failure preserves state and ordinary retry",
  async (ctx) => {
    const { owner, sibling, foreign, target, other } = await setup(ctx);
    await storage(ctx, target.id, "none");

    const member = ctx.actor("member");
    const memberEmail = ctx.uniqueEmail("member");
    expect(
      (
        await member.client.signUp.email({
          name: "Member",
          email: memberEmail,
          password: "password123",
        })
      ).error,
    ).toBeNull();

    const invitation = await owner.client.$fetch("/organization/invite-member", {
      method: "POST",
      body: { organizationId: target.id, email: memberEmail, role: "member" },
    });
    expect(invitation.error).toBeNull();

    const invitationId = z.object({ id: z.string() }).parse(invitation.data).id;
    expect(
      (
        await member.client.$fetch("/organization/accept-invitation", {
          method: "POST",
          body: { invitationId },
        })
      ).error,
    ).toBeNull();

    const before = await state(ctx);

    const memberDenied = await update(member, target.id, {});
    expect(memberDenied.error?.status).toBe(403);

    const guest = await ctx.rawRequest({
      path: "/api/auth/organization/update",
      method: "POST",
      json: { organizationId: target.id, data: {} },
    });
    expect(guest.status).toBe(401);

    const emptyWire: Wire = {};
    const empty = await update(owner, target.id, {}, emptyWire);
    expect(emptyWire).toEqual({ status: 500, body: "", contentType: null });
    expect(empty.error?.status).toBe(500);

    const afterEmpty = await state(ctx);
    expect(afterEmpty).toEqual(before);

    const foreignDenied = await update(foreign, target.id, {});
    expect(foreignDenied.error?.status).toBe(400);

    const duplicate = await update(owner, target.id, { slug: other.slug });
    expect(duplicate.error?.status).toBe(400);
    expect(await state(ctx)).toEqual(before);

    // An empty organization id falls back to the sibling session's active organization.
    const retry = await update(sibling, "", { name: "Recovered", logo: null });
    expect(retry.error).toBeNull();
    expect(
      z.object({ id: z.string(), name: z.string(), logo: z.null() }).parse(retry.data),
    ).toMatchObject({ id: target.id, name: "Recovered", logo: null });

    const afterRetry = await state(ctx);
    preserved(before, afterRetry, target.id);
    expect(afterRetry.organizations.find((row) => row.id === target.id)).toEqual({
      ...before.organizations.find((row) => row.id === target.id)!,
      name: "Recovered",
      logo: null,
    });

    await storage(ctx, target.id, "veto");
    const veto = await update(owner, target.id, { name: "Vetoed" });
    expect(veto.error?.status).toBe(500);
    expect(await state(ctx)).toEqual(afterRetry);

    await storage(ctx, target.id, "none");

    return {
      before,
      emptyWire,
      guest,
      memberDenied: ctx.snapshot(memberDenied),
      empty: ctx.snapshot(empty),
      afterEmpty,
      foreignDenied: ctx.snapshot(foreignDenied),
      duplicate: ctx.snapshot(duplicate),
      retry: ctx.snapshot(retry),
      afterRetry,
      veto: ctx.snapshot(veto),
    };
  },
  ["POST /organization/update"],
);

compatScenario(
  "default organization update distinguishes ignored SQL from real row disappearance after authorization",
  async (ctx) => {
    const { owner, target } = await setup(ctx);
    const before = await state(ctx);

    await storage(ctx, target.id, "ignore");
    const ignoredWire: Wire = {};
    const ignored = await update(owner, target.id, { name: "Ignored" }, ignoredWire);
    expect(ignoredWire).toEqual({ status: 200, body: "null", contentType: "application/json" });
    expect(ignored.error).toBeNull();
    expect(ignored.data).toBeNull();
    expect(await state(ctx)).toEqual(before);

    await storage(ctx, target.id, "delete");
    const vanishedWire: Wire = {};
    const vanished = await update(owner, target.id, { name: "Gone" }, vanishedWire);
    expect(vanishedWire).toEqual({ status: 200, body: "null", contentType: "application/json" });
    expect(vanished.error).toBeNull();
    expect(vanished.data).toBeNull();

    const after = await state(ctx);
    expect(after.organizations.some((row) => row.id === target.id)).toBe(false);
    expect(after.organizations).toEqual(before.organizations.filter((row) => row.id !== target.id));
    expect(after.members.filter((row) => row.organizationId !== target.id)).toEqual(
      before.members.filter((row) => row.organizationId !== target.id),
    );
    expect(after.members.filter((row) => row.organizationId === target.id)).toEqual([]);
    expect(after.users).toEqual(before.users);
    expect(after.sessions).toEqual(before.sessions);

    await storage(ctx, target.id, "none");

    return {
      before,
      ignoredWire,
      vanishedWire,
      ignored: ctx.snapshot(ignored),
      vanished: ctx.snapshot(vanished),
      after,
    };
  },
  ["POST /organization/update"],
);
