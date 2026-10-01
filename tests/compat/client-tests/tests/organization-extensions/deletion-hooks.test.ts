import { disconnectedRequest } from "./disconnect";
import { expect } from "bun:test";
import { z } from "zod";
import { createTracingFetch, type TraceEntry } from "../../support/trace";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { data, orgActor, signUp, serverOperation } from "./helpers";
import type { FixtureProfile } from "../../support/profiles";
const profile = "org-deletion-hooks" as const;
const row = z.object({ id: z.string() }).passthrough();
const snapshot = z.object({
  organizations: z.array(row),
  members: z.array(row),
  invitations: z.array(row),
  teams: z.array(row),
  teamMembers: z.array(row),
  sessions: z.array(row),
  users: z.array(row),
});
const receipt = z.object({
  phase: z.string(),
  organization: z.record(z.string(), z.unknown()),
  user: z.object({ id: z.string(), email: z.string(), name: z.string() }),
  session: row,
  header: z.string().nullable(),
  request: z
    .object({
      method: z.string(),
      path: z.string(),
      header: z.string().nullable(),
    })
    .nullable(),
  snapshot,
});
const stateSchema = z.object({ receipts: z.array(receipt), snapshot });
async function configure(ctx: ScenarioContext, mode: string) {
  expect(
    (
      await ctx.rawRequest({
        path: "/__test/organization-delete-hooks-configure",
        method: "POST",
        json: { mode },
      })
    ).status,
  ).toBe(200);
}
async function state(ctx: ScenarioContext, waitFor?: string) {
  const response = await ctx.rawRequest({
    path:
      "/__test/organization-delete-hooks-state" +
      (waitFor ? `?waitFor=${waitFor}` : ""),
  });
  expect(response.status).toBe(200);
  return stateSchema.parse(response.body);
}
async function setup(
  ctx: ScenarioContext,
  label: string,
  selected: FixtureProfile = profile,
) {
  const owner = await signUp(ctx, `${label}-owner`, selected),
    foreign = await signUp(ctx, `${label}-foreign`, selected);
  const created = await owner.client.organization.create({
    name: `${label} Target`,
    slug: ctx.uniqueToken(`${label}-target`),
    metadata: { guard: label, large: 1e20 },
  });
  const org = data(created);
  const unrelated = await foreign.client.organization.create({
    name: `${label} Foreign`,
    slug: ctx.uniqueToken(`${label}-foreign`),
    metadata: { guard: "unrelated" },
  });
  const foreignOrg = data(unrelated);
  const sibling = orgActor(ctx, `${label}-sibling`, selected);
  data(
    await sibling.signIn.email({ email: owner.email, password: "password123" }),
  );
  data(await sibling.organization.setActive({ organizationId: org.id }));
  const invited = await owner.client.organization.inviteMember({
    organizationId: org.id,
    email: ctx.uniqueEmail(`${label}-pending`),
    role: "member",
  });
  data(invited);
  return {
    owner,
    foreign,
    sibling,
    org,
    foreignOrg,
    created,
    unrelated,
    invited,
    session: data(await owner.client.getSession()).session,
  };
}
function isolation(
  before: z.infer<typeof snapshot>,
  after: z.infer<typeof snapshot>,
  target: Awaited<ReturnType<typeof setup>>,
) {
  for (const key of ["organizations", "members", "invitations"] as const)
    expect(
      after[key].filter(
        (r) =>
          r.id === target.foreignOrg.id ||
          r.organizationId === target.foreignOrg.id,
      ),
    ).toEqual(
      before[key].filter(
        (r) =>
          r.id === target.foreignOrg.id ||
          r.organizationId === target.foreignOrg.id,
      ),
    );
  for (const key of ["teams", "teamMembers", "users"] as const)
    expect(after[key]).toEqual(before[key]);
  expect(after.sessions.filter((r) => r.id !== target.session.id)).toEqual(
    before.sessions.filter((r) => r.id !== target.session.id),
  );
  expect(after.sessions.find((r) => r.id === target.session.id)).toMatchObject({
    activeOrganizationId: null,
    activeTeamId: target.session.activeTeamId,
  });
}
const remove = (target: Awaited<ReturnType<typeof setup>>, header: string) =>
  target.owner.client.$fetch("/organization/delete", {
    method: "POST",
    headers: { "x-delete-hook": header },
    body: {
      organizationId: target.org.id,
      userId: target.foreign.user.id,
      role: "admin",
      mode: "reject-before",
    },
  });
compatScenario(
  "organization deletion hooks receive raw rows and original authority after token clearing and before committed deletion",
  async (ctx) => {
    await configure(ctx, "record");
    const target = await setup(ctx, "ordered");
    const before = await state(ctx);
    const deleted = await remove(target, "actual-http-header");
    expect(deleted.error).toBeNull();
    expect(deleted.data).toMatchObject({
      id: target.org.id,
      metadata: '{"guard":"ordered","large":100000000000000000000}',
    });
    const after = await state(ctx);
    expect(after.receipts.map((r) => r.phase)).toEqual(["before", "after"]);
    for (const r of after.receipts) {
      expect(r.user).toMatchObject({
        id: target.owner.user.id,
        email: target.owner.email,
      });
      expect(r.organization).toMatchObject({
        id: target.org.id,
        name: target.org.name,
        metadata: '{"guard":"ordered","large":100000000000000000000}',
      });
      expect(r.session).toMatchObject({
        id: target.session.id,
        userId: target.owner.user.id,
        activeOrganizationId: target.org.id,
        activeTeamId: target.session.activeTeamId,
      });
      expect(r.header).toBe("actual-http-header");
      expect(r.request).toEqual({
        method: "POST",
        path: "/organization/delete",
        header: "actual-http-header",
      });
      isolation(before.snapshot, r.snapshot, target);
    }
    for (const key of ["organizations", "members", "invitations"] as const) {
      expect(
        after.receipts[0]!.snapshot[key].some(
          (r) => r.id === target.org.id || r.organizationId === target.org.id,
        ),
      ).toBe(true);
      expect(
        after.receipts[1]!.snapshot[key].some(
          (r) => r.id === target.org.id || r.organizationId === target.org.id,
        ),
      ).toBe(false);
    }
    isolation(before.snapshot, after.snapshot, target);
    expect(
      data(await target.sibling.getSession()).session.activeOrganizationId,
    ).toBe(target.org.id);
    return {
      created: target.created,
      unrelated: target.unrelated,
      invited: target.invited,
      before,
      deleted: ctx.snapshot(deleted),
      after,
    };
  },
  ["POST /organization/delete"],
);
compatScenario(
  "organization deletion hook rejections preserve their exact nontransactional partial writes",
  async (ctx) => {
    const observations = [];
    for (const phase of ["before", "after"]) {
      await configure(ctx, "record");
      const target = await setup(ctx, `reject-${phase}`);
      const before = await state(ctx);
      await configure(ctx, `reject-${phase}`);
      const rejected = await remove(target, `reject-${phase}-header`);
      expect(rejected.error).toMatchObject({
        status: 400,
        code: "DELETION_HOOK_REJECTED",
        message: `Rejected ${phase}`,
      });
      const after = await state(ctx);
      expect(after.receipts.map((r) => r.phase)).toEqual(
        phase === "before" ? ["before"] : ["before", "after"],
      );
      isolation(before.snapshot, after.snapshot, target);
      for (const key of ["organizations", "members", "invitations"] as const) {
        if (phase === "before")
          expect(after.snapshot[key]).toEqual(before.snapshot[key]);
        else
          expect(
            after.snapshot[key].some(
              (r) =>
                r.id === target.org.id || r.organizationId === target.org.id,
            ),
          ).toBe(false);
      }
      observations.push({ before, rejected: ctx.snapshot(rejected), after });
    }
    return observations;
  },
  ["POST /organization/delete"],
);
compatScenario(
  "organization deletion guards prevent configured callbacks for denied authority and genuine missing rows",
  async (ctx) => {
    await configure(ctx, "reject-before");
    const target = await setup(ctx, "guards");
    const before = await state(ctx);
    const foreign = await target.foreign.client.$fetch("/organization/delete", {
      method: "POST",
      body: { organizationId: target.org.id, userId: target.owner.user.id },
    });
    expect(foreign.error).toMatchObject({
      status: 400,
      code: "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
    });
    const invalid = await ctx.rawRequest({
      path: "/__test/profiles/org-deletion-hooks/api/auth/organization/delete",
      method: "POST",
      json: { organizationId: 7 },
    });
    expect(invalid.status).toBe(400);
    const guest = await ctx.rawRequest({
      path: "/__test/profiles/org-deletion-hooks/api/auth/organization/delete",
      method: "POST",
      json: { organizationId: target.org.id },
    });
    expect(guest.status).toBe(401);
    expect(await state(ctx)).toEqual(before);
    const orphan = await serverOperation(
      ctx,
      { operation: "orphan-organization", organizationId: target.org.id },
      "org-teams",
    );
    expect(orphan.status).toBe(200);
    const rows = await state(ctx);
    const missing = await remove(target, "missing-header");
    expect(missing.error?.status).toBe(400);
    const after = await state(ctx);
    expect(after.receipts).toEqual([]);
    for (const key of ["organizations", "members", "invitations"] as const)
      expect(after.snapshot[key]).toEqual(rows.snapshot[key]);
    isolation(rows.snapshot, after.snapshot, target);
    const disabled = await signUp(
      ctx,
      "hook-disabled",
      "org-deletion-hooks-disabled",
    );
    const disabledOrg = data(
      await disabled.client.organization.create({
        name: "Disabled",
        slug: ctx.uniqueToken("hook-disabled"),
      }),
    );
    const disabledBefore = await state(ctx);
    const denied = await disabled.client.organization.delete({
      organizationId: disabledOrg.id,
    });
    expect(denied.error).toMatchObject({
      status: 404,
      code: "ORGANIZATION_DELETION_DISABLED",
    });
    expect(await state(ctx)).toEqual(disabledBefore);
    return {
      before,
      foreign: ctx.snapshot(foreign),
      invalid,
      guest,
      orphan,
      rows,
      missing: ctx.snapshot(missing),
      after,
      disabledBefore,
      denied,
    };
  },
  ["POST /organization/delete"],
);
compatScenario(
  "organization trusted header deletion invokes callbacks without an HTTP request and honors cookie ownership",
  async (ctx) => {
    await configure(ctx, "record");
    const target = await setup(ctx, "trusted");
    const before = await state(ctx);
    const call = async (
      actor: string,
      organizationId = target.org.id,
      selected: FixtureProfile = profile,
    ) => {
      const response = await ctx
        .actor(actor, profile)
        .fetch("/__test/organization-delete-hooks-server", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-delete-hook": "actual-trusted-header",
          },
          body: JSON.stringify({
            profile: selected,
            headerCase: "mixed",
            organizationId,
            userId: target.owner.user.id,
          }),
        });
      const text = await response.text();
      return { status: response.status, body: text ? JSON.parse(text) : null };
    };
    const foreign = await call("trusted-foreign");
    expect(foreign.status).toBe(400);
    expect(foreign.body).toMatchObject({
      code: "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
    });
    const guest = await call("trusted-guest");
    expect(guest.status).toBe(401);
    expect(await state(ctx)).toEqual(before);
    const deleted = await call("trusted-owner");
    expect(deleted.status).toBe(200);
    expect(deleted.body).toMatchObject({ id: target.org.id });
    const after = await state(ctx);
    expect(after.receipts.map((r) => r.phase)).toEqual(["before", "after"]);
    for (const r of after.receipts) {
      expect(r.request).toBeNull();
      expect(r.header).toBe("actual-trusted-header");
      expect(r.user.id).toBe(target.owner.user.id);
      expect(r.session.activeOrganizationId).toBe(target.org.id);
    }
    isolation(before.snapshot, after.snapshot, target);
    const next = data(
      await target.owner.client.organization.create({
        name: "Trusted rejected",
        slug: ctx.uniqueToken("trusted-rejected"),
        metadata: { guard: "rejected" },
      }),
    );
    const rejecting = {
      ...target,
      org: next,
      session: data(await target.owner.client.getSession()).session,
    };
    await configure(ctx, "reject-before");
    const beforeReject = await state(ctx);
    const rejected = await call("trusted-owner", next.id);
    expect(rejected.status).toBe(400);
    expect(rejected.body).toMatchObject({
      code: "DELETION_HOOK_REJECTED",
      message: "Rejected before",
    });
    const afterReject = await state(ctx);
    expect(afterReject.receipts).toHaveLength(1);
    expect(afterReject.receipts[0]!.request).toBeNull();
    expect(afterReject.receipts[0]!.header).toBe("actual-trusted-header");
    for (const key of ["organizations", "members", "invitations"] as const)
      expect(afterReject.snapshot[key]).toEqual(beforeReject.snapshot[key]);
    isolation(beforeReject.snapshot, afterReject.snapshot, rejecting);
    const disabledGuest = await call(
      "trusted-guest",
      next.id,
      "org-deletion-hooks-disabled",
    );
    expect(disabledGuest.status).toBe(404);
    expect(disabledGuest.body).toMatchObject({
      code: "ORGANIZATION_DELETION_DISABLED",
    });
    expect(await state(ctx)).toEqual(afterReject);
    return {
      before,
      foreign,
      guest,
      deleted,
      after,
      beforeReject,
      rejected,
      afterReject,
      disabledGuest,
    };
  },
);
compatScenario(
  "organization deletion keeps its original callback and response snapshots after a real before hook write",
  async (ctx) => {
    await configure(ctx, "write-before");
    const target = await setup(ctx, "snapshot");
    const before = await state(ctx);
    const deleted = await remove(target, "snapshot-header");
    expect(deleted.error).toBeNull();
    expect(deleted.data).toMatchObject({ name: target.org.name });
    const after = await state(ctx);
    expect(after.receipts[0]!.organization.name).toBe(target.org.name);
    expect(
      after.receipts[0]!.snapshot.organizations.find(
        (r) => r.id === target.org.id,
      ),
    ).toMatchObject({ name: "Written By Hook" });
    expect(after.receipts[1]!.organization.name).toBe(target.org.name);
    expect(
      after.snapshot.organizations.some((r) => r.id === target.org.id),
    ).toBe(false);
    isolation(before.snapshot, after.snapshot, target);
    return { before, deleted: ctx.snapshot(deleted), after };
  },
  ["POST /organization/delete"],
);
compatScenario(
  "organization deletion awaits its actual asynchronous before hook before deleting persisted records",
  async (ctx) => {
    await configure(ctx, "pause-before");
    const target = await setup(ctx, "awaited");
    const before = await state(ctx);
    let completed = false;
    const pending = remove(target, "paused-header").then((value) => {
      completed = true;
      return value;
    });
    let paused: Awaited<ReturnType<typeof state>> | undefined;
    const releaseTrace: TraceEntry[] = [];
    try {
      paused = await state(ctx, "before");
      expect(completed).toBe(false);
      expect(paused.receipts.map((r) => r.phase)).toEqual(["before"]);
      for (const key of ["organizations", "members", "invitations"] as const)
        expect(paused.snapshot[key]).toEqual(before.snapshot[key]);
      isolation(before.snapshot, paused.snapshot, target);
    } finally {
      // Preserve both complete concurrent traces in a defined observation order.
      const release = await createTracingFetch(
        ctx.baseURL,
        "hook-release",
        releaseTrace,
      )("/__test/organization-delete-hooks-release", { method: "POST" });
      expect(release.status).toBe(200);
      expect(await release.json()).toEqual({ released: true });
    }
    const deleted = await pending;
    ctx.recordTransport(releaseTrace);
    expect(deleted.error).toBeNull();
    const after = await state(ctx);
    expect(after.receipts.map((r) => r.phase)).toEqual(["before", "after"]);
    expect(
      after.snapshot.organizations.some((r) => r.id === target.org.id),
    ).toBe(false);
    isolation(before.snapshot, after.snapshot, target);
    await configure(ctx, "record");
    const abortTarget = await setup(ctx, "disconnected-delete");
    await configure(ctx, "pause-before");
    const marker = ctx.uniqueToken("disconnected-delete");
    let abortBefore!: Awaited<ReturnType<typeof state>>;
    const wire = await disconnectedRequest(
      ctx,
      "disconnected-delete-owner",
      profile,
      abortTarget.owner.email,
      "/organization/delete",
      {
        organizationId: abortTarget.org.id,
        userId: abortTarget.foreign.user.id,
      },
      marker,
      async () => {
        data(
          await abortTarget.owner.client.organization.setActive({
            organizationId: abortTarget.org.id,
          }),
        );
        abortTarget.session = data(
          await abortTarget.owner.client.getSession(),
        ).session;
        abortBefore = await state(ctx);
      },
    );
    // The actual signed-in token was selected before the raw request was sent.
    let abortPaused: Awaited<ReturnType<typeof state>> | undefined;
    let dropped: unknown;
    try {
      abortPaused = await state(ctx, "before");
      expect(abortPaused.receipts.map((r) => r.phase)).toEqual(["before"]);
      expect(abortPaused.snapshot.organizations).toEqual(
        abortBefore.snapshot.organizations,
      );
      dropped = await wire.close();
    } finally {
      wire.dispose();
      expect(
        (
          await ctx.rawRequest({
            path: "/__test/organization-delete-hooks-release",
            method: "POST",
          })
        ).status,
      ).toBe(200);
    }
    const completion = await ctx.rawRequest({
      path: `/__test/organization-transport-completion?marker=${encodeURIComponent(marker)}`,
    });
    expect(completion.status).toBe(200);
    expect(completion.body).toEqual({ marker, completed: true });
    const continued = await state(ctx, "after");
    expect(continued.receipts.map((r) => r.phase)).toEqual(["before", "after"]);
    for (const key of ["organizations", "members", "invitations"] as const)
      expect(
        continued.snapshot[key].some(
          (r) =>
            r.id === abortTarget.org.id ||
            r.organizationId === abortTarget.org.id,
        ),
      ).toBe(false);
    isolation(abortBefore.snapshot, continued.snapshot, abortTarget);
    expect(continued.receipts[1]!.user.id).toBe(abortTarget.owner.user.id);
    return {
      before,
      paused,
      deleted: ctx.snapshot(deleted),
      after,
      wire: { signin: wire.signin, request: wire.request },
      abortBefore,
      abortPaused,
      dropped,
      completion,
      continued,
    };
  },
  ["POST /organization/delete"],
);
