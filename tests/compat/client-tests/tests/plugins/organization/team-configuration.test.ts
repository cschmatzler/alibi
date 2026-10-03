import { expect } from "bun:test";

import { z } from "zod";

import type { FixtureProfile } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import { data, orgActor, serverOperation, signUp, state, type CompatContext } from "./helpers";

const row = z.object({ id: z.string() }).passthrough();
const snapshotSchema = z.object({
  organizations: z.array(row),
  members: z.array(row),
  teams: z.array(row),
  teamMembers: z.array(row),
  sessions: z.array(row),
  users: z.array(row),
});
const evidenceSchema = z.object({
  receipts: z.array(z.object({ phase: z.string(), snapshot: snapshotSchema }).passthrough()),
  snapshot: snapshotSchema,
});
async function evidence(ctx: CompatContext, organizationId: string, profile: FixtureProfile) {
  const result = await serverOperation(
    ctx,
    { operation: "team-config-evidence", organizationId },
    profile,
  );
  expect(result.status).toBe(200);
  return evidenceSchema.parse(result.body);
}
async function signed(ctx: CompatContext, actor: string, body: Record<string, unknown>) {
  const response = await ctx
    .actor(actor, "org-team-hooks")
    .fetch(new URL("/__test/organization-api", ctx.baseURL), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...body, profile: "org-team-hooks", authority: "headers" }),
    });
  return { status: response.status, body: await response.json() };
}

compatScenario(
  "default factory errors return empty 500 and retain prior selection plus independent team write",
  async (ctx) => {
    const profile = "org-team-factory";
    const owner = await signUp(ctx, "factory-owner", profile);
    const selected = data(
      await owner.client.organization.create({
        name: "Existing factory",
        slug: ctx.uniqueToken("existing-factory"),
      }),
    );
    const before = data(await owner.client.getSession()).session;
    const failed = await owner.client.organization.create({
      name: "Factory error",
      slug: ctx.uniqueToken("factory-error"),
    });
    expect(failed.error?.status).toBe(500);
    expect(failed.error).not.toHaveProperty("message");
    const rows = await evidence(ctx, selected.id, profile);
    const failedOrg = rows.snapshot.organizations.find((r) => r.name === "Factory error")!;
    expect(failedOrg).toBeDefined();
    const actual = await evidence(ctx, failedOrg.id, profile);
    expect(actual.receipts.map((r) => r.phase)).toEqual(["before-create", "factory"]);
    const teams = actual.snapshot.teams.filter((r) => r.organizationId === failedOrg.id);
    expect(teams).toHaveLength(1);
    expect(teams[0]).toMatchObject({ name: "Factory:Factory error", memberCount: 0 });
    expect(actual.snapshot.members.filter((r) => r.organizationId === failedOrg.id)).toHaveLength(
      1,
    );
    expect(actual.snapshot.teamMembers.filter((r) => r.teamId === teams[0]!.id)).toEqual([]);
    const after = data(await owner.client.getSession()).session;
    expect(after).toEqual(before);
    return { failed, actual, before, after };
  },
);

compatScenario(
  "team callback errors return empty 500 at each write boundary while API vetoes retain their response",
  async (ctx) => {
    const profile = "org-team-hooks";
    const owner = await signUp(ctx, "hooks-owner", profile);
    const org = data(
      await owner.client.organization.create({
        name: "Hook organization",
        slug: ctx.uniqueToken("hook-org"),
      }),
    );
    const foreign = await signUp(ctx, "hooks-foreign", profile);
    const outside = data(
      await foreign.client.organization.create({
        name: "Unrelated organization",
        slug: ctx.uniqueToken("unrelated"),
      }),
    );
    const unrelated = await state(ctx, outside.id, profile);
    const selection = data(await owner.client.getSession()).session;
    const observations = [];
    for (const phase of [
      "before-create",
      "after-create",
      "before-update",
      "after-update",
      "before-delete",
      "after-delete",
      "before-add-member",
      "after-add-member",
      "before-remove-member",
      "after-remove-member",
    ] as const) {
      const marker = `error-${phase}`;
      const memberPhase = phase.includes("member");
      const testTeam = phase.includes("create")
        ? undefined
        : data(
            await owner.client.organization.createTeam({
              name: phase.includes("delete") ? marker : `Target:${phase}`,
            }),
          );
      let userId = owner.user.id;
      if (memberPhase) {
        const seeded = await serverOperation(
          ctx,
          {
            operation: "seed-member",
            organizationId: org.id,
            id: ctx.uniqueToken(phase),
            email: ctx.uniqueEmail(phase),
            name: marker,
          },
          profile,
        );
        userId = z.object({ userId: z.string() }).parse(seeded.body).userId;
        if (phase.includes("remove")) {
          data(await owner.client.organization.addTeamMember({ teamId: testTeam!.id, userId }));
        }
      }
      let result;
      if (phase.includes("create")) {
        result = await owner.client.organization.createTeam({ name: marker });
      } else if (phase.includes("update")) {
        result = await owner.client.organization.updateTeam({
          teamId: testTeam!.id,
          data: { name: marker },
        });
      } else if (phase.includes("delete")) {
        result = await owner.client.organization.removeTeam({ teamId: testTeam!.id });
      } else if (phase.includes("add")) {
        result = await owner.client.organization.addTeamMember({ teamId: testTeam!.id, userId });
      } else {
        result = await owner.client.organization.removeTeamMember({ teamId: testTeam!.id, userId });
      }
      expect(result.error?.status).toBe(500);
      expect(result.error).not.toHaveProperty("message");
      const actual = await evidence(ctx, org.id, profile);
      const receipt = z
        .object({ phase: z.string(), independentSnapshot: snapshotSchema })
        .passthrough()
        .parse(actual.receipts.at(-1));
      expect(receipt.phase).toBe(phase);
      expect(receipt.independentSnapshot.teams.some((r) => r.name === `Independent:${phase}`)).toBe(
        true,
      );
      expect(actual.snapshot.teams.some((r) => r.name === `Independent:${phase}`)).toBe(true);
      if (phase.includes("create")) {
        expect(actual.snapshot.teams.some((r) => r.name === `Hook:${marker}`)).toBe(
          phase.startsWith("after"),
        );
      }
      if (phase.includes("update")) {
        expect(actual.snapshot.teams.find((r) => r.id === testTeam!.id)?.name).toBe(
          phase.startsWith("after") ? `Hook:${marker}` : testTeam!.name,
        );
      }
      if (phase.includes("delete")) {
        expect(actual.snapshot.teams.some((r) => r.id === testTeam!.id)).toBe(
          phase.startsWith("before"),
        );
      }
      if (memberPhase) {
        expect(
          actual.snapshot.teamMembers.some((r) => r.teamId === testTeam!.id && r.userId === userId),
        ).toBe(phase.includes("add") ? phase.startsWith("after") : phase.startsWith("before"));
      }
      expect(data(await owner.client.getSession()).session).toEqual(selection);
      expect((await state(ctx, outside.id, profile)).raw).toEqual(unrelated.raw);
      observations.push({ phase, result, actual, stored: (await state(ctx, org.id, profile)).raw });
    }
    const veto = await owner.client.organization.createTeam({ name: "reject-before-create" });
    expect(veto.error).toMatchObject({
      status: 400,
      code: "TEAM_HOOK_REJECTED",
      message: "Rejected before-create",
    });
    return { observations, veto, selection, unrelated: unrelated.raw };
  },
  [],
  90000,
);

compatScenario(
  "signed server team methods enforce real caller authority and active-team protection",
  async (ctx) => {
    const profile = "org-team-hooks";
    const owner = await signUp(ctx, "server-owner", profile);
    const foreign = await signUp(ctx, "server-foreign", profile);
    const sibling = orgActor(ctx, "server-sibling", profile);
    data(await sibling.signIn.email({ email: owner.email, password: "password123" }));
    const org = data(
      await owner.client.organization.create({
        name: "Server authority",
        slug: ctx.uniqueToken("server-org"),
      }),
    );
    const initial = await state(ctx, org.id, profile);
    const selected = initial.parsed.teams[0]!;
    const member = initial.parsed.members.find((r) => r.userId === owner.user.id)!;
    const current = data(await owner.client.getSession()).session;
    const siblingBefore = data(await sibling.getSession()).session;
    const foreignBefore = data(await foreign.client.getSession()).session;
    const signedCreate = await signed(ctx, "server-owner", {
      operation: "create-team",
      organizationId: org.id,
      name: "Signed server",
    });
    expect(signedCreate.status).toBe(200);
    const signedReceipts = await evidence(ctx, org.id, profile);
    expect(signedReceipts.receipts.at(-2)).toMatchObject({
      phase: "before-create",
      user: { id: owner.user.id },
    });
    const foreignCreate = await signed(ctx, "server-foreign", {
      operation: "create-team",
      organizationId: org.id,
      name: "Foreign server",
    });
    expect(foreignCreate.status).toBe(403);
    const missing = await signed(ctx, "server-missing", {
      operation: "create-team",
      organizationId: org.id,
      name: "Missing principal",
    });
    expect(missing.status).toBe(401);
    const forged = await ctx.rawRequest({
      path: "/__test/organization-api",
      method: "POST",
      headers: { cookie: "better-auth.session_token=forged.invalid" },
      json: {
        operation: "create-team",
        profile,
        authority: "headers",
        organizationId: org.id,
        name: "Forged principal",
      },
    });
    expect(forged.status).toBe(401);
    expect((await evidence(ctx, org.id, profile)).receipts).toEqual(signedReceipts.receipts);
    await serverOperation(
      ctx,
      { operation: "set-member-role", organizationId: org.id, memberId: member.id, role: "member" },
      profile,
    );
    const denied = await signed(ctx, "server-owner", {
      operation: "create-team",
      organizationId: org.id,
      name: "Member denied",
    });
    expect(denied.status).toBe(403);
    const trusted = await serverOperation(
      ctx,
      { operation: "create-team", organizationId: org.id, name: "Trusted requestless" },
      profile,
    );
    expect(trusted.status).toBe(200);
    const trustedId = z.object({ id: z.string() }).parse(trusted.body).id;
    const trustedReceipts = await evidence(ctx, org.id, profile);
    expect(trustedReceipts.receipts.at(-2)).toMatchObject({ phase: "before-create", user: null });
    const wrongScope = await serverOperation(
      ctx,
      { operation: "remove-team", organizationId: ctx.uniqueToken("wrong-org"), teamId: trustedId },
      profile,
    );
    expect(wrongScope.status).toBe(400);
    const deniedRemove = await signed(ctx, "server-owner", {
      operation: "remove-team",
      organizationId: org.id,
      teamId: trustedId,
    });
    expect(deniedRemove.status).toBe(403);
    await serverOperation(
      ctx,
      { operation: "set-member-role", organizationId: org.id, memberId: member.id, role: "owner" },
      profile,
    );
    const protectedTeam = await signed(ctx, "server-owner", {
      operation: "remove-team",
      organizationId: org.id,
      teamId: selected.id,
    });
    expect(protectedTeam.status).toBe(403);
    const foreignRemove = await signed(ctx, "server-foreign", {
      operation: "remove-team",
      organizationId: org.id,
      teamId: trustedId,
    });
    expect(foreignRemove.status).toBe(403);
    const siblingRemove = await signed(ctx, "server-sibling", {
      operation: "remove-team",
      organizationId: org.id,
      teamId: selected.id,
    });
    expect(siblingRemove.status).toBe(200);
    expect(data(await owner.client.getSession()).session).toEqual(current);
    const stale = await owner.client.organization.listTeamMembers();
    expect(stale.error?.code).toBe("TEAM_NOT_FOUND");
    expect(data(await sibling.getSession()).session).toEqual(siblingBefore);
    expect(data(await foreign.client.getSession()).session).toEqual(foreignBefore);
    const trustedRemove = await serverOperation(
      ctx,
      { operation: "remove-team", organizationId: org.id, teamId: trustedId },
      profile,
    );
    expect(trustedRemove.status).toBe(200);
    return {
      signedCreate,
      signedReceipts,
      foreignCreate,
      missing,
      forged,
      denied,
      trusted,
      trustedReceipts,
      wrongScope,
      deniedRemove,
      protectedTeam,
      foreignRemove,
      siblingRemove,
      stale,
      trustedRemove,
      stored: (await state(ctx, org.id, profile)).raw,
      actual: await evidence(ctx, org.id, profile),
    };
  },
);
