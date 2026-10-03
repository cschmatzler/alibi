import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { organizationClient } from "better-auth/client/plugins";
import { z } from "zod";

import { authProfilePath, type FixtureProfile } from "../../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../../support/scenario";
import { createTracingFetch, type TraceEntry } from "../../../support/trace";

function date(value: unknown) {
  return value instanceof Date ? value.getTime() : new Date(value as string | number).getTime();
}
const row = z.object({ id: z.string() }).passthrough();
const snapshotSchema = z.object({
  invitations: z.array(row),
  members: z.array(row),
  teams: z.array(row),
  teamMembers: z.array(row),
  sessions: z.array(row),
  organizations: z.array(row),
});
const stateSchema = z.object({
  receipts: z.array(
    z.object({
      phase: z.string(),
      context: z.record(z.string(), z.unknown()),
      snapshot: snapshotSchema,
    }),
  ),
  snapshot: snapshotSchema,
  waiting: z.number(),
});
type State = z.infer<typeof stateSchema>;
async function state(ctx: ScenarioContext, wait = false): Promise<State> {
  const result = await ctx.rawRequest({
    path: `/__test/organization-invitation-life/state${wait ? "?wait=1" : ""}`,
  });
  expect(result.status).toBe(200);
  const state = stateSchema.parse(result.body);
  for (const snapshot of [state.snapshot, ...state.receipts.map((r) => r.snapshot)]) {
    for (const member of snapshot.teamMembers) {
      if (typeof member.membershipKey === "string") {
        expect(member.membershipKey).toBe(
          new Bun.CryptoHasher("sha256")
            .update(JSON.stringify([member.teamId, member.userId]))
            .digest("base64url"),
        );
        member.membershipKey = {
          token: member.membershipKey,
          inputs: { teamId: { id: member.teamId }, userId: { id: member.userId } },
        };
      }
    }
  }
  for (const receipt of state.receipts) {
    const invitation = receipt.context.invitation;
    if (
      invitation &&
      typeof invitation === "object" &&
      "teamIds" in invitation &&
      Array.isArray(invitation.teamIds)
    ) {
      for (const id of invitation.teamIds) {
        expect(receipt.snapshot.teams.some((team) => team.id === id)).toBe(true);
      }
      invitation.teamIds = invitation.teamIds.map((id: string) => ({ id }));
    }
  }
  return state;
}
function wire(values: { status: number; contentType: string | null; text: string }[]) {
  return values.map((value) => ({
    ...value,
    text:
      value.contentType?.includes("application/json") && value.text
        ? (JSON.parse(value.text) as unknown)
        : value.text,
  }));
}
async function configure(ctx: ScenarioContext, mode: string, limit?: number | string) {
  const result = await ctx.rawRequest({
    path: "/__test/organization-invitation-life/configure",
    method: "POST",
    json: { mode, limit },
  });
  expect(result.status).toBe(200);
  expect(result.body).toEqual({ configured: true });
  return result;
}
async function signup(ctx: ScenarioContext, name: string, profile: FixtureProfile) {
  const actor = ctx.actor(name, profile);
  const wire: { status: number; contentType: string | null; text: string }[] = [];
  const client = createAuthClient({
    baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
    plugins: [organizationClient({ teams: { enabled: true } })],
    fetchOptions: {
      customFetchImpl: async (input, init) => {
        const headers = new Headers(init?.headers);
        headers.set("x-invitation-marker", "actual-application-header");
        const result = await actor.fetch(input, { ...init, headers });
        wire.push({
          status: result.status,
          contentType: result.headers.get("content-type"),
          text: await result.clone().text(),
        });
        return result;
      },
    },
  });
  const email = ctx.uniqueEmail(name);
  const signed = await client.signUp.email({ name, email, password: "password123" });
  expect(signed.error).toBeNull();
  return {
    client,
    actor,
    wire,
    email,
    user: row.parse(signed.data!.user),
    signup: ctx.snapshot(signed),
  };
}
async function setup(ctx: ScenarioContext, profile: FixtureProfile = "org-invite-life") {
  const owner = await signup(ctx, "life-owner", profile);
  const target = await signup(ctx, "life-target", profile);
  const foreign = await signup(ctx, "life-foreign", profile);
  const created = await owner.client.organization.create({
    name: "Invitation lifecycle",
    slug: ctx.uniqueToken("life-org"),
    metadata: { application: true },
  });
  expect(created.error).toBeNull();
  const org = row.parse(created.data);
  const other = await foreign.client.organization.create({
    name: "Foreign lifecycle",
    slug: ctx.uniqueToken("life-foreign"),
    metadata: { foreign: true },
  });
  expect(other.error).toBeNull();
  const team = await owner.client.organization.createTeam({
    organizationId: org.id,
    name: "Life team",
  });
  expect(team.error).toBeNull();
  const foreignTeam = await foreign.client.organization.createTeam({
    organizationId: row.parse(other.data).id,
    name: "Foreign team",
  });
  expect(foreignTeam.error).toBeNull();
  const sibling = ctx.actor("life-target-sibling", profile);
  const signed = await sibling.client.signIn.email({
    email: target.email,
    password: "password123",
  });
  expect(signed.error).toBeNull();
  return {
    owner,
    target,
    foreign,
    org,
    other: row.parse(other.data),
    team: row.parse(team.data),
    foreignTeam: row.parse(foreignTeam.data),
    sibling,
    profile,
  };
}
type Setup = Awaited<ReturnType<typeof setup>>;
function invitationBody(s: Setup) {
  return {
    organizationId: s.org.id,
    email: s.target.email.toUpperCase(),
    role: "member" as const,
    teamId: s.team.id,
  };
}
function untouched(before: State, after: State) {
  for (const key of ["members", "teams", "teamMembers", "sessions", "organizations"] as const) {
    expect(after.snapshot[key]).toEqual(before.snapshot[key]);
  }
}
async function observed(s: Setup) {
  const invitations = await s.owner.client.organization.listInvitations({
    query: { organizationId: s.org.id },
  });
  expect(invitations.error).toBeNull();
  const members = await s.owner.client.organization.listMembers({
    query: { organizationId: s.org.id },
  });
  expect(members.error).toBeNull();
  const teams = await s.owner.client.organization.listTeams({
    query: { organizationId: s.org.id },
  });
  expect(teams.error).toBeNull();
  const current = await s.target.client.getSession();
  expect(current.error).toBeNull();
  const sibling = await s.sibling.client.getSession();
  expect(sibling.error).toBeNull();
  const foreign = await s.foreign.client.organization.getFullOrganization({
    query: { organizationId: s.other.id },
  });
  expect(foreign.error).toBeNull();
  const foreignSession = await s.foreign.client.getSession();
  expect(foreignSession.error).toBeNull();
  return { invitations, members, teams, current, sibling, foreign, foreignSession };
}
async function denied(ctx: ScenarioContext, s: Setup, before: State, invitation?: string) {
  const guest = ctx.actor("life-guest", s.profile);
  const guestResult = await guest.client.$fetch("/organization/invite-member", {
    method: "POST",
    body: invitationBody(s),
  });
  expect(guestResult.error?.status).toBe(401);
  const wrong = await s.foreign.client.organization.inviteMember(invitationBody(s));
  expect(wrong.error).toMatchObject({ status: 400, code: "MEMBER_NOT_FOUND" });
  const bad = await s.owner.client.organization.inviteMember({
    ...invitationBody(s),
    role: "absent" as "member",
  });
  expect(bad.error?.status).toBe(400);
  const ownerRole = await s.target.client.organization.inviteMember({
    ...invitationBody(s),
    role: "owner",
  });
  expect(ownerRole.error).toMatchObject({ status: 400, code: "MEMBER_NOT_FOUND" });
  if (invitation) {
    const reject = await s.foreign.client.organization.rejectInvitation({
      invitationId: invitation,
    });
    expect(reject.error).toMatchObject({
      status: 403,
      code: "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION",
    });
    const cancel = await s.foreign.client.organization.cancelInvitation({
      invitationId: invitation,
    });
    expect(cancel.error).toMatchObject({ status: 400, code: "MEMBER_NOT_FOUND" });
  }
  expect(await state(ctx)).toEqual(before);
  return { guestResult, wrong, bad, ownerRole };
}
function deliveryCheck(s: Setup, receipt: State["receipts"][number], invitation: string) {
  expect(receipt.context).toMatchObject({
    id: invitation,
    email: s.target.email.toLowerCase(),
    role: "member",
    organization: { id: s.org.id },
    inviter: { userId: s.owner.user.id, user: { id: s.owner.user.id } },
    invitation: { id: invitation, organizationId: s.org.id },
    request: {
      method: "POST",
      path: `${authProfilePath(s.profile)}/organization/invite-member`,
      marker: "actual-application-header",
    },
  });
  expect(receipt.snapshot.invitations.find((r) => r.id === invitation)?.status).toBe("pending");
}

for (const mode of [
  "record",
  "before-create-error",
  "before-create-internal",
  "delivery-start-error",
  "delivery-start-internal",
  "delivery-end-error",
  "after-create-error",
  "after-create-internal",
] as const) {
  compatScenario(`invitation lifecycle create ${mode}`, async (ctx) => {
    const s = await setup(ctx);
    await configure(ctx, mode);
    const before = await state(ctx);
    const denials = await denied(ctx, s, before);
    const created = await s.owner.client.organization.inviteMember(invitationBody(s));
    const hookFailure = mode.startsWith("before-") || mode.startsWith("after-");
    expect(created.error?.status ?? 200).toBe(
      hookFailure ? (mode.endsWith("internal") ? 500 : 403) : 200,
    );
    if (mode.endsWith("internal") && hookFailure) {
      expect(s.owner.wire.at(-1)).toEqual({ status: 500, contentType: null, text: "" });
    }
    const after = await state(ctx);
    untouched(before, after);
    const persisted = !mode.startsWith("before-");
    expect(after.snapshot.invitations).toHaveLength(persisted ? 1 : 0);
    expect(after.receipts.map((r) => r.phase)).toEqual(
      mode.startsWith("before-")
        ? ["before-create"]
        : mode.startsWith("delivery-start")
          ? ["before-create", "delivery-start", "after-create"]
          : ["before-create", "delivery-start", "delivery-end", "after-create"],
    );
    if (persisted) deliveryCheck(s, after.receipts[1]!, after.snapshot.invitations[0]!.id);
    for (const receipt of after.receipts) {
      untouched(before, { ...after, snapshot: receipt.snapshot });
    }
    await configure(ctx, "record");
    const retry = await s.owner.client.organization.inviteMember(invitationBody(s));
    expect(retry.error?.status ?? 200).toBe(persisted ? 400 : 200);
    if (persisted) expect(retry.error?.code).toBe("USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION");
    return ctx.snapshot({
      denials,
      before,
      created,
      after,
      retry,
      final: await state(ctx),
      observations: await observed(s),
      wire: wire(s.owner.wire),
    });
  });
}

for (const action of ["reject", "cancel"] as const) {
  for (const mode of [
    "record",
    `before-${action}-error`,
    `before-${action}-internal`,
    `after-${action}-error`,
    `after-${action}-internal`,
  ] as const) {
    compatScenario(`invitation lifecycle ${action} ${mode}`, async (ctx) => {
      const s = await setup(ctx);
      const created = await s.owner.client.organization.inviteMember(invitationBody(s));
      expect(created.error).toBeNull();
      const invitation = row.parse(created.data);
      await configure(ctx, mode);
      const before = await state(ctx);
      const denials = await denied(ctx, s, before, invitation.id);
      const client = action === "reject" ? s.target : s.owner;
      const result =
        action === "reject"
          ? await client.client.organization.rejectInvitation({ invitationId: invitation.id })
          : await client.client.organization.cancelInvitation({ invitationId: invitation.id });
      expect(result.error?.status ?? 200).toBe(
        mode === "record" ? 200 : mode.endsWith("internal") ? 500 : 403,
      );
      if (mode.endsWith("internal")) {
        expect(client.wire.at(-1)).toEqual({ status: 500, contentType: null, text: "" });
      }
      const after = await state(ctx);
      untouched(before, after);
      expect(after.snapshot.invitations).toHaveLength(1);
      const status = mode.startsWith("before-")
        ? "pending"
        : action === "reject"
          ? "rejected"
          : "canceled";
      expect(after.snapshot.invitations[0]).toEqual({ ...before.snapshot.invitations[0]!, status });
      expect(after.receipts.map((r) => r.phase)).toEqual(
        mode.startsWith("before-") ? [`before-${action}`] : [`before-${action}`, `after-${action}`],
      );
      expect(after.receipts[0]!.context).toMatchObject({
        invitation: { id: invitation.id, status: "pending" },
        organization: { id: s.org.id },
        [action === "reject" ? "user" : "cancelledBy"]: { id: client.user.id },
      });
      await configure(ctx, "record");
      const retry =
        action === "reject"
          ? await s.target.client.organization.rejectInvitation({ invitationId: invitation.id })
          : await s.owner.client.organization.cancelInvitation({ invitationId: invitation.id });
      expect(retry.error?.status ?? 200).toBe(
        action === "reject" && status !== "pending" ? 400 : 200,
      );
      return ctx.snapshot({
        denials,
        before,
        result,
        after,
        retry,
        final: await state(ctx),
        observations: await observed(s),
        wire: wire(client.wire),
      });
    });
  }
}

for (const mode of ["record", "delivery-start-error", "delivery-end-internal"] as const) {
  compatScenario(`invitation lifecycle resend preserves identity ${mode}`, async (ctx) => {
    const s = await setup(ctx);
    const created = await s.owner.client.organization.inviteMember(invitationBody(s));
    expect(created.error).toBeNull();
    const invitation = row.parse(created.data);
    await configure(ctx, mode);
    const before = await state(ctx);
    // Preserve actual time passage: renewed expiry must differ from the original.
    await Bun.sleep(20);
    const resent = await s.owner.client.organization.inviteMember({
      ...invitationBody(s),
      role: "admin",
      teamId: s.foreignTeam.id,
      resend: true,
    });
    expect(resent.error).toBeNull();
    const after = await state(ctx);
    untouched(before, after);
    expect(after.snapshot.invitations).toHaveLength(1);
    const updated = after.snapshot.invitations[0]!;
    const original = before.snapshot.invitations[0]!;
    expect(updated).toEqual({ ...original, expiresAt: updated.expiresAt });
    expect(date(updated.expiresAt)).toBeGreaterThan(date(original.expiresAt));
    expect(row.parse(resent.data).id).toBe(invitation.id);
    expect(row.parse(resent.data).role).toBe("member");
    expect(after.receipts.map((r) => r.phase)).toEqual(
      mode === "delivery-start-error" ? ["delivery-start"] : ["delivery-start", "delivery-end"],
    );
    expect(after.receipts[0]!.snapshot.invitations).toEqual(after.snapshot.invitations);
    expect(after.receipts[0]!.context).toMatchObject({
      id: invitation.id,
      role: "member",
      email: s.target.email,
      invitation: { id: invitation.id, role: "member", teamId: s.team.id },
    });
    await configure(ctx, "record");
    const retry = await s.owner.client.organization.inviteMember({
      ...invitationBody(s),
      resend: true,
    });
    expect(retry.error).toBeNull();
    return ctx.snapshot({
      before,
      resent,
      after,
      retry,
      final: await state(ctx),
      observations: await observed(s),
      wire: wire(s.owner.wire),
    });
  });
}

for (const mode of [
  "record",
  "before-create-error",
  "after-create-error",
  "delivery-start-error",
  "delivery-end-internal",
  "foreign-team",
] as const) {
  compatScenario(`invitation lifecycle reinvite retains canceled row ${mode}`, async (ctx) => {
    const s = await setup(ctx, "org-invite-reinvite");
    const created = await s.owner.client.organization.inviteMember(invitationBody(s));
    expect(created.error).toBeNull();
    const invitation = row.parse(created.data);
    await configure(ctx, mode);
    const before = await state(ctx);
    const reinvited = await s.owner.client.organization.inviteMember({
      ...invitationBody(s),
      role: "admin",
      ...(mode === "foreign-team" ? { teamId: s.foreignTeam.id } : {}),
    });
    expect(reinvited.error?.status ?? 200).toBe(
      mode === "record" || mode.startsWith("delivery-") ? 200 : mode === "foreign-team" ? 400 : 403,
    );
    const after = await state(ctx);
    untouched(before, after);
    expect(after.snapshot.invitations[0]).toEqual({
      ...before.snapshot.invitations[0]!,
      status: "canceled",
    });
    expect(after.snapshot.invitations).toHaveLength(
      mode === "record" || mode === "after-create-error" || mode.startsWith("delivery-") ? 2 : 1,
    );
    for (const receipt of after.receipts) {
      expect(receipt.snapshot.invitations[0]?.status).toBe("canceled");
    }
    if (after.snapshot.invitations.length === 2) {
      expect(after.snapshot.invitations[1]!.id).not.toBe(invitation.id);
      expect(after.snapshot.invitations[1]!.role).toBe("admin");
    }
    await configure(ctx, "record");
    const retry = await s.owner.client.organization.inviteMember(invitationBody(s));
    expect(retry.error).toBeNull();
    return ctx.snapshot({
      before,
      reinvited,
      after,
      retry,
      final: await state(ctx),
      observations: await observed(s),
      wire: wire(s.owner.wire),
    });
  });
}

for (const [suffix, maximum] of [
  ["none", 3],
  ["zero", 0],
  ["fractional", 2],
  ["negative", 0],
  ["nan", 3],
  ["infinity", 3],
] as const) {
  compatScenario(`invitation lifecycle raw ${suffix} quota`, async (ctx) => {
    const s = await setup(ctx, `org-invite-limit-${suffix}`);
    await configure(ctx, "record");
    const before = await state(ctx);
    const results = [];
    for (let i = 0; i < 3; i++) {
      const result = await s.owner.client.organization.inviteMember({
        ...invitationBody(s),
        email: ctx.uniqueEmail(`raw-${i}`),
      });
      expect(result.error?.status ?? 200).toBe(i < maximum ? 200 : 403);
      results.push(result);
    }
    const after = await state(ctx);
    untouched(before, after);
    expect(after.snapshot.invitations).toHaveLength(maximum);
    expect(after.receipts.filter((r) => r.phase === "before-create")).toHaveLength(maximum);
    return ctx.snapshot({ before, results, after, observations: await observed(s) });
  });
}
for (const limit of [0, -0.5, 1.5, "nan", "infinity"] as const) {
  compatScenario(`invitation lifecycle resolver ${limit} raw result`, async (ctx) => {
    const s = await setup(ctx, "org-invite-limit-resolver");
    await configure(ctx, "record", limit);
    const before = await state(ctx);
    const results = [];
    for (let i = 0; i < 3; i++) {
      const result = await s.owner.client.organization.inviteMember({
        ...invitationBody(s),
        email: ctx.uniqueEmail(`resolver-${i}`),
      });
      expect(result.error?.status ?? 200).toBe(typeof limit === "string" || i < limit ? 200 : 403);
      results.push(result);
    }
    const after = await state(ctx);
    untouched(before, after);
    expect(after.receipts.filter((r) => r.phase === "limit")).toHaveLength(3);
    for (const receipt of after.receipts.filter((r) => r.phase === "limit")) {
      expect(receipt.context).toMatchObject({
        user: { id: s.owner.user.id },
        member: { userId: s.owner.user.id, organizationId: s.org.id },
        organization: { id: s.org.id },
      });
    }
    return ctx.snapshot({ before, results, after, observations: await observed(s) });
  });
}
for (const suffix of ["zero", "negative", "fractional", "nan"] as const) {
  compatScenario(`invitation lifecycle raw ${suffix} expiry`, async (ctx) => {
    const s = await setup(ctx, `org-invite-expiry-${suffix}`);
    await configure(ctx, "record");
    const before = await state(ctx);
    const result = await s.owner.client.organization.inviteMember(invitationBody(s));
    expect(result.error).toBeNull();
    const invitation = row.parse(result.data);
    const createdAt = date(invitation.createdAt);
    const expiresAt = date(invitation.expiresAt);
    const expected = suffix === "negative" ? -500 : suffix === "fractional" ? 125 : 172800000;
    expect(Math.abs(expiresAt - createdAt - expected)).toBeLessThan(100);
    const after = await state(ctx);
    untouched(before, after);
    return ctx.snapshot({ before, result, after, observations: await observed(s) });
  });
}
for (const profile of ["org-invite-life", "org-invite-background"] as const) {
  for (const mode of [
    "hold-delivery",
    "hold-delivery-end-internal",
    "hold-delivery-observer-error",
  ] as const) {
    compatScenario(`invitation lifecycle ${profile} actual ${mode} completion`, async (ctx) => {
      const s = await setup(ctx, profile);
      await configure(ctx, mode);
      const before = await state(ctx);
      let completed = false;
      const pending = s.owner.client.organization.inviteMember(invitationBody(s)).then((result) => {
        completed = true;
        return result;
      });
      const held = await state(ctx, true);
      expect(held.waiting).toBe(1);
      untouched(before, held);
      expect(held.receipts.map((r) => r.phase)).toEqual(
        profile === "org-invite-background"
          ? ["before-create", "delivery-start", "after-create"]
          : ["before-create", "delivery-start"],
      );
      if (profile === "org-invite-background") await pending;
      expect(completed).toBe(profile === "org-invite-background");
      const releaseTraces: TraceEntry[] = [];
      const response = await createTracingFetch(
        ctx.baseURL,
        "invitation-delivery-release",
        releaseTraces,
      )("/__test/organization-invitation-life/release", { method: "POST" });
      expect(response.status).toBe(200);
      const release = { status: response.status, body: (await response.json()) as unknown };
      expect(release.body).toEqual({ released: true });
      const result = await pending;
      ctx.recordTransport(releaseTraces);
      expect(result.error).toBeNull();
      const after = await state(ctx);
      expect(after.waiting).toBe(0);
      expect(after.receipts.map((r) => r.phase)).toEqual(
        profile === "org-invite-background"
          ? ["before-create", "delivery-start", "after-create", "delivery-end"]
          : ["before-create", "delivery-start", "delivery-end", "after-create"],
      );
      return ctx.snapshot({
        before,
        held,
        release,
        result,
        after,
        observations: await observed(s),
      });
    });
  }
}

function ownerOn(ctx: ScenarioContext, s: Setup, profile: FixtureProfile) {
  return createAuthClient({
    baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
    plugins: [organizationClient({ teams: { enabled: true } })],
    fetchOptions: { customFetchImpl: s.owner.actor.fetch },
  });
}
compatScenario("invitation lifecycle adapter page applies before expiry filtering", async (ctx) => {
  const s = await setup(ctx, "org-invite-page-one");
  const expiredClient = ownerOn(ctx, s, "org-invite-expiry-negative");
  const expired = await expiredClient.organization.inviteMember(invitationBody(s));
  expect(expired.error).toBeNull();
  await configure(ctx, "record");
  const before = await state(ctx);
  const first = await s.owner.client.organization.inviteMember(invitationBody(s));
  expect(first.error).toBeNull();
  const second = await s.owner.client.organization.inviteMember(invitationBody(s));
  expect(second.error).toBeNull();
  const after = await state(ctx);
  untouched(before, after);
  expect(after.snapshot.invitations).toHaveLength(3);
  expect(after.snapshot.invitations.map((r) => r.status)).toEqual([
    "pending",
    "pending",
    "pending",
  ]);
  expect(after.snapshot.invitations[0]).toEqual(before.snapshot.invitations[0]!);
  expect(row.parse(first.data).id).not.toBe(row.parse(second.data).id);
  const listed = await s.owner.client.organization.listInvitations({
    query: { organizationId: s.org.id },
  });
  expect(listed.error).toBeNull();
  expect(listed.data).toHaveLength(1);
  expect(row.parse(listed.data![0]).id).toBe(row.parse(expired.data).id);
  return ctx.snapshot({
    expired,
    before,
    first,
    second,
    after,
    listed,
    observations: await observed(s),
  });
});
compatScenario(
  "invitation lifecycle reinvite cancels only first unexpired match before quota denial",
  async (ctx) => {
    const s = await setup(ctx, "org-invite-page-one");
    const expired = await ownerOn(ctx, s, "org-invite-expiry-negative").organization.inviteMember(
      invitationBody(s),
    );
    expect(expired.error).toBeNull();
    const first = await s.owner.client.organization.inviteMember(invitationBody(s));
    expect(first.error).toBeNull();
    const second = await s.owner.client.organization.inviteMember(invitationBody(s));
    expect(second.error).toBeNull();
    await configure(ctx, "record");
    const before = await state(ctx);
    const result = await ownerOn(ctx, s, "org-invite-reinvite").organization.inviteMember(
      invitationBody(s),
    );
    expect(result.error).toMatchObject({ status: 403, code: "INVITATION_LIMIT_REACHED" });
    const after = await state(ctx);
    untouched(before, after);
    expect(after.snapshot.invitations).toEqual(
      before.snapshot.invitations.map((r) =>
        r.id === row.parse(first.data).id ? { ...r, status: "canceled" } : r,
      ),
    );
    expect(after.receipts).toEqual([]);
    const retry = await ownerOn(ctx, s, "org-invite-reinvite").organization.inviteMember(
      invitationBody(s),
    );
    expect(retry.error).toBeNull();
    const final = await state(ctx);
    expect(final.snapshot.invitations).toHaveLength(4);
    expect(final.snapshot.invitations.map((r) => r.status)).toEqual([
      "pending",
      "canceled",
      "canceled",
      "pending",
    ]);
    return ctx.snapshot({
      expired,
      first,
      second,
      before,
      result,
      after,
      retry,
      final,
      observations: await observed(s),
    });
  },
);
compatScenario(
  "invitation lifecycle async limit failure precedes callbacks and allows retry",
  async (ctx) => {
    const s = await setup(ctx, "org-invite-limit-resolver");
    await configure(ctx, "limit-error");
    const before = await state(ctx);
    const denials = await denied(ctx, s, before);
    const result = await s.owner.client.organization.inviteMember(invitationBody(s));
    expect(result.error).toMatchObject({ status: 403, code: "INVITATION_APPLICATION_REJECTED" });
    const after = await state(ctx);
    expect(after.snapshot).toEqual(before.snapshot);
    expect(after.receipts.map((r) => r.phase)).toEqual(["limit"]);
    await configure(ctx, "record");
    const retry = await s.owner.client.organization.inviteMember(invitationBody(s));
    expect(retry.error).toBeNull();
    return ctx.snapshot({
      denials,
      before,
      result,
      after,
      retry,
      final: await state(ctx),
      observations: await observed(s),
    });
  },
);
compatScenario(
  "invitation lifecycle admitted member and admin authority denies before hooks",
  async (ctx) => {
    const s = await setup(ctx);
    const created = await s.owner.client.organization.inviteMember(invitationBody(s));
    expect(created.error).toBeNull();
    const invitation = row.parse(created.data);
    const accepted = await s.target.client.organization.acceptInvitation({
      invitationId: invitation.id,
    });
    expect(accepted.error).toBeNull();
    const freshBody = { ...invitationBody(s), email: ctx.uniqueEmail("authority-denied") };
    await configure(ctx, "record");
    const beforeMember = await state(ctx);
    const deniedMember = await s.target.client.organization.inviteMember(freshBody);
    expect(deniedMember.error).toMatchObject({
      status: 403,
      code: "YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION",
    });
    expect(await state(ctx)).toEqual(beforeMember);
    const member = row.parse(accepted.data!.member);
    const promoted = await s.owner.client.organization.updateMemberRole({
      organizationId: s.org.id,
      memberId: member.id,
      role: "admin",
    });
    expect(promoted.error).toBeNull();
    const beforeAdmin = await state(ctx);
    const deniedAdmin = await s.target.client.organization.inviteMember({
      ...freshBody,
      role: "owner",
    });
    expect(deniedAdmin.error).toMatchObject({
      status: 403,
      code: "YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE",
    });
    expect(await state(ctx)).toEqual(beforeAdmin);
    const malformed = await s.owner.client.$fetch("/organization/invite-member", {
      method: "POST",
      body: { ...freshBody, resend: "yes" },
    });
    expect(malformed.error?.status).toBe(400);
    expect(await state(ctx)).toEqual(beforeAdmin);
    return ctx.snapshot({
      created,
      accepted,
      beforeMember,
      deniedMember,
      promoted,
      beforeAdmin,
      deniedAdmin,
      malformed,
      observations: await observed(s),
      final: await state(ctx),
    });
  },
);
compatScenario(
  "invitation lifecycle trusted draft patch reaches storage and delivery",
  async (ctx) => {
    const s = await setup(ctx);
    await configure(ctx, "patch-role");
    const before = await state(ctx);
    const result = await s.owner.client.organization.inviteMember(invitationBody(s));
    expect(result.error).toBeNull();
    expect(row.parse(result.data).role).toBe("admin");
    const after = await state(ctx);
    untouched(before, after);
    expect(after.receipts[0]!.context).toMatchObject({ invitation: { role: "member" } });
    expect(after.receipts[1]!.context).toMatchObject({
      role: "admin",
      invitation: { role: "admin" },
    });
    expect(after.receipts[3]!.context).toMatchObject({ invitation: { role: "admin" } });
    expect(after.snapshot.invitations[0]!.role).toBe("admin");
    return ctx.snapshot({ before, result, after, observations: await observed(s) });
  },
);

compatScenario(
  "invitation lifecycle absent limit uses one hundred actual pending rows",
  async (ctx) => {
    const s = await setup(ctx, "org-invite-limit-none");
    const results = [];
    for (let index = 0; index < 100; index++) {
      const result = await s.owner.client.organization.inviteMember({
        ...invitationBody(s),
        email: ctx.uniqueEmail(`default-pending-${index}`),
      });
      expect(result.error).toBeNull();
      results.push(result);
    }
    await configure(ctx, "record");
    const before = await state(ctx);
    expect(before.snapshot.invitations).toHaveLength(100);
    const result = await s.owner.client.organization.inviteMember(invitationBody(s));
    expect(result.error).toMatchObject({ status: 403, code: "INVITATION_LIMIT_REACHED" });
    const after = await state(ctx);
    expect(after).toEqual(before);
    return ctx.snapshot({ results, before, result, after, observations: await observed(s) });
  },
);

compatScenario(
  "invitation lifecycle trusted persisted overrides retain originals and normalized delivery recipient",
  async (ctx) => {
    const s = await setup(ctx);
    await configure(ctx, "patch-persisted");
    const before = await state(ctx);
    const result = await s.owner.client.organization.inviteMember(invitationBody(s));
    expect(result.error).toBeNull();
    const invitation = row.parse(result.data);
    expect(invitation).toMatchObject({
      id: `trusted-${s.org.id}`,
      role: "admin",
      email: s.target.email.toUpperCase(),
      status: "rejected",
    });
    expect(date(invitation.createdAt)).toBe(Date.parse("2020-01-02T03:04:05.123Z"));
    expect(date(invitation.expiresAt)).toBe(Date.parse("2020-01-03T03:04:05.456Z"));
    const after = await state(ctx);
    untouched(before, after);
    expect(after.receipts[0]!.context).toMatchObject({
      invitation: { role: "member", email: s.target.email },
    });
    expect(after.receipts[1]!.context).toMatchObject({
      id: invitation.id,
      role: "admin",
      email: s.target.email,
      invitation: { id: invitation.id, email: s.target.email.toUpperCase(), status: "rejected" },
    });
    expect(after.receipts[3]!.context).toMatchObject({
      invitation: { id: invitation.id, status: "rejected" },
      inviter: { id: s.owner.user.id },
      organization: { id: s.org.id },
    });
    return ctx.snapshot({ before, result, after, observations: await observed(s) });
  },
);
for (const status of ["rejected", "accepted"] as const) {
  compatScenario(
    `invitation lifecycle cancellation permits original ${status} row`,
    async (ctx) => {
      const s = await setup(ctx);
      const created = await s.owner.client.organization.inviteMember(invitationBody(s));
      expect(created.error).toBeNull();
      const invitation = row.parse(created.data);
      const transition =
        status === "rejected"
          ? await s.target.client.organization.rejectInvitation({ invitationId: invitation.id })
          : await s.target.client.organization.acceptInvitation({ invitationId: invitation.id });
      expect(transition.error).toBeNull();
      await configure(ctx, "record");
      const before = await state(ctx);
      const result = await s.owner.client.organization.cancelInvitation({
        invitationId: invitation.id,
      });
      expect(result.error).toBeNull();
      const after = await state(ctx);
      untouched(before, after);
      expect(after.snapshot.invitations).toEqual(
        before.snapshot.invitations.map((r) => ({ ...r, status: "canceled" })),
      );
      expect(after.receipts[0]!.context).toMatchObject({
        invitation: { id: invitation.id, status },
      });
      expect(after.receipts[1]!.context).toMatchObject({
        invitation: { id: invitation.id, status: "canceled" },
      });
      return ctx.snapshot({
        created,
        transition,
        before,
        result,
        after,
        observations: await observed(s),
      });
    },
  );
}
compatScenario(
  "invitation lifecycle expired pending row can be rejected with callbacks",
  async (ctx) => {
    const s = await setup(ctx);
    const created = await ownerOn(ctx, s, "org-invite-expiry-negative").organization.inviteMember(
      invitationBody(s),
    );
    expect(created.error).toBeNull();
    const invitation = row.parse(created.data);
    await configure(ctx, "record");
    const before = await state(ctx);
    const result = await s.target.client.organization.rejectInvitation({
      invitationId: invitation.id,
    });
    expect(result.error).toBeNull();
    const after = await state(ctx);
    untouched(before, after);
    expect(after.snapshot.invitations[0]).toEqual({
      ...before.snapshot.invitations[0]!,
      status: "rejected",
    });
    expect(after.receipts.map((r) => r.phase)).toEqual(["before-reject", "after-reject"]);
    return ctx.snapshot({ created, before, result, after, observations: await observed(s) });
  },
);
