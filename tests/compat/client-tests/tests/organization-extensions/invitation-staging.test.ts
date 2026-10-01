import { expect } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { organizationClient } from "better-auth/client/plugins";
import { Cookie } from "tough-cookie";
import { z } from "zod";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { authProfilePath, type FixtureProfile } from "../../support/profiles";
import { createTracingFetch, type TraceEntry } from "../../support/trace";
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
    z
      .object({
        phase: z.enum(["before-accept", "team-limit", "after-accept"]),
        context: z.record(z.string(), z.unknown()),
        snapshot: snapshotSchema.optional(),
        invitationStatus: z
          .array(
            z
              .object({
                id: z.string(),
                status: z.enum(["pending", "accepted", "rejected", "canceled"]),
              })
              .strict(),
          )
          .optional(),
      })
      .superRefine((receipt, context) => {
        if (
          receipt.phase === "team-limit"
            ? receipt.invitationStatus === undefined ||
              receipt.snapshot !== undefined
            : receipt.snapshot === undefined ||
              receipt.invitationStatus !== undefined
        )
          context.addIssue({
            code: "custom",
            message:
              "Callback observation must match its actual storage boundary",
          });
      }),
  ),
  snapshot: snapshotSchema,
  waiting: z.number(),
});
function protectKeys<T extends z.infer<typeof stateSchema>>(state: T) {
  const snapshots = [
    state.snapshot,
    ...state.receipts.flatMap((receipt) =>
      receipt.snapshot ? [receipt.snapshot] : [],
    ),
  ];
  for (const snapshot of snapshots)
    for (const member of snapshot.teamMembers)
      if (typeof member.membershipKey === "string") {
        expect(member.membershipKey).toBe(
          new Bun.CryptoHasher("sha256")
            .update(JSON.stringify([member.teamId, member.userId]))
            .digest("base64url"),
        );
        member.membershipKey = {
          token: member.membershipKey,
          inputs: {
            teamId: { id: member.teamId },
            userId: { id: member.userId },
          },
        };
      }
  return state;
}
async function state(ctx: ScenarioContext, waitFor?: number) {
  const result = await ctx.rawRequest({
    path:
      "/__test/organization-invitation-stage/state" +
      (waitFor === undefined ? "" : `?waitFor=${waitFor}`),
  });
  expect(result.status).toBe(200);
  return protectKeys(stateSchema.parse(result.body));
}
async function configure(
  ctx: ScenarioContext,
  mode: string,
  invitationId?: string,
  userId?: string,
) {
  const response = await ctx.rawRequest({
    path: "/__test/organization-invitation-stage/configure",
    method: "POST",
    json: { mode, invitationId, userId },
  });
  expect(response.status).toBe(200);
  expect(response.body).toEqual({ configured: true });
  return response;
}
async function signup(
  ctx: ScenarioContext,
  name: string,
  profile: FixtureProfile,
  rememberMe?: boolean,
) {
  const actor = ctx.actor(name, profile),
    cookies: string[][] = [],
    wire: { status: number; contentType: string | null; text: string }[] = [];
  const fetchImpl = async (
    input: string | URL | Request,
    init?: RequestInit,
  ) => {
    const response = await actor.fetch(input, init);
    cookies.push(response.headers.getSetCookie());
    wire.push({
      status: response.status,
      contentType: response.headers.get("content-type"),
      text: await response.clone().text(),
    });
    return response;
  };
  const client = createAuthClient({
    baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
    plugins: [organizationClient({ teams: { enabled: true } })],
    fetchOptions: { customFetchImpl: fetchImpl },
  });
  const email = ctx.uniqueEmail(name),
    signup = await client.signUp.email({
      name,
      email,
      password: "password123",
      ...(rememberMe === undefined ? {} : { rememberMe }),
    });
  expect(signup.error).toBeNull();
  if (rememberMe === false) {
    expect(cookies.at(-1)!.map((raw) => Cookie.parse(raw)!.key)).toEqual([
      "better-auth.session_token",
      "better-auth.dont_remember",
    ]);
    for (const raw of cookies.at(-1)!)
      expect(Cookie.parse(raw)!.maxAge).toBeNull();
  }
  const user = z
    .object({ id: z.string(), email: z.string(), name: z.string() })
    .passthrough()
    .parse(signup.data!.user);
  return { client, cookies, wire, user, email, signup: ctx.snapshot(signup) };
}
async function setup(
  ctx: ScenarioContext,
  profile: FixtureProfile = "org-invitation-stage",
  rememberMe?: boolean,
) {
  const owner = await signup(ctx, "stage-owner", profile),
    target = await signup(ctx, "stage-target", profile, rememberMe),
    foreign = await signup(ctx, "stage-foreign", profile);
  const created = await owner.client.organization.create({
    name: "Staged invitation organization",
    slug: ctx.uniqueToken("stage-org"),
    metadata: { actual: true },
  });
  expect(created.error).toBeNull();
  const org = row.parse(created.data);
  const other = await foreign.client.organization.create({
    name: "Foreign organization",
    slug: ctx.uniqueToken("stage-foreign-org"),
    metadata: { foreign: true },
  });
  expect(other.error).toBeNull();
  let team: z.infer<typeof row> | undefined;
  if (!profile.endsWith("no-team")) {
    const result = await owner.client.organization.createTeam({
      organizationId: org.id,
      name: "Actual invitation team",
    });
    expect(result.error).toBeNull();
    team = row.parse(result.data);
  }
  const result = await owner.client.organization.inviteMember({
    organizationId: org.id,
    email: target.email,
    role: "member",
    ...(team ? { teamId: team.id } : {}),
  });
  expect(result.error).toBeNull();
  const invitation = row.parse(result.data);
  const sibling = ctx.actor("stage-target-sibling", profile);
  const signed = await sibling.client.signIn.email({
    email: target.email,
    password: "password123",
  });
  expect(signed.error).toBeNull();
  const foreignBefore = await ctx.readUserState({ userId: foreign.user.id });
  return {
    owner,
    target,
    foreign,
    org,
    other: row.parse(other.data),
    team,
    invitation,
    sibling,
    foreignBefore,
    profile,
  };
}
type Setup = Awaited<ReturnType<typeof setup>>;
async function denied(
  ctx: ScenarioContext,
  s: Setup,
  before: Awaited<ReturnType<typeof state>>,
) {
  const guest = createAuthClient({
    baseURL: `${ctx.baseURL}${authProfilePath(s.profile)}`,
    plugins: [organizationClient()],
    fetchOptions: {
      customFetchImpl: ctx.actor("stage-guest", s.profile).fetch,
    },
  });
  const noSession = await guest.organization.acceptInvitation({
    invitationId: s.invitation.id,
  });
  expect(noSession.error?.status).toBe(401);
  const wrong = await s.foreign.client.organization.acceptInvitation({
    invitationId: s.invitation.id,
  });
  expect(wrong.error).toMatchObject({
    status: 403,
    code: "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION",
  });
  expect(await state(ctx)).toEqual(before);
  return { noSession: ctx.snapshot(noSession), wrong: ctx.snapshot(wrong) };
}
function phases(result: Awaited<ReturnType<typeof state>>) {
  return result.receipts.map((receipt) => receipt.phase);
}
function unchangedPeers(
  s: Setup,
  before: Awaited<ReturnType<typeof state>>,
  after: Awaited<ReturnType<typeof state>>,
  selected: boolean,
) {
  expect(after.snapshot.organizations).toEqual(before.snapshot.organizations);
  const ownSession = before.snapshot.sessions.find(
    (session) => session.userId === s.target.user.id,
  )!;
  expect(
    after.snapshot.sessions.filter((session) => session.id !== ownSession.id),
  ).toEqual(
    before.snapshot.sessions.filter((session) => session.id !== ownSession.id),
  );
  const current = after.snapshot.sessions.find(
    (session) => session.id === ownSession.id,
  )!;
  if (selected) {
    expect(current).toMatchObject({
      ...ownSession,
      activeOrganizationId: s.org.id,
      ...(s.team ? { activeTeamId: s.team.id } : {}),
      updatedAt: current.updatedAt,
    });
    expect(current.token).toBe(ownSession.token);
  } else expect(current).toEqual(ownSession);
}
function accepted(
  s: Setup,
  before: Awaited<ReturnType<typeof state>>,
  after: Awaited<ReturnType<typeof state>>,
) {
  expect(after.snapshot.invitations).toEqual(
    before.snapshot.invitations.map((row) =>
      row.id === s.invitation.id ? { ...row, status: "accepted" } : row,
    ),
  );
  expect(after.snapshot.members).toHaveLength(
    before.snapshot.members.length + 1,
  );
  const member = after.snapshot.members.at(-1)!;
  expect(member).toMatchObject({
    organizationId: s.org.id,
    userId: s.target.user.id,
    role: s.invitation.role,
  });
  expect(before.snapshot.members.some((row) => row.id === member.id)).toBe(
    false,
  );
  expect(after.snapshot.members.slice(0, -1)).toEqual(before.snapshot.members);
  if (s.team) {
    expect(after.snapshot.teamMembers).toHaveLength(
      before.snapshot.teamMembers.length + 1,
    );
    expect(after.snapshot.teamMembers.at(-1)).toMatchObject({
      teamId: s.team.id,
      userId: s.target.user.id,
    });
    expect(after.snapshot.teams).toEqual(
      before.snapshot.teams.map((team) =>
        team.id === s.team!.id
          ? { ...team, memberCount: Number(team.memberCount) + 1 }
          : team,
      ),
    );
  } else {
    expect(after.snapshot.teamMembers).toEqual(before.snapshot.teamMembers);
    expect(after.snapshot.teams).toEqual(before.snapshot.teams);
  }
  unchangedPeers(s, before, after, true);
}
function cookiePolicy(cookies: string[], expected: boolean) {
  expect(cookies).toHaveLength(expected ? 1 : 0);
  if (expected) {
    const cookie = Cookie.parse(cookies[0]!);
    expect(cookie).toMatchObject({
      key: "better-auth.session_token",
      path: "/",
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      maxAge: 604800,
    });
  }
  return cookies.map((raw) => {
    const cookie = Cookie.parse(raw)!;
    return {
      key: cookie.key,
      path: cookie.path,
      httpOnly: cookie.httpOnly,
      secure: cookie.secure,
      sameSite: cookie.sameSite,
      maxAge: cookie.maxAge,
    };
  });
}
for (const mode of [
  "before-accept-error",
  "before-accept-internal",
  "before-accept-public500",
  "team-limit-error",
  "team-limit-internal",
  "team-limit-public500",
  "team-full",
  "sql-member",
  "sql-team",
  "sql-session",
  "sql-reset",
  "sql-reset-api",
  "after-accept-error",
  "after-accept-internal",
  "after-accept-public500",
] as const) {
  compatScenario(
    `organization invitation staged acceptance ${mode} preserves exact phase state and authority`,
    async (ctx) => {
      const s = await setup(ctx);
      if (mode === "team-full") {
        const add = await s.owner.client.organization.addTeamMember({
          teamId: s.team!.id,
          userId: s.owner.user.id,
          organizationId: s.org.id,
        });
        expect(add.error).toBeNull();
      }
      await configure(ctx, mode, s.invitation.id, s.target.user.id);
      const before = await state(ctx),
        guards = await denied(ctx, s, before);
      const result = await s.target.client.organization.acceptInvitation({
          invitationId: s.invitation.id,
        }),
        cookies = s.target.cookies.at(-1)!;
      const transport = s.target.wire.at(-1)!;
      const after = await state(ctx),
        early = mode.startsWith("before"),
        late = mode.startsWith("after"),
        resetVeto = mode === "sql-reset" || mode === "sql-reset-api";
      const status = mode.endsWith("error") || mode === "team-full" ? 403 : 500;
      expect(result.error?.status).toBe(status);
      if (mode.endsWith("error"))
        expect(result.error).toMatchObject({
          code: "INVITATION_APPLICATION_REJECTED",
          message: `Rejected ${early ? "before-accept" : late ? "after-accept" : "team-limit"}`,
        });
      if (mode.endsWith("public500"))
        expect(result.error).toMatchObject({
          code: "PUBLIC_INVITATION_500",
          message: `Explicit ${early ? "before-accept" : late ? "after-accept" : "team-limit"} error`,
        });
      if (mode.endsWith("internal") || mode.startsWith("sql-")) {
        expect(transport.text).toBe("");
        expect(transport.contentType).toBeNull();
      } else {
        expect(transport.contentType).toContain("application/json");
        expect(JSON.parse(transport.text)).toMatchObject({
          message: result.error!.message,
        });
      }
      const policies = cookiePolicy(
        cookies,
        late && mode !== "after-accept-internal",
      );
      expect(phases(after)).toEqual(
        early
          ? ["before-accept"]
          : late
            ? ["before-accept", "team-limit", "after-accept"]
            : ["before-accept", "team-limit"],
      );
      expect(after.receipts[0]!.context).toMatchObject({
        invitation: ctx.snapshot({ ...s.invitation, status: "pending" }),
        user: ctx.snapshot(s.target.user),
        organization: {
          id: s.org.id,
          name: s.org.name,
          metadata: JSON.stringify({ actual: true }),
        },
      });
      expect(after.receipts[0]!.snapshot).toEqual(before.snapshot);
      if (!early) {
        const receipt = after.receipts[1]!;
        expect(receipt.context).toMatchObject({
          teamId: s.team!.id,
          organizationId: s.org.id,
          session: {
            user: ctx.snapshot(s.target.user),
            session: {
              userId: s.target.user.id,
              activeOrganizationId: null,
              activeTeamId: null,
            },
          },
        });
        expect(receipt.snapshot).toBeUndefined();
        expect(receipt.invitationStatus).toEqual([
          { id: s.invitation.id, status: "accepted" },
        ]);
      }
      if (late) {
        accepted(s, before, after);
        expect(after.receipts[2]!.snapshot).toEqual(after.snapshot);
        expect(after.receipts[2]!.context).toMatchObject({
          invitation: ctx.snapshot({ ...s.invitation, status: "accepted" }),
          member: after.snapshot.members.at(-1),
          user: ctx.snapshot(s.target.user),
        });
      } else {
        expect(after.snapshot.members).toEqual(before.snapshot.members);
        expect(after.snapshot.teamMembers).toEqual(before.snapshot.teamMembers);
        expect(after.snapshot.teams).toEqual(before.snapshot.teams);
        expect(after.snapshot.invitations).toEqual(
          before.snapshot.invitations.map((row) =>
            resetVeto && row.id === s.invitation.id
              ? { ...row, status: "accepted" }
              : row,
          ),
        );
        unchangedPeers(s, before, after, false);
      }
      expect(await ctx.readUserState({ userId: s.foreign.user.id })).toEqual(
        s.foreignBefore,
      );
      await configure(ctx, "record");
      const retryBefore = await state(ctx),
        retry = await s.target.client.organization.acceptInvitation({
          invitationId: s.invitation.id,
        });
      if (late || resetVeto) {
        expect(retry.error).toMatchObject({
          status: 400,
          code: "INVITATION_NOT_FOUND",
        });
        expect(await state(ctx)).toEqual(retryBefore);
      } else if (mode === "team-full") {
        /* The genuine callback configuration raised capacity before retry. */ expect(
          retry.error,
        ).toBeNull();
      } else expect(retry.error).toBeNull();
      const final = await state(ctx);
      if (!late && !resetVeto) accepted(s, retryBefore, final);
      const current = await s.target.client.getSession();
      expect(current.data!.user.id).toBe(s.target.user.id);
      expect(current.data!.session.token).toBe(
        z
          .string()
          .parse(
            before.snapshot.sessions.find(
              (row) => row.userId === s.target.user.id,
            )!.token,
          ),
      );
      expect(current.data!.session.activeOrganizationId).toBe(
        late || !resetVeto ? s.org.id : null,
      );
      const sibling = await s.sibling.client.getSession();
      expect(
        z
          .object({ activeOrganizationId: z.null(), activeTeamId: z.null() })
          .parse(sibling.data!.session),
      ).toEqual({ activeOrganizationId: null, activeTeamId: null });
      return {
        signup: [s.owner.signup, s.target.signup, s.foreign.signup],
        before,
        guards,
        result: ctx.snapshot(result),
        transport: {
          ...transport,
          text: transport.text === "" ? "" : JSON.parse(transport.text),
        },
        policies,
        after,
        retryBefore,
        retry: ctx.snapshot(retry),
        final,
        current: ctx.snapshot(current),
        sibling: ctx.snapshot(sibling),
        foreignBefore: s.foreignBefore,
        foreignAfter: await ctx.readUserState({ userId: s.foreign.user.id }),
      };
    },
    ["POST /organization/accept-invitation"],
  );
}
for (const profile of [
  "org-invitation-stage",
  "org-invitation-stage-no-team",
] as const)
  compatScenario(
    `organization invitation ${profile} accepts a real existing membership as a distinct row`,
    async (ctx) => {
      const s = await setup(ctx, profile);
      const addition = await ctx.rawRequest({
        path: "/__test/organization-member-addition/server",
        method: "POST",
        json: {
          profile: "org-member-addition-no-team",
          body: {
            organizationId: s.org.id,
            userId: s.target.user.id,
            role: "admin",
          },
        },
      });
      expect(addition.status).toBe(200);
      const original = row.parse(addition.body);
      await configure(ctx, "record");
      const before = await state(ctx),
        guards = await denied(ctx, s, before),
        result = await s.target.client.organization.acceptInvitation({
          invitationId: s.invitation.id,
        });
      expect(result.error).toBeNull();
      const after = await state(ctx);
      accepted(s, before, after);
      expect(
        after.snapshot.members.filter(
          (row) =>
            row.organizationId === s.org.id && row.userId === s.target.user.id,
        ),
      ).toHaveLength(2);
      expect(
        after.snapshot.members.find((row) => row.id === original.id),
      ).toEqual(original);
      expect(phases(after)).toEqual(
        s.team
          ? ["before-accept", "team-limit", "after-accept"]
          : ["before-accept", "after-accept"],
      );
      if (s.team)
        expect(after.receipts[1]!.invitationStatus).toEqual([
          { id: s.invitation.id, status: "accepted" },
        ]);
      expect(after.receipts.at(-1)!.context).toMatchObject({
        invitation: ctx.snapshot({ ...s.invitation, status: "accepted" }),
        member: after.snapshot.members.at(-1),
        user: ctx.snapshot(s.target.user),
      });
      const policies = cookiePolicy(s.target.cookies.at(-1)!, Boolean(s.team));
      const current = await s.target.client.getSession();
      expect(current.data!.session.activeOrganizationId).toBe(s.org.id);
      expect(current.data!.session.activeTeamId).toBe(s.team?.id);
      const replay = await s.target.client.organization.acceptInvitation({
        invitationId: s.invitation.id,
      });
      expect(replay.error?.status).toBe(400);
      expect(await state(ctx)).toEqual(after);
      expect(await ctx.readUserState({ userId: s.foreign.user.id })).toEqual(
        s.foreignBefore,
      );
      return {
        addition,
        before,
        guards,
        result: ctx.snapshot(result),
        after,
        policies,
        current: ctx.snapshot(current),
        replay: ctx.snapshot(replay),
        foreignBefore: s.foreignBefore,
        foreignAfter: await ctx.readUserState({ userId: s.foreign.user.id }),
      };
    },
    ["POST /organization/accept-invitation"],
  );

// Both requests complete genuine membership admission before the application
// barrier releases them. Serial release observes status CAS and keeps full traces.
for (const differentRecipients of [false, true])
  compatScenario(
    `organization invitation staged concurrent ${differentRecipients ? "different recipients retain prior capacity admission" : "same invitation has one status claimant"}`,
    async (ctx) => {
      const s = await setup(ctx, "org-invitation-stage-limit-two");
      const secondTarget = differentRecipients
        ? await signup(ctx, "stage-second-target", s.profile)
        : s.target;
      let secondInvitation = s.invitation;
      if (differentRecipients) {
        const issued = await s.owner.client.organization.inviteMember({
          organizationId: s.org.id,
          email: secondTarget.email,
          role: "admin",
          teamId: s.team!.id,
        });
        expect(issued.error).toBeNull();
        secondInvitation = row.parse(issued.data);
      }
      await configure(ctx, "pause-before");
      const before = await state(ctx),
        guards = await denied(ctx, s, before);
      const releaseTraces: TraceEntry[] = [];
      async function release(name: string) {
        const response = await createTracingFetch(
          ctx.baseURL,
          name,
          releaseTraces,
        )("/__test/organization-invitation-stage/release", { method: "POST" });
        expect(response.status).toBe(200);
        expect(await response.json()).toEqual({ released: true });
      }
      let first:
        | ReturnType<typeof s.target.client.organization.acceptInvitation>
        | undefined;
      let second:
        | ReturnType<typeof s.target.client.organization.acceptInvitation>
        | undefined;
      let firstResult, secondResult, one, held, firstState;
      try {
        first = s.target.client.organization.acceptInvitation({
          invitationId: s.invitation.id,
        });
        one = await state(ctx, 1);
        expect(one.waiting).toBe(1);
        expect(phases(one)).toEqual(["before-accept"]);
        expect(one.snapshot).toEqual(before.snapshot);
        second = secondTarget.client.organization.acceptInvitation({
          invitationId: secondInvitation.id,
        });
        held = await state(ctx, 2);
        expect(held.waiting).toBe(2);
        expect(phases(held)).toEqual(["before-accept", "before-accept"]);
        expect(held.snapshot).toEqual(before.snapshot);
        expect(held.receipts.map((receipt) => receipt.context)).toEqual([
          { ...one.receipts[0]!.context },
          {
            invitation: ctx.snapshot(secondInvitation),
            user: ctx.snapshot(secondTarget.user),
            organization: one.receipts[0]!.context.organization,
          },
        ]);
        await release("invitation-release-first");
        firstResult = await first;
        expect(firstResult.error).toBeNull();
        ctx.recordTransport(releaseTraces.splice(0));
        firstState = await state(ctx);
        expect(firstState.waiting).toBe(1);
        accepted(s, before, firstState);
        await release("invitation-release-second");
        secondResult = await second;
        ctx.recordTransport(releaseTraces.splice(0));
        if (differentRecipients) expect(secondResult.error).toBeNull();
        else
          expect(secondResult.error).toMatchObject({
            status: 400,
            code: "INVITATION_NOT_FOUND",
          });
      } finally {
        if (!firstResult || !secondResult) {
          await configure(ctx, "off");
          await Promise.allSettled([first, second]);
          ctx.recordTransport(releaseTraces.splice(0));
        }
      }
      const after = await state(ctx);
      expect(after.waiting).toBe(0);
      if (differentRecipients) {
        const secondSetup = {
          ...s,
          target: secondTarget,
          invitation: secondInvitation,
        };
        accepted(secondSetup, firstState!, after);
        expect(
          after.snapshot.members.filter(
            (member) => member.organizationId === s.org.id,
          ),
        ).toHaveLength(3);
        expect(after.snapshot.members.at(-1)).toMatchObject({ role: "admin" });
        expect(phases(after)).toEqual([
          "before-accept",
          "before-accept",
          "team-limit",
          "after-accept",
          "team-limit",
          "after-accept",
        ]);
        cookiePolicy(secondTarget.cookies.at(-1)!, true);
      } else {
        expect(after.snapshot).toEqual(firstState!.snapshot);
        expect(after.receipts).toEqual(firstState!.receipts);
        expect(phases(after)).toEqual([
          "before-accept",
          "before-accept",
          "team-limit",
          "after-accept",
        ]);
        cookiePolicy(s.target.cookies.at(-1)!, false);
      }
      const claimedIds = differentRecipients
        ? [s.invitation.id, secondInvitation.id]
        : [s.invitation.id];
      expect(
        after.receipts
          .filter((receipt) => receipt.phase === "team-limit")
          .map((receipt) => receipt.invitationStatus),
      ).toEqual(claimedIds.map((id) => [{ id, status: "accepted" }]));
      expect(
        after.receipts
          .filter((receipt) => receipt.phase === "after-accept")
          .map((receipt) => receipt.context.member),
      ).toEqual(after.snapshot.members.slice(before.snapshot.members.length));
      const firstPolicies = cookiePolicy(
        differentRecipients
          ? s.target.cookies.at(-1)!
          : s.target.cookies.at(-2)!,
        true,
      );
      const current = await s.target.client.getSession();
      expect(current.data!.session.activeOrganizationId).toBe(s.org.id);
      expect(current.data!.session.activeTeamId).toBe(s.team!.id);
      const replay = await secondTarget.client.organization.acceptInvitation({
        invitationId: secondInvitation.id,
      });
      expect(replay.error?.status).toBe(400);
      expect(await state(ctx)).toEqual(after);
      expect(await ctx.readUserState({ userId: s.foreign.user.id })).toEqual(
        s.foreignBefore,
      );
      return {
        before,
        guards,
        one,
        held,
        firstResult: ctx.snapshot(firstResult),
        firstState,
        secondResult: ctx.snapshot(secondResult),
        after,
        firstPolicies,
        current: ctx.snapshot(current),
        replay: ctx.snapshot(replay),
        foreignBefore: s.foreignBefore,
        foreignAfter: await ctx.readUserState({ userId: s.foreign.user.id }),
      };
    },
    ["POST /organization/accept-invitation"],
  );

compatScenario(
  "organization invitation staged expiry denies before hooks without any acceptance side effect",
  async (ctx) => {
    const s = await setup(ctx);
    await ctx.expireInvitation({
      invitationId: s.invitation.id,
      expiresAt: "2000-01-01T00:00:00.000Z",
    });
    await configure(ctx, "record");
    const before = await state(ctx);
    expect(
      before.snapshot.invitations.find(
        (invitation) => invitation.id === s.invitation.id,
      ),
    ).toMatchObject({
      status: "pending",
      expiresAt: "2000-01-01T00:00:00.000Z",
    });
    const principalsBefore = await Promise.all(
      [s.owner, s.target, s.foreign].map(({ user }) =>
        ctx.readUserState({ userId: user.id }),
      ),
    );
    const guest = createAuthClient({
      baseURL: `${ctx.baseURL}${authProfilePath(s.profile)}`,
      plugins: [organizationClient()],
      fetchOptions: {
        customFetchImpl: ctx.actor("stage-expired-guest", s.profile).fetch,
      },
    });
    const unauthenticated = await guest.organization.acceptInvitation({
      invitationId: s.invitation.id,
    });
    expect(unauthenticated.error?.status).toBe(401);
    expect(await state(ctx)).toEqual(before);
    const result = await s.target.client.organization.acceptInvitation({
      invitationId: s.invitation.id,
    });
    expect(result.error).toMatchObject({
      status: 400,
      code: "INVITATION_NOT_FOUND",
    });
    const foreign = await s.foreign.client.organization.acceptInvitation({
      invitationId: s.invitation.id,
    });
    expect(foreign.error).toMatchObject({
      status: 400,
      code: "INVITATION_NOT_FOUND",
    });
    const after = await state(ctx);
    expect(after).toEqual(before);
    expect(after.receipts).toEqual([]);
    const principalsAfter = await Promise.all(
      [s.owner, s.target, s.foreign].map(({ user }) =>
        ctx.readUserState({ userId: user.id }),
      ),
    );
    expect(principalsAfter).toEqual(principalsBefore);
    cookiePolicy(s.target.cookies.at(-1)!, false);
    expect(await ctx.readUserState({ userId: s.foreign.user.id })).toEqual(
      s.foreignBefore,
    );
    return {
      before,
      principalsBefore,
      unauthenticated: ctx.snapshot(unauthenticated),
      result: ctx.snapshot(result),
      foreign: ctx.snapshot(foreign),
      after,
      principalsAfter,
      foreignBefore: s.foreignBefore,
      foreignAfter: await ctx.readUserState({ userId: s.foreign.user.id }),
    };
  },
  ["POST /organization/accept-invitation"],
);

for (const mode of [
  "record",
  "after-accept-internal",
  "after-accept-public500",
] as const)
  compatScenario(
    `organization invitation staged ${mode} preserves browser-session preference and both owned cookie stages`,
    async (ctx) => {
      const s = await setup(ctx, "org-invitation-stage", false);
      await configure(ctx, mode);
      const before = await state(ctx),
        guards = await denied(ctx, s, before);
      const result = await s.target.client.organization.acceptInvitation({
          invitationId: s.invitation.id,
        }),
        cookies = s.target.cookies.at(-1)!,
        transport = s.target.wire.at(-1)!;
      if (mode === "record") expect(result.error).toBeNull();
      else {
        expect(result.error?.status).toBe(500);
        if (mode === "after-accept-public500")
          expect(result.error).toMatchObject({
            code: "PUBLIC_INVITATION_500",
            message: "Explicit after-accept error",
          });
      }
      expect(cookies).toHaveLength(mode === "after-accept-internal" ? 0 : 2);
      const policies = cookies.map((raw) => {
        const cookie = Cookie.parse(raw)!;
        expect(cookie).toMatchObject({
          path: "/",
          httpOnly: true,
          secure: false,
          sameSite: "lax",
        });
        expect(cookie.maxAge).toBeNull();
        expect(cookie.expires).toBe("Infinity");
        const value = decodeURIComponent(cookie.value);
        expect(value.lastIndexOf(".")).toBeGreaterThan(0);
        return {
          key: cookie.key,
          path: cookie.path,
          httpOnly: cookie.httpOnly,
          secure: cookie.secure,
          sameSite: cookie.sameSite,
          maxAge: cookie.maxAge ?? null,
          expires: cookie.expires,
          value: value.slice(0, value.lastIndexOf(".")),
        };
      });
      if (policies.length) {
        expect(policies.map((cookie) => cookie.key)).toEqual([
          "better-auth.session_token",
          "better-auth.dont_remember",
        ]);
        expect(policies[0]!.value).toBe(
          z
            .string()
            .parse(
              before.snapshot.sessions.find(
                (row) => row.userId === s.target.user.id,
              )!.token,
            ),
        );
        expect(policies[1]!.value).toBe("true");
      }
      if (mode === "after-accept-internal") {
        expect(transport.text).toBe("");
        expect(transport.contentType).toBeNull();
      }
      const after = await state(ctx);
      accepted(s, before, after);
      expect(phases(after)).toEqual([
        "before-accept",
        "team-limit",
        "after-accept",
      ]);
      expect(after.receipts[1]!.invitationStatus).toEqual([
        { id: s.invitation.id, status: "accepted" },
      ]);
      expect(after.receipts[2]!.snapshot).toEqual(after.snapshot);
      const current = await s.target.client.getSession();
      expect(current.data!.user.id).toBe(s.target.user.id);
      expect(current.data!.session.token).toBe(
        z
          .string()
          .parse(
            before.snapshot.sessions.find(
              (row) => row.userId === s.target.user.id,
            )!.token,
          ),
      );
      expect(current.data!.session.activeOrganizationId).toBe(s.org.id);
      expect(current.data!.session.activeTeamId).toBe(s.team!.id);
      const replay = await s.target.client.organization.acceptInvitation({
        invitationId: s.invitation.id,
      });
      expect(replay.error?.status).toBe(400);
      expect(await state(ctx)).toEqual(after);
      expect(await ctx.readUserState({ userId: s.foreign.user.id })).toEqual(
        s.foreignBefore,
      );
      return {
        signup: s.target.signup,
        before,
        guards,
        result: ctx.snapshot(result),
        transport: {
          ...transport,
          text: transport.text ? JSON.parse(transport.text) : "",
        },
        policies: policies.map((cookie) =>
          cookie.key === "better-auth.session_token"
            ? { ...cookie, value: { token: cookie.value } }
            : cookie,
        ),
        after,
        current: ctx.snapshot(current),
        replay: ctx.snapshot(replay),
        foreignBefore: s.foreignBefore,
        foreignAfter: await ctx.readUserState({ userId: s.foreign.user.id }),
      };
    },
    ["POST /organization/accept-invitation"],
  );
