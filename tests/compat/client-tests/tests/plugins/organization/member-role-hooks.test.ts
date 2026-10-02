import { expect } from "bun:test";

import { Cookie } from "tough-cookie";
import { z } from "zod";

import { compatScenario, type ScenarioContext } from "../../../support/scenario";
import { createTracingFetch, type TraceEntry } from "../../../support/trace";

const row = z.object({ id: z.string() }).passthrough();

const snapshot = z.object({
  organizations: z.array(row),
  members: z.array(row),
  users: z.array(row),
  sessions: z.array(row),
});

const receipt = z.object({
  phase: z.string(),
  organization: z.record(z.string(), z.unknown()),
  newRole: z.string().nullable(),
  previousRole: z.string().nullable(),
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

const memberSchema = z
  .object({ id: z.string(), organizationId: z.string(), userId: z.string(), role: z.string() })
  .passthrough();

async function configure(ctx: ScenarioContext, mode: string) {
  const response = await ctx.rawRequest({
    path: "/__test/organization-member-role-hooks-configure",
    method: "POST",
    json: { mode },
  });
  expect(response.status).toBe(200);
}

async function state(ctx: ScenarioContext, waitFor?: string) {
  const result = await ctx.rawRequest({
    path: "/__test/organization-member-role-hooks-state" + (waitFor ? `?waitFor=${waitFor}` : ""),
  });
  expect(result.status).toBe(200);
  return stateSchema.parse(result.body);
}

async function signup(ctx: ScenarioContext, name: string) {
  const actor = ctx.actor(name, "org-member-role-hooks");
  const email = ctx.uniqueEmail(name);
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

async function setup(ctx: ScenarioContext, name: string) {
  const owner = await signup(ctx, `${name}-owner`);
  const target = await signup(ctx, `${name}-target`);
  const foreign = await signup(ctx, `${name}-foreign`);
  const org = await create(ctx, owner, `${name}-org`);
  const other = await create(ctx, foreign, `${name}-other`);

  const invitation = await owner.client.$fetch("/organization/invite-member", {
    method: "POST",
    body: { organizationId: org.id, email: target.email, role: "member" },
  });
  expect(invitation.error).toBeNull();

  const invitationId = z.object({ id: z.string() }).parse(invitation.data).id;
  const accepted = await target.client.$fetch("/organization/accept-invitation", {
    method: "POST",
    body: { invitationId },
  });
  expect(accepted.error).toBeNull();

  const member = memberSchema.parse(z.object({ member: memberSchema }).parse(accepted.data).member);

  const sibling = ctx.actor(`${name}-sibling`, "org-member-role-hooks");
  expect(
    (await sibling.client.signIn.email({ email: target.email, password: "password123" })).error,
  ).toBeNull();

  return { owner, target, foreign, org, other, member, sibling };
}

function update(
  actor: Actor,
  organizationId: string,
  memberId: string,
  role: string | string[] = "admin",
) {
  return actor.client.$fetch("/organization/update-member-role", {
    method: "POST",
    body: { organizationId, memberId, role },
  });
}

function stable(
  before: Awaited<ReturnType<typeof state>>,
  after: Awaited<ReturnType<typeof state>>,
  memberId: string,
) {
  expect(after.snapshot.members.filter((row) => row.id !== memberId)).toEqual(
    before.snapshot.members.filter((row) => row.id !== memberId),
  );
  for (const key of ["organizations", "users", "sessions"] as const) {
    expect(after.snapshot[key]).toEqual(before.snapshot[key]);
  }
}

async function fullState(ctx: ScenarioContext, actors: Actor[]) {
  const users = [];
  for (const actor of actors) {
    const response = await ctx.rawRequest({
      path: `/__test/user-state?userId=${encodeURIComponent(actor.userId)}`,
    });
    expect(response.status).toBe(200);
    users.push(response.body);
  }
  return { hooks: await state(ctx), users };
}

async function rawRole(
  ctx: ScenarioContext,
  actor: ReturnType<ScenarioContext["actor"]>,
  body: string,
  media = "application/json",
) {
  const response = await actor.fetch(
    `${ctx.baseURL}/__test/profiles/org-member-role-hooks/api/auth/organization/update-member-role`,
    { method: "POST", headers: { "content-type": media }, body },
  );
  const text = await response.text();
  return {
    status: response.status,
    empty: text.length === 0,
    body: text ? JSON.parse(text) : null,
  };
}

compatScenario(
  "organization member role callbacks use the target user and normalized initial role with source patch fallback",
  async (ctx) => {
    const { owner, target, org, member } = await setup(ctx, "role-patches");
    const observations = [];

    const read = await owner.client.$fetch("/organization/get-organization", {
      query: { organizationId: org.id },
    });
    expect(read.error).toBeNull();

    const rawOrganization = organization.parse(ctx.snapshot(read.data));

    for (const [mode, expected] of [
      ["record", "admin,member,admin"],
      ["empty", "admin,member,admin"],
      ["absent", "admin,member,admin"],
      ["patch", "hook-unregistered-role"],
    ] as const) {
      await configure(ctx, mode);
      const before = await state(ctx);
      const result = await update(owner, org.id, member.id, [" admin ,member ", "admin"]);
      expect(result.error).toBeNull();
      expect(memberSchema.parse(result.data).role).toBe(expected);

      const after = await state(ctx);
      expect(after.receipts.map((row) => row.phase)).toEqual(["before-role", "after-role"]);

      const first = after.receipts[0]!;
      const last = after.receipts[1]!;
      expect(first.newRole).toBe("admin,member,admin");
      expect(first.previousRole).toBeNull();
      expect(last.newRole).toBeNull();
      expect(first.user).toEqual({
        id: target.userId,
        email: target.email,
        name: "role-patches-target",
      });
      expect(last.user).toEqual(first.user);
      expect(first.member).toEqual(
        memberSchema.parse(before.snapshot.members.find((row) => row.id === member.id)),
      );
      expect(last.member).toEqual(
        memberSchema.parse(after.snapshot.members.find((row) => row.id === member.id)),
      );
      expect(last.previousRole).toBe(first.member.role);
      expect(first.organization).toEqual(rawOrganization);
      expect(last.organization).toEqual(first.organization);
      expect(first.organization.metadata).toBe('{"original":true}');

      expect(after.snapshot.members.find((row) => row.id === member.id)).toHaveProperty(
        "role",
        expected,
      );

      stable(before, after, member.id);
      observations.push({ before, result: ctx.snapshot(result), after });
    }

    await configure(ctx, "record");
    const beforeDenied = await state(ctx);
    const denied = await update(target, org.id, member.id, "member");
    expect(denied.error).toMatchObject({ status: 403 });
    expect(await state(ctx)).toEqual(beforeDenied);

    return { observations, denied: ctx.snapshot(denied), beforeDenied };
  },
  ["POST /organization/update-member-role"],
);

compatScenario(
  "organization member role revoked and expired sessions preserve cleanup and sibling authority",
  async (ctx) => {
    const { owner, target, foreign, org, member } = await setup(ctx, "role-input-session");
    const actors = [owner, target, foreign];

    const ownerSibling = ctx.actor("role-input-owner-sibling", "org-member-role-hooks");
    expect(
      (await ownerSibling.client.signIn.email({ email: owner.email, password: "password123" }))
        .error,
    ).toBeNull();

    const current = await owner.client.getSession();
    expect(current.error).toBeNull();

    const token = z.string().parse(current.data?.session.token);
    await configure(ctx, "record");

    // Revoke the owner's primary session from its sibling.
    const beforeRevocation = await fullState(ctx, actors);
    const userState = z.object({ sessions: z.array(row) }).passthrough();
    const revokedId = z
      .string()
      .parse(
        userState
          .parse(beforeRevocation.users[0])
          .sessions.find((session) => session.token === token)?.id,
      );
    const revoked = await ownerSibling.client.revokeSession({ token });
    expect(revoked.error).toBeNull();

    const afterRevocation = await fullState(ctx, actors);
    expect(afterRevocation.hooks).toEqual({
      ...beforeRevocation.hooks,
      snapshot: {
        ...beforeRevocation.hooks.snapshot,
        sessions: beforeRevocation.hooks.snapshot.sessions.filter(
          (session) => session.id !== revokedId,
        ),
      },
    });
    expect(afterRevocation.users).toEqual(
      beforeRevocation.users.map((value) => {
        const parsed = userState.parse(value);
        return {
          ...parsed,
          sessions: parsed.sessions.filter((session) => session.token !== token),
        };
      }),
    );

    async function rejected() {
      const response = await owner.fetch(
        `${ctx.baseURL}/__test/profiles/org-member-role-hooks/api/auth/organization/update-member-role`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ organizationId: org.id, memberId: member.id, role: "admin" }),
        },
      );
      expect(response.status).toBe(401);

      const body = await response.json();
      expect(body).toEqual({ code: "UNAUTHORIZED", message: "Unauthorized" });

      const cookies = response.headers.getSetCookie().map((value) => Cookie.parse(value));
      const sessionCookie = cookies.find((cookie) => cookie?.key === "better-auth.session_token");
      expect(sessionCookie).toBeDefined();
      expect(sessionCookie?.value).toBe("");
      expect(sessionCookie?.maxAge).toBe(0);
      expect(sessionCookie?.path).toBe("/");
      expect(sessionCookie?.httpOnly).toBe(true);

      return { status: response.status, body };
    }

    const revokedResult = await rejected();
    expect(await fullState(ctx, actors)).toEqual(afterRevocation);
    expect((await ownerSibling.client.getSession()).data?.user.id).toBe(owner.userId);

    // Sign in again, then expire that session in storage.
    const signin = await owner.client.signIn.email({ email: owner.email, password: "password123" });
    expect(signin.error).toBeNull();

    const expiryToken = z.string().parse(signin.data?.token);
    const expiry = await ctx.rawRequest({
      path: "/__test/expire-session",
      method: "POST",
      json: { token: expiryToken, expiresAt: "2000-01-01T00:00:00.000Z" },
    });
    expect(expiry.status).toBe(200);
    expect(expiry.body).toEqual({ updated: 1 });

    const beforeExpiry = await fullState(ctx, actors);
    const expiredResult = await rejected();
    const afterExpiry = await fullState(ctx, actors);
    const expiredId = z
      .string()
      .parse(
        userState
          .parse(beforeExpiry.users[0])
          .sessions.find((session) => session.token === expiryToken)?.id,
      );
    expect(afterExpiry.hooks).toEqual({
      ...beforeExpiry.hooks,
      snapshot: {
        ...beforeExpiry.hooks.snapshot,
        sessions: beforeExpiry.hooks.snapshot.sessions.filter(
          (session) => session.id !== expiredId,
        ),
      },
    });
    expect(afterExpiry.users).toEqual(
      beforeExpiry.users.map((value) => {
        const parsed = userState.parse(value);
        return {
          ...parsed,
          sessions: parsed.sessions.filter((session) => session.token !== expiryToken),
        };
      }),
    );
    expect((await ownerSibling.client.getSession()).data?.user.id).toBe(owner.userId);

    // A fresh session can still change the role.
    const retrySignin = await owner.client.signIn.email({
      email: owner.email,
      password: "password123",
    });
    expect(retrySignin.error).toBeNull();

    const retry = await update(owner, org.id, member.id, "admin");
    expect(retry.error).toBeNull();

    const afterRetry = await fullState(ctx, actors);
    expect(afterRetry.hooks.receipts.map((receipt) => receipt.phase)).toEqual([
      "before-role",
      "after-role",
    ]);
    expect(
      afterRetry.hooks.snapshot.members.find((memberRow) => memberRow.id === member.id),
    ).toHaveProperty("role", "admin");
    expect(afterRetry.users.slice(1)).toEqual(afterExpiry.users.slice(1));
    expect(afterRetry.hooks.snapshot.organizations).toEqual(
      afterExpiry.hooks.snapshot.organizations,
    );
    expect(afterRetry.hooks.snapshot.users).toEqual(afterExpiry.hooks.snapshot.users);
    expect(
      afterRetry.hooks.snapshot.members.filter((memberRow) => memberRow.id !== member.id),
    ).toEqual(afterExpiry.hooks.snapshot.members.filter((memberRow) => memberRow.id !== member.id));

    const retryToken = z.string().parse(retrySignin.data?.token);
    const retryId = z
      .string()
      .parse(
        userState
          .parse(afterRetry.users[0])
          .sessions.find((session) => session.token === retryToken)?.id,
      );
    expect(afterRetry.hooks.snapshot.sessions.filter((session) => session.id !== retryId)).toEqual(
      afterExpiry.hooks.snapshot.sessions,
    );

    return {
      beforeRevocation,
      revoked: ctx.snapshot(revoked),
      afterRevocation,
      revokedResult,
      beforeExpiry,
      expiredResult,
      afterExpiry,
      retrySignin: ctx.snapshot(retrySignin),
      retry: ctx.snapshot(retry),
      afterRetry,
    };
  },
  ["POST /organization/update-member-role"],
);

compatScenario(
  "organization member role callback errors distinguish no write from a committed role change",
  async (ctx) => {
    const { owner, org, member } = await setup(ctx, "role-errors");
    const observations = [];

    for (const phase of ["before-role", "after-role"]) {
      await configure(ctx, `reject-${phase}`);
      const before = await state(ctx);
      const result = await update(owner, org.id, member.id);
      expect(result.error).toMatchObject({
        status: 400,
        code: "ROLE_HOOK_REJECTED",
        message: `Rejected ${phase}`,
      });

      const after = await state(ctx);
      expect(after.receipts.map((row) => row.phase)).toEqual(
        phase === "before-role" ? ["before-role"] : ["before-role", "after-role"],
      );

      if (phase === "before-role") {
        expect(after.snapshot).toEqual(before.snapshot);
      } else {
        expect(after.snapshot.members.find((row) => row.id === member.id)).toHaveProperty(
          "role",
          "admin",
        );
        stable(before, after, member.id);
      }

      observations.push({ before, result: ctx.snapshot(result), after });
    }

    return observations;
  },
  ["POST /organization/update-member-role"],
);

compatScenario(
  "organization member role validation and foreign authorization reject before any callback or write",
  async (ctx) => {
    const { owner, target, foreign, org, other, member } = await setup(ctx, "role-guards");
    await configure(ctx, "reject-before-role");
    const before = await state(ctx);
    const observations = [];

    for (const [actor, orgId, role, status] of [
      [owner, org.id, "unknown-role", 400],
      [foreign, org.id, "admin", 400],
      [owner, other.id, "admin", 400],
      [target, org.id, "admin", 403],
    ] as const) {
      const result = await update(actor, orgId, member.id, role);
      expect(result.error).toMatchObject({ status });
      expect(await state(ctx)).toEqual(before);

      observations.push(ctx.snapshot(result));
    }

    return { before, observations };
  },
  ["POST /organization/update-member-role"],
);

compatScenario(
  "organization member role after callback keeps original target snapshots across independent writes",
  async (ctx) => {
    const { owner, target, org, member } = await setup(ctx, "role-snapshots");
    await configure(ctx, "mutate-target");
    const before = await state(ctx);
    const result = await update(owner, org.id, member.id);
    expect(result.error).toBeNull();

    const after = await state(ctx);
    expect(after.receipts.map((row) => row.phase)).toEqual(["before-role", "after-role"]);

    const afterReceipt = after.receipts[1]!;
    expect(afterReceipt.user).toEqual(after.receipts[0]!.user);
    expect(afterReceipt.user.name).toBe("role-snapshots-target");
    expect(afterReceipt.previousRole).toBe("member");
    expect(after.snapshot.users.find((row) => row.id === target.userId)).toHaveProperty(
      "name",
      "Stored Target Name",
    );
    expect(after.snapshot.members.find((row) => row.id === member.id)).toHaveProperty(
      "role",
      "admin",
    );
    expect(after.snapshot.organizations).toEqual(before.snapshot.organizations);
    expect(after.snapshot.sessions).toEqual(before.snapshot.sessions);
    expect(after.snapshot.users.filter((row) => row.id !== target.userId)).toEqual(
      before.snapshot.users.filter((row) => row.id !== target.userId),
    );
    expect(after.snapshot.members.filter((row) => row.id !== member.id)).toEqual(
      before.snapshot.members.filter((row) => row.id !== member.id),
    );

    // The next callback sees the values the previous hook wrote.
    await configure(ctx, "record");
    const repeat = await update(owner, org.id, member.id, "member");
    expect(repeat.error).toBeNull();

    const repeated = await state(ctx);
    expect(repeated.receipts[0]!.user.name).toBe("Stored Target Name");
    expect(repeated.receipts[0]!.member.role).toBe("admin");

    return { before, result: ctx.snapshot(result), after, repeat: ctx.snapshot(repeat), repeated };
  },
  ["POST /organization/update-member-role"],
);

compatScenario(
  "organization member role before callback deletion yields actual missing-member rejection without after callback",
  async (ctx) => {
    const { owner, org, member } = await setup(ctx, "role-delete");
    await configure(ctx, "delete-row");
    const before = await state(ctx);
    const result = await update(owner, org.id, member.id);
    expect(result.error).toMatchObject({
      status: 400,
      code: "MEMBER_NOT_FOUND",
      message: "Member not found",
    });

    const after = await state(ctx);
    expect(after.receipts.map((row) => row.phase)).toEqual(["before-role"]);
    expect(after.snapshot.members.find((row) => row.id === member.id)).toBeUndefined();

    stable(before, after, member.id);

    return { before, result: ctx.snapshot(result), after };
  },
  ["POST /organization/update-member-role"],
);

compatScenario(
  "organization member role update awaits async callback before changing the stored role",
  async (ctx) => {
    const { owner, org, member } = await setup(ctx, "role-await");
    await configure(ctx, "pause-before");
    const before = await state(ctx);

    let completed = false;
    const pending = update(owner, org.id, member.id).then((result) => {
      completed = true;
      return result;
    });

    let paused: Awaited<ReturnType<typeof state>> | undefined;
    const trace: TraceEntry[] = [];

    try {
      paused = await state(ctx, "before-role");
      expect(paused.receipts.map((row) => row.phase)).toEqual(["before-role"]);
      expect(completed).toBe(false);
      expect(paused.snapshot).toEqual(before.snapshot);
    } finally {
      const release = await createTracingFetch(
        ctx.baseURL,
        "role-hook-release",
        trace,
      )("/__test/organization-member-role-hooks-release", { method: "POST" });
      expect(release.status).toBe(200);
      expect(await release.json()).toEqual({ released: true });
    }

    const result = await pending;
    ctx.recordTransport(trace);
    expect(result.error).toBeNull();

    const after = await state(ctx);
    expect(after.receipts.map((row) => row.phase)).toEqual(["before-role", "after-role"]);
    expect(after.snapshot.members.find((row) => row.id === member.id)).toHaveProperty(
      "role",
      "admin",
    );

    stable(before, after, member.id);

    return { before, paused, result: ctx.snapshot(result), after };
  },
  ["POST /organization/update-member-role"],
);

compatScenario(
  "organization member role ECMAScript whitespace normalizes arrays and duplicates before callbacks and storage",
  async (ctx) => {
    const { owner, target, foreign, org, member } = await setup(ctx, "role-js-space");
    const actors = [owner, target, foreign];
    await configure(ctx, "record");
    const before = await fullState(ctx, actors);

    const role = ["\ufeffadmin\ufeff", "\u00a0member\u3000", " admin "];
    const result = await update(owner, org.id, member.id, role);
    expect(result.error).toBeNull();
    expect(memberSchema.parse(result.data).role).toBe("admin,member,admin");

    const after = await fullState(ctx, actors);
    expect(after.hooks.receipts.map((receipt) => receipt.phase)).toEqual([
      "before-role",
      "after-role",
    ]);
    expect(after.hooks.receipts[0]!.newRole).toBe("admin,member,admin");
    expect(after.hooks.receipts[1]!.member.role).toBe("admin,member,admin");
    expect(after.hooks.snapshot.members.find((row) => row.id === member.id)).toHaveProperty(
      "role",
      "admin,member,admin",
    );

    stable(before.hooks, after.hooks, member.id);
    expect(after.users).toEqual(before.users);

    // A role made only of ECMAScript whitespace is rejected with an empty body.
    await configure(ctx, "record");
    const beforeEmpty = await fullState(ctx, actors);
    const whitespace =
      "\u0009\u000a\u000b\u000c\u000d\u0020\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff";
    const empty = await rawRole(
      ctx,
      owner,
      JSON.stringify({ organizationId: org.id, memberId: member.id, role: whitespace }),
    );
    expect(empty).toEqual({ status: 400, empty: true, body: null });
    expect(await fullState(ctx, actors)).toEqual(beforeEmpty);

    return { before, result: ctx.snapshot(result), after, beforeEmpty, empty };
  },
  ["POST /organization/update-member-role"],
);

compatScenario(
  "organization member role preserves NEL as a non-whitespace unknown role without callbacks or writes",
  async (ctx) => {
    const { owner, target, foreign, org, member } = await setup(ctx, "role-nel");
    const actors = [owner, target, foreign];
    await configure(ctx, "record");
    const before = await fullState(ctx, actors);
    const observations = [];

    for (const role of ["\u0085", "\u0085admin\u0085"]) {
      const result = await rawRole(
        ctx,
        owner,
        JSON.stringify({ organizationId: org.id, memberId: member.id, role }),
      );
      expect(result).toEqual({
        status: 400,
        empty: false,
        body: { code: "ROLE_NOT_FOUND", message: `ROLE_NOT_FOUND: ${role}` },
      });
      expect(await fullState(ctx, actors)).toEqual(before);

      observations.push(result);
    }

    const retry = await update(owner, org.id, member.id, [" admin ", "member", "admin"]);
    expect(retry.error).toBeNull();

    const after = await fullState(ctx, actors);
    expect(after.hooks.receipts[0]!.newRole).toBe("admin,member,admin");
    expect(after.hooks.snapshot.members.find((row) => row.id === member.id)).toHaveProperty(
      "role",
      "admin,member,admin",
    );

    stable(before.hooks, after.hooks, member.id);
    expect(after.users).toEqual(before.users);

    return { before, observations, retry: ctx.snapshot(retry), after };
  },
  ["POST /organization/update-member-role"],
);

compatScenario(
  "organization member role empty input rejects before callbacks and preserves actual full owned and foreign state",
  async (ctx) => {
    const { owner, target, foreign, org, member } = await setup(ctx, "role-input-empty");
    const actors = [owner, target, foreign];
    await configure(ctx, "record");
    const before = await fullState(ctx, actors);
    const observations = [];

    for (const role of ["", " , , ", [], ["", " "]]) {
      const response = await rawRole(
        ctx,
        owner,
        JSON.stringify({ organizationId: org.id, memberId: member.id, role }),
      );
      expect(response).toEqual({ status: 400, empty: true, body: null });
      expect(await fullState(ctx, actors)).toEqual(before);

      observations.push({ role, response });
    }

    const retry = await update(owner, org.id, member.id, "admin");
    expect(retry.error).toBeNull();

    const after = await fullState(ctx, actors);
    expect(after.hooks.receipts.map((row) => row.phase)).toEqual(["before-role", "after-role"]);
    expect(after.hooks.snapshot.members.find((row) => row.id === member.id)).toHaveProperty(
      "role",
      "admin",
    );

    stable(before.hooks, after.hooks, member.id);
    expect(after.users).toEqual(before.users);

    return { before, observations, retry: ctx.snapshot(retry), after };
  },
  ["POST /organization/update-member-role"],
);

compatScenario(
  "organization member role ordered union and field validation runs before guest authentication without side effects",
  async (ctx) => {
    const { owner, target, foreign, org, member } = await setup(ctx, "role-input-schema");
    const actors = [owner, target, foreign];
    await configure(ctx, "record");
    const before = await fullState(ctx, actors);
    const guest = ctx.actor("schema-guest", "org-member-role-hooks");
    const observations = [];
    const valid = { organizationId: org.id, memberId: member.id };

    for (const [body, message] of [
      [{ ...valid, role: null }, "[body.role] Invalid input"],
      [{ ...valid, role: 1 }, "[body.role] Invalid input"],
      [{ ...valid, role: {} }, "[body.role] Invalid input"],
      [{ ...valid, role: [1] }, "[body.role] Invalid input"],
      [
        {},
        "[body.role] Invalid input; [body.memberId] Invalid input: expected string, received undefined",
      ],
      [
        { role: true, memberId: null, organizationId: null },
        "[body.role] Invalid input; [body.memberId] Invalid input: expected string, received null; [body.organizationId] Invalid input: expected string, received null",
      ],
      [
        { role: "admin", memberId: 1, organizationId: false },
        "[body.memberId] Invalid input: expected string, received number; [body.organizationId] Invalid input: expected string, received boolean",
      ],
    ] as const) {
      const response = await rawRole(ctx, guest, JSON.stringify(body));
      expect(response.status).toBe(400);
      expect(response.body).toEqual({ code: "VALIDATION_ERROR", message });
      expect(await fullState(ctx, actors)).toEqual(before);

      observations.push(response);
    }

    // Only a schema-valid body reaches the authentication check.
    const validGuest = await rawRole(
      ctx,
      guest,
      JSON.stringify({ ...valid, role: "admin", userId: owner.userId }),
    );
    expect(validGuest.status).toBe(401);
    expect(validGuest.body).toEqual({ code: "UNAUTHORIZED", message: "Unauthorized" });
    expect(await fullState(ctx, actors)).toEqual(before);

    const denied = await update(target, org.id, member.id, "admin");
    expect(denied.error).toMatchObject({ status: 403 });
    expect(await fullState(ctx, actors)).toEqual(before);

    return { before, observations, validGuest, denied: ctx.snapshot(denied) };
  },
  ["POST /organization/update-member-role"],
);

compatScenario(
  "organization member role media and malformed JSON rejection precede authentication with a valid retry",
  async (ctx) => {
    const { owner, target, foreign, org, member } = await setup(ctx, "role-input-media");
    const actors = [owner, target, foreign];
    await configure(ctx, "record");
    const before = await fullState(ctx, actors);
    const guest = ctx.actor("media-guest", "org-member-role-hooks");
    const observations = [];

    for (const [body, media, status, error] of [
      [
        "{",
        "application/json",
        400,
        { code: "BAD_REQUEST", message: "Invalid JSON in request body" },
      ],
      [
        JSON.stringify({ organizationId: org.id, memberId: member.id, role: "admin" }),
        "text/plain",
        415,
        {
          code: "UNSUPPORTED_MEDIA_TYPE",
          message: 'Content-Type "text/plain" is not allowed. Allowed types: application/json',
        },
      ],
      [
        "role=admin",
        "application/x-www-form-urlencoded",
        415,
        {
          code: "UNSUPPORTED_MEDIA_TYPE",
          message:
            'Content-Type "application/x-www-form-urlencoded" is not allowed. Allowed types: application/json',
        },
      ],
    ] as const) {
      const response = await rawRole(ctx, guest, body, media);
      expect(response.status).toBe(status);
      expect(response.body).toEqual(error);
      expect(await fullState(ctx, actors)).toEqual(before);

      observations.push(response);
    }

    const retry = await rawRole(
      ctx,
      owner,
      JSON.stringify({ organizationId: org.id, memberId: member.id, role: "admin" }),
      "APPLICATION/JSON; charset=utf-8",
    );
    expect(retry.status).toBe(200);
    expect(retry.body).toHaveProperty("role", "admin");

    const after = await fullState(ctx, actors);
    expect(after.hooks.receipts.map((row) => row.phase)).toEqual(["before-role", "after-role"]);

    stable(before.hooks, after.hooks, member.id);
    expect(after.users).toEqual(before.users);

    return { before, observations, retry, after };
  },
  ["POST /organization/update-member-role"],
);

compatScenario(
  "organization member role selectors retain source empty-role precedence and literal whitespace IDs",
  async (ctx) => {
    const { owner, target, foreign, org, member, sibling } = await setup(
      ctx,
      "role-input-selector",
    );
    const actors = [owner, target, foreign];
    await configure(ctx, "record");
    const before = await fullState(ctx, actors);
    const observations = [];

    for (const [actor, organizationId, role, status, body] of [
      [sibling, undefined, "", 400, null],
      [
        sibling,
        undefined,
        [],
        400,
        { code: "NO_ACTIVE_ORGANIZATION", message: "No active organization" },
      ],
      [
        sibling,
        "",
        "admin",
        400,
        { code: "NO_ACTIVE_ORGANIZATION", message: "No active organization" },
      ],
      [owner, " ", "admin", 400, { code: "MEMBER_NOT_FOUND", message: "Member not found" }],
      [
        owner,
        ` ${org.id} `,
        "admin",
        400,
        { code: "MEMBER_NOT_FOUND", message: "Member not found" },
      ],
    ] as const) {
      const response = await rawRole(
        ctx,
        actor,
        JSON.stringify({ memberId: member.id, organizationId, role }),
      );
      expect(response.status).toBe(status);
      expect(response.body).toEqual(body);

      if (body === null) {
        expect(response.empty).toBe(true);
      }

      expect(await fullState(ctx, actors)).toEqual(before);

      observations.push(response);
    }

    // An empty organization ID falls back to the owner's active organization.
    const retry = await rawRole(
      ctx,
      owner,
      JSON.stringify({ memberId: member.id, organizationId: "", role: "admin" }),
    );
    expect(retry.status).toBe(200);
    expect(retry.body).toHaveProperty("organizationId", org.id);

    const after = await fullState(ctx, actors);
    expect(after.hooks.receipts.map((row) => row.phase)).toEqual(["before-role", "after-role"]);

    stable(before.hooks, after.hooks, member.id);
    expect(after.users).toEqual(before.users);

    return { before, observations, retry, after };
  },
  ["POST /organization/update-member-role"],
);
