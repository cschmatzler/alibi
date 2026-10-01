import { z } from "zod";
import type { ScenarioContext } from "../scenario";
import type { FixtureProfile } from "../profiles";
import { upstreamPin } from "./common";

const actor = z.number().int().min(0).max(3);
const user = z.number().int().min(0).max(1);
const handle = z.string().regex(/^[a-z][a-z0-9-]{0,40}$/);
export const actionSchema = z.discriminatedUnion("kind", [
  z
    .object({ kind: z.literal("signup"), actor, user, session: handle })
    .strict(),
  z
    .object({
      kind: z.literal("signin"),
      actor,
      user,
      session: handle,
      credential: z.enum(["current", "previous", "wrong"]),
    })
    .strict(),
  z
    .object({
      kind: z.enum([
        "session",
        "list",
        "signout",
        "revoke-all",
        "revoke-others",
        "delete",
        "update",
      ]),
      actor,
    })
    .strict(),
  z
    .object({
      kind: z.literal("change-password"),
      actor,
      revoke: z.boolean(),
      session: handle,
    })
    .strict(),
  z.object({ kind: z.literal("revoke"), actor, session: handle }).strict(),
  z.object({ kind: z.literal("expire"), session: handle }).strict(),
  z.object({ kind: z.literal("replay"), session: handle }).strict(),
  z.object({ kind: z.literal("reset"), user }).strict(),
  z.object({ kind: z.literal("reset-replay"), user }).strict(),
]);
export const generatedCaseSchema = z
  .object({
    schemaVersion: z.literal(1),
    generatorVersion: z.literal(1),
    upstreamVersion: z.literal(upstreamPin.version),
    seed: z.number().int().min(0).max(0xffffffff),
    profile: z.enum(["default", "session-no-refresh", "session-deferred"]),
    actions: z.array(actionSchema).min(1).max(300),
  })
  .strict();
export type GeneratedCase = z.infer<typeof generatedCaseSchema>;
export type Action = z.infer<typeof actionSchema>;

export class ModelViolation extends Error {
  constructor(
    readonly invariant: string,
    action = "unknown",
  ) {
    super(
      `Generated compatibility invariant failed: ${invariant}; action=${action}`,
    );
    this.name = "ModelViolation";
  }
}
export class InvalidSequence extends Error {
  constructor() {
    super(
      "Generated sequence refers to a prerequisite removed during reduction",
    );
    this.name = "InvalidSequence";
  }
}

/** Generate a complete symbolic log before contacting either implementation. */
export function generateCase(
  seed: number,
  steps = 12,
  profile: GeneratedCase["profile"] = "default",
): GeneratedCase {
  if (
    !Number.isInteger(seed) ||
    seed < 0 ||
    seed > 0xffffffff ||
    !Number.isInteger(steps) ||
    steps < 0 ||
    steps > 200
  )
    throw new Error("Seed must be uint32 and generated steps must be 0..200");
  let random = seed || 0x9e3779b9;
  const next = (limit: number) => {
    random ^= random << 13;
    random ^= random >>> 17;
    random ^= random << 5;
    return (random >>> 0) % limit;
  };
  const actions: Action[] = [
    { kind: "signup", actor: 0, user: 0, session: "s0" },
    { kind: "signup", actor: 1, user: 1, session: "s1" },
    { kind: "signin", actor: 2, user: 0, session: "s2", credential: "current" },
    { kind: "revoke", actor: 1, session: "s2" },
    { kind: "replay", session: "s2" },
    { kind: "change-password", actor: 0, revoke: false, session: "unused" },
    {
      kind: "signin",
      actor: 3,
      user: 0,
      session: "old",
      credential: "previous",
    },
    { kind: "signin", actor: 3, user: 0, session: "s3", credential: "current" },
    { kind: "revoke", actor: 0, session: "s2" },
    { kind: "replay", session: "s2" },
    { kind: "reset", user: 0 },
    { kind: "reset-replay", user: 0 },
    { kind: "signin", actor: 2, user: 0, session: "s4", credential: "current" },
    { kind: "expire", session: "s4" },
    { kind: "replay", session: "s4" },
    { kind: "revoke-others", actor: 0 },
    { kind: "signout", actor: 0 },
    { kind: "signin", actor: 0, user: 0, session: "s5", credential: "current" },
  ];
  const kinds = [
    "session",
    "list",
    "update",
    "signin",
    "signout",
    "revoke",
    "revoke-all",
    "revoke-others",
    "change-password",
    "expire",
    "replay",
    "reset",
  ] as const;
  for (let index = 0; index < steps; index++) {
    const kind = kinds[next(kinds.length)]!,
      actor = next(4),
      user = next(2),
      session = `s${next(6)}`;
    if (kind === "signin")
      actions.push({
        kind,
        actor,
        user,
        session: `random-${index}`,
        credential: ["current", "previous", "wrong"][next(3)] as
          | "current"
          | "previous"
          | "wrong",
      });
    else if (kind === "change-password")
      actions.push({
        kind,
        actor,
        revoke: next(2) === 0,
        session: `rotated-${index}`,
      });
    else if (kind === "revoke") actions.push({ kind, actor, session });
    else if (kind === "expire" || kind === "replay")
      actions.push({ kind, session });
    else if (kind === "reset") actions.push({ kind, user });
    else actions.push({ kind, actor });
  }
  actions.push(
    {
      kind: "signin",
      actor: 0,
      user: 0,
      session: "last",
      credential: "current",
    },
    { kind: "delete", actor: 0 },
    {
      kind: "signin",
      actor: 0,
      user: 0,
      session: "deleted",
      credential: "current",
    },
  );
  return generatedCaseSchema.parse({
    schemaVersion: 1,
    generatorVersion: 1,
    upstreamVersion: upstreamPin.version,
    seed,
    profile,
    actions,
  });
}

type User = {
  id: string;
  email: string;
  exists: boolean;
  password: string;
  previous: string;
  resetToken?: string;
};
type Session = {
  token: string;
  cookie: string;
  user: number;
  present: boolean;
  expired: boolean;
};
const issuedSchema = z
  .object({
    token: z.string().min(1),
    user: z.object({ id: z.string().min(1) }).passthrough(),
  })
  .passthrough();
const persistedSchema = z
  .object({
    user: z.object({ id: z.string() }).passthrough().nullable(),
    accounts: z.array(
      z.object({ userId: z.string(), providerId: z.string() }).passthrough(),
    ),
    sessions: z.array(
      z.object({ token: z.string(), userId: z.string() }).passthrough(),
    ),
  })
  .passthrough();

/** An independent state model guards effects even when both fixtures return the same response. */
export async function executeGenerated(
  ctx: ScenarioContext,
  generated: GeneratedCase,
) {
  const users = new Map<number, User>(),
    sessions = new Map<string, Session>(),
    bindings = new Map<number, string>();
  const profile: FixtureProfile | undefined =
    generated.profile === "default" ? undefined : generated.profile;
  const snapshots: unknown[] = [];
  let passwordVersion = 0;
  let currentAction: Action | undefined;
  function requireInvariant(value: unknown, name: string): asserts value {
    if (!value) throw new ModelViolation(name, JSON.stringify(currentAction));
  }
  const nextPassword = () =>
    `Assurance-password-${generated.seed}-${++passwordVersion}!`;
  const knownUser = (id: number) => {
    const user = users.get(id);
    if (!user) throw new InvalidSequence();
    return user;
  };
  const knownSession = (handle: string) => {
    const session = sessions.get(handle);
    if (!session) throw new InvalidSequence();
    return session;
  };
  const live = (session: Session | undefined) =>
    !!session &&
    session.present &&
    !session.expired &&
    knownUser(session.user).exists;
  const principal = (actor: number) => {
    const binding = bindings.get(actor);
    const session = binding ? sessions.get(binding) : undefined;
    return live(session) ? session : undefined;
  };
  async function request(
    actor: number,
    path: string,
    body?: unknown,
    cookie?: string,
  ) {
    const headers = new Headers();
    if (body !== undefined) headers.set("content-type", "application/json");
    if (cookie) headers.set("cookie", cookie);
    const response = await ctx
      .actor(`generated-${actor}`, profile)
      .fetch(`/api/auth${path}`, {
        method: body === undefined ? "GET" : "POST",
        headers,
        ...(cookie ? { credentials: "omit" as const } : {}),
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        redirect: "manual",
      });
    if (
      !cookie &&
      response.headers
        .getSetCookie()
        .some(
          (value) =>
            value.startsWith("better-auth.session_token=") &&
            /;\s*max-age=0(?:;|$)/i.test(value),
        )
    )
      bindings.delete(actor);
    const text = await response.text();
    let value: unknown = null;
    try {
      value = text ? JSON.parse(text) : null;
    } catch {
      value = text;
    }
    return {
      status: response.status,
      body: value,
      cookie: response.headers
        .getSetCookie()
        .find((value) => value.startsWith("better-auth.session_token="))
        ?.split(";")[0],
    };
  }
  function saveSession(
    handle: string,
    actor: number,
    user: number,
    response: Awaited<ReturnType<typeof request>>,
  ) {
    const issued = issuedSchema.parse(response.body);
    requireInvariant(response.cookie, "issued-signed-cookie");
    requireInvariant(issued.user.id === knownUser(user).id, "session-owner");
    if (sessions.has(handle)) throw new InvalidSequence();
    sessions.set(handle, {
      token: issued.token,
      cookie: response.cookie,
      user,
      present: true,
      expired: false,
    });
    bindings.set(actor, handle);
  }
  async function inspect() {
    const result: unknown[] = [];
    for (const [id, user] of users) {
      const state = persistedSchema.parse(
        await ctx.readUserState({ userId: user.id }),
      );
      requireInvariant(
        (state.user !== null) === user.exists,
        "persisted-user-existence",
      );
      requireInvariant(
        state.accounts.length === (user.exists ? 1 : 0),
        "persisted-credential-existence",
      );
      requireInvariant(
        state.accounts.every(
          (account) =>
            account.userId === user.id && account.providerId === "credential",
        ),
        "persisted-credential-owner",
      );
      const expected = [...sessions.values()]
        .filter((session) => session.user === id && session.present)
        .map((session) => session.token)
        .sort();
      requireInvariant(
        JSON.stringify(
          state.sessions.map((session) => session.token).sort(),
        ) === JSON.stringify(expected),
        "persisted-session-membership",
      );
      requireInvariant(
        state.sessions.every((session) => session.userId === user.id),
        "persisted-session-owner",
      );
      result.push(state);
    }
    return result;
  }
  async function replay(handle: string) {
    const session = knownSession(handle),
      valid = live(session);
    const response = await request(
      3,
      "/get-session?disableRefresh=true",
      undefined,
      session.cookie,
    );
    requireInvariant(response.status === 200, "saved-cookie-read-status");
    if (valid) {
      const value = z
        .object({
          user: z.object({ id: z.string() }),
          session: z.object({ token: z.string() }),
        })
        .parse(response.body);
      requireInvariant(
        value.user.id === knownUser(session.user).id &&
          value.session.token === session.token,
        "saved-cookie-owner",
      );
    } else
      requireInvariant(
        response.body === null,
        "revoked-or-expired-cookie-rejected",
      );
    // Deferred GET reads reject expiry but reserve physical cleanup for POST.
    if (session.expired && generated.profile !== "session-deferred")
      session.present = false;
    return { status: response.status, body: response.body };
  }
  for (const [index, action] of generated.actions.entries()) {
    currentAction = action;
    let observation: unknown;
    if (action.kind === "signup") {
      if (users.has(action.user)) throw new InvalidSequence();
      const email = ctx.uniqueEmail(
          `generated-${generated.seed}-${action.user}`,
        ),
        password = nextPassword();
      const response = await request(action.actor, "/sign-up/email", {
        email,
        password,
        name: `Generated ${action.user}`,
      });
      requireInvariant(response.status === 200, "signup-success");
      const issued = issuedSchema.parse(response.body);
      users.set(action.user, {
        id: issued.user.id,
        email,
        exists: true,
        password,
        previous: "Never-correct-password!",
      });
      saveSession(action.session, action.actor, action.user, response);
      observation = response.body;
    } else if (action.kind === "signin") {
      const user = knownUser(action.user),
        password =
          action.credential === "current"
            ? user.password
            : action.credential === "previous"
              ? user.previous
              : "Never-correct-password!";
      const response = await request(action.actor, "/sign-in/email", {
        email: user.email,
        password,
      });
      const successful = user.exists && action.credential === "current";
      requireInvariant(
        response.status === (successful ? 200 : 401),
        "credential-persistence",
      );
      if (successful)
        saveSession(action.session, action.actor, action.user, response);
      observation = response.body;
    } else if (action.kind === "expire") {
      const session = knownSession(action.session);
      const expired = await ctx.rawRequest({
        path: "/__test/expire-session",
        method: "POST",
        json: {
          token: session.token,
          expiresAt: new Date(Date.now() - 10_000).toISOString(),
        },
      });
      requireInvariant(expired.status === 200, "expiry-control");
      if (session.present) session.expired = true;
      observation = expired;
    } else if (action.kind === "replay")
      observation = await replay(action.session);
    else if (action.kind === "reset" || action.kind === "reset-replay") {
      const user = knownUser(action.user);
      if (action.kind === "reset") {
        if (!user.exists) throw new InvalidSequence();
        const issue = await request(3, "/request-password-reset", {
          email: user.email,
          redirectTo: "/reset",
        });
        requireInvariant(issue.status === 200, "reset-request-success");
        const delivery = await ctx.rawRequest({
          path: `/__test/reset-password-token?email=${encodeURIComponent(user.email)}`,
        });
        requireInvariant(delivery.status === 200, "reset-delivery");
        user.resetToken = z
          .object({ token: z.string().min(1) })
          .parse(delivery.body).token;
      }
      if (!user.resetToken) throw new InvalidSequence();
      const password = nextPassword(),
        response = await request(3, "/reset-password", {
          token: user.resetToken,
          newPassword: password,
        });
      requireInvariant(
        action.kind === "reset"
          ? response.status === 200
          : response.status >= 400 && response.status < 500,
        "reset-single-use",
      );
      if (action.kind === "reset") {
        user.previous = user.password;
        user.password = password;
      }
      observation = response.body;
    } else {
      const session = principal(action.actor),
        owner = session ? knownUser(session.user) : undefined;
      if (action.kind === "session") {
        const response = await request(
          action.actor,
          "/get-session?disableRefresh=true",
        );
        requireInvariant(response.status === 200, "session-read-status");
        if (owner)
          requireInvariant(
            z
              .object({ user: z.object({ id: z.string() }) })
              .parse(response.body).user.id === owner.id,
            "actor-session-owner",
          );
        else
          requireInvariant(response.body === null, "actor-session-revocation");
        observation = response.body;
      } else if (action.kind === "signout") {
        const binding = bindings.get(action.actor);
        const response = await request(action.actor, "/sign-out", {});
        requireInvariant(response.status === 200, "signout-success");
        if (binding) knownSession(binding).present = false;
        bindings.delete(action.actor);
        observation = response.body;
      } else {
        const target =
          action.kind === "revoke" ? knownSession(action.session) : undefined;
        const password =
          action.kind === "change-password" ? nextPassword() : undefined;
        const endpoint = {
          list: "/list-sessions",
          update: "/update-user",
          delete: "/delete-user",
          revoke: "/revoke-session",
          "revoke-all": "/revoke-sessions",
          "revoke-others": "/revoke-other-sessions",
          "change-password": "/change-password",
        }[action.kind];
        const body =
          action.kind === "list"
            ? undefined
            : action.kind === "update"
              ? { name: `Generated ${generated.seed} step ${index}` }
              : action.kind === "revoke"
                ? { token: target!.token }
                : action.kind === "change-password"
                  ? {
                      currentPassword: owner?.password ?? "Unknown-password!",
                      newPassword: password,
                      revokeOtherSessions: action.revoke,
                    }
                  : {};
        const response = await request(action.actor, endpoint, body);
        requireInvariant(
          response.status === (owner ? 200 : 401),
          `authenticated-${action.kind}`,
        );
        if (owner && session) {
          if (action.kind === "revoke" && target?.user === session.user)
            target.present = false;
          if (
            action.kind === "revoke-all" ||
            action.kind === "delete" ||
            (action.kind === "change-password" && action.revoke)
          )
            for (const value of sessions.values())
              if (value.user === session.user) value.present = false;
          if (action.kind === "revoke-others")
            for (const value of sessions.values())
              if (
                value.user === session.user &&
                value !== session &&
                !value.expired
              )
                value.present = false;
          if (action.kind === "delete") owner.exists = false;
          if (action.kind === "change-password") {
            owner.previous = owner.password;
            owner.password = password!;
            if (action.revoke)
              saveSession(action.session, action.actor, session.user, response);
          }
          if (action.kind === "list") {
            const listed = z
              .array(z.object({ token: z.string() }))
              .parse(response.body);
            const expected = [...sessions.values()]
              .filter((value) => value.user === session.user && live(value))
              .map((value) => value.token)
              .sort();
            requireInvariant(
              JSON.stringify(listed.map((value) => value.token).sort()) ===
                JSON.stringify(expected),
              "listed-session-membership",
            );
          }
        }
        observation = response.body;
      }
    }
    const beforeProbes = await inspect();
    const probes = [];
    for (const handle of sessions.keys()) probes.push(await replay(handle));
    snapshots.push({
      action,
      observation,
      beforeProbes,
      probes,
      afterProbes: await inspect(),
    });
  }
  return { seed: generated.seed, profile: generated.profile, snapshots };
}

/** Delta debugging accepts only the same failure; invalid prerequisites never count. */
export async function reduceActions(
  actions: Action[],
  reproduces: (candidate: Action[]) => Promise<boolean>,
  budget = 100,
) {
  let current = actions.slice(),
    partitions = 2,
    attempts = 0;
  while (current.length > 1 && attempts < budget) {
    const width = Math.ceil(current.length / partitions);
    let reduced = false;
    for (
      let start = 0;
      start < current.length && attempts < budget;
      start += width
    ) {
      const candidate = [
        ...current.slice(0, start),
        ...current.slice(start + width),
      ];
      if (!candidate.length) continue;
      attempts++;
      if (await reproduces(candidate)) {
        current = candidate;
        partitions = Math.max(2, partitions - 1);
        reduced = true;
        break;
      }
    }
    if (!reduced) {
      if (partitions >= current.length) break;
      partitions = Math.min(current.length, partitions * 2);
    }
  }
  return { actions: current, attempts, exhausted: attempts >= budget };
}
