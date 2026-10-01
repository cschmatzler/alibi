import { expect } from "bun:test";
import { verifyPassword } from "better-auth/crypto";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import type { FixtureProfile } from "../../support/profiles";
type Row = Record<string, unknown>;
type Store = { users: Row[]; accounts: Row[]; sessions: Row[]; events: Row[] };
async function read(ctx: ScenarioContext) {
  const r = await ctx.rawRequest({ path: "/__test/set-password/state" });
  expect(r.status).toBe(200);
  return r.body as Store;
}
function hashEvidence(value: unknown) {
  if (typeof value !== "string") return value;
  const [salt, key] = value.split(":");
  expect(value).toMatch(/^[a-f0-9]{32}:[a-f0-9]{128}$/);
  return {
    token: value,
    salt: { token: salt, length: salt!.length },
    derivedKey: { token: key, length: key!.length },
    encoding: "hex-lower",
  };
}
function observed(s: Store) {
  return {
    ...s,
    accounts: s.accounts.map((r) => ({
      ...r,
      password: hashEvidence(r.password),
    })),
    events: s.events.map((e) => ({
      ...e,
      ...(typeof e.hash === "string" ? { hash: hashEvidence(e.hash) } : {}),
    })),
  };
}
async function call(
  ctx: ScenarioContext,
  actor: string,
  profile: FixtureProfile,
  json: Row,
  headers: Record<string, string> = {},
) {
  const response = await ctx
    .actor(actor, profile)
    .fetch(
      ctx.baseURL +
        (json.operation === "set"
          ? "/__test/server-api/set-password"
          : "/__test/set-password"),
      {
        method: "POST",
        headers: { "content-type": "application/json", ...headers },
        body: JSON.stringify({ profile, ...json }),
      },
    );
  const text = await response.text();
  let body: unknown = text;
  try {
    body = JSON.parse(text);
  } catch {}
  return {
    status: response.status,
    location: response.headers.get("location"),
    body,
  };
}
async function setup(
  ctx: ScenarioContext,
  profile: FixtureProfile = "set-password-default",
  keepCredential = false,
) {
  const owner = ctx.actor("owner", profile),
    foreign = ctx.actor("foreign", profile);
  const reset = await call(ctx, "owner", profile, {
    operation: "mode",
    mode: "normal",
  });
  expect(reset.status).toBe(200);
  const signup = await owner.client.signUp.email({
    email: ctx.uniqueEmail("owner"),
    password: "initial-password123",
    name: "Passwordless Owner",
  });
  expect(signup.error).toBeNull();
  const other = await foreign.client.signUp.email({
    email: ctx.uniqueEmail("foreign"),
    password: "foreign-password123",
    name: "Foreign Principal",
  });
  expect(other.error).toBeNull();
  let removed: unknown;
  if (!keepCredential)
    removed = await ctx.removeCredentialAccount({
      email: ctx.uniqueEmail("owner"),
    });
  const configured = await call(ctx, "owner", profile, {
    operation: "mode",
    mode: "normal",
  });
  expect(configured.status).toBe(200);
  return {
    reset,
    owner,
    foreign,
    signup,
    other,
    removed,
    configured,
    before: await read(ctx),
    foreignBefore: await ctx.readUserState({ userId: other.data!.user.id }),
  };
}
compatScenario(
  "server-only setPassword creates a genuine credential for only its physical passwordless owner",
  async (ctx) => {
    const p = "set-password-default",
      s = await setup(ctx, p),
      password = "Ａuth-é-🔒123";
    expect(
      s.before.accounts.filter((a) => a.userId === s.signup.data!.user.id),
    ).toHaveLength(0);
    const set = await call(ctx, "owner", p, {
      operation: "set",
      newPassword: password,
      userId: s.other.data!.user.id,
    });
    expect(set).toMatchObject({ status: 200, body: { status: true } });
    const after = await read(ctx),
      credential = after.accounts.find(
        (a) =>
          a.userId === s.signup.data!.user.id && a.providerId === "credential",
      )!;
    expect(credential).toMatchObject({
      accountId: s.signup.data!.user.id,
      providerId: "credential",
      userId: s.signup.data!.user.id,
    });
    expect(
      await verifyPassword({ hash: String(credential.password), password }),
    ).toBe(true);
    expect(after.accounts).toHaveLength(s.before.accounts.length + 1);
    expect(after.users).toEqual(s.before.users);
    expect(after.sessions).toEqual(s.before.sessions);
    const replay = await call(ctx, "owner", p, {
      operation: "set",
      newPassword: "replacement-password123",
    });
    expect(replay).toMatchObject({
      status: 400,
      body: {
        code: "PASSWORD_ALREADY_SET",
        message: "User already has a password set",
      },
    });
    const replayed = await read(ctx);
    expect(replayed.accounts).toEqual(after.accounts);
    expect(
      replayed.events.filter((e) => e.stage === "hash-enter"),
    ).toHaveLength(2);
    const original = await s.owner.client.getSession();
    expect(original.data?.user.id).toBe(s.signup.data!.user.id);
    const signin = await ctx.actor("credential-login", p).client.signIn.email({
      email: ctx.uniqueEmail("owner"),
      password: "Auth-e\u0301-🔒123",
    });
    expect(signin.error).toBeNull();
    expect(signin.data?.user.id).toBe(s.signup.data!.user.id);
    const old = await ctx.actor("old", p).client.signIn.email({
      email: ctx.uniqueEmail("owner"),
      password: "initial-password123",
    });
    expect(old.error?.status).toBe(401);
    const wrong = await ctx
      .actor("wrong-owner", p)
      .client.signIn.email({ email: ctx.uniqueEmail("foreign"), password });
    expect(wrong.error?.status).toBe(401);
    expect(await ctx.readUserState({ userId: s.other.data!.user.id })).toEqual(
      s.foreignBefore,
    );
    const response = await s.owner.fetch("/api/auth/set-password", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ newPassword: "public-password123" }),
    });
    expect(response.status).toBe(404);
    return {
      signup: ctx.snapshot(s.signup),
      other: ctx.snapshot(s.other),
      removed: s.removed,
      configured: s.configured,
      before: observed(s.before),
      set,
      after: observed(after),
      replay,
      replayed: observed(replayed),
      original: ctx.snapshot(original),
      signin: ctx.snapshot(signin),
      old: ctx.snapshot(old),
      wrong: ctx.snapshot(wrong),
      final: observed(await read(ctx)),
      foreignBefore: s.foreignBefore,
      foreignAfter: await ctx.readUserState({ userId: s.other.data!.user.id }),
      publicRoute: { status: response.status, body: await response.text() },
    };
  },
  ["POST /sign-in/email", "GET /get-session"],
);
compatScenario(
  "server-only setPassword fills a null credential and preserves authoritative sessions",
  async (ctx) => {
    const p = "set-password-default",
      s = await setup(ctx, p, true),
      account = s.before.accounts.find(
        (a) => a.userId === s.signup.data!.user.id,
      )!;
    const cleared = await call(ctx, "owner", p, {
      operation: "clear-password",
      accountId: account.id,
    });
    expect(cleared.status).toBe(200);
    const before = await read(ctx);
    expect(
      before.accounts.find((a) => a.id === account.id)?.password,
    ).toBeNull();
    const result = await call(ctx, "owner", p, {
      operation: "set",
      newPassword: "actual-new-password123",
    });
    expect(result).toMatchObject({ status: 200, body: { status: true } });
    const after = await read(ctx),
      updated = after.accounts.find((a) => a.id === account.id)!;
    expect(updated).toMatchObject({
      id: account.id,
      createdAt: account.createdAt,
      userId: account.userId,
      accountId: account.accountId,
    });
    expect(
      await verifyPassword({
        hash: String(updated.password),
        password: "actual-new-password123",
      }),
    ).toBe(true);
    expect(after.accounts).toHaveLength(before.accounts.length);
    expect(after.users).toEqual(before.users);
    expect(after.sessions).toEqual(before.sessions);
    return {
      signup: ctx.snapshot(s.signup),
      other: ctx.snapshot(s.other),
      before: observed(before),
      cleared,
      result,
      after: observed(after),
      foreignBefore: s.foreignBefore,
      foreignAfter: await ctx.readUserState({ userId: s.other.data!.user.id }),
    };
  },
);
compatScenario(
  "server-only setPassword enforces initialized UTF16 bounds before hashing or ownership writes",
  async (ctx) => {
    const p = "set-password-policy",
      s = await setup(ctx, p),
      outcomes = [];
    for (const password of ["123456789", "🙂🙂🙂🙂x", "x".repeat(21)]) {
      const result = await call(ctx, "owner", p, {
        operation: "set",
        newPassword: password,
      });
      expect(result).toMatchObject({
        status: 400,
        body: {
          code:
            password.length < 10 ? "PASSWORD_TOO_SHORT" : "PASSWORD_TOO_LONG",
          message:
            password.length < 10 ? "Password too short" : "Password too long",
        },
      });
      const after = await read(ctx);
      expect(after).toEqual(s.before);
      outcomes.push({ password, result, after: observed(after) });
    }
    const password = "🙂".repeat(5),
      accepted = await call(ctx, "owner", p, {
        operation: "set",
        newPassword: password,
      });
    expect(accepted.status).toBe(200);
    const after = await read(ctx),
      credential = after.accounts.find(
        (a) => a.userId === s.signup.data!.user.id,
      )!;
    expect(
      await verifyPassword({ hash: String(credential.password), password }),
    ).toBe(true);
    return {
      signup: ctx.snapshot(s.signup),
      other: ctx.snapshot(s.other),
      before: observed(s.before),
      outcomes,
      password,
      accepted,
      after: observed(after),
      foreignBefore: s.foreignBefore,
      foreignAfter: await ctx.readUserState({ userId: s.other.data!.user.id }),
    };
  },
);
compatScenario(
  "server-only setPassword rejects guests and authoritative revoked cached sessions without hashing",
  async (ctx) => {
    const p = "set-password-cache",
      s = await setup(ctx, p),
      cached = await s.owner.client.getSession();
    expect(cached.data?.user.id).toBe(s.signup.data!.user.id);
    const guest = await call(ctx, "guest", p, {
      operation: "set",
      newPassword: "guest-password123",
      userId: s.signup.data!.user.id,
    });
    expect(guest).toMatchObject({
      status: 401,
      body: { code: "UNAUTHORIZED", message: "Unauthorized" },
    });
    expect(await read(ctx)).toEqual(s.before);
    const revoked = await call(ctx, "owner", p, {
      operation: "revoke",
      token: cached.data!.session.token,
    });
    expect(revoked.status).toBe(200);
    const before = await read(ctx);
    const stillCached = await s.owner.client.getSession();
    expect(stillCached.data?.user.id).toBe(s.signup.data!.user.id);
    const denied = await call(ctx, "owner", p, {
      operation: "set",
      newPassword: "revoked-password123",
    });
    expect(denied).toMatchObject({
      status: 401,
      body: { code: "UNAUTHORIZED", message: "Unauthorized" },
    });
    expect(await read(ctx)).toEqual(before);
    return {
      signup: ctx.snapshot(s.signup),
      other: ctx.snapshot(s.other),
      before: observed(s.before),
      cached: ctx.snapshot(cached),
      guest,
      revoked,
      revokedState: observed(before),
      stillCached: ctx.snapshot(stillCached),
      denied,
      after: observed(await read(ctx)),
      foreignBefore: s.foreignBefore,
      foreignAfter: await ctx.readUserState({ userId: s.other.data!.user.id }),
    };
  },
);
for (const mode of ["hash-error", "create-error", "update-error"] as const)
  compatScenario(
    `server-only setPassword actual ${mode} preserves principals and can retry`,
    async (ctx) => {
      const p = "set-password-default",
        s = await setup(ctx, p, mode === "update-error");
      if (mode === "update-error") {
        const account = s.before.accounts.find(
          (a) => a.userId === s.signup.data!.user.id,
        )!;
        const cleared = await call(ctx, "owner", p, {
          operation: "clear-password",
          accountId: account.id,
        });
        expect(cleared.status).toBe(200);
      }
      const configured = await call(ctx, "owner", p, {
        operation: "mode",
        mode,
      });
      expect(configured.status).toBe(200);
      const before = await read(ctx),
        password = "actual-failure-password123";
      const failed = await call(ctx, "owner", p, {
        operation: "set",
        newPassword: password,
      });
      expect(failed.status).toBe(500);
      const after = await read(ctx);
      expect(after.users).toEqual(before.users);
      expect(after.accounts).toEqual(before.accounts);
      expect(after.sessions).toEqual(before.sessions);
      expect(after.events.filter((e) => e.stage === "hash-enter")).toHaveLength(
        1,
      );
      const restored = await call(ctx, "owner", p, {
        operation: "mode",
        mode: "normal",
      });
      expect(restored.status).toBe(200);
      const retried = await call(ctx, "owner", p, {
        operation: "set",
        newPassword: password,
      });
      expect(retried.status).toBe(200);
      const persisted = await read(ctx);
      expect(
        await verifyPassword({
          hash: String(
            persisted.accounts.find((a) => a.userId === s.signup.data!.user.id)!
              .password,
          ),
          password,
        }),
      ).toBe(true);
      return {
        signup: ctx.snapshot(s.signup),
        other: ctx.snapshot(s.other),
        configured,
        before: observed(before),
        failed,
        after: observed(after),
        restored,
        retried,
        persisted: observed(persisted),
        foreignBefore: s.foreignBefore,
        foreignAfter: await ctx.readUserState({
          userId: s.other.data!.user.id,
        }),
      };
    },
  );
for (const admission of [
  "null-credential updates",
  "missing-credential creates",
] as const)
  compatScenario(
    `server-only setPassword simultaneous ${admission} retain Source outcomes and original authority`,
    async (ctx) => {
      const p = "set-password-default",
        s = await setup(ctx, p, admission === "null-credential updates"),
        account = s.before.accounts.find(
          (a) => a.userId === s.signup.data!.user.id,
        )!;
      if (admission === "null-credential updates")
        expect(
          (
            await call(ctx, "owner", p, {
              operation: "clear-password",
              accountId: account.id,
            })
          ).status,
        ).toBe(200);
      expect(
        (
          await call(ctx, "owner", p, {
            operation: "mode",
            mode: "barrier",
            userId: s.signup.data!.user.id,
          })
        ).status,
      ).toBe(200);
      const before = await read(ctx),
        password = "same-concurrent-password123";
      const [left, right] = await Promise.all([
        call(ctx, "owner", p, { operation: "set", newPassword: password }),
        call(ctx, "owner", p, { operation: "set", newPassword: password }),
      ]);
      expect(left.status).toBe(200);
      expect(right.status).toBe(200);
      const after = await read(ctx);
      expect(after.accounts).toHaveLength(
        before.accounts.length +
          (admission === "missing-credential creates" ? 2 : 0),
      );
      const owned = after.accounts.filter(
        (a) => a.userId === s.signup.data!.user.id,
      );
      expect(owned).toHaveLength(
        admission === "missing-credential creates" ? 2 : 1,
      );
      for (const row of owned) {
        expect(row).toMatchObject({
          userId: s.signup.data!.user.id,
          accountId: s.signup.data!.user.id,
          providerId: "credential",
        });
        expect(
          await verifyPassword({ hash: String(row.password), password }),
        ).toBe(true);
      }
      expect(new Set(owned.map((row) => row.id)).size).toBe(owned.length);
      if (admission === "null-credential updates")
        expect(owned[0]!.id).toBe(account.id);
      else {
        const hashes = after.events.filter(
          (event) => event.stage === "hash-result",
        );
        expect(owned.map((row) => row.password)).toEqual(
          hashes.map((event) => event.hash),
        );
      }
      expect(after.users).toEqual(before.users);
      expect(after.sessions).toEqual(before.sessions);
      expect(after.events.filter((e) => e.stage === "hash-enter")).toHaveLength(
        2,
      );

      const restored = await call(ctx, "owner", p, {
        operation: "mode",
        mode: "normal",
      });
      expect(restored.status).toBe(200);
      const signin = await ctx
        .actor("after-race", p)
        .client.signIn.email({ email: ctx.uniqueEmail("owner"), password });
      expect(signin.data?.user.id).toBe(s.signup.data!.user.id);
      expect(
        await ctx.readUserState({ userId: s.other.data!.user.id }),
      ).toEqual(s.foreignBefore);
      return {
        admission,
        removed: s.removed,
        signup: ctx.snapshot(s.signup),
        other: ctx.snapshot(s.other),
        before: observed(before),
        left,
        right,
        after: observed(after),
        restored,
        signin: ctx.snapshot(signin),
        final: observed(await read(ctx)),
        foreignBefore: s.foreignBefore,
        foreignAfter: await ctx.readUserState({
          userId: s.other.data!.user.id,
        }),
      };
    },
  );
compatScenario(
  "server-only setPassword ignores an actual credential row with a foreign account identity",
  async (ctx) => {
    const p = "set-password-default",
      s = await setup(ctx, p, true),
      account = s.before.accounts.find(
        (a) => a.userId === s.signup.data!.user.id,
      )!;
    const removedForeign = await ctx.removeCredentialAccount({
        email: ctx.uniqueEmail("foreign"),
      }),
      foreignBefore = await ctx.readUserState({
        userId: s.other.data!.user.id,
      });
    const misbound = await call(ctx, "owner", p, {
      operation: "misbind-credential",
      accountId: account.id,
      userId: s.other.data!.user.id,
    });
    expect(misbound.status).toBe(200);
    const before = await read(ctx),
      foreignRow = before.accounts.find((a) => a.id === account.id)!;
    expect(foreignRow).toMatchObject({
      userId: s.signup.data!.user.id,
      accountId: s.other.data!.user.id,
      password: null,
    });
    const password = "canonical-owner-password123",
      result = await call(ctx, "owner", p, {
        operation: "set",
        newPassword: password,
      });
    expect(result.status).toBe(200);
    const after = await read(ctx),
      canonical = after.accounts.find(
        (a) =>
          a.userId === s.signup.data!.user.id &&
          a.accountId === s.signup.data!.user.id,
      )!;
    expect(after.accounts).toHaveLength(before.accounts.length + 1);
    expect(after.accounts.find((a) => a.id === account.id)).toEqual(foreignRow);
    expect(canonical).toMatchObject({
      providerId: "credential",
      userId: s.signup.data!.user.id,
      accountId: s.signup.data!.user.id,
    });
    expect(
      await verifyPassword({ hash: String(canonical.password), password }),
    ).toBe(true);
    expect(after.users).toEqual(before.users);
    expect(after.sessions).toEqual(before.sessions);
    expect(await ctx.readUserState({ userId: s.other.data!.user.id })).toEqual(
      foreignBefore,
    );
    return {
      signup: ctx.snapshot(s.signup),
      other: ctx.snapshot(s.other),
      removedForeign,
      misbound,
      before: observed(before),
      result,
      after: observed(after),
      foreignBefore,
      foreignAfter: await ctx.readUserState({ userId: s.other.data!.user.id }),
    };
  },
);

compatScenario(
  "server-only setPassword discards foreign virtual session authority before genuine physical authorization",
  async (ctx) => {
    const p = "set-password-default",
      s = await setup(ctx, p),
      foreignSession = await s.foreign.client.getSession();
    expect(foreignSession.data?.user.id).toBe(s.other.data!.user.id);
    const headers = {
        "x-test-virtual-token": foreignSession.data!.session.token,
      },
      guest = await call(
        ctx,
        "guest",
        p,
        { operation: "set", newPassword: "virtual-guest-password123" },
        headers,
      );
    expect(guest).toMatchObject({
      status: 401,
      body: { code: "UNAUTHORIZED", message: "Unauthorized" },
    });
    const denied = await read(ctx);
    expect(denied.users).toEqual(s.before.users);
    expect(denied.accounts).toEqual(s.before.accounts);
    expect(denied.sessions).toEqual(s.before.sessions);
    expect(
      denied.events.filter((e) => e.stage === "virtual-session"),
    ).toHaveLength(1);
    expect(denied.events.filter((e) => e.stage === "hash-enter")).toHaveLength(
      0,
    );
    const accepted = await call(
      ctx,
      "owner",
      p,
      { operation: "set", newPassword: "physical-owner-password123" },
      headers,
    );
    expect(accepted.status).toBe(200);
    const after = await read(ctx),
      credential = after.accounts.find(
        (a) => a.userId === s.signup.data!.user.id,
      )!;
    expect(credential.accountId).toBe(s.signup.data!.user.id);
    expect(
      await verifyPassword({
        hash: String(credential.password),
        password: "physical-owner-password123",
      }),
    ).toBe(true);
    expect(after.accounts).toHaveLength(s.before.accounts.length + 1);
    expect(after.users).toEqual(s.before.users);
    expect(after.sessions).toEqual(s.before.sessions);
    expect(await ctx.readUserState({ userId: s.other.data!.user.id })).toEqual(
      s.foreignBefore,
    );
    return {
      signup: ctx.snapshot(s.signup),
      other: ctx.snapshot(s.other),
      foreignSession: ctx.snapshot(foreignSession),
      before: observed(s.before),
      guest,
      denied: observed(denied),
      accepted,
      after: observed(after),
      foreignBefore: s.foreignBefore,
      foreignAfter: await ctx.readUserState({ userId: s.other.data!.user.id }),
    };
  },
);
compatScenario(
  "server-only setPassword rejects an expired physical session while preserving cached identity and unrelated principals",
  async (ctx) => {
    const p = "set-password-cache",
      s = await setup(ctx, p),
      cached = await s.owner.client.getSession();
    expect(cached.data?.user.id).toBe(s.signup.data!.user.id);
    const expired = await call(ctx, "owner", p, {
      operation: "expire",
      token: cached.data!.session.token,
      expiresAt: "2020-01-01T00:00:00.000Z",
    });
    expect(expired.status).toBe(200);
    const before = await read(ctx),
      stillCached = await s.owner.client.getSession();
    expect(stillCached.data?.user.id).toBe(s.signup.data!.user.id);
    const result = await call(ctx, "owner", p, {
      operation: "set",
      newPassword: "expired-password123",
    });
    expect(result).toMatchObject({
      status: 401,
      body: { code: "UNAUTHORIZED", message: "Unauthorized" },
    });
    const after = await read(ctx);
    expect(after.accounts).toEqual(before.accounts);
    expect(after.users).toEqual(before.users);
    expect(after.events).toEqual(before.events);
    expect(after.sessions).toEqual(
      before.sessions.filter((row) => row.token !== cached.data!.session.token),
    );
    expect(await ctx.readUserState({ userId: s.other.data!.user.id })).toEqual(
      s.foreignBefore,
    );
    return {
      signup: ctx.snapshot(s.signup),
      other: ctx.snapshot(s.other),
      cached: ctx.snapshot(cached),
      expired,
      before: observed(before),
      stillCached: ctx.snapshot(stillCached),
      result,
      after: observed(after),
      foreignBefore: s.foreignBefore,
      foreignAfter: await ctx.readUserState({ userId: s.other.data!.user.id }),
    };
  },
);
compatScenario(
  "server-only setPassword invokes the configured hash before an existing-password denial",
  async (ctx) => {
    const p = "set-password-default",
      s = await setup(ctx, p, true),
      mode = await call(ctx, "owner", p, {
        operation: "mode",
        mode: "hash-error",
      });
    expect(mode.status).toBe(200);
    const before = await read(ctx),
      failed = await call(ctx, "owner", p, {
        operation: "set",
        newPassword: "callback-before-denial123",
      });
    expect(failed.status).toBe(500);
    const after = await read(ctx);
    expect(after.accounts).toEqual(before.accounts);
    expect(after.users).toEqual(before.users);
    expect(after.sessions).toEqual(before.sessions);
    expect(after.events.filter((e) => e.stage === "hash-result")).toHaveLength(
      1,
    );
    return {
      signup: ctx.snapshot(s.signup),
      other: ctx.snapshot(s.other),
      mode,
      before: observed(before),
      failed,
      after: observed(after),
      foreignBefore: s.foreignBefore,
      foreignAfter: await ctx.readUserState({ userId: s.other.data!.user.id }),
    };
  },
);
