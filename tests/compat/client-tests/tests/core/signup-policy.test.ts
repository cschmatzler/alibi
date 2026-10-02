import { expect } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { verifyPassword } from "better-auth/crypto";
import type { FixtureProfile } from "../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { createTracingFetch, type TraceEntry } from "../../support/trace";

type Row = Record<string, unknown>;
type State = {
  users: Row[];
  accounts: Row[];
  sessions: Row[];
  verifications: Row[];
  events: Row[];
};
async function control(ctx: ScenarioContext, json: Row) {
  const result = await ctx.rawRequest({ path: "/__test/signup-policy", method: "POST", json });
  expect(result.status).toBe(200);
  return result;
}
async function read(ctx: ScenarioContext, profile: FixtureProfile) {
  const result = await ctx.rawRequest({ path: `/__test/signup-policy/state?profile=${profile}` });
  expect(result.status).toBe(200);
  return result.body as State;
}
function hashEvidence(value: unknown) {
  if (typeof value !== "string" || value === "") return value;
  expect(value).toMatch(/^[a-f0-9]{32}:[a-f0-9]{128}$/);
  const [salt, key] = value.split(":");
  return {
    token: value,
    salt: { token: salt, length: salt!.length },
    derivedKey: { token: key, length: key!.length },
    encoding: "hex-lower",
  };
}
function observed(state: State) {
  return {
    ...state,
    accounts: state.accounts.map((row) => ({ ...row, password: hashEvidence(row.password) })),
    verifications: state.verifications.map((row) => {
      if (typeof row.identifier === "string" && row.identifier.startsWith("reset-password:"))
        return {
          ...row,
          identifier: {
            prefix: "reset-password:",
            token: row.identifier.slice("reset-password:".length),
          },
          value: { userId: row.value },
        };
      if (
        typeof row.identifier === "string" &&
        row.identifier.startsWith("email-verification-otp-") &&
        typeof row.value === "string"
      ) {
        const [otp, attempts] = row.value.split(":");
        expect(row.value).toMatch(/^\d{6}:\d+$/);
        return { ...row, value: { token: otp, separator: ":", attempts } };
      }
      return row;
    }),
    events: state.events.map((event) => ({
      ...event,
      ...(typeof event.hash === "string" ? { hash: hashEvidence(event.hash) } : {}),
      ...(typeof event.otp === "string"
        ? { otp: { token: event.otp, length: event.otp.length, encoding: "decimal" } }
        : {}),
    })),
  };
}
function rows(state: State) {
  return {
    users: state.users,
    accounts: state.accounts,
    sessions: state.sessions,
    verifications: state.verifications,
  };
}
async function foreign(ctx: ScenarioContext) {
  await control(ctx, { operation: "mode", mode: "normal" });
  const result = await ctx.actor("foreign", "signup-standard").client.signUp.email({
    email: ctx.uniqueEmail("foreign-policy"),
    name: "Unrelated Principal",
    password: "foreign-password123",
  });
  expect(result.error).toBeNull();
  return { result, state: await ctx.readUserState({ userId: result.data!.user.id }) };
}

compatScenario(
  "configured signup disablement rejects the registered route without callbacks or principal writes",
  async (ctx) => {
    const other = await foreign(ctx);
    const observations: unknown[] = [];
    for (const profile of ["signup-disabled", "signup-password-disabled"] as const) {
      const configured = await control(ctx, { operation: "mode", mode: "normal" });
      const before = await read(ctx, profile);
      const result = await ctx.actor(profile, profile).client.signUp.email({
        email: ctx.uniqueEmail(profile),
        name: "Disabled Registration",
        password: "password123",
      });
      expect(result.error).toMatchObject({
        status: 400,
        code: "EMAIL_PASSWORD_SIGN_UP_DISABLED",
        message: "Email and password sign up is not enabled",
      });
      expect(result.data).toBeNull();
      const after = await read(ctx, profile);
      expect(rows(after)).toEqual(rows(before));
      expect(after.events).toEqual([]);
      observations.push({
        profile,
        configured,
        result,
        before: observed(before),
        after: observed(after),
      });
    }
    expect(await ctx.readUserState({ userId: other.result.data!.user.id })).toEqual(other.state);
    return { foreign: other, observations };
  },
  ["POST /sign-up/email"],
);

compatScenario(
  "signup autoSignIn false returns a fresh synthetic duplicate after real hash and existing-user callbacks",
  async (ctx) => {
    const profile = "signup-no-auto",
      other = await foreign(ctx),
      owner = ctx.actor("owner", profile),
      email = ctx.uniqueEmail("no-auto-policy");
    const configured = await control(ctx, { operation: "mode", mode: "normal" });
    const signup = await owner.client.signUp.email({
      email,
      name: "Physical Principal",
      password: "original-password123",
    });
    expect(signup.error).toBeNull();
    expect(signup.data?.token).toBeNull();
    const realId = signup.data!.user.id;
    const before = await read(ctx, profile);
    expect(before.sessions.filter((row) => row.userId === realId)).toEqual([]);
    const credential = before.accounts.find((row) => row.userId === realId)!;
    expect(
      await verifyPassword({ hash: String(credential.password), password: "original-password123" }),
    ).toBe(true);
    const reset = await control(ctx, { operation: "mode", mode: "normal" });
    const duplicate = await owner.client.signUp.email(
      {
        email: email.toUpperCase(),
        name: "Requested Synthetic Principal",
        password: "duplicate-password123",
        image: "https://images.example/requested.png",
      },
      { headers: { "x-test-policy-marker": "actual-duplicate-request" } },
    );
    expect(duplicate.error).toBeNull();
    expect(duplicate.data?.token).toBeNull();
    expect(duplicate.data?.user).toMatchObject({
      name: "Requested Synthetic Principal",
      email,
      emailVerified: false,
      image: "https://images.example/requested.png",
    });
    expect(duplicate.data?.user.id).not.toBe(realId);
    const after = await read(ctx, profile);
    expect(rows(after)).toEqual(rows(before));
    expect(after.users.some((row) => row.id === duplicate.data?.user.id)).toBe(false);
    expect(after.events.map((row) => row.stage)).toEqual([
      "hash-enter",
      "hash-result",
      "existing-user",
      "existing-complete",
    ]);
    expect(after.events[2]).toMatchObject({
      user: { id: realId, name: "Physical Principal", email },
      request: {
        method: "POST",
        path: "/sign-up/email",
        marker: "actual-duplicate-request",
        contentType: "application/json",
      },
    });
    const session = await owner.client.getSession();
    expect(session.data).toBeNull();
    const wrong = await ctx
      .actor("wrong", profile)
      .client.signIn.email({ email, password: "duplicate-password123" });
    expect(wrong.error?.status).toBe(401);
    const signin = await ctx
      .actor("real", profile)
      .client.signIn.email({ email, password: "original-password123" });
    expect(signin.error).toBeNull();
    expect(signin.data?.user.id).toBe(realId);
    const signed = await read(ctx, profile);
    expect(signed.users).toEqual(before.users);
    expect(signed.accounts).toEqual(before.accounts);
    expect(signed.sessions.filter((row) => row.userId === realId)).toHaveLength(1);
    expect(await ctx.readUserState({ userId: other.result.data!.user.id })).toEqual(other.state);
    return {
      foreign: other,
      configured,
      signup,
      before: observed(before),
      reset,
      duplicate,
      after: observed(after),
      session,
      wrong,
      signin,
      signed: observed(signed),
    };
  },
  ["POST /sign-up/email", "POST /sign-in/email"],
);

compatScenario(
  "user-creation 403 uses a synthetic response only under enumeration-safe signup policy",
  async (ctx) => {
    const other = await foreign(ctx),
      observations = [];
    for (const profile of [
      "signup-standard",
      "signup-no-auto",
      "signup-required",
      "signup-custom",
    ] as const) {
      const before = await read(ctx, profile),
        configured = await control(ctx, { operation: "mode", mode: "user-forbidden" }),
        email = ctx.uniqueEmail(profile);
      const result = await ctx
        .actor(profile, profile)
        .client.signUp.email({ email, name: "Unpersisted Signup", password: "password123" });
      if (profile === "signup-standard")
        expect(result.error).toMatchObject({
          status: 403,
          code: "USER_CREATION_DENIED",
          message: "Configured user creation denied",
        });
      else {
        expect(result.error).toBeNull();
        expect(result.data?.token).toBeNull();
        expect(result.data?.user).toMatchObject({
          email,
          name: profile === "signup-custom" ? "Synthetic Unpersisted Signup" : "Unpersisted Signup",
        });
      }
      const after = await read(ctx, profile);
      expect(rows(after)).toEqual(rows(before));
      expect(after.events.map((row) => row.stage)).toEqual(
        profile === "signup-custom"
          ? ["hash-enter", "hash-result", "user-create-denied", "synthetic-user"]
          : ["hash-enter", "hash-result", "user-create-denied"],
      );
      expect(after.events.some((row) => row.stage === "existing-user")).toBe(false);
      expect(await ctx.actor(profile, profile).client.getSession()).toMatchObject({
        data: null,
        error: null,
      });
      observations.push({
        profile,
        before: observed(before),
        configured,
        result,
        after: observed(after),
      });
    }
    expect(await ctx.readUserState({ userId: other.result.data!.user.id })).toEqual(other.state);
    return { foreign: other, observations };
  },
  ["POST /sign-up/email"],
);

compatScenario(
  "signup creation cancellation and ordinary hook errors retain rejection rather than synthesizing success",
  async (ctx) => {
    const other = await foreign(ctx),
      observations = [];
    for (const profile of ["signup-standard", "signup-no-auto"] as const)
      for (const mode of ["user-cancel", "user-error"]) {
        const before = await read(ctx, profile),
          configured = await control(ctx, { operation: "mode", mode }),
          result = await ctx.actor(profile, profile).client.signUp.email({
            email: ctx.uniqueEmail(`${profile}-${mode}`),
            name: "Rejected Creation",
            password: "password123",
          });
        expect(result.error).toMatchObject({
          status: mode === "user-cancel" ? 400 : 422,
          code: "FAILED_TO_CREATE_USER",
          message: "Failed to create user",
        });
        const after = await read(ctx, profile);
        expect(rows(after)).toEqual(rows(before));
        expect(after.events.map((row) => row.stage)).toEqual([
          "hash-enter",
          "hash-result",
          mode === "user-cancel" ? "user-create-cancelled" : "user-create-error",
        ]);
        observations.push({
          profile,
          mode,
          before: observed(before),
          configured,
          result,
          after: observed(after),
        });
      }
    expect(await ctx.readUserState({ userId: other.result.data!.user.id })).toEqual(other.state);
    return { foreign: other, observations };
  },
  ["POST /sign-up/email"],
);

compatScenario(
  "reset expired and missing-user proofs are consumed before any hasher or callback runs",
  async (ctx) => {
    const profile = "signup-policy",
      other = await foreign(ctx),
      before = await read(ctx, profile),
      observations = [];
    for (const kind of ["expired", "missing-user"]) {
      const token = ctx.uniqueToken(`reset-${kind}`),
        seeded = await ctx.rawRequest({
          path: "/__test/verification-state",
          method: "POST",
          json: {
            action: "seed",
            identifier: `reset-password:${token}`,
            value:
              kind === "expired"
                ? other.result.data!.user.id
                : "11111111-1111-4111-8111-111111111111",
            expiresAt:
              kind === "expired"
                ? "2001-01-01T00:00:00.000Z"
                : new Date(Date.now() + 90_000).toISOString(),
          },
        });
      expect(seeded.status).toBe(200);
      const physical = await read(ctx, profile);
      expect(
        physical.verifications.filter((row) => row.identifier === `reset-password:${token}`),
      ).toHaveLength(1);
      const configured = await control(ctx, { operation: "mode", mode: "normal" }),
        result = await ctx
          .actor(kind, profile)
          .client.resetPassword({ newPassword: "newPassword123", token });
      expect(result.error).toMatchObject({
        status: 400,
        code: kind === "expired" ? "INVALID_TOKEN" : "USER_NOT_FOUND",
      });
      const after = await read(ctx, profile);
      expect(rows(after)).toEqual(rows(before));
      expect(after.events).toEqual([]);
      const replay = await ctx
        .actor(kind, profile)
        .client.resetPassword({ newPassword: "newPassword123", token });
      expect(replay.error?.code).toBe("INVALID_TOKEN");
      expect(await read(ctx, profile)).toEqual(after);
      observations.push({
        kind,
        token,
        seeded,
        physical: observed(physical),
        configured,
        result,
        after: observed(after),
        replay,
      });
    }
    expect(await ctx.readUserState({ userId: other.result.data!.user.id })).toEqual(other.state);
    return { foreign: other, before: observed(before), observations };
  },
  ["POST /reset-password"],
);

compatScenario(
  "concurrent reset requests consume one physical proof and produce one credential update and callback",
  async (ctx) => {
    const profile = "signup-policy",
      other = await foreign(ctx),
      owner = ctx.actor("owner", profile),
      email = ctx.uniqueEmail("reset-race");
    const signup = await owner.client.signUp.email({
      email,
      name: "Reset Race",
      password: "originalPassword123",
    });
    expect(signup.error).toBeNull();
    const reset = await requestReset(ctx, profile, email),
      configured = await control(ctx, { operation: "mode", mode: "normal" }),
      password = "newPassword123";
    const outcomes = await Promise.all(
      [0, 1].map(async () => {
        const entries: TraceEntry[] = [],
          client = createAuthClient({
            baseURL: `${ctx.baseURL}/__test/profiles/${profile}/api/auth`,
            fetchOptions: {
              customFetchImpl: createTracingFetch(
                ctx.baseURL,
                "reset-racer",
                entries,
                `/__test/profiles/${profile}/api/auth`,
              ),
            },
          });
        return {
          entries,
          result: await client.resetPassword({ newPassword: password, token: reset.token }),
        };
      }),
    );
    outcomes.sort((a, b) => (a.result.error?.status ?? 200) - (b.result.error?.status ?? 200));
    ctx.recordTransport(outcomes.flatMap((outcome) => outcome.entries));
    const results = outcomes.map((outcome) => outcome.result);
    expect(results[0]!.error).toBeNull();
    expect(results[1]!.error).toMatchObject({ status: 400, code: "INVALID_TOKEN" });
    const after = await read(ctx, profile);
    expect(after.users).toEqual(reset.state.users);
    expect(
      after.verifications.filter((row) => row.identifier === `reset-password:${reset.token}`),
    ).toEqual([]);
    expect(after.accounts.filter((row) => row.userId === signup.data!.user.id)).toHaveLength(1);
    expect(after.sessions.filter((row) => row.userId === signup.data!.user.id)).toEqual([]);
    const account = after.accounts.find((row) => row.userId === signup.data!.user.id)!;
    expect(await verifyPassword({ hash: String(account.password), password })).toBe(true);
    expect(after.events.map((row) => row.stage)).toEqual([
      "hash-enter",
      "hash-result",
      "password-reset",
    ]);
    const login = await ctx.actor("new-password", profile).client.signIn.email({ email, password });
    expect(login.error).toBeNull();
    expect(login.data?.user.id).toBe(signup.data!.user.id);
    expect(await ctx.readUserState({ userId: other.result.data!.user.id })).toEqual(other.state);
    return {
      foreign: other,
      signup,
      reset: { ...reset, state: observed(reset.state) },
      configured,
      results,
      after: observed(after),
      login,
    };
  },
  ["POST /request-password-reset", "POST /reset-password", "POST /sign-in/email"],
);

compatScenario(
  "reset delivery masks sender and background-observer errors while retaining the full one-hour proof and foreign principals",
  async (ctx) => {
    const other = await foreign(ctx),
      observations = [];
    for (const profile of ["signup-standard", "signup-background"] as const) {
      await control(ctx, { operation: "mode", mode: "normal" });
      const owner = ctx.actor(profile, profile),
        email = ctx.uniqueEmail(profile);
      const signup = await owner.client.signUp.email({
        email,
        name: "Delivery Principal",
        password: "password123",
      });
      expect(signup.error).toBeNull();
      for (const mode of ["normal", "reset-sender-error", "background-error"]) {
        const before = await read(ctx, profile),
          configured = await control(ctx, { operation: "mode", mode }),
          requested = await owner.client.requestPasswordReset(
            { email, redirectTo: "/delivery-policy" },
            { headers: { "x-test-policy-marker": mode } },
          );
        expect(requested.error).toBeNull();
        expect(requested.data?.status).toBe(true);
        const after = await read(ctx, profile);
        expect(after.users).toEqual(before.users);
        expect(after.accounts).toEqual(before.accounts);
        expect(after.sessions).toEqual(before.sessions);
        expect(after.verifications).toHaveLength(before.verifications.length + 1);
        expect(after.events.map((row) => row.stage)).toEqual(
          profile === "signup-background"
            ? ["reset-delivery", "background-register"]
            : ["reset-delivery"],
        );
        const delivery = after.events[0]!;
        expect(delivery).toMatchObject({
          user: JSON.parse(JSON.stringify(signup.data!.user)),
          request: {
            method: "POST",
            path: "/request-password-reset",
            marker: mode,
            contentType: "application/json",
          },
        });
        const proof = after.verifications.find(
          (row) => row.identifier === `reset-password:${delivery.token}`,
        )!;
        expect(proof.value).toBe(signup.data!.user.id);
        expect(
          Date.parse(String(proof.expiresAt)) - Date.parse(String(proof.createdAt)),
        ).toBeGreaterThanOrEqual(3_599_000);
        expect(
          Date.parse(String(proof.expiresAt)) - Date.parse(String(proof.createdAt)),
        ).toBeLessThanOrEqual(3_600_000);
        const blank = await control(ctx, { operation: "mode", mode: "normal" }),
          absent = await owner.client.requestPasswordReset({
            email: ctx.uniqueEmail("absent-reset"),
            redirectTo: "/delivery-policy",
          });
        expect(absent.error).toBeNull();
        const missing = await read(ctx, profile);
        expect(rows(missing)).toEqual(rows(after));
        expect(missing.events).toEqual([]);
        observations.push({
          profile,
          signup,
          mode,
          before: observed(before),
          configured,
          requested,
          after: observed(after),
          blank,
          absent,
          missing: observed(missing),
        });
      }
    }
    expect(await ctx.readUserState({ userId: other.result.data!.user.id })).toEqual(other.state);
    return { foreign: other, observations };
  },
  ["POST /request-password-reset"],
);

compatScenario(
  "custom synthetic duplicate filters application fields and propagates callback failures without principal writes",
  async (ctx) => {
    const profile = "signup-custom",
      other = await foreign(ctx),
      owner = ctx.actor("owner", profile),
      email = ctx.uniqueEmail("custom-synthetic");
    const signup = await owner.client.signUp.email({
      email,
      name: "Physical Custom",
      password: "original-password123",
    });
    expect(signup.error).toBeNull();
    expect(signup.data?.token).toBeNull();
    const before = await read(ctx, profile),
      observations = [];
    for (const mode of ["normal", "synthetic-error", "synthetic-api"]) {
      const configured = await control(ctx, { operation: "mode", mode });
      const result = await ctx.rawRequest({
        path: `/__test/profiles/${profile}/api/auth/sign-up/email`,
        method: "POST",
        headers: { "x-test-policy-marker": "synthetic-request" },
        json: {
          email: email.toUpperCase(),
          name: "Requested Custom",
          password: "duplicate-password123",
          image: "https://images.example/requested.png",
        },
      });
      const after = await read(ctx, profile);
      expect(rows(after)).toEqual(rows(before));
      expect(after.events.map((row) => row.stage)).toEqual([
        "hash-enter",
        "hash-result",
        "existing-user",
        "existing-complete",
        "synthetic-user",
      ]);
      const input = after.events[4]!;
      expect(input).toMatchObject({
        coreFields: {
          name: "Requested Custom",
          email,
          emailVerified: false,
          image: "https://images.example/requested.png",
        },
        additionalFields: {},
      });
      expect(input.id).not.toBe(signup.data!.user.id);
      if (mode === "normal") {
        expect(result.status).toBe(200);
        const body = result.body as { token: null; user: Row };
        expect(body.token).toBeNull();
        expect(body.user).toMatchObject({
          id: input.id,
          name: "Synthetic Requested Custom",
          email,
          emailVerified: true,
          image: "https://images.example/synthetic.png",
        });
        expect(Object.keys(body.user).sort()).toEqual([
          "createdAt",
          "email",
          "emailVerified",
          "id",
          "image",
          "name",
          "updatedAt",
        ]);
        expect(after.users.some((row) => row.id === body.user.id)).toBe(false);
      } else if (mode === "synthetic-error") {
        expect(result.status).toBe(500);
        expect(result.body).toBeNull();
      } else {
        expect(result.status).toBe(403);
        expect(result.body).toEqual({
          code: "SYNTHETIC_REJECTED",
          message: "Configured synthetic-user rejected",
        });
      }
      observations.push({ mode, configured, result, after: observed(after) });
    }
    expect(await owner.client.getSession()).toMatchObject({ data: null, error: null });
    expect(await ctx.readUserState({ userId: other.result.data!.user.id })).toEqual(other.state);
    return { foreign: other, signup, before: observed(before), observations };
  },
  ["POST /sign-up/email"],
);

compatScenario(
  "existing-user notification masks ordinary and API errors after genuine hash without changing physical credentials",
  async (ctx) => {
    const profile = "signup-no-auto",
      other = await foreign(ctx),
      owner = ctx.actor("owner", profile),
      email = ctx.uniqueEmail("existing-errors");
    const signup = await owner.client.signUp.email({
      email,
      name: "Existing Notification",
      password: "original-password123",
    });
    expect(signup.error).toBeNull();
    const before = await read(ctx, profile),
      observations = [];
    for (const mode of ["existing-error", "existing-api"]) {
      const configured = await control(ctx, { operation: "mode", mode });
      const duplicate = await owner.client.signUp.email(
        { email, name: "Synthetic Notification", password: "duplicate-password123" },
        { headers: { "x-test-policy-marker": mode } },
      );
      expect(duplicate.error).toBeNull();
      expect(duplicate.data?.token).toBeNull();
      expect(duplicate.data?.user.id).not.toBe(signup.data!.user.id);
      const after = await read(ctx, profile);
      expect(rows(after)).toEqual(rows(before));
      expect(after.events.map((row) => row.stage)).toEqual([
        "hash-enter",
        "hash-result",
        "existing-user",
      ]);
      expect(after.events[2]).toMatchObject({
        user: JSON.parse(JSON.stringify(signup.data!.user)),
        request: {
          method: "POST",
          path: "/sign-up/email",
          marker: mode,
          contentType: "application/json",
        },
      });
      observations.push({ mode, configured, duplicate, after: observed(after) });
    }
    expect(await ctx.readUserState({ userId: other.result.data!.user.id })).toEqual(other.state);
    return { foreign: other, signup, before: observed(before), observations };
  },
  ["POST /sign-up/email"],
);

async function waitForStage(ctx: ScenarioContext, profile: FixtureProfile, stage: string) {
  const response = await control(ctx, { operation: "wait-stage", stage });
  return response.body as { events: Row[] };
}
compatScenario(
  "existing-user callback is awaited by default and remains owned when background completion is dropped",
  async (ctx) => {
    const other = await foreign(ctx),
      observations = [];
    for (const profile of ["signup-no-auto", "signup-background"] as const) {
      await control(ctx, { operation: "mode", mode: "normal" });
      const owner = ctx.actor(profile, profile),
        email = ctx.uniqueEmail(profile);
      const signup = await owner.client.signUp.email({
        email,
        name: "Background Physical",
        password: "original-password123",
      });
      expect(signup.error).toBeNull();
      const before = await read(ctx, profile),
        configured = await control(ctx, { operation: "mode", mode: "existing-block" });
      let completed = false;
      const entries: TraceEntry[] = [],
        pendingClient = createAuthClient({
          baseURL: `${ctx.baseURL}/__test/profiles/${profile}/api/auth`,
          fetchOptions: {
            customFetchImpl: createTracingFetch(
              ctx.baseURL,
              profile,
              entries,
              `/__test/profiles/${profile}/api/auth`,
            ),
          },
        });
      const pending = pendingClient.signUp
        .email(
          { email, name: "Background Synthetic", password: "duplicate-password123" },
          { headers: { "x-test-policy-marker": profile } },
        )
        .then((result) => {
          completed = true;
          return result;
        });
      const paused = await waitForStage(ctx, profile, "existing-user");
      expect(paused.events.some((row) => row.stage === "existing-complete")).toBe(false);
      let duplicate;
      if (profile === "signup-background") {
        duplicate = await pending;
        expect(completed).toBe(true);
        expect(paused.events.map((row) => row.stage)).toEqual([
          "hash-enter",
          "hash-result",
          "existing-user",
          "background-register",
        ]);
      } else {
        expect(completed).toBe(false);
        expect(paused.events.map((row) => row.stage)).toEqual([
          "hash-enter",
          "hash-result",
          "existing-user",
        ]);
      }
      const released = await control(ctx, { operation: "release-existing" });
      duplicate ??= await pending;
      ctx.recordTransport(entries);
      expect(duplicate.error).toBeNull();
      expect(duplicate.data?.token).toBeNull();
      const completedCallback = await waitForStage(ctx, profile, "existing-complete"),
        finished = await read(ctx, profile);
      expect(rows(finished)).toEqual(rows(before));
      expect(finished.events.at(-1)).toEqual({ stage: "existing-complete" });
      const errorConfigured = await control(ctx, { operation: "mode", mode: "background-error" });
      const observerError = await owner.client.signUp.email({
        email,
        name: "Observer Synthetic",
        password: "duplicate-password123",
      });
      expect(observerError.error).toBeNull();
      const observerState = await read(ctx, profile);
      expect(rows(observerState)).toEqual(rows(before));
      expect(observerState.events.map((row) => row.stage)).toEqual(
        profile === "signup-background"
          ? [
              "hash-enter",
              "hash-result",
              "existing-user",
              "existing-complete",
              "background-register",
            ]
          : ["hash-enter", "hash-result", "existing-user", "existing-complete"],
      );
      observations.push({
        profile,
        signup,
        before: observed(before),
        configured,
        paused: {
          events: paused.events.map((event) => ({
            ...event,
            ...(typeof event.hash === "string" ? { hash: hashEvidence(event.hash) } : {}),
          })),
        },
        duplicate,
        released,
        completedCallback: {
          events: completedCallback.events.map((event) => ({
            ...event,
            ...(typeof event.hash === "string" ? { hash: hashEvidence(event.hash) } : {}),
          })),
        },
        finished: observed(finished),
        errorConfigured,
        observerError,
        observerState: observed(observerState),
      });
    }
    expect(await ctx.readUserState({ userId: other.result.data!.user.id })).toEqual(other.state);
    return { foreign: other, observations };
  },
  ["POST /sign-up/email"],
  30000,
);

compatScenario(
  "configured password lengths use UTF-16 before callbacks while sign-in only checks the upper bound",
  async (ctx) => {
    const profile = "signup-policy",
      other = await foreign(ctx),
      owner = ctx.actor("owner", profile),
      observations = [];
    for (const password of ["a".repeat(9), "a".repeat(21), "😀".repeat(11)]) {
      const configured = await control(ctx, { operation: "mode", mode: "normal" }),
        before = await read(ctx, profile);
      const result = await owner.client.signUp.email({
        email: ctx.uniqueEmail("policy-denied"),
        name: "Bounds",
        password,
      });
      expect(result.error).toMatchObject({
        status: 400,
        code: password.length < 10 ? "PASSWORD_TOO_SHORT" : "PASSWORD_TOO_LONG",
      });
      const after = await read(ctx, profile);
      expect(rows(after)).toEqual(rows(before));
      expect(after.events).toEqual([]);
      observations.push({
        password,
        configured,
        result,
        before: observed(before),
        after: observed(after),
      });
    }
    await control(ctx, { operation: "mode", mode: "normal" });
    const password = "😀".repeat(5),
      email = ctx.uniqueEmail("utf16-valid"),
      signup = await owner.client.signUp.email({ email, name: "UTF16", password });
    expect(signup.error).toBeNull();
    const before = await read(ctx, profile);
    const credential = before.accounts.find((row) => row.userId === signup.data!.user.id)!;
    expect(await verifyPassword({ hash: String(credential.password), password })).toBe(true);
    for (const candidate of ["x", "a".repeat(21)]) {
      const configured = await control(ctx, { operation: "mode", mode: "normal" });
      const result = await ctx
        .actor(`signin-${candidate.length}`, profile)
        .client.signIn.email({ email, password: candidate });
      expect(result.error).toMatchObject(
        candidate.length > 20
          ? { status: 400, code: "PASSWORD_TOO_LONG" }
          : { status: 401, code: "INVALID_EMAIL_OR_PASSWORD" },
      );
      const after = await read(ctx, profile);
      expect(rows(after)).toEqual(rows(before));
      expect(after.events.map((row) => row.stage)).toEqual(
        candidate.length > 20 ? [] : ["verify-enter", "verify-result"],
      );
      observations.push({ candidate, configured, result, after: observed(after) });
    }
    const login = await ctx.actor("real", profile).client.signIn.email({ email, password });
    expect(login.error).toBeNull();
    const after = await read(ctx, profile);
    expect(after.users).toEqual(before.users);
    expect(after.accounts).toEqual(before.accounts);
    expect(after.sessions.filter((row) => row.userId === signup.data!.user.id)).toHaveLength(2);
    expect(await ctx.readUserState({ userId: other.result.data!.user.id })).toEqual(other.state);
    return {
      foreign: other,
      observations,
      signup,
      before: observed(before),
      login,
      after: observed(after),
    };
  },
  ["POST /sign-up/email", "POST /sign-in/email"],
);

compatScenario(
  "standard duplicate and disabled sign-in preserve validation ordering without crypto or storage effects",
  async (ctx) => {
    const other = await foreign(ctx),
      profile = "signup-standard",
      owner = ctx.actor("owner", profile),
      email = ctx.uniqueEmail("standard-order");
    const signup = await owner.client.signUp.email({
      email,
      name: "",
      password: "original-password123",
    });
    expect(signup.error).toBeNull();
    expect(signup.data?.user.name).toBe("");
    const before = await read(ctx, profile),
      observations = [];
    for (const request of [
      {
        profile,
        path: "sign-up/email",
        json: { email, name: "Duplicate", password: "duplicate-password123" },
        code: "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL",
        status: 422,
      },
      {
        profile,
        path: "sign-up/email",
        json: { email: "invalid-email", name: "Invalid", password: "password123" },
        code: "VALIDATION_ERROR",
        status: 400,
      },
      {
        profile,
        path: "sign-up/email",
        json: { email, name: "Empty Password", password: "" },
        code: "VALIDATION_ERROR",
        status: 400,
      },
      {
        profile,
        path: "sign-in/email",
        json: { email: "invalid-email", password: "password123" },
        code: "INVALID_EMAIL",
        status: 400,
      },
      {
        profile: "signup-password-disabled",
        path: "sign-in/email",
        json: { email: "invalid-email", password: "password123" },
        code: "EMAIL_PASSWORD_DISABLED",
        status: 400,
      },
    ] as const) {
      const configured = await control(ctx, { operation: "mode", mode: "normal" }),
        result = await ctx.rawRequest({
          path: `/__test/profiles/${request.profile}/api/auth/${request.path}`,
          method: "POST",
          json: request.json,
        });
      expect(result.status).toBe(request.status);
      expect(result.body).toMatchObject({ code: request.code });
      const after = await read(ctx, profile);
      expect(rows(after)).toEqual(rows(before));
      expect(after.events).toEqual([]);
      observations.push({ request, configured, result, after: observed(after) });
    }
    expect(await ctx.readUserState({ userId: other.result.data!.user.id })).toEqual(other.state);
    return { foreign: other, signup, before: observed(before), observations };
  },
  ["POST /sign-up/email", "POST /sign-in/email"],
);

compatScenario(
  "required verification and username duplicate hooks retain real principals while synthetic output carries only registered fields",
  async (ctx) => {
    const other = await foreign(ctx),
      observations = [];
    for (const profile of ["signup-required", "signup-username"] as const) {
      await control(ctx, { operation: "mode", mode: "normal" });
      const owner = ctx.actor(profile, profile),
        email = ctx.uniqueEmail(profile),
        username = ctx.uniqueToken("physical_username").replace(/-/g, "_").slice(0, 29);
      const signup = await owner.client.signUp.email({
        email,
        name: "Physical Policy",
        password: "original-password123",
        ...(profile === "signup-username" ? { username: username.toUpperCase() } : {}),
      });
      expect(signup.error).toBeNull();
      expect(signup.data?.token).toBeNull();
      const before = await read(ctx, profile);
      expect(before.sessions.filter((row) => row.userId === signup.data!.user.id)).toEqual([]);
      if (profile === "signup-required")
        expect(before.events.map((row) => row.stage)).toEqual([
          "hash-enter",
          "hash-result",
          "verification-email",
        ]);
      else
        expect(signup.data?.user).toMatchObject({
          username,
          displayUsername: username.toUpperCase(),
        });
      const configured = await control(ctx, { operation: "mode", mode: "normal" }),
        duplicate = await owner.client.signUp.email({
          email,
          name: "Requested Policy",
          password: "duplicate-password123",
          username: "fresh_synthetic_username",
          displayUsername: "Synthetic Display",
        });
      expect(duplicate.error).toBeNull();
      expect(duplicate.data?.token).toBeNull();
      expect(duplicate.data?.user.id).not.toBe(signup.data!.user.id);
      if (profile === "signup-username")
        expect(duplicate.data?.user).toMatchObject({
          username: "fresh_synthetic_username",
          displayUsername: "Synthetic Display",
        });
      else {
        expect(Object.hasOwn(duplicate.data!.user, "username")).toBe(false);
        expect(Object.hasOwn(duplicate.data!.user, "displayUsername")).toBe(false);
      }
      const after = await read(ctx, profile);
      expect(rows(after)).toEqual(rows(before));
      expect(after.events.map((row) => row.stage)).toEqual([
        "hash-enter",
        "hash-result",
        "existing-user",
        "existing-complete",
      ]);
      let taken, takenState;
      if (profile === "signup-username") {
        await control(ctx, { operation: "mode", mode: "normal" });
        taken = await owner.client.signUp.email({
          email,
          name: "Taken Before Crypto",
          password: "duplicate-password123",
          username: username.toUpperCase(),
        });
        expect(taken.error?.code).toBe("USERNAME_IS_ALREADY_TAKEN");
        takenState = await read(ctx, profile);
        expect(rows(takenState)).toEqual(rows(before));
        expect(takenState.events).toEqual([]);
      }
      observations.push({
        profile,
        signup,
        before: observed(before),
        configured,
        duplicate,
        after: observed(after),
        taken,
        takenState: takenState && observed(takenState),
      });
    }
    expect(await ctx.readUserState({ userId: other.result.data!.user.id })).toEqual(other.state);
    return { foreign: other, observations };
  },
  ["POST /sign-up/email"],
);

compatScenario(
  "email OTP signup override suppresses duplicate delivery and admits verified password sessions only after real proof consumption",
  async (ctx) => {
    const profile = "signup-otp",
      other = await foreign(ctx),
      owner = ctx.actor("owner", profile),
      email = ctx.uniqueEmail("signup-otp");
    await control(ctx, { operation: "mode", mode: "normal" });
    const signup = await owner.client.signUp.email({
      email,
      name: "OTP Physical",
      password: "original-password123",
    });
    expect(signup.error).toBeNull();
    expect(signup.data?.token).toBeNull();
    const before = await read(ctx, profile);
    expect(before.events.map((row) => row.stage)).toEqual(["hash-enter", "hash-result", "otp"]);
    const delivery = before.events[2]!;
    expect(delivery).toMatchObject({ email, type: "email-verification" });
    expect(String(delivery.otp)).toMatch(/^\d{6}$/);
    expect(
      before.verifications.filter((row) => row.identifier === `email-verification-otp-${email}`),
    ).toHaveLength(1);
    expect(
      before.verifications.find((row) => row.identifier === `email-verification-otp-${email}`)
        ?.value,
    ).toBe(`${delivery.otp}:0`);
    const configured = await control(ctx, { operation: "mode", mode: "normal" }),
      duplicate = await owner.client.signUp.email({
        email,
        name: "OTP Synthetic",
        password: "duplicate-password123",
      });
    expect(duplicate.error).toBeNull();
    const after = await read(ctx, profile);
    expect(rows(after)).toEqual(rows(before));
    expect(after.events.map((row) => row.stage)).toEqual([
      "hash-enter",
      "hash-result",
      "existing-user",
      "existing-complete",
    ]);
    const unverified = await ctx
      .actor("unverified", profile)
      .client.signIn.email({ email, password: "original-password123" });
    expect(unverified.error?.code).toBe("EMAIL_NOT_VERIFIED");
    const verified = await owner.client.emailOtp.verifyEmail({ email, otp: String(delivery.otp) });
    expect(verified.error).toBeNull();
    const proven = await read(ctx, profile);
    expect(proven.users.find((row) => row.id === signup.data!.user.id)?.emailVerified).toBe(true);
    expect(
      proven.verifications.filter((row) => row.identifier === `email-verification-otp-${email}`),
    ).toEqual([]);
    const replay = await owner.client.emailOtp.verifyEmail({ email, otp: String(delivery.otp) });
    expect(replay.error?.code).toBe("INVALID_OTP");
    const login = await ctx
      .actor("verified", profile)
      .client.signIn.email({ email, password: "original-password123" });
    expect(login.error).toBeNull();
    expect(login.data?.user.id).toBe(signup.data!.user.id);
    const final = await read(ctx, profile);
    expect(final.accounts).toEqual(before.accounts);
    expect(final.sessions.filter((row) => row.userId === signup.data!.user.id)).toHaveLength(1);
    expect(await ctx.readUserState({ userId: other.result.data!.user.id })).toEqual(other.state);
    return {
      foreign: other,
      signup,
      before: observed(before),
      configured,
      duplicate,
      after: observed(after),
      unverified,
      verified,
      proven: observed(proven),
      replay,
      login,
      final: observed(final),
    };
  },
  ["POST /sign-up/email", "POST /email-otp/verify-email", "POST /sign-in/email"],
);

async function requestReset(ctx: ScenarioContext, profile: FixtureProfile, email: string) {
  const configured = await control(ctx, { operation: "mode", mode: "normal" }),
    requested = await ctx
      .actor("reset-sender", profile)
      .client.requestPasswordReset(
        { email, redirectTo: "/reset-policy" },
        { headers: { "x-test-policy-marker": "actual-reset-delivery" } },
      );
  expect(requested.error).toBeNull();
  const state = await read(ctx, profile),
    delivery = state.events.find((row) => row.stage === "reset-delivery")!;
  expect(delivery).toMatchObject({
    user: { email },
    request: {
      method: "POST",
      path: "/request-password-reset",
      marker: "actual-reset-delivery",
      contentType: "application/json",
    },
  });
  expect(new URL(String(delivery.url)).pathname).toBe(
    `/__test/profiles/${profile}/api/auth/reset-password/${delivery.token}`,
  );
  expect(
    state.verifications.find((row) => row.identifier === `reset-password:${delivery.token}`)?.value,
  ).toBe((delivery.user as Row).id);
  return { configured, requested, state, delivery, token: String(delivery.token) };
}
compatScenario(
  "zero password options initialize the default bounds and one-hour reset proof across real signup sign-in and reset",
  async (ctx) => {
    const profile = "signup-zero-policy",
      other = await foreign(ctx),
      owner = ctx.actor("owner", profile),
      email = ctx.uniqueEmail("zero-password-policy");
    const configured = await control(ctx, { operation: "mode", mode: "normal" }),
      signup = await owner.client.signUp.email({
        email,
        name: "Effective Default Password",
        password: "password",
      });
    expect(signup.error).toBeNull();
    const before = await read(ctx, profile),
      credential = before.accounts.find((row) => row.userId === signup.data!.user.id)!;
    expect(await verifyPassword({ hash: String(credential.password), password: "password" })).toBe(
      true,
    );
    const observations = [];
    for (const [password, code] of [
      ["a".repeat(7), "PASSWORD_TOO_SHORT"],
      ["a".repeat(129), "PASSWORD_TOO_LONG"],
    ] as const) {
      const configured = await control(ctx, { operation: "mode", mode: "normal" }),
        result = await ctx.actor(code, profile).client.signUp.email({
          email: ctx.uniqueEmail(code),
          name: "Rejected Default Bound",
          password,
        });
      expect(result.error).toMatchObject({ status: 400, code });
      const after = await read(ctx, profile);
      expect(rows(after)).toEqual(rows(before));
      expect(after.events).toEqual([]);
      observations.push({ password, configured, result, after: observed(after) });
    }
    const signin = await ctx
      .actor("signin", profile)
      .client.signIn.email({ email, password: "password" });
    expect(signin.error).toBeNull();
    expect(signin.data?.user.id).toBe(signup.data!.user.id);
    const reset = await requestReset(ctx, profile, email),
      proof = reset.state.verifications.find(
        (row) => row.identifier === `reset-password:${reset.token}`,
      )!;
    expect(
      Date.parse(String(proof.expiresAt)) - Date.parse(String(proof.createdAt)),
    ).toBeGreaterThanOrEqual(3_599_000);
    expect(
      Date.parse(String(proof.expiresAt)) - Date.parse(String(proof.createdAt)),
    ).toBeLessThanOrEqual(3_600_000);
    const shortMode = await control(ctx, { operation: "mode", mode: "normal" }),
      short = await owner.client.resetPassword({ newPassword: "a".repeat(7), token: reset.token });
    expect(short.error).toMatchObject({ status: 400, code: "PASSWORD_TOO_SHORT" });
    const retained = await read(ctx, profile);
    expect(rows(retained)).toEqual(rows(reset.state));
    expect(retained.events).toEqual([]);
    const resetMode = await control(ctx, { operation: "mode", mode: "normal" }),
      result = await owner.client.resetPassword({ newPassword: "new-pass", token: reset.token });
    expect(result.error).toBeNull();
    const after = await read(ctx, profile);
    expect(after.users).toEqual(reset.state.users);
    expect(after.sessions).toEqual(reset.state.sessions);
    expect(
      after.verifications.filter((row) => row.identifier === `reset-password:${reset.token}`),
    ).toEqual([]);
    expect(
      await verifyPassword({
        hash: String(after.accounts.find((row) => row.userId === signup.data!.user.id)!.password),
        password: "new-pass",
      }),
    ).toBe(true);
    expect(after.events.map((row) => row.stage)).toEqual([
      "hash-enter",
      "hash-result",
      "password-reset",
    ]);
    const replay = await owner.client.resetPassword({
      newPassword: "new-pass",
      token: reset.token,
    });
    expect(replay.error?.code).toBe("INVALID_TOKEN");
    const login = await ctx
      .actor("new-password", profile)
      .client.signIn.email({ email, password: "new-pass" });
    expect(login.error).toBeNull();
    expect(await ctx.readUserState({ userId: other.result.data!.user.id })).toEqual(other.state);
    return {
      foreign: other,
      configured,
      signup,
      before: observed(before),
      observations,
      signin,
      reset: { ...reset, state: observed(reset.state) },
      shortMode,
      short,
      retained: observed(retained),
      resetMode,
      result,
      after: observed(after),
      replay,
      login,
    };
  },
  [
    "POST /sign-up/email",
    "POST /sign-in/email",
    "POST /request-password-reset",
    "POST /reset-password",
  ],
);
compatScenario(
  "reset password checks token presence and initialized UTF-16 bounds before consuming its configured ninety-second proof",
  async (ctx) => {
    const profile = "signup-policy",
      other = await foreign(ctx),
      owner = ctx.actor("owner", profile),
      email = ctx.uniqueEmail("reset-bounds");
    const signup = await owner.client.signUp.email({
      email,
      name: "Reset Bounds",
      password: "originalPassword123",
    });
    expect(signup.error).toBeNull();
    const reset = await requestReset(ctx, profile, email),
      proof = reset.state.verifications.find(
        (row) => row.identifier === `reset-password:${reset.token}`,
      )!;
    expect(
      Date.parse(String(proof.expiresAt)) - Date.parse(String(proof.createdAt)),
    ).toBeGreaterThanOrEqual(89_000);
    expect(
      Date.parse(String(proof.expiresAt)) - Date.parse(String(proof.createdAt)),
    ).toBeLessThanOrEqual(90_000);
    const observations = [];
    for (const [password, token, code] of [
      ["x", undefined, "INVALID_TOKEN"],
      ["a".repeat(9), reset.token, "PASSWORD_TOO_SHORT"],
      ["😀".repeat(11), reset.token, "PASSWORD_TOO_LONG"],
    ] as const) {
      const configured = await control(ctx, { operation: "mode", mode: "normal" }),
        result = await owner.client.resetPassword({
          newPassword: password,
          ...(token ? { token } : {}),
        });
      expect(result.error).toMatchObject({ status: 400, code });
      const after = await read(ctx, profile);
      expect(rows(after)).toEqual(rows(reset.state));
      expect(after.events).toEqual([]);
      observations.push({ password, token, configured, result, after: observed(after) });
    }
    const configured = await control(ctx, { operation: "mode", mode: "normal" }),
      password = "😀".repeat(5),
      result = await ctx.rawRequest({
        path: `/__test/profiles/${profile}/api/auth/reset-password?token=${reset.token}`,
        method: "POST",
        headers: { "x-test-policy-marker": "actual-query-reset" },
        json: { newPassword: password, token: "" },
      });
    expect(result.status).toBe(200);
    const after = await read(ctx, profile);
    expect(
      after.verifications.filter((row) => row.identifier === `reset-password:${reset.token}`),
    ).toEqual([]);
    expect(after.sessions.filter((row) => row.userId === signup.data!.user.id)).toEqual([]);
    expect(after.users).toEqual(reset.state.users);
    const credential = after.accounts.find((row) => row.userId === signup.data!.user.id)!;
    expect(await verifyPassword({ hash: String(credential.password), password })).toBe(true);
    expect(after.events.map((row) => row.stage)).toEqual([
      "hash-enter",
      "hash-result",
      "password-reset",
    ]);
    expect(after.events[2]).toMatchObject({
      user: JSON.parse(JSON.stringify(signup.data!.user)),
      request: {
        method: "POST",
        path: "/reset-password",
        marker: "actual-query-reset",
        contentType: "application/json",
      },
    });
    const replay = await owner.client.resetPassword({ newPassword: password, token: reset.token });
    expect(replay.error?.code).toBe("INVALID_TOKEN");
    const login = await ctx.actor("new-password", profile).client.signIn.email({ email, password });
    expect(login.error).toBeNull();
    expect(await ctx.readUserState({ userId: other.result.data!.user.id })).toEqual(other.state);
    return {
      foreign: other,
      signup,
      reset: { ...reset, state: observed(reset.state) },
      observations,
      configured,
      result,
      after: observed(after),
      replay,
      login,
    };
  },
  ["POST /request-password-reset", "POST /reset-password", "POST /sign-in/email"],
);

for (const contract of [
  {
    name: "reset hashing failure consumes the proof without changing passwords or existing sessions",
    modes: ["hash-error", "hash-api"],
  },
  {
    name: "reset callback failure propagates after writing the password and before revoking existing sessions",
    modes: ["reset-callback-error", "reset-callback-api"],
  },
] as const)
  compatScenario(
    contract.name,
    async (ctx) => {
      const profile = "signup-policy",
        other = await foreign(ctx),
        owner = ctx.actor("owner", profile),
        email = ctx.uniqueEmail("reset-errors");
      const signup = await owner.client.signUp.email({
        email,
        name: "Reset Errors",
        password: "originalPassword123",
      });
      expect(signup.error).toBeNull();
      const observations = [];
      for (const mode of contract.modes) {
        const reset = await requestReset(ctx, profile, email),
          configured = await control(ctx, { operation: "mode", mode }),
          password = "newPassword123",
          result = await ctx.rawRequest({
            path: `/__test/profiles/${profile}/api/auth/reset-password`,
            method: "POST",
            headers: { "x-test-policy-marker": mode },
            json: { newPassword: password, token: reset.token },
          });
        expect(result.status).toBe(mode.endsWith("api") ? 403 : 500);
        expect(result.body).toEqual(
          mode.endsWith("api")
            ? {
                code: mode.startsWith("hash") ? "HASH_REJECTED" : "RESET_REJECTED",
                message: mode.startsWith("hash")
                  ? "Configured hash rejected"
                  : "Configured reset callback rejected",
              }
            : null,
        );
        const after = await read(ctx, profile);
        expect(
          after.verifications.filter((row) => row.identifier === `reset-password:${reset.token}`),
        ).toEqual([]);
        expect(after.users).toEqual(reset.state.users);
        expect(after.sessions).toEqual(reset.state.sessions);
        expect(after.events.map((row) => row.stage)).toEqual(
          mode.startsWith("hash")
            ? ["hash-enter", "hash-result"]
            : ["hash-enter", "hash-result", "password-reset"],
        );
        if (mode.startsWith("hash")) expect(after.accounts).toEqual(reset.state.accounts);
        else {
          const account = after.accounts.find((row) => row.userId === signup.data!.user.id)!;
          expect(await verifyPassword({ hash: String(account.password), password })).toBe(true);
        }
        const replay = await owner.client.resetPassword({
          newPassword: password,
          token: reset.token,
        });
        expect(replay.error?.code).toBe("INVALID_TOKEN");
        expect(await read(ctx, profile)).toEqual(after);
        observations.push({
          mode,
          reset: { ...reset, state: observed(reset.state) },
          configured,
          result,
          after: observed(after),
          replay,
        });
      }
      await control(ctx, { operation: "mode", mode: "normal" });
      const login = await ctx.actor("written", profile).client.signIn.email({
        email,
        password: contract.modes[0] === "hash-error" ? "originalPassword123" : "newPassword123",
      });
      expect(login.error).toBeNull();
      expect(await ctx.readUserState({ userId: other.result.data!.user.id })).toEqual(other.state);
      return { foreign: other, signup, observations, login };
    },
    ["POST /request-password-reset", "POST /reset-password", "POST /sign-in/email"],
  );

compatScenario(
  "configured hash and verifier failures propagate with no signup or session writes and missing credentials use the real hasher",
  async (ctx) => {
    const profile = "signup-standard",
      other = await foreign(ctx),
      owner = ctx.actor("owner", profile),
      email = ctx.uniqueEmail("crypto-errors");
    const signup = await owner.client.signUp.email({
      email,
      name: "Crypto Physical",
      password: "original-password123",
    });
    expect(signup.error).toBeNull();
    const before = await read(ctx, profile),
      observations = [];
    for (const mode of ["hash-error", "hash-api", "verify-error", "verify-api"]) {
      const configured = await control(ctx, { operation: "mode", mode });
      const isHash = mode.startsWith("hash"),
        result = await ctx.rawRequest({
          path: `/__test/profiles/${profile}/api/auth/${isHash ? "sign-up" : "sign-in"}/email`,
          method: "POST",
          json: {
            email: isHash ? ctx.uniqueEmail(mode) : email,
            name: "Failing Crypto",
            password: "original-password123",
          },
        });
      expect(result.status).toBe(mode.endsWith("api") ? 403 : 500);
      expect(result.body).toEqual(
        mode.endsWith("api")
          ? {
              code: isHash ? "HASH_REJECTED" : "VERIFY_REJECTED",
              message: isHash ? "Configured hash rejected" : "Configured verifier rejected",
            }
          : null,
      );
      const after = await read(ctx, profile);
      expect(rows(after)).toEqual(rows(before));
      expect(after.events.map((row) => row.stage)).toEqual(
        isHash ? ["hash-enter", "hash-result"] : ["verify-enter", "verify-result"],
      );
      observations.push({ mode, configured, result, after: observed(after) });
    }
    for (const missing of ["unknown", "null", "empty", "absent"]) {
      await control(ctx, { operation: "mode", mode: "normal" });
      let cleared;
      if (missing === "null" || missing === "empty") {
        const credential = before.accounts.find((row) => row.userId === signup.data!.user.id)!;
        cleared = await control(ctx, {
          operation: "clear-password",
          profile,
          accountId: credential.id,
          ...(missing === "empty" ? { password: "" } : {}),
        });
      }
      if (missing === "absent") cleared = await ctx.removeCredentialAccount({ email });
      const configured = await control(ctx, { operation: "mode", mode: "normal" }),
        physical = await read(ctx, profile);
      const result = await ctx.actor(missing, profile).client.signIn.email({
        email: missing === "unknown" ? ctx.uniqueEmail("missing") : email,
        password: "short",
      });
      expect(result.error).toMatchObject({ status: 401, code: "INVALID_EMAIL_OR_PASSWORD" });
      const after = await read(ctx, profile);
      expect(rows(after)).toEqual(rows(physical));
      expect(after.events.map((row) => row.stage)).toEqual(["hash-enter", "hash-result"]);
      expect(await verifyPassword({ hash: String(after.events[1]!.hash), password: "short" })).toBe(
        true,
      );
      observations.push({
        missing,
        cleared,
        configured,
        physical: observed(physical),
        result,
        after: observed(after),
      });
    }
    expect(await ctx.readUserState({ userId: other.result.data!.user.id })).toEqual(other.state);
    return { foreign: other, signup, before: observed(before), observations };
  },
  ["POST /sign-up/email", "POST /sign-in/email"],
);
