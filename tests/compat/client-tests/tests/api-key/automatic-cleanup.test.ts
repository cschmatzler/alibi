import { expect } from "bun:test";

import { apiKeyClient } from "@better-auth/api-key/client";
import { createAuthClient } from "better-auth/client";
import { z } from "zod";

import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { createTracingFetch, type TraceEntry } from "../../support/trace";

type Profile = "api-key-automatic" | "api-key-automatic-deferred" | "api-key-automatic-other";

const path = (profile: Profile) => `/__test/profiles/${profile}/api/auth`;
const eventSchema = z.array(z.object({ kind: z.string() }).passthrough());

const rowsSchema = z.array(
  z
    .object({
      id: z.string(),
      name: z.string(),
      referenceId: z.string(),
      key: z.string(),
      remaining: z.number(),
      expiresAt: z.string().nullable(),
      createdAt: z.string(),
      updatedAt: z.string(),
      lastRequest: z.string().nullable(),
    })
    .passthrough(),
);

function client(ctx: ScenarioContext, actor: string, profile: Profile) {
  return createAuthClient({
    baseURL: `${ctx.baseURL}${path(profile)}`,
    plugins: [apiKeyClient()],
    fetchOptions: { customFetchImpl: ctx.actor(actor, profile).fetch },
  });
}

async function control(ctx: ScenarioContext, json: Record<string, unknown>) {
  const result = await ctx.rawRequest({
    path: "/__test/api-key-background/control",
    method: "POST",
    json,
  });
  expect(result.status).toBe(200);
  return eventSchema.parse(result.body);
}

async function state(ctx: ScenarioContext) {
  const result = await ctx.rawRequest({ path: "/__test/api-key-background/state" });
  expect(result.status).toBe(200);
  return rowsSchema.parse(result.body);
}

async function force(ctx: ScenarioContext, profile: Profile) {
  const result = await ctx.rawRequest({
    path: `/__test/api-key-background/cleanup?profile=${profile}`,
    method: "POST",
  });
  expect(result.status).toBe(200);
  expect(result.body).toEqual({ success: true, error: null });

  return result.body;
}

async function verify(ctx: ScenarioContext, profile: Profile, key: string) {
  const result = await ctx.rawRequest({
    path: `/__test/api-key-background/verify?profile=${profile}`,
    method: "POST",
    json: { key },
  });
  expect(result.status).toBe(200);
  expect(result.body).toMatchObject({ valid: true, error: null });

  return result.body;
}

async function setup(ctx: ScenarioContext, profile: Profile) {
  await control(ctx, { action: "reset" });
  await control(ctx, { action: "restore" });
  const owner = client(ctx, "owner", profile);
  const foreign = client(ctx, "foreign", profile);
  const other = client(ctx, "other-instance", "api-key-automatic-other");
  const created = await owner.signUp.email({
    email: ctx.uniqueEmail("cleanup-owner"),
    password: "password123",
    name: "Cleanup Owner",
  });
  const foreignCreated = await foreign.signUp.email({
    email: ctx.uniqueEmail("cleanup-foreign"),
    password: "password123",
    name: "Cleanup Foreign",
  });
  expect(created.error).toBeNull();
  expect(foreignCreated.error).toBeNull();

  if (!created.data || !foreignCreated.data) {
    throw new Error("real owners required");
  }

  const forced = await force(ctx, profile);
  const forcedReceipt = await control(ctx, { action: "wait", kind: "cleanup-complete", count: 1 });
  expect(forcedReceipt).toMatchObject([
    { kind: "cleanup-enter", profile, serial: 1 },
    { kind: "cleanup-complete", serial: 1, success: true },
  ]);

  const keys = [];

  for (const [selected, name] of [
    [owner, "a-expired-owner"],
    [foreign, "b-expired-foreign"],
    [owner, "c-live-owner"],
    [foreign, "d-live-foreign"],
  ] as const) {
    const result = await selected.apiKey.create({ name });
    expect(result.error).toBeNull();

    if (!result.data) {
      throw new Error("real key required");
    }

    keys.push(result.data);
  }

  for (const key of keys) {
    await control(ctx, { action: "remaining", keyId: key.id });
  }

  const [expiredOwner, expiredForeign, liveOwner, liveForeign] = keys;

  if (!expiredOwner || !expiredForeign || !liveOwner || !liveForeign) {
    throw new Error("four owned rows required");
  }

  const forbidden = await foreign.apiKey.get({ query: { id: liveOwner.id } });
  expect(forbidden.error).not.toBeNull();

  for (const key of [expiredOwner, expiredForeign]) {
    await control(ctx, { action: "expire", keyId: key.id });
  }

  const baseline = await state(ctx);
  expect(baseline).toHaveLength(4);
  expect(baseline.find((row) => row.id === expiredOwner.id)?.referenceId).toBe(
    created.data.user.id,
  );
  expect(baseline.find((row) => row.id === expiredForeign.id)?.referenceId).toBe(
    foreignCreated.data.user.id,
  );

  const ownerState = await ctx.readUserState({ userId: created.data.user.id });
  const foreignState = await ctx.readUserState({ userId: foreignCreated.data.user.id });
  return {
    owner,
    foreign,
    other,
    created,
    foreignCreated,
    keys,
    liveOwner,
    liveForeign,
    forced,
    forcedReceipt,
    forbidden,
    baseline,
    ownerState,
    foreignState,
  };
}

async function retained(ctx: ScenarioContext, ready: Awaited<ReturnType<typeof setup>>) {
  expect(await ctx.readUserState({ userId: ready.created.data!.user.id })).toEqual(
    ready.ownerState,
  );
  expect(await ctx.readUserState({ userId: ready.foreignCreated.data!.user.id })).toEqual(
    ready.foreignState,
  );
}

function counts(events: z.infer<typeof eventSchema>, kind: string) {
  return events.filter((event) => event.kind === kind);
}

function observation(ready: Awaited<ReturnType<typeof setup>>) {
  const { owner, foreign, other, ...observed } = ready;
  return observed;
}

// The runtime's real module-global throttle is ten seconds. Only these owners
// receive 30s for both actual windows, preserving all other default deadlines.
compatScenario(
  "api-key automatic creation starts hot global cleanup before a rejecting generator and ignores the optional observer",
  async (ctx) => {
    const ready = await setup(ctx, "api-key-automatic");
    await control(ctx, { action: "window" });
    await control(ctx, { action: "configure", hold: true, generator: "throw" });
    const rejected = await ready.owner.apiKey.create({ name: "generator-rejected" });
    expect(rejected.error?.status).toBe(500);

    const paused = await control(ctx, { action: "wait", kind: "cleanup-enter", count: 1 });
    expect(paused.slice(-2)).toMatchObject([
      { kind: "cleanup-enter", profile: "api-key-automatic", serial: 2 },
      { kind: "generator" },
    ]);
    expect(counts(paused, "cleanup-complete")).toHaveLength(1);
    expect(counts(paused, "background-register")).toHaveLength(0);
    expect(await state(ctx)).toEqual(ready.baseline);

    const guest = client(ctx, "generator-guest", "api-key-automatic");
    const guestRejected = await guest.apiKey.create({ name: "guest-generator-rejected" });
    expect(guestRejected.error).toMatchObject({
      status: 401,
      code: "UNAUTHORIZED_SESSION",
      message: "Unauthorized or invalid session",
    });
    expect(await control(ctx, { action: "wait", kind: "cleanup-enter", count: 1 })).toEqual(paused);
    expect(await state(ctx)).toEqual(ready.baseline);

    await retained(ctx, ready);
    const session = await ready.owner.getSession({
      fetchOptions: { headers: { "x-api-key": ready.liveOwner.key } },
    });
    expect(session.error).toBeNull();
    expect(session.data?.user.id).toBe(ready.created.data!.user.id);

    const defaultVerification = await verify(ctx, "api-key-automatic", ready.liveOwner.key);
    const otherSession = await ready.other.getSession({
      fetchOptions: { headers: { "x-api-key": ready.liveForeign.key } },
    });
    expect(otherSession.error).toBeNull();
    expect(otherSession.data?.user.id).toBe(ready.foreignCreated.data!.user.id);

    const shared = await control(ctx, { action: "wait", kind: "background-complete", count: 1 });
    expect(counts(shared, "cleanup-enter")).toHaveLength(2);
    expect(counts(shared, "background-register")).toHaveLength(1);

    const during = await state(ctx);
    expect(during).toHaveLength(4);
    expect(during.find((row) => row.id === ready.liveOwner.id)?.remaining).toBe(9);
    expect(during.find((row) => row.id === ready.liveForeign.id)?.remaining).toBe(10);

    await control(ctx, { action: "release" });
    const finished = await control(ctx, { action: "wait", kind: "cleanup-complete", count: 2 });
    const after = await state(ctx);
    expect(after.map((row) => row.name)).toEqual(["c-live-owner", "d-live-foreign"]);
    expect(after).toEqual(during.filter((row) => row.expiresAt === null));

    await retained(ctx, ready);
    await control(ctx, { action: "configure" });
    const forcedAgain = await force(ctx, "api-key-automatic-other");
    const final = await control(ctx, { action: "wait", kind: "cleanup-complete", count: 3 });
    expect(counts(final, "cleanup-enter").at(-1)).toMatchObject({
      profile: "api-key-automatic-other",
      serial: 3,
    });
    expect(await state(ctx)).toEqual(after);

    return ctx.snapshot({
      ...observation(ready),
      rejected,
      guestRejected,
      paused,
      session,
      defaultVerification,
      otherSession,
      shared,
      during,
      finished,
      after,
      forcedAgain,
      final,
    });
  },
  ["POST /api-key/create", "GET /get-session"],
  30_000,
);

for (const observer of ["default", "observe", "ignore"] as const) {
  compatScenario(
    `api-key automatic middleware ${observer} admits one concurrent cleanup and retains both credential owners`,
    async (ctx) => {
      const profile = observer === "default" ? "api-key-automatic" : "api-key-automatic-deferred";
      const ready = await setup(ctx, profile);
      await control(ctx, { action: "window" });
      await control(ctx, { action: "configure", hold: true, observer });
      const outcomes = await Promise.all(
        [ready.liveOwner, ready.liveForeign].map(async (key, index) => {
          const entries: TraceEntry[] = [];
          const racer = createAuthClient({
            baseURL: `${ctx.baseURL}${path(profile)}`,
            plugins: [apiKeyClient()],
            fetchOptions: {
              headers: { "x-api-key": key.key },
              customFetchImpl: createTracingFetch(
                ctx.baseURL,
                `cleanup-race-${index}`,
                entries,
                path(profile),
              ),
            },
          });
          return { result: await racer.getSession(), entries };
        }),
      );
      expect(outcomes.every((outcome) => outcome.entries.length === 1)).toBe(true);

      ctx.recordTransport(outcomes.flatMap((outcome) => outcome.entries));
      const results = outcomes.map((outcome) => outcome.result);
      expect(results.every((result) => result.error === null)).toBe(true);
      expect(results[0]?.data?.user.id).toBe(ready.created.data!.user.id);
      expect(results[1]?.data?.user.id).toBe(ready.foreignCreated.data!.user.id);

      const paused = await control(ctx, { action: "wait", kind: "cleanup-enter", count: 1 });
      expect(counts(paused, "cleanup-enter")).toHaveLength(2);
      expect(counts(paused, "cleanup-complete")).toHaveLength(1);
      expect(counts(paused, "background-register")).toHaveLength(observer === "default" ? 0 : 2);

      const during = await state(ctx);
      expect(during).toHaveLength(4);
      expect(during.filter((row) => row.expiresAt === null).map((row) => row.remaining)).toEqual([
        10, 10,
      ]);

      await retained(ctx, ready);
      await control(ctx, { action: "release" });
      const finished = await control(ctx, {
        action: "wait",
        kind: observer === "observe" ? "background-complete" : "cleanup-complete",
        count: 2,
      });

      if (observer === "observe") {
        expect(counts(finished, "background-complete")).toEqual([
          { kind: "background-complete", fulfilled: true },
          { kind: "background-complete", fulfilled: true },
        ]);
      } else {
        expect(counts(finished, "background-complete")).toHaveLength(0);
      }

      const after = await state(ctx);
      expect(after).toEqual(during.filter((row) => row.expiresAt === null));

      await retained(ctx, ready);
      return ctx.snapshot({ ...observation(ready), results, paused, during, finished, after });
    },
    ["GET /get-session"],
    30_000,
  );
}

compatScenario(
  "api-key background handler failures preserve consumed usage running cleanup and genuine application 403",
  async (ctx) => {
    const ready = await setup(ctx, "api-key-automatic-deferred");
    await control(ctx, { action: "window" });
    await control(ctx, { action: "configure", hold: true, observer: "throw" });
    const rejected = await ready.owner.getSession({
      fetchOptions: { headers: { "x-api-key": ready.liveOwner.key } },
    });
    expect(rejected.error?.status).toBe(500);

    const paused = await control(ctx, { action: "wait", kind: "cleanup-enter", count: 1 });
    expect(counts(paused, "background-register")).toHaveLength(1);
    expect(counts(paused, "cleanup-complete")).toHaveLength(1);

    await control(ctx, { action: "configure", hold: true, observer: "api" });
    const application = await ready.foreign.getSession({
      fetchOptions: { headers: { "x-api-key": ready.liveForeign.key } },
    });
    expect(application.error).toMatchObject({
      status: 403,
      code: "BACKGROUND_TASK_DENIED",
      message: "Application background observer denied",
    });

    const observed = await control(ctx, { action: "wait", kind: "background-register", count: 2 });
    expect(counts(observed, "cleanup-enter")).toHaveLength(2);

    const during = await state(ctx);
    expect(during).toHaveLength(4);
    expect(during.filter((row) => row.expiresAt === null).map((row) => row.remaining)).toEqual([
      10, 10,
    ]);

    await retained(ctx, ready);
    await control(ctx, { action: "release" });
    const finished = await control(ctx, { action: "wait", kind: "cleanup-complete", count: 2 });
    expect(counts(finished, "background-complete")).toHaveLength(0);

    const after = await state(ctx);
    expect(after).toEqual(during.filter((row) => row.expiresAt === null));

    await retained(ctx, ready);
    return ctx.snapshot({
      ...observation(ready),
      rejected,
      application,
      paused,
      observed,
      during,
      finished,
      after,
    });
  },
  ["GET /get-session"],
  30_000,
);

compatScenario(
  "api-key trusted deferred verification catches actual cleanup errors and forced retry bypasses the shared throttle",
  async (ctx) => {
    const ready = await setup(ctx, "api-key-automatic-deferred");
    const defaultVerification = await verify(ctx, "api-key-automatic", ready.liveOwner.key);
    const beforeWindow = await control(ctx, { action: "wait", kind: "cleanup-complete", count: 1 });
    expect(counts(beforeWindow, "background-register")).toHaveLength(0);

    await control(ctx, { action: "window" });
    await control(ctx, { action: "veto" });
    await control(ctx, { action: "configure", hold: true, observer: "observe" });
    const verified = await verify(ctx, "api-key-automatic-deferred", ready.liveOwner.key);
    const paused = await control(ctx, { action: "wait", kind: "cleanup-enter", count: 1 });
    expect(counts(paused, "background-register")).toHaveLength(1);

    const during = await state(ctx);
    expect(during).toHaveLength(4);
    expect(during.find((row) => row.id === ready.liveOwner.id)?.remaining).toBe(9);

    await control(ctx, { action: "release" });
    const failed = await control(ctx, { action: "wait", kind: "background-complete", count: 1 });
    expect(counts(failed, "cleanup-complete").at(-1)).toEqual({
      kind: "cleanup-complete",
      serial: 2,
      success: false,
    });
    expect(counts(failed, "background-complete")).toEqual([
      { kind: "background-complete", fulfilled: true },
    ]);
    expect(await state(ctx)).toEqual(during);

    const throttled = await ready.other.getSession({
      fetchOptions: { headers: { "x-api-key": ready.liveForeign.key } },
    });
    expect(throttled.error).toBeNull();
    expect(throttled.data?.user.id).toBe(ready.foreignCreated.data!.user.id);

    const suppressed = await control(ctx, {
      action: "wait",
      kind: "background-complete",
      count: 2,
    });
    expect(counts(suppressed, "cleanup-enter")).toHaveLength(2);

    const beforeRetry = await state(ctx);
    expect(beforeRetry).toHaveLength(4);

    await control(ctx, { action: "restore" });
    await control(ctx, { action: "configure" });
    const forcedRetry = await force(ctx, "api-key-automatic-other");
    const final = await control(ctx, { action: "wait", kind: "cleanup-complete", count: 3 });
    expect(counts(final, "cleanup-complete").at(-1)).toEqual({
      kind: "cleanup-complete",
      serial: 3,
      success: true,
    });

    const after = await state(ctx);
    expect(after).toEqual(beforeRetry.filter((row) => row.expiresAt === null));

    await retained(ctx, ready);
    return ctx.snapshot({
      ...observation(ready),
      defaultVerification,
      beforeWindow,
      verified,
      paused,
      during,
      failed,
      throttled,
      suppressed,
      beforeRetry,
      forcedRetry,
      final,
      after,
    });
  },
  ["GET /get-session"],
  30_000,
);
