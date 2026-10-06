import { expect } from "bun:test";

import { apiKeyClient } from "@better-auth/api-key/client";
import { createAuthClient } from "better-auth/client";
import { z } from "zod";

import { type ScenarioContext } from "../../../support/scenario";
import { createTracingFetch, type TraceEntry } from "../../../support/trace";

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

export function client(ctx: ScenarioContext, actor: string, profile: Profile) {
  return createAuthClient({
    baseURL: `${ctx.baseURL}${path(profile)}`,
    plugins: [apiKeyClient()],
    fetchOptions: { customFetchImpl: ctx.actor(actor, profile).fetch },
  });
}

export async function control(ctx: ScenarioContext, json: Record<string, unknown>) {
  const result = await ctx.rawRequest({
    path: "/__test/api-key-background/control",
    method: "POST",
    json,
  });
  expect(result.status).toBe(200);
  return eventSchema.parse(result.body);
}

export async function state(ctx: ScenarioContext) {
  const result = await ctx.rawRequest({ path: "/__test/api-key-background/state" });
  expect(result.status).toBe(200);
  return rowsSchema.parse(result.body);
}

export async function force(ctx: ScenarioContext, profile: Profile) {
  const result = await ctx.rawRequest({
    path: `/__test/api-key-background/cleanup?profile=${profile}`,
    method: "POST",
  });
  expect(result.status).toBe(200);
  expect(result.body).toEqual({ success: true, error: null });

  return result.body;
}

export async function verify(ctx: ScenarioContext, profile: Profile, key: string) {
  const result = await ctx.rawRequest({
    path: `/__test/api-key-background/verify?profile=${profile}`,
    method: "POST",
    json: { key },
  });
  expect(result.status).toBe(200);
  expect(result.body).toMatchObject({ valid: true, error: null });

  return result.body;
}

export async function setup(ctx: ScenarioContext, profile: Profile) {
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

export async function retained(ctx: ScenarioContext, ready: Awaited<ReturnType<typeof setup>>) {
  expect(await ctx.readUserState({ userId: ready.created.data!.user.id })).toEqual(
    ready.ownerState,
  );
  expect(await ctx.readUserState({ userId: ready.foreignCreated.data!.user.id })).toEqual(
    ready.foreignState,
  );
}

export function counts(events: z.infer<typeof eventSchema>, kind: string) {
  return events.filter((event) => event.kind === kind);
}

export function observation(ready: Awaited<ReturnType<typeof setup>>) {
  const { owner, foreign, other, ...observed } = ready;
  return observed;
}

export async function cleanupObserver(
  ctx: ScenarioContext,
  observer: "default" | "observe" | "ignore",
) {
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
}
