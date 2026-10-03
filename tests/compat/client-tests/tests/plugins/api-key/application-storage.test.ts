import { expect } from "bun:test";
import { createHash } from "node:crypto";

import { apiKeyClient } from "@better-auth/api-key/client";
import { createAuthClient } from "better-auth/client";
import { organizationClient } from "better-auth/client/plugins";

import { compatScenario, type ScenarioContext } from "../../../support/scenario";
import { createTracingFetch, type TraceEntry } from "../../../support/trace";

type Data = Record<string, any>;
const profiles = [
  "api-key-storage-secondary",
  "api-key-storage-custom",
  "api-key-storage-fallback",
  "api-key-storage-custom-fallback",
  "api-key-storage-deferred",
  "api-key-storage-fallback-deferred",
] as const;
type Profile = (typeof profiles)[number] | "api-key-storage-many-groups";
async function control(ctx: ScenarioContext, input: Data) {
  const response = await ctx.rawRequest({
    path: "/__test/api-key-storage/control",
    method: "POST",
    json: input,
  });
  expect(response.status).toBe(200);
  return response.body as Data;
}
async function snapshot(ctx: ScenarioContext) {
  const stores = await ctx.rawRequest({ path: "/__test/api-key-storage/state" });
  const sql = await ctx.rawRequest({ path: "/__test/api-key-storage/database" });
  expect(stores.status).toBe(200);
  expect(sql.status).toBe(200);
  return { stores: stores.body as Data[], database: sql.body as Data[] };
}
function entries(state: Awaited<ReturnType<typeof snapshot>>, store: string) {
  return state.stores.find((value) => value.store === store)!.entries as Data[];
}
function cached(
  state: Awaited<ReturnType<typeof snapshot>>,
  store: string,
  id: string,
  namespace = "hash",
) {
  return entries(state, store).find(
    (entry) => entry.namespace === namespace && entry.value.id === id,
  );
}
function hash(key: string) {
  return createHash("sha256").update(key).digest("base64url");
}
function indexes(
  state: Awaited<ReturnType<typeof snapshot>>,
  store: string,
  key: Data,
  fallback: boolean,
) {
  const byHash = cached(state, store, key.id)!;
  const byId = cached(state, store, key.id, "id")!;
  expect(byHash).toBeDefined();
  expect(byId).toBeDefined();
  expect(byHash.value).toEqual(byId.value);
  expect(byHash.lookup).toEqual({ key: hash(key.key) });
  expect(byId.lookup).toEqual({ id: key.id });
  expect(byHash.value).toMatchObject({
    id: key.id,
    referenceId: key.referenceId,
    configId: key.configId,
    key: hash(key.key),
  });
  for (const entry of [byHash, byId]) {
    if (key.expiresAt === null) expect(entry.expiresAt).toBeNull();
    else {
      const expiry = new Date(key.expiresAt).getTime();
      expect(Date.parse(entry.expiresAt)).toBeGreaterThan(expiry - 1001);
      expect(Date.parse(entry.expiresAt)).toBeLessThanOrEqual(expiry + 1);
    }
  }
  const reference = entries(state, store).find(
    (entry) => entry.namespace === "reference" && entry.lookup.referenceId === key.referenceId,
  );
  if (!fallback) {
    expect(reference).toBeDefined();
    expect(reference!.expiresAt).toBeNull();
    expect(reference!.value).toContainEqual({ id: key.id });
  }
  expect(state.database.some((row) => row.id === key.id)).toBe(fallback);
}
async function setup(ctx: ScenarioContext, profile: Profile) {
  await control(ctx, { action: "reset" });
  const client = (actor: string) =>
    createAuthClient({
      baseURL: `${ctx.baseURL}/__test/profiles/${profile}/api/auth`,
      plugins: [apiKeyClient(), organizationClient()],
      fetchOptions: { customFetchImpl: ctx.actor(actor, profile).fetch },
    });
  const owner = client("storage-owner");
  const foreign = client("storage-foreign");
  const signup = await owner.signUp.email({
    name: "Storage Owner",
    email: ctx.uniqueEmail("storage-owner"),
    password: "password123",
  });
  const other = await foreign.signUp.email({
    name: "Storage Foreign",
    email: ctx.uniqueEmail("storage-foreign"),
    password: "password123",
  });
  expect(signup.error).toBeNull();
  expect(other.error).toBeNull();
  const fallback = profile.includes("fallback");
  const deferred = profile.includes("deferred");
  const store =
    profile === "api-key-storage-secondary" || profile === "api-key-storage-fallback"
      ? "secondary"
      : "custom";
  const verify = (key: string, extra: Data = {}) =>
    ctx.rawRequest({
      path: `/__test/api-key-storage/verify?profile=${profile}`,
      method: "POST",
      json: { key, ...extra },
    });
  return {
    owner,
    foreign,
    ownerId: signup.data!.user.id,
    foreignId: other.data!.user.id,
    fallback,
    deferred,
    store,
    verify,
    signup: ctx.snapshot(signup),
    other: ctx.snapshot(other),
  };
}
for (const profile of profiles) {
  compatScenario(
    `api-key ${profile} application indexes preserve authority, TTL, fallback, refill, exhaustion and expiry`,
    async (ctx) => {
      const s = await setup(ctx, profile);
      const observations: Data[] = [];
      const target = await s.owner.apiKey.create({
        name: "a-target",
        metadata: { application: { meaning: "retained" } },
        expiresIn: 120.5,
      });
      const foreign = await s.foreign.apiKey.create({ name: "foreign-key" });
      const other = await s.owner.apiKey.create({ name: "b-other", configId: "other" });
      expect(target.error).toBeNull();
      expect(foreign.error).toBeNull();
      expect(other.error).toBeNull();
      const key = target.data!;
      const initial = await snapshot(ctx);
      indexes(initial, s.store, key, s.fallback);
      expect(cached(initial, s.store, key.id)!.value.metadata).toEqual({
        application: { meaning: "retained" },
      });
      expect(cached(initial, s.store, key.id)!.expiresAt).not.toBeNull();
      expect(cached(initial, s.store, foreign.data!.id)!.expiresAt).toBeNull();
      if (s.store === "custom") expect(entries(initial, "secondary")).toEqual([]);
      const foreignState = await ctx.readUserState({ userId: s.foreignId });
      const denied = [
        await s.foreign.apiKey.get({ query: { id: key.id } }),
        await s.foreign.apiKey.update({ keyId: key.id, name: "stolen" }),
        await s.foreign.apiKey.delete({ keyId: key.id }),
        await s.owner.apiKey.get({ query: { id: key.id, configId: "other" } }),
      ];
      const deniedVerification = [
        await s.verify(key.key, { configId: "other" }),
        await s.verify(key.key, { permissions: { resource: ["write"] } }),
      ];
      expect(denied.every((value) => value.error !== null)).toBe(true);
      expect(deniedVerification.every((value) => (value.body as Data).valid === false)).toBe(true);
      expect(await snapshot(ctx)).toEqual(initial);
      observations.push({ initial, denied: ctx.snapshot(denied), deniedVerification });
      const first = await s.owner.apiKey.list({
        query: { limit: 1, sortBy: "name", sortDirection: "asc" },
      });
      const second = await s.owner.apiKey.list({
        query: { limit: 1, offset: 1, sortBy: "name", sortDirection: "asc" },
      });
      expect(first.data!.total).toBe(2);
      expect(first.data!.apiKeys.map((row) => row.name)).toEqual(["a-target"]);
      expect(second.data!.apiKeys.map((row) => row.name)).toEqual(["b-other"]);
      const listed = await snapshot(ctx);
      indexes(listed, s.store, key, s.fallback);
      observations.push({ first: ctx.snapshot(first), second: ctx.snapshot(second), listed });
      const isolated = await s.owner.apiKey.create({ name: "isolated-key", configId: "isolated" });
      expect(isolated.error).toBeNull();
      const beforeIsolation = await snapshot(ctx);
      await control(ctx, { action: "configure", failure: "get", store: "isolated" });
      const selected = await s.owner.apiKey.list({
        query: { configId: "default", sortBy: "name" },
      });
      expect(selected.error).toBeNull();
      expect(selected.data!.apiKeys.map((row) => row.id)).toEqual([key.id]);
      expect(await snapshot(ctx)).toEqual(beforeIsolation);
      await control(ctx, { action: "configure" });
      observations.push({
        isolated: ctx.snapshot(isolated),
        selected: ctx.snapshot(selected),
        beforeIsolation,
      });
      // A stale reference index is real application data; it must not grant another user's row.
      await control(ctx, {
        action: "misindex",
        store: s.store,
        referenceId: s.ownerId,
        keyId: foreign.data!.id,
      });
      const misindexed = await snapshot(ctx);
      const rejectedList = await s.owner.apiKey.list({ query: { configId: "default" } });
      expect(rejectedList.error).toBeNull();
      expect(rejectedList.data!.apiKeys).toEqual([]);
      expect(await snapshot(ctx)).toEqual(misindexed);
      observations.push({ misindexed, rejectedList: ctx.snapshot(rejectedList) });
      await control(ctx, { action: "clear" });
      if (s.fallback) {
        const reload = await s.owner.apiKey.get({ query: { id: key.id } });
        expect(reload.error).toBeNull();
        const loaded = await snapshot(ctx);
        indexes(loaded, s.store, key, true);
        expect(entries(loaded, s.store).filter((entry) => entry.namespace === "reference")).toEqual(
          [],
        );
        observations.push({ reload: ctx.snapshot(reload), loaded });
        const list = await s.owner.apiKey.list({
          query: { configId: "default", limit: 1, sortBy: "name" },
        });
        expect(list.data!.total).toBe(1);
        observations.push({ list: ctx.snapshot(list), state: await snapshot(ctx) });
      } else {
        const missing = await s.owner.apiKey.get({ query: { id: key.id } });
        expect(missing.error).not.toBeNull();
        expect((await snapshot(ctx)).database).toEqual([]);
        observations.push({ missing: ctx.snapshot(missing), state: await snapshot(ctx) });
      }
      const quota = await s.owner.apiKey.create({ name: "quota-target" });
      expect(quota.error).toBeNull();
      await control(ctx, {
        action: "patch",
        keyId: quota.data!.id,
        database: s.fallback,
        patch: {
          remaining: 0,
          refillAmount: 3,
          refillInterval: 60000,
          lastRefillAt: "1970-01-01T00:00:00.000Z",
        },
      });
      const due = await snapshot(ctx);
      const consumed = [];
      for (let count = 0; count < 3; count++) {
        const value = await s.verify(quota.data!.key);
        expect(value.body).toMatchObject({ valid: true, error: null });
        await control(ctx, { action: "drain" });
        consumed.push({ value, state: await snapshot(ctx) });
        expect(cached(consumed.at(-1)!.state, s.store, quota.data!.id)!.value.remaining).toBe(
          2 - count,
        );
      }
      const exhaustedState = await snapshot(ctx);
      const exhausted = await s.verify(quota.data!.key);
      expect((exhausted.body as Data).error.code).toBe("USAGE_EXCEEDED");
      await control(ctx, { action: "drain" });
      expect(await snapshot(ctx)).toEqual(exhaustedState);
      observations.push({ due, consumed, exhausted });
      await control(ctx, {
        action: "patch",
        keyId: quota.data!.id,
        database: s.fallback,
        patch: { expiresAt: "1970-01-01T00:00:00.000Z" },
      });
      const beforeExpiry = await snapshot(ctx);
      const expired = await s.verify(quota.data!.key);
      expect((expired.body as Data).error.code).toBe("KEY_EXPIRED");
      await control(ctx, { action: "drain" });
      const afterExpiry = await snapshot(ctx);
      expect(cached(afterExpiry, s.store, quota.data!.id)).toBeUndefined();
      expect(afterExpiry.database.some((row) => row.id === quota.data!.id)).toBe(false);
      observations.push({ beforeExpiry, expired, afterExpiry });
      expect(await ctx.readUserState({ userId: s.foreignId })).toEqual(foreignState);
      return {
        signup: s.signup,
        other: s.other,
        target: ctx.snapshot(target),
        foreign: ctx.snapshot(foreign),
        otherKey: ctx.snapshot(other),
        observations,
        foreignState,
      };
    },
  );
}

function pendingVerification(
  ctx: ScenarioContext,
  profile: Profile,
  key: string,
  actor = "storage-verification",
) {
  const traces: TraceEntry[] = [];
  let finished = false;
  const pending = createTracingFetch(
    ctx.baseURL,
    actor,
    traces,
  )(`/__test/api-key-storage/verify?profile=${profile}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ key }),
    signal: AbortSignal.timeout(5000),
  }).then(async (response) => {
    finished = true;
    return { status: response.status, body: (await response.json()) as Data };
  });
  return { pending, traces, finished: () => finished };
}
for (const profile of profiles) {
  compatScenario(
    `api-key ${profile} usage merges into the current application row at its awaited or deferred boundary`,
    async (ctx) => {
      const s = await setup(ctx, profile);
      const created = await s.owner.apiKey.create({
        name: "merge-target",
        metadata: { application: { meaning: "keep-current" } },
      });
      expect(created.error).toBeNull();
      const key = created.data!;
      await control(ctx, {
        action: "patch",
        keyId: key.id,
        database: s.fallback,
        patch: { remaining: 4 },
      });
      const before = await snapshot(ctx);
      await control(ctx, {
        action: "configure",
        store: s.store,
        holdAt: s.fallback ? 1 : 2,
        captureBeforeWait: s.fallback,
      });
      const work = pendingVerification(ctx, profile, key.key);
      let paused;
      let changed;
      let response;
      try {
        await control(ctx, { action: "wait", count: 1 });
        paused = await snapshot(ctx);
        expect(paused).toEqual(before);
        if (s.deferred && !s.fallback) {
          response = await work.pending;
          expect(response.body).toMatchObject({
            valid: true,
            key: { name: "merge-target", remaining: 3 },
          });
        } else expect(work.finished()).toBe(false);
        await control(ctx, {
          action: "patch",
          keyId: key.id,
          database: s.fallback,
          cache: !s.fallback,
          patch: { name: "current-row", remaining: 77 },
        });
        changed = await snapshot(ctx);
      } finally {
        await control(ctx, { action: "release" });
      }
      response ??= await work.pending;
      ctx.recordTransport(work.traces);
      await control(ctx, { action: "drain" });
      const merged = await snapshot(ctx);
      expect(response.body).toMatchObject({
        valid: true,
        key: {
          name: s.deferred && !s.fallback ? "merge-target" : "current-row",
          remaining: s.fallback ? 76 : 3,
        },
      });
      expect(cached(merged, s.store, key.id)!.value).toMatchObject({
        name: "current-row",
        remaining: s.fallback ? 76 : 3,
        metadata: { application: { meaning: "keep-current" } },
      });
      expect(cached(merged, s.store, key.id)!.value).toEqual(
        cached(merged, s.store, key.id, "id")!.value,
      );
      if (s.fallback) expect(merged.database.find((row) => row.id === key.id)!.remaining).toBe(76);
      else expect(merged.database).toEqual([]);
      await control(ctx, { action: "expire-cache", keyId: key.id });
      const expiredCache = await snapshot(ctx);
      const read = await s.owner.apiKey.get({ query: { id: key.id } });
      expect(read.error === null).toBe(s.fallback);
      const reloaded = await snapshot(ctx);
      if (s.fallback) indexes(reloaded, s.store, key, true);
      else expect(cached(reloaded, s.store, key.id, "id")).toBeUndefined();
      return {
        signup: s.signup,
        other: s.other,
        created: ctx.snapshot(created),
        before,
        paused,
        changed,
        response,
        merged,
        expiredCache,
        read: ctx.snapshot(read),
        reloaded,
      };
    },
  );
  compatScenario(
    `api-key ${profile} partial index writes preserve actual storage effects and retries`,
    async (ctx) => {
      const s = await setup(ctx, profile);
      const observations: Data[] = [];
      for (const operation of [
        "set-hash",
        "set-id",
        s.fallback ? "delete-reference" : "set-reference",
      ]) {
        const created = await s.owner.apiKey.create({ name: `write-${operation}` });
        expect(created.error).toBeNull();
        const key = created.data!;
        await control(ctx, {
          action: "patch",
          keyId: key.id,
          database: s.fallback,
          patch: { remaining: 4 },
        });
        const listed = await s.owner.apiKey.list({ query: { configId: "default" } });
        expect(listed.error).toBeNull();
        const before = await snapshot(ctx);
        await control(ctx, { action: "configure", failure: operation, store: s.store });
        const failed = await s.verify(key.key);
        await control(ctx, { action: "drain" });
        const partial = await snapshot(ctx);
        expect((failed.body as Data).valid).toBe(s.deferred && !s.fallback);
        expect(cached(partial, s.store, key.id)!.value.remaining).toBe(
          operation === "set-hash" ? 4 : 3,
        );
        expect(cached(partial, s.store, key.id, "id")!.value.remaining).toBe(
          operation === "set-id" ? 4 : 3,
        );
        if (s.fallback) {
          expect(partial.database.find((row) => row.id === key.id)!.remaining).toBe(3);
          expect(entries(partial, s.store).some((entry) => entry.namespace === "reference")).toBe(
            operation === "delete-reference",
          );
        }
        await control(ctx, { action: "configure" });
        const retry = await s.verify(key.key);
        expect(retry.body).toMatchObject({ valid: true, error: null });
        await control(ctx, { action: "drain" });
        const settled = await snapshot(ctx);
        expect(cached(settled, s.store, key.id)!.value.remaining).toBe(
          !s.fallback && operation === "set-hash" ? 3 : 2,
        );
        expect(cached(settled, s.store, key.id)!.value).toEqual(
          cached(settled, s.store, key.id, "id")!.value,
        );
        observations.push({
          created: ctx.snapshot(created),
          listed: ctx.snapshot(listed),
          operation,
          before,
          failed,
          partial,
          retry,
          settled,
        });
      }
      return { signup: s.signup, other: s.other, observations };
    },
  );
  compatScenario(
    `api-key ${profile} same-snapshot admission retains configured store consistency`,
    async (ctx) => {
      const s = await setup(ctx, profile);
      const created = await s.owner.apiKey.create({ name: "concurrent-target" });
      expect(created.error).toBeNull();
      const key = created.data!;
      await control(ctx, {
        action: "patch",
        keyId: key.id,
        database: s.fallback,
        patch: { remaining: 1 },
      });
      const before = await snapshot(ctx);
      await control(ctx, {
        action: "configure",
        store: s.store,
        holdAt: 0,
        captureBeforeWait: true,
      });
      const work = [
        pendingVerification(ctx, profile, key.key, "storage-concurrent"),
        pendingVerification(ctx, profile, key.key, "storage-concurrent"),
      ];
      let paused;
      try {
        await control(ctx, { action: "wait", count: 2 });
        expect(work.every((item) => !item.finished())).toBe(true);
        paused = await snapshot(ctx);
        expect(paused).toEqual(before);
      } finally {
        await control(ctx, { action: "release" });
      }
      const outcomes = await Promise.all(
        work.map(async (item) => ({ response: await item.pending, traces: item.traces })),
      );
      outcomes.sort((a, b) => Number(a.response.body.valid) - Number(b.response.body.valid));
      ctx.recordTransport(outcomes.flatMap((item) => item.traces));
      const responses = outcomes.map((item) => item.response);
      expect(responses.filter((item) => item.body.valid).length).toBe(s.fallback ? 1 : 2);
      await control(ctx, { action: "drain" });
      const admitted = await snapshot(ctx);
      expect(cached(admitted, s.store, key.id)!.value.remaining).toBe(0);
      if (s.fallback) expect(admitted.database.find((row) => row.id === key.id)!.remaining).toBe(0);
      else expect(admitted.database).toEqual([]);
      const exhausted = await s.verify(key.key);
      expect((exhausted.body as Data).error.code).toBe("USAGE_EXCEEDED");
      await control(ctx, { action: "drain" });
      const retired = await snapshot(ctx);
      expect(cached(retired, s.store, key.id)).toBeUndefined();
      expect(cached(retired, s.store, key.id, "id")).toBeUndefined();
      expect(retired.database.some((row) => row.id === key.id)).toBe(false);
      return {
        signup: s.signup,
        other: s.other,
        created: ctx.snapshot(created),
        before,
        paused,
        responses,
        admitted,
        exhausted,
        retired,
      };
    },
  );
  compatScenario(
    `api-key ${profile} a failing hash write returns while initiated ID storage remains pending`,
    async (ctx) => {
      const s = await setup(ctx, profile);
      const created = await s.owner.apiKey.create({ name: "pending-write-target" });
      expect(created.error).toBeNull();
      const key = created.data!;
      await control(ctx, {
        action: "patch",
        keyId: key.id,
        database: s.fallback,
        patch: { remaining: 4 },
      });
      const listed = await s.owner.apiKey.list({ query: { configId: "default" } });
      const before = await snapshot(ctx);
      await control(ctx, {
        action: "configure",
        failure: "set-hash",
        store: s.store,
        holdOperation: "set-id",
      });
      const work = pendingVerification(ctx, profile, key.key);
      let paused;
      let response;
      try {
        const blocked = await control(ctx, { action: "wait", count: 1 });
        expect(blocked.pending).toBe(1);
        response = await work.pending;
        expect(response.body.valid).toBe(s.deferred && !s.fallback);
        paused = await snapshot(ctx);
        expect(cached(paused, s.store, key.id)!.value.remaining).toBe(4);
        expect(cached(paused, s.store, key.id, "id")!.value.remaining).toBe(4);
        if (s.fallback) {
          expect(paused.database.find((row) => row.id === key.id)!.remaining).toBe(3);
          expect(
            entries(paused, s.store).filter((entry) => entry.namespace === "reference"),
          ).toEqual([]);
        }
      } finally {
        await control(ctx, { action: "release" });
      }
      ctx.recordTransport(work.traces);
      await control(ctx, { action: "drain" });
      const settled = await snapshot(ctx);
      expect(cached(settled, s.store, key.id)!.value.remaining).toBe(4);
      expect(cached(settled, s.store, key.id, "id")!.value.remaining).toBe(3);
      await control(ctx, { action: "configure" });
      const retry = await s.verify(key.key);
      expect(retry.body).toMatchObject({ valid: true, error: null });
      await control(ctx, { action: "drain" });
      const repaired = await snapshot(ctx);
      expect(cached(repaired, s.store, key.id)!.value).toEqual(
        cached(repaired, s.store, key.id, "id")!.value,
      );
      return {
        signup: s.signup,
        other: s.other,
        created: ctx.snapshot(created),
        listed: ctx.snapshot(listed),
        before,
        paused,
        response,
        settled,
        retry,
        repaired,
      };
    },
  );
  compatScenario(
    `api-key ${profile} partial deletion failures retain started index effects and database authority`,
    async (ctx) => {
      const s = await setup(ctx, profile);
      const observations: Data[] = [];
      for (const operation of ["delete-hash", "delete-id", "delete-reference"]) {
        const created = await s.owner.apiKey.create({ name: `retire-${operation}` });
        expect(created.error).toBeNull();
        const key = created.data!;
        const listed = await s.owner.apiKey.list({ query: { configId: "default" } });
        expect(listed.error).toBeNull();
        await control(ctx, {
          action: "patch",
          keyId: key.id,
          database: s.fallback,
          patch: { expiresAt: "1970-01-01T00:00:00.000Z" },
        });
        const before = await snapshot(ctx);
        await control(ctx, {
          action: "configure",
          failure: operation,
          store: s.store,
          holdOperation: operation === "delete-hash" ? "delete-id" : "",
        });
        const work = pendingVerification(ctx, profile, key.key);
        let response;
        let paused;
        try {
          if (operation === "delete-hash") await control(ctx, { action: "wait", count: 1 });
          response = await work.pending;
          expect(response.body.valid).toBe(false);
          expect(response.body.error.code).toBe(s.deferred ? "KEY_EXPIRED" : "INVALID_API_KEY");
          if (operation === "delete-hash") {
            paused = await snapshot(ctx);
            expect(cached(paused, s.store, key.id)).toBeDefined();
            expect(cached(paused, s.store, key.id, "id")).toBeDefined();
          }
        } finally {
          await control(ctx, { action: "release" });
        }
        ctx.recordTransport(work.traces);
        await control(ctx, { action: "drain" });
        const partial = await snapshot(ctx);
        expect(!!cached(partial, s.store, key.id)).toBe(operation === "delete-hash");
        expect(!!cached(partial, s.store, key.id, "id")).toBe(operation === "delete-id");
        expect(partial.database.some((row) => row.id === key.id)).toBe(s.fallback);
        await control(ctx, { action: "configure" });
        const retry = await s.verify(key.key);
        expect((retry.body as Data).valid).toBe(false);
        await control(ctx, { action: "drain" });
        const retried = await snapshot(ctx);
        observations.push({
          created: ctx.snapshot(created),
          listed: ctx.snapshot(listed),
          operation,
          before,
          response,
          paused: paused ?? null,
          partial,
          retry,
          retried,
        });
      }
      return { signup: s.signup, other: s.other, observations };
    },
  );
}
for (const profile of profiles.filter((profile) => profile.includes("fallback"))) {
  compatScenario(
    `api-key ${profile} a failed first list group preserves independently started fallback cache writes`,
    async (ctx) => {
      const s = await setup(ctx, profile);
      const created = await s.owner.apiKey.create({ name: "group-default" });
      const isolated = await s.owner.apiKey.create({
        name: "group-isolated",
        configId: "isolated",
      });
      expect(created.error).toBeNull();
      expect(isolated.error).toBeNull();
      await control(ctx, { action: "clear" });
      const before = await snapshot(ctx);
      await control(ctx, { action: "configure", failure: "get", store: s.store });
      const failed = await s.owner.apiKey.list();
      expect(failed.error).not.toBeNull();
      await control(ctx, { action: "drain" });
      const partial = await snapshot(ctx);
      expect(cached(partial, "isolated", created.data!.id)).toBeDefined();
      expect(cached(partial, "isolated", isolated.data!.id)).toBeDefined();
      expect(entries(partial, s.store)).toEqual([]);
      expect(partial.database).toEqual(before.database);
      await control(ctx, { action: "configure" });
      const retry = await s.owner.apiKey.list({ query: { sortBy: "name" } });
      expect(retry.error).toBeNull();
      expect(retry.data!.apiKeys.map((row) => row.name)).toEqual([
        "group-default",
        "group-isolated",
      ]);
      const repaired = await snapshot(ctx);
      return {
        signup: s.signup,
        other: s.other,
        created: ctx.snapshot(created),
        isolated: ctx.snapshot(isolated),
        before,
        failed: ctx.snapshot(failed),
        partial,
        retry: ctx.snapshot(retry),
        repaired,
      };
    },
  );
}
for (const profile of profiles) {
  compatScenario(
    `api-key ${profile} application storage preserves organization ownership and configuration scope`,
    async (ctx) => {
      const s = await setup(ctx, profile);
      const organization = await s.owner.organization.create({
        name: "Storage Organization",
        slug: "storage-organization",
      });
      expect(organization.error).toBeNull();
      const created = await s.owner.apiKey.create({
        name: "organization-key",
        configId: "organization",
        organizationId: organization.data!.id,
      });
      expect(created.error).toBeNull();
      const key = created.data!;
      const before = await snapshot(ctx);
      indexes(before, s.store, key, s.fallback);
      const user = await ctx.readUserState({ userId: s.foreignId });
      const rejected = [
        await s.foreign.apiKey.get({ query: { id: key.id, configId: "organization" } }),
        await s.foreign.apiKey.update({
          keyId: key.id,
          configId: "organization",
          name: "stolen-org-key",
        }),
        await s.foreign.apiKey.delete({ keyId: key.id, configId: "organization" }),
        await s.foreign.apiKey.create({
          name: "foreign-org-key",
          configId: "organization",
          organizationId: organization.data!.id,
        }),
        await s.foreign.apiKey.list({
          query: { configId: "organization", organizationId: organization.data!.id },
        }),
        await s.owner.apiKey.get({ query: { id: key.id, configId: "default" } }),
      ];
      expect(rejected.every((value) => value.error !== null)).toBe(true);
      expect(await snapshot(ctx)).toEqual(before);
      expect(await ctx.readUserState({ userId: s.foreignId })).toEqual(user);
      const userList = await s.owner.apiKey.list({ query: { configId: "default" } });
      const orgList = await s.owner.apiKey.list({
        query: { configId: "organization", organizationId: organization.data!.id },
      });
      expect(userList.data!.apiKeys).toEqual([]);
      expect(orgList.data!.apiKeys.map((row) => row.id)).toEqual([key.id]);
      const listed = await snapshot(ctx);
      await control(ctx, { action: "configure", failure: "get", store: s.store });
      const readFailure = await s.owner.apiKey.get({
        query: { id: key.id, configId: "organization" },
      });
      expect(readFailure.error?.status).toBe(500);
      expect(await snapshot(ctx)).toEqual(listed);
      await control(ctx, { action: "configure" });
      const read = await s.owner.apiKey.get({ query: { id: key.id, configId: "organization" } });
      expect(read.error).toBeNull();
      const after = await snapshot(ctx);
      expect(after).toEqual(listed);
      return {
        signup: s.signup,
        other: s.other,
        organization: ctx.snapshot(organization),
        created: ctx.snapshot(created),
        before,
        rejected: ctx.snapshot(rejected),
        user,
        userList: ctx.snapshot(userList),
        orgList: ctx.snapshot(orgList),
        listed,
        readFailure: ctx.snapshot(readFailure),
        read: ctx.snapshot(read),
        after,
      };
    },
  );
}

compatScenario(
  "api-key api-key-storage-many-groups a later failing group rejects while the first of 32 groups remains held",
  async (ctx) => {
    const profile = "api-key-storage-many-groups";
    const s = await setup(ctx, profile);
    const created = await s.owner.apiKey.create({ name: "first-group", configId: "group-0" });
    const later = await s.owner.apiKey.create({ name: "last-group", configId: "group-31" });
    expect(created.error).toBeNull();
    expect(later.error).toBeNull();
    const before = await snapshot(ctx);
    indexes(before, "group-0", created.data!, false);
    indexes(before, "group-31", later.data!, false);
    await control(ctx, {
      action: "configure",
      failure: "get",
      store: "group-31",
      holdOperation: "get-reference",
      holdStore: "group-0",
    });
    const actor = ctx.actor("storage-owner", profile);
    const client = createAuthClient({
      baseURL: `${ctx.baseURL}/__test/profiles/${profile}/api/auth`,
      plugins: [apiKeyClient()],
      fetchOptions: {
        customFetchImpl: (input, init) =>
          actor.fetch(input, { ...init, signal: AbortSignal.timeout(5000) }),
      },
    });
    const pending = client.apiKey.list();
    let failed;
    let paused;
    try {
      await control(ctx, { action: "wait", count: 1 });
      failed = await pending;
      expect(failed.error?.status).toBe(500);
      paused = await snapshot(ctx);
      expect(paused).toEqual(before);
    } finally {
      await control(ctx, { action: "release" });
    }
    await control(ctx, { action: "drain" });
    const settled = await snapshot(ctx);
    expect(settled).toEqual(before);
    await control(ctx, { action: "configure" });
    const retry = await s.owner.apiKey.list({ query: { sortBy: "name" } });
    expect(retry.error).toBeNull();
    expect(retry.data!.apiKeys.map((row) => row.configId)).toEqual(["group-0", "group-31"]);
    return {
      signup: s.signup,
      other: s.other,
      created: ctx.snapshot(created),
      later: ctx.snapshot(later),
      before,
      failed: ctx.snapshot(failed),
      paused,
      settled,
      retry: ctx.snapshot(retry),
      repaired: await snapshot(ctx),
    };
  },
);

compatScenario(
  "api-key api-key-storage-custom list ID reads preserve Source concurrency bound and result order",
  async (ctx) => {
    const profile = "api-key-storage-custom";
    const s = await setup(ctx, profile);
    const issued = [];
    for (let index = 0; index < 12; index++) {
      const created = await s.owner.apiKey.create({
        name: `bounded-${String(index).padStart(2, "0")}`,
      });
      expect(created.error).toBeNull();
      issued.push(ctx.snapshot(created));
    }
    const before = await snapshot(ctx);
    await control(ctx, { action: "configure", store: "custom", holdOperation: "get-id" });
    let finished = false;
    const pending = s.owner.apiKey.list({ query: { configId: "default" } }).then((result) => {
      finished = true;
      return result;
    });
    let barrier;
    let paused;
    try {
      const response = await ctx
        .actor("storage-barrier", profile)
        .fetch("/__test/api-key-storage/control", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ action: "wait", count: 10 }),
          signal: AbortSignal.timeout(5000),
        });
      expect(response.status).toBe(200);
      barrier = await response.json();
      expect(barrier).toEqual({ entered: 10, pending: 10 });
      expect(finished).toBe(false);
      paused = await snapshot(ctx);
      expect(paused).toEqual(before);
    } finally {
      await control(ctx, { action: "release" });
    }
    const listed = await pending;
    expect(listed.error).toBeNull();
    expect(listed.data!.apiKeys.map((row) => row.name)).toEqual(
      Array.from({ length: 12 }, (_, index) => `bounded-${String(index).padStart(2, "0")}`),
    );
    await control(ctx, { action: "drain" });
    const after = await snapshot(ctx);
    expect(after).toEqual(before);
    return {
      signup: s.signup,
      other: s.other,
      issued,
      before,
      barrier,
      paused,
      listed: ctx.snapshot(listed),
      after,
    };
  },
);
