import { expect } from "bun:test";
import { apiKeyClient } from "@better-auth/api-key/client";
import { createAuthClient } from "better-auth/client";
import { z } from "zod";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { createTracingFetch, type TraceEntry } from "../../support/trace";

const profiles = ["api-key-automatic", "api-key-automatic-deferred"] as const;
const eventsSchema = z.array(z.object({ kind: z.string() }).passthrough());
const rowSchema = z
  .object({
    id: z.string(),
    referenceId: z.string(),
    remaining: z.number().nullable(),
    requestCount: z.number(),
    lastRefillAt: z.string().nullable(),
    lastRequest: z.string().nullable(),
    updatedAt: z.string(),
    refillAmount: z.number().nullable(),
    refillInterval: z.number().nullable(),
    rateLimitEnabled: z.boolean(),
  })
  .passthrough();
async function control(ctx: ScenarioContext, input: Record<string, unknown>) {
  const response = await ctx.rawRequest({
    path: "/__test/api-key-background/control",
    method: "POST",
    json: input,
  });
  expect(response.status).toBe(200);
  return eventsSchema.parse(response.body);
}
async function rows(ctx: ScenarioContext) {
  const response = await ctx.rawRequest({ path: "/__test/api-key-background/state?usage=true" });
  expect(response.status).toBe(200);
  return z.array(rowSchema).parse(response.body);
}
for (const profile of profiles)
  compatScenario(
    `api-key ${profile} successful database usage awaits actual refill and preserves non-due quota and foreign state`,
    async (ctx) => {
      await control(ctx, { action: "reset" });
      const make = (actor: string) =>
        createAuthClient({
          baseURL: `${ctx.baseURL}/__test/profiles/${profile}/api/auth`,
          plugins: [apiKeyClient()],
          fetchOptions: { customFetchImpl: ctx.actor(actor, profile).fetch },
        });
      const owner = make("usage-owner"),
        foreign = make("usage-foreign");
      const signup = await owner.signUp.email({
        name: "Usage Owner",
        email: ctx.uniqueEmail("usage-owner"),
        password: "password123",
      });
      expect(signup.error).toBeNull();
      const other = await foreign.signUp.email({
        name: "Usage Foreign",
        email: ctx.uniqueEmail("usage-foreign"),
        password: "password123",
      });
      expect(other.error).toBeNull();
      const force = await ctx.rawRequest({
        path: `/__test/api-key-background/cleanup?profile=${profile}`,
        method: "POST",
      });
      expect(force.body).toEqual({ success: true, error: null });
      const target = await owner.apiKey.create({ name: "usage-target" }),
        retained = await foreign.apiKey.create({ name: "usage-foreign" });
      expect(target.error).toBeNull();
      expect(retained.error).toBeNull();
      if (!signup.data || !other.data || !target.data || !retained.data)
        throw new Error("real identities and keys required");
      const denied = await foreign.apiKey.get({ query: { id: target.data.id } });
      expect(denied.error).not.toBeNull();
      await control(ctx, { action: "refill", keyId: target.data.id });
      const before = await rows(ctx),
        ownerBefore = await ctx.readUserState({ userId: signup.data.user.id }),
        foreignBefore = await ctx.readUserState({ userId: other.data.user.id });
      const selected = before.find((row) => row.id === target.data!.id)!;
      expect(selected).toMatchObject({
        remaining: 0,
        refillAmount: 3,
        refillInterval: 60000,
        rateLimitEnabled: false,
      });
      expect(Date.parse(z.string().parse(selected.lastRefillAt))).toBe(0);
      const verify = async (permissions?: Record<string, string[]>) =>
        ctx.rawRequest({
          path: `/__test/api-key-background/verify?profile=${profile}`,
          method: "POST",
          json: { key: target.data!.key, ...(permissions ? { permissions } : {}) },
        });
      const forbidden = await verify({ resource: ["read"] });
      expect(forbidden.body).toEqual({
        valid: false,
        error: { code: "KEY_NOT_FOUND", message: "API Key not found" },
        key: null,
      });
      expect(await rows(ctx)).toEqual(before);
      await control(ctx, {
        action: "configure",
        hold: true,
        observeUsage: true,
        observer: "observe",
      });
      const pendingEntries: TraceEntry[] = [],
        releaseEntries: TraceEntry[] = [];
      let finished = false;
      const pending = createTracingFetch(
        ctx.baseURL,
        "usage-verification",
        pendingEntries,
      )(`/__test/api-key-background/verify?profile=${profile}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ key: target.data.key }),
      }).then(async (response) => {
        finished = true;
        return { status: response.status, body: await response.json() };
      });
      let paused: ReturnType<typeof eventsSchema.parse>;
      try {
        paused = await control(ctx, { action: "wait", kind: "usage-enter", count: 1 });
        expect(finished).toBe(false);
        expect(await rows(ctx)).toEqual(before);
        expect(paused.filter((event) => event.kind === "usage-enter")).toEqual([
          { kind: "usage-enter", profile, serial: 2, key: { id: target.data.id } },
        ]);
        expect(paused.filter((event) => event.kind === "background-register")).toEqual([]);
      } finally {
        const released = await createTracingFetch(
          ctx.baseURL,
          "usage-release",
          releaseEntries,
        )("/__test/api-key-background/control", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ action: "release" }),
        });
        expect(released.status).toBe(200);
        eventsSchema.parse(await released.json());
      }
      const first = await pending;
      ctx.recordTransport([...pendingEntries, ...releaseEntries]);
      expect(first.status).toBe(200);
      expect(first.body).toMatchObject({
        valid: true,
        error: null,
        key: {
          id: target.data.id,
          referenceId: signup.data.user.id,
          remaining: 2,
          requestCount: 0,
          refillAmount: 3,
          refillInterval: 60000,
          rateLimitEnabled: false,
        },
      });
      const refilled = await rows(ctx),
        row = refilled.find((value) => value.id === target.data!.id)!;
      expect(row.lastRefillAt).not.toBe(selected.lastRefillAt);
      expect(row.lastRefillAt).toBe(first.body.key.lastRefillAt);
      expect(row.lastRequest).toBe(first.body.key.lastRequest);
      expect(row.updatedAt).toBe(first.body.key.updatedAt);
      expect(refilled.find((value) => value.id === retained.data!.id)).toEqual(
        before.find((value) => value.id === retained.data!.id),
      );
      await control(ctx, { action: "configure", observeUsage: true, observer: "observe" });
      const session = await owner.getSession({
        fetchOptions: { headers: { "x-api-key": target.data.key } },
      });
      expect(session.error).toBeNull();
      expect(session.data?.user.id).toBe(signup.data.user.id);
      expect(session.data?.session.userId).toBe(signup.data.user.id);
      const second = await rows(ctx);
      expect(second.find((value) => value.id === target.data!.id)).toMatchObject({
        remaining: 1,
        lastRefillAt: row.lastRefillAt,
        requestCount: 0,
      });
      const third = await verify();
      expect(third.body).toMatchObject({
        valid: true,
        error: null,
        key: {
          id: target.data.id,
          referenceId: signup.data.user.id,
          remaining: 0,
          lastRefillAt: row.lastRefillAt,
          requestCount: 0,
        },
      });
      const exhausted = await verify();
      expect(exhausted.body).toEqual({
        valid: false,
        error: { code: "USAGE_EXCEEDED", message: "API Key has reached its usage limit" },
        key: null,
      });
      const after = await rows(ctx);
      expect(after.find((value) => value.id === target.data!.id)).toMatchObject({
        remaining: 0,
        lastRefillAt: row.lastRefillAt,
      });
      expect(after.find((value) => value.id === retained.data!.id)).toEqual(
        before.find((value) => value.id === retained.data!.id),
      );
      expect(await ctx.readUserState({ userId: signup.data.user.id })).toEqual(ownerBefore);
      expect(await ctx.readUserState({ userId: other.data.user.id })).toEqual(foreignBefore);
      const events = await control(ctx, { action: "wait", kind: "usage-complete", count: 4 });
      expect(events.filter((event) => event.kind === "row-delete-enter")).toEqual([]);
      expect(events.filter((event) => event.kind === "cleanup-enter")).toHaveLength(1);
      return ctx.snapshot({
        signup,
        other,
        force,
        target,
        retained,
        denied,
        forbidden,
        before,
        ownerBefore,
        foreignBefore,
        paused: paused!,
        first,
        refilled,
        session,
        second,
        third,
        exhausted,
        after,
        events,
        ownerAfter: await ctx.readUserState({ userId: signup.data.user.id }),
        foreignAfter: await ctx.readUserState({ userId: other.data.user.id }),
      });
    },
    ["GET /get-session"],
  );
