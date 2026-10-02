import { expect } from "bun:test";

import { apiKeyClient } from "@better-auth/api-key/client";
import { createAuthClient } from "better-auth/client";
import { z } from "zod";

import { compatScenario, type ScenarioContext } from "../../../support/scenario";

async function control(ctx: ScenarioContext, json: Record<string, unknown>) {
  const response = await ctx.rawRequest({
    path: "/__test/api-key-background/control",
    method: "POST",
    json,
  });
  expect(response.status).toBe(200);
  return response.body;
}

const stateSchema = z.array(
  z
    .object({
      id: z.string(),
      referenceId: z.string(),
      remaining: z.number().nullable(),
      requestCount: z.number(),
      lastRefillAt: z.string().nullable(),
      lastRequest: z.string().nullable(),
      updatedAt: z.string(),
    })
    .passthrough(),
);

async function state(ctx: ScenarioContext) {
  const response = await ctx.rawRequest({ path: "/__test/api-key-background/state?usage=true" });
  expect(response.status).toBe(200);
  return stateSchema.parse(response.body);
}

type Profile = "api-key-usage-rate" | "api-key-usage-rate-deferred";

async function setup(ctx: ScenarioContext, profile: Profile) {
  await control(ctx, { action: "reset" });
  await control(ctx, { action: "usage-restore" });
  const client = (name: string) =>
    createAuthClient({
      baseURL: `${ctx.baseURL}/__test/profiles/${profile}/api/auth`,
      plugins: [apiKeyClient()],
      fetchOptions: { customFetchImpl: ctx.actor(name, profile).fetch },
    });
  const owner = client("phase-owner");
  const foreign = client("phase-foreign");
  const signup = await owner.signUp.email({
    name: "Phase Owner",
    email: ctx.uniqueEmail("phase-owner"),
    password: "password123",
  });
  expect(signup.error).toBeNull();

  const other = await foreign.signUp.email({
    name: "Phase Foreign",
    email: ctx.uniqueEmail("phase-foreign"),
    password: "password123",
  });
  expect(other.error).toBeNull();

  const force = await ctx.rawRequest({
    path: `/__test/api-key-background/cleanup?profile=${profile}`,
    method: "POST",
  });
  expect(force.body).toEqual({ success: true, error: null });

  const target = await owner.apiKey.create({ name: "phase-target" });
  const retained = await foreign.apiKey.create({ name: "phase-foreign" });
  expect(target.error).toBeNull();
  expect(retained.error).toBeNull();

  if (!signup.data || !other.data || !target.data || !retained.data) {
    throw new Error("actual owners and keys required");
  }

  const originalToken = signup.data.token;

  if (typeof originalToken !== "string") {
    throw new Error("actual signup session required");
  }

  const denied = await foreign.apiKey.get({ query: { id: target.data.id } });
  expect(denied.error).not.toBeNull();

  await control(ctx, { action: "phase-refill", keyId: target.data.id });
  const before = await state(ctx);
  const selected = before.find((row) => row.id === target.data!.id)!;
  expect(selected).toMatchObject({
    remaining: 0,
    refillAmount: 3,
    refillInterval: 60000,
    rateLimitEnabled: true,
    rateLimitMax: 3,
    rateLimitTimeWindow: 60000,
    requestCount: 0,
    lastRequest: null,
  });
  expect(Date.parse(z.string().parse(selected.lastRefillAt))).toBe(0);

  const ownerBefore = await ctx.readUserState({ userId: signup.data.user.id });
  const foreignBefore = await ctx.readUserState({ userId: other.data.user.id });
  const verify = async (permissions?: Record<string, string[]>) =>
    ctx.rawRequest({
      path: `/__test/api-key-background/verify?profile=${profile}`,
      method: "POST",
      json: { key: target.data!.key, ...(permissions ? { permissions } : {}) },
    });
  const permission = await verify({ resource: ["read"] });
  expect(permission.body).toEqual({
    valid: false,
    error: { code: "KEY_NOT_FOUND", message: "API Key not found" },
    key: null,
  });
  expect(await state(ctx)).toEqual(before);

  return {
    owner,
    foreign,
    signup,
    other,
    force,
    target,
    retained,
    denied,
    permission,
    before,
    selected,
    ownerBefore,
    foreignBefore,
    verify,
    originalToken,
  };
}

for (const profile of ["api-key-usage-rate", "api-key-usage-rate-deferred"] as const) {
  for (const phase of ["rate", "final"] as const) {
    compatScenario(
      `api-key ${profile} ${phase} SQL failure retains genuine prior quota phases and owner-safe retry`,
      async (ctx) => {
        const {
          owner,
          signup,
          other,
          force,
          target,
          retained,
          denied,
          permission,
          before,
          selected,
          ownerBefore,
          foreignBefore,
          verify,
          originalToken,
        } = await setup(ctx, profile);
        await control(ctx, { action: "usage-veto", phase });
        const trusted = await verify();
        expect(trusted.body).toEqual({
          valid: false,
          error: {
            code: "INVALID_API_KEY",
            message: { code: "INVALID_API_KEY", message: "Invalid API key." },
          },
          key: null,
        });

        const afterTrusted = await state(ctx);
        const first = afterTrusted.find((row) => row.id === target.data!.id)!;
        expect(first.remaining).toBe(2);
        expect(first.lastRefillAt).not.toBe(selected.lastRefillAt);

        z.iso.datetime({ offset: true }).parse(first.lastRefillAt);
        expect(first.updatedAt).toBe(selected.updatedAt);
        expect(first.requestCount).toBe(phase === "rate" ? 0 : 1);
        expect(first.lastRequest === null).toBe(phase === "rate");
        expect(afterTrusted.find((row) => row.id === retained.data!.id)).toEqual(
          before.find((row) => row.id === retained.data!.id),
        );

        const middleware = await owner.getSession({
          fetchOptions: { headers: { "x-api-key": target.data!.key } },
        });
        expect(middleware.error?.status).toBe(500);

        const afterMiddleware = await state(ctx);
        const second = afterMiddleware.find((row) => row.id === target.data!.id)!;
        expect(second).toMatchObject({
          remaining: 1,
          lastRefillAt: first.lastRefillAt,
          updatedAt: selected.updatedAt,
          requestCount: phase === "rate" ? 0 : 2,
        });

        const failedEvents = await control(ctx, { action: "configure", observer: "observe" });
        expect(
          z
            .array(z.object({ kind: z.string() }).passthrough())
            .parse(failedEvents)
            .filter((event) => event.kind === "background-register"),
        ).toEqual([]);

        await control(ctx, { action: "usage-restore" });
        const retry = await verify();
        expect(retry.body).toMatchObject({
          valid: true,
          error: null,
          key: {
            id: target.data!.id,
            referenceId: signup.data!.user.id,
            remaining: 0,
            lastRefillAt: first.lastRefillAt,
            requestCount: phase === "rate" ? 1 : 3,
          },
        });

        const exhausted = await verify();
        expect(exhausted.body).toEqual({
          valid: false,
          error: { code: "USAGE_EXCEEDED", message: "API Key has reached its usage limit" },
          key: null,
        });

        const after = await state(ctx);
        expect(after.find((row) => row.id === retained.data!.id)).toEqual(
          before.find((row) => row.id === retained.data!.id),
        );

        const row = after.find((row) => row.id === target.data!.id)!;
        const returned = z
          .object({ key: z.object({ updatedAt: z.string(), lastRequest: z.string() }) })
          .parse(retry.body);
        expect(row.updatedAt).toBe(returned.key.updatedAt);
        expect(row.lastRequest).toBe(returned.key.lastRequest);
        expect(row.remaining).toBe(0);

        const current = await owner.getSession();
        expect(current.error).toBeNull();
        expect(current.data?.session.token).toBe(originalToken);
        expect(current.data?.user.id).toBe(signup.data!.user.id);
        expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(ownerBefore);
        expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(foreignBefore);

        return ctx.snapshot({
          signup,
          other,
          force,
          target,
          retained,
          denied,
          permission,
          before,
          ownerBefore,
          foreignBefore,
          trusted,
          afterTrusted,
          middleware,
          afterMiddleware,
          failedEvents,
          retry,
          exhausted,
          after,
          current,
          ownerAfter: await ctx.readUserState({ userId: signup.data!.user.id }),
          foreignAfter: await ctx.readUserState({ userId: other.data!.user.id }),
        });
      },
      ["GET /get-session"],
    );
  }
}

compatScenario(
  "api-key final current-row reread retains genuine intervening target changes and original key owner",
  async (ctx) => {
    const fixture = await setup(ctx, "api-key-usage-rate-deferred");
    await control(ctx, { action: "usage-current-read" });
    const verified = await fixture.verify();
    expect(verified.body).toMatchObject({
      valid: true,
      error: null,
      key: {
        id: fixture.target.data!.id,
        referenceId: fixture.signup.data!.user.id,
        name: "current-row",
        remaining: 77,
        requestCount: 1,
      },
    });

    const after = await state(ctx);
    const row = after.find((value) => value.id === fixture.target.data!.id)!;
    expect(row).toMatchObject({
      name: "current-row",
      remaining: 77,
      requestCount: 1,
      referenceId: fixture.signup.data!.user.id,
    });

    const returned = z
      .object({
        key: z.object({ updatedAt: z.string(), lastRequest: z.string(), lastRefillAt: z.string() }),
      })
      .parse(verified.body);
    expect(row.updatedAt).toBe(returned.key.updatedAt);
    expect(row.lastRequest).toBe(returned.key.lastRequest);
    expect(row.lastRefillAt).toBe(returned.key.lastRefillAt);
    expect(after.find((value) => value.id === fixture.retained.data!.id)).toEqual(
      fixture.before.find((value) => value.id === fixture.retained.data!.id),
    );
    expect(await ctx.readUserState({ userId: fixture.signup.data!.user.id })).toEqual(
      fixture.ownerBefore,
    );
    expect(await ctx.readUserState({ userId: fixture.other.data!.user.id })).toEqual(
      fixture.foreignBefore,
    );

    const current = await fixture.owner.getSession();
    expect(current.error).toBeNull();
    expect(current.data?.session.token).toBe(fixture.originalToken);
    expect(current.data?.user.id).toBe(fixture.signup.data!.user.id);

    const { owner, foreign, verify, originalToken, ...observed } = fixture;
    return ctx.snapshot({
      ...observed,
      originalSession: { token: originalToken },
      verified,
      after,
      current,
      ownerAfter: await ctx.readUserState({ userId: fixture.signup.data!.user.id }),
      foreignAfter: await ctx.readUserState({ userId: fixture.other.data!.user.id }),
    });
  },
);
