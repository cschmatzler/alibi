import { expect } from "vitest";
import { z } from "zod";

import { compatScenario } from "../../../support/scenario";
import { issueSession } from "../../../support/server-session-revocation";
import { readUserState } from "../../../support/verification";
const session = z
  .object({
    id: z.string(),
    token: z.string(),
    userId: z.string(),
    expiresAt: z.string(),
    createdAt: z.string(),
    updatedAt: z.string(),
    ipAddress: z.string().nullable(),
    userAgent: z.string().nullable(),
  })
  .passthrough();
const observation = z.object({
  result: z
    .object({
      ok: z.boolean(),
      status: z.number().optional(),
      body: z
        .object({ code: z.string().optional(), message: z.string().optional() })
        .passthrough()
        .optional(),
      value: z
        .object({ response: z.array(session), headers: z.record(z.string(), z.string()) })
        .optional(),
    })
    .passthrough(),
  events: z.array(
    z
      .object({
        stage: z.string(),
        path: z.string().nullable(),
        request: z.unknown(),
        session: z
          .object({ user: z.object({ id: z.string() }), session: session })
          .passthrough()
          .nullable(),
      })
      .passthrough(),
  ),
});
compatScenario(
  "logical listSessions uses cached freshness and returns only active owned physical sessions",
  async (ctx) => {
    const ownerEmail = ctx.uniqueEmail("logical-list-owner");
    const owner = await issueSession(ctx, "owner", ownerEmail);
    const active = await issueSession(ctx, "active", ownerEmail, true);
    const expired = await issueSession(ctx, "expired", ownerEmail, true);
    const foreign = await issueSession(ctx, "foreign", ctx.uniqueEmail("logical-list-foreign"));
    const ownerToken = z.string().parse(owner.result.data!.token);
    const activeToken = z.string().parse(active.result.data!.token);
    const expiredToken = z.string().parse(expired.result.data!.token);
    const foreignToken = z.string().parse(foreign.result.data!.token);
    const old = "2020-01-01T00:00:00.000Z";
    async function clock(token: string, expiresAt: string, createdAt?: string) {
      const result = await ctx.rawRequest({
        path: "/__test/expire-session",
        method: "POST",
        json: { token, expiresAt, ...(createdAt === undefined ? {} : { createdAt }) },
      });
      expect(result.body).toEqual({ updated: 1 });
      return result;
    }
    const expiredClock = await clock(expiredToken, old);
    async function state() {
      return {
        owner: await readUserState(ctx, owner.result.data!.user.id),
        foreign: await readUserState(ctx, foreign.result.data!.user.id),
      };
    }
    async function invoke(headers?: Record<string, string>, disableCookieCache = false) {
      const result = await ctx.rawRequest({
        path: "/__test/server-dispatch-cache/call",
        method: "POST",
        json: {
          operation: "listSessions",
          query: { disableRefresh: true, disableCookieCache },
          ...(headers === undefined ? {} : { headers }),
        },
      });
      expect(result.status).toBe(200);
      return observation.parse(result.body);
    }
    const before = await state();
    expect(before.owner.sessions).toHaveLength(3);
    const missingHeaders = await invoke();
    expect(missingHeaders.result.status).toBe(400);
    expect(missingHeaders.result.body!.message).toBe("Headers is required");
    const guest = await invoke({});
    expect(guest.result.status).toBe(401);
    expect(guest.result.body!.code).toBe("UNAUTHORIZED");
    const listed = await invoke(owner.headers);
    expect(listed.result.ok).toBe(true);
    expect(listed.result.value!.response.map((row) => row.token).sort()).toEqual(
      [ownerToken, activeToken].sort(),
    );
    expect(
      listed.result.value!.response.every((row) => row.userId === owner.result.data!.user.id),
    ).toBe(true);
    const hook = listed.events.find((event) => event.stage === "user-after")!;
    expect(hook.path).toBe("/list-sessions");
    expect(hook.request).toBeNull();
    expect(hook.session!.user.id).toBe(owner.result.data!.user.id);
    expect(await state()).toEqual(before);
    const ownerRow = listed.result.value!.response.find((row) => row.token === ownerToken)!;
    const agedClock = await clock(ownerToken, ownerRow.expiresAt, old);
    const aged = await state();
    const cached = await invoke(owner.headers);
    expect(cached.result.ok).toBe(true);
    expect(cached.result.value!.response.find((row) => row.token === ownerToken)!.createdAt).toBe(
      old,
    );
    const stale = await invoke(owner.headers, true);
    expect(stale.result.status).toBe(403);
    expect(stale.result.body!.code).toBe("SESSION_NOT_FRESH");
    expect(await state()).toEqual(aged);
    const ownerExpiredClock = await clock(ownerToken, old, old);
    const ownerExpired = await state();
    const cachedExpired = await invoke(owner.headers);
    expect(cachedExpired.result.ok).toBe(true);
    expect(cachedExpired.result.value!.response.map((row) => row.token)).toEqual([activeToken]);
    const absent = await invoke(owner.headers, true);
    expect(absent.result.status).toBe(401);
    expect(absent.result.body!.code).toBe("UNAUTHORIZED");
    const afterExpiredLookup = await state();
    expect(afterExpiredLookup.owner.sessions).toEqual(
      ownerExpired.owner.sessions.filter((row) => row.token !== ownerToken),
    );
    expect(afterExpiredLookup.owner.user).toEqual(ownerExpired.owner.user);
    expect(afterExpiredLookup.owner.accounts).toEqual(ownerExpired.owner.accounts);
    expect(afterExpiredLookup.foreign).toEqual(ownerExpired.foreign);
    const foreignList = await invoke(foreign.headers);
    expect(foreignList.result.value!.response.map((row) => row.token)).toEqual([foreignToken]);
    return {
      owner,
      active,
      expired,
      foreign,
      expiredClock,
      before,
      missingHeaders,
      guest,
      listed,
      agedClock,
      aged,
      cached,
      stale,
      ownerExpiredClock,
      ownerExpired,
      cachedExpired,
      absent,
      foreignList,
      afterExpiredLookup,
    };
  },
);
