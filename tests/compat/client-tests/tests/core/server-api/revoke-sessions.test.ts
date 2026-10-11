import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { issueSession, revocationObservation } from "../../../support/server-session-revocation";
import { readUserState } from "../../../support/verification";

compatScenario(
  "logical revokeSessions deletes every owned row and rejects cached authority",
  async (ctx) => {
    const profile = "server-dispatch-cache";
    const ownerEmail = ctx.uniqueEmail("logical-revoke-all-owner");
    const owner = await issueSession(ctx, "owner", ownerEmail);
    const active = await issueSession(ctx, "active", ownerEmail, true);
    const expired = await issueSession(ctx, "expired", ownerEmail, true);
    const foreign = await issueSession(
      ctx,
      "foreign",
      ctx.uniqueEmail("logical-revoke-all-foreign"),
    );
    const expiredAt = "2020-01-01T00:00:00.000Z";
    const clock = await ctx.rawRequest({
      path: "/__test/expire-session",
      method: "POST",
      json: { token: expired.result.data!.token, expiresAt: expiredAt },
    });
    expect(clock.body).toEqual({ updated: 1 });
    async function state() {
      return {
        owner: await readUserState(ctx, owner.result.data!.user.id),
        foreign: await readUserState(ctx, foreign.result.data!.user.id),
      };
    }
    async function invoke(headers?: Record<string, string>) {
      const result = await ctx.rawRequest({
        path: `/__test/${profile}/call`,
        method: "POST",
        json: {
          operation: "revokeSessions",
          body: { token: foreign.result.data!.token },
          query: { disableRefresh: true },
          ...(headers === undefined ? {} : { headers }),
        },
      });
      expect(result.status).toBe(200);
      return revocationObservation.parse(result.body);
    }
    const before = await state();
    const missingHeaders = await invoke();
    expect(missingHeaders.result.status).toBe(400);
    expect(missingHeaders.result.body!.message).toBe("Headers is required");
    const guest = await invoke({});
    expect(guest.result.status).toBe(401);
    expect(guest.result.body!.code).toBe("UNAUTHORIZED");
    expect(await state()).toEqual(before);
    const revoked = await invoke(owner.headers);
    expect(revoked.result.value!.response).toEqual({ status: true });
    expect(revoked.result.value!.headers["set-cookie"]).toBeUndefined();
    const after = await state();
    expect(after.owner.sessions).toEqual([]);
    expect(after.owner.user).toEqual(before.owner.user);
    expect(after.owner.accounts).toEqual(before.owner.accounts);
    expect(after.foreign).toEqual(before.foreign);
    const hook = revoked.events.find((event) => event.stage === "user-after")!;
    expect(hook.path).toBe("/revoke-sessions");
    expect(hook.request).toBeNull();
    expect(hook.session!.user.id).toBe(owner.result.data!.user.id);
    const stale = await invoke(active.headers);
    expect(stale.result.status).toBe(401);
    expect(stale.result.body!.code).toBe("UNAUTHORIZED");
    expect(await state()).toEqual(after);
    const staleOwner = await invoke(owner.headers);
    expect(staleOwner.result.status).toBe(401);
    expect(staleOwner.result.body!.code).toBe("UNAUTHORIZED");
    expect(await state()).toEqual(after);
    return {
      owner,
      active,
      expired,
      foreign,
      clock,
      before,
      missingHeaders,
      guest,
      revoked,
      after,
      stale,
      staleOwner,
    };
  },
);
