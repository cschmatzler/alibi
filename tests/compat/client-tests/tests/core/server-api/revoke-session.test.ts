import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { issueSession, revocationObservation } from "../../../support/server-session-revocation";
import { readUserState } from "../../../support/verification";

compatScenario(
  "logical revokeSession scopes deletion and rejects revoked cached authority",
  async (ctx) => {
    const profile = "server-dispatch-cache";
    const ownerEmail = ctx.uniqueEmail("logical-revoke-owner");
    const owner = await issueSession(ctx, "logical-revoke-owner", ownerEmail);
    const other = await issueSession(ctx, "logical-revoke-other", ownerEmail, true);
    const foreign = await issueSession(
      ctx,
      "logical-revoke-foreign",
      ctx.uniqueEmail("logical-revoke-foreign"),
    );
    async function state() {
      return {
        owner: await readUserState(ctx, owner.result.data!.user.id),
        foreign: await readUserState(ctx, foreign.result.data!.user.id),
      };
    }
    async function invoke(body: unknown, headers?: Record<string, string>) {
      const result = await ctx.rawRequest({
        path: `/__test/${profile}/call`,
        method: "POST",
        json: {
          operation: "revokeSession",
          body,
          query: { disableRefresh: true },
          ...(headers === undefined ? {} : { headers }),
        },
      });
      expect(result.status).toBe(200);
      return revocationObservation.parse(result.body);
    }
    const before = await state();
    const malformed = [];
    for (const body of [{}, { token: null }, { token: 7 }]) {
      const denied = await invoke(body);
      expect(denied.result.status).toBe(400);
      expect(denied.result.body!.code).toBe("VALIDATION_ERROR");
      expect(denied.result.body!.message).toContain("[body.token]");
      malformed.push(denied);
    }
    const missingHeaders = await invoke({ token: other.result.data!.token });
    expect(missingHeaders.result.status).toBe(400);
    expect(missingHeaders.result.body!.message).toBe("Headers is required");
    const guest = await invoke({ token: other.result.data!.token }, {});
    expect(guest.result.status).toBe(401);
    expect(guest.result.body!.code).toBe("UNAUTHORIZED");
    const noops = [];
    for (const token of [foreign.result.data!.token, "missing-session", ""]) {
      const noop = await invoke({ token }, owner.headers);
      expect(noop.result.value!.response).toEqual({ status: true });
      expect(noop.result.value!.headers["set-cookie"]).toBeUndefined();
      noops.push(noop);
    }
    expect(await state()).toEqual(before);
    const revoked = await invoke({ token: other.result.data!.token }, owner.headers);
    expect(revoked.result.value!.response).toEqual({ status: true });
    expect(revoked.result.value!.headers["set-cookie"]).toBeUndefined();
    const current = await state();
    expect(current.foreign).toEqual(before.foreign);
    expect(current.owner.user).toEqual(before.owner.user);
    expect(current.owner.accounts).toEqual(before.owner.accounts);
    expect(current.owner.sessions).toEqual(
      before.owner.sessions.filter((session) => session.token !== other.result.data!.token),
    );
    const after = revoked.events.find((event) => event.stage === "user-after")!;
    expect(after.path).toBe("/revoke-session");
    expect(after.request).toBeNull();
    expect(after.session!.user.id).toBe(owner.result.data!.user.id);
    const staleOther = await invoke({ token: foreign.result.data!.token }, other.headers);
    expect(staleOther.result.status).toBe(401);
    expect(staleOther.result.body!.code).toBe("UNAUTHORIZED");
    expect(await state()).toEqual(current);
    const selfRevoke = await invoke({ token: owner.result.data!.token }, owner.headers);
    expect(selfRevoke.result.value!.response).toEqual({ status: true });
    expect(selfRevoke.result.value!.headers["set-cookie"]).toBeUndefined();
    const final = await state();
    expect(final.owner.sessions).toEqual([]);
    expect(final.owner.user).toEqual(before.owner.user);
    expect(final.owner.accounts).toEqual(before.owner.accounts);
    expect(final.foreign).toEqual(before.foreign);
    const staleOwner = await invoke({ token: foreign.result.data!.token }, owner.headers);
    expect(staleOwner.result.status).toBe(401);
    expect(await state()).toEqual(final);
    return {
      owner,
      other,
      foreign,
      before,
      malformed,
      missingHeaders,
      guest,
      noops,
      revoked,
      current,
      staleOther,
      selfRevoke,
      final,
      staleOwner,
    };
  },
);
