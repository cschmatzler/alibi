import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
import { issueSession, revocationObservation } from "../../../support/server-session-revocation";
import { readUserState } from "../../../support/verification";

compatScenario(
  "pathless server setPassword owns credential creation and logical hook admission",
  async (ctx) => {
    const profile = "server-dispatch-cache";
    const email = ctx.uniqueEmail("logical-set-owner");
    const owner = await issueSession(ctx, "logical-set-owner", email);
    const sibling = await issueSession(ctx, "logical-set-sibling", email, true);
    const foreign = await issueSession(
      ctx,
      "logical-set-foreign",
      ctx.uniqueEmail("logical-set-foreign"),
    );
    const removed = await ctx.removeCredentialAccount({ email });
    const password = "replacement-password-205";
    async function state() {
      return {
        owner: await readUserState(ctx, owner.result.data!.user.id),
        foreign: await readUserState(ctx, foreign.result.data!.user.id),
      };
    }
    async function invoke(body: unknown, cookie?: string) {
      const result = await ctx.rawRequest({
        path: `/__test/${profile}/call`,
        method: "POST",
        json: {
          operation: "setPassword",
          body,
          query: { disableRefresh: true },
          ...(cookie === undefined ? {} : { headers: { cookie } }),
        },
      });
      expect(result.status).toBe(200);
      return revocationObservation
        .extend({
          result: revocationObservation.shape.result.extend({
            value: revocationObservation.shape.result.shape.value.unwrap().passthrough().optional(),
          }),
        })
        .passthrough()
        .parse(result.body);
    }
    const before = await state();
    expect(before.owner.accounts).toHaveLength(0);
    const malformed = [];
    for (const body of [{}, { newPassword: null }, { newPassword: 7 }]) {
      const denial = await invoke(body);
      expect(denial.result.status).toBe(400);
      expect(denial.result.body!.code).toBe("VALIDATION_ERROR");
      malformed.push(denial);
    }
    const guest = await invoke({ newPassword: password });
    expect(guest.result.status).toBe(401);
    expect(guest.result.body!.code).toBe("UNAUTHORIZED");
    const short = await invoke({ newPassword: "short" }, owner.headers.cookie);
    expect(short.result.status).toBe(400);
    expect(short.result.body!.code).toBe("PASSWORD_TOO_SHORT");
    expect(await state()).toEqual(before);
    const set = await invoke(
      { newPassword: password, userId: foreign.result.data!.user.id },
      owner.headers.cookie,
    );
    expect(set.result.ok).toBe(true);
    expect(set.result.value!.response).toEqual({ status: true });
    expect(set.result.value!.headers["set-cookie"]).toBeUndefined();
    const admitted = set.events.find((e) => e.stage === "user-after")!;
    expect(admitted.path).toBe("/");
    expect(admitted.request).toBeNull();
    expect(admitted.session!.user.id).toBe(owner.result.data!.user.id);
    expect(admitted).toMatchObject({ body: { newPassword: password } });
    const after = await state();
    expect(after.owner.user).toEqual(before.owner.user);
    expect(after.owner.sessions).toEqual(before.owner.sessions);
    expect(after.foreign).toEqual(before.foreign);
    expect(after.owner.accounts).toHaveLength(1);
    expect(after.owner.accounts[0]).toMatchObject({
      providerId: "credential",
      userId: owner.result.data!.user.id,
      accountId: owner.result.data!.user.id,
    });
    const duplicate = await invoke({ newPassword: "another-password-205" }, sibling.headers.cookie);
    expect(duplicate.result.status).toBe(400);
    expect(duplicate.result.body!.code).toBe("PASSWORD_ALREADY_SET");
    expect(await state()).toEqual(after);
    const signout = await ctx.actor("logical-set-owner", profile).client.signOut();
    expect(signout.error).toBeNull();
    const revokedBefore = await state();
    const revoked = await invoke({ newPassword: "another-password-205" }, owner.headers.cookie);
    expect(revoked.result.status).toBe(401);
    expect(revoked.result.body!.code).toBe("UNAUTHORIZED");
    expect(await state()).toEqual(revokedBefore);
    const login = await ctx
      .actor("logical-set-new-login", profile)
      .client.signIn.email({ email, password });
    expect(login.error).toBeNull();
    expect(login.data!.user.id).toBe(owner.result.data!.user.id);
    const http = await ctx.rawRequest({
      path: `/__test/profiles/${profile}/api/auth/set-password`,
      method: "POST",
      headers: { cookie: sibling.headers.cookie },
      json: { newPassword: password },
    });
    expect(http.status).toBe(404);
    return {
      owner,
      sibling,
      foreign,
      removed,
      before,
      malformed,
      guest,
      short,
      set,
      after,
      duplicate,
      signout,
      revokedBefore,
      revoked,
      login,
      http,
    };
  },
  [],
  30_000,
  {
    oracle: {
      unroutedRequests:
        "asserts that the pathless server-only operation has no public set-password route",
    },
  },
);
