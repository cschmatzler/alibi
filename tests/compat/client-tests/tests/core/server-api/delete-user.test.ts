import { expect } from "bun:test";

import { splitSetCookieHeader } from "better-auth/cookies";
import { z } from "zod";

import { cacheReceipt } from "../../../support/compact-cache-receipt";
import { compatScenario } from "../../../support/scenario";
import { issueSession, revocationObservation } from "../../../support/server-session-revocation";
import { readUserState } from "../../../support/verification";

compatScenario(
  "server deleteUser removes only its authenticated owner and all owned sessions",
  async (ctx) => {
    const email = ctx.uniqueEmail("logical-delete-owner");
    const owner = await issueSession(ctx, "logical-delete-owner", email);
    const second = await issueSession(ctx, "logical-delete-second", email, true);
    const foreign = await issueSession(
      ctx,
      "logical-delete-foreign",
      ctx.uniqueEmail("logical-delete-foreign"),
    );
    const schema = revocationObservation
      .extend({
        result: revocationObservation.shape.result.extend({
          headers: z.record(z.string(), z.string()).nullable().optional(),
          value: revocationObservation.shape.result.shape.value
            .unwrap()
            .extend({
              response: z.object({ success: z.boolean(), message: z.string() }).passthrough(),
            })
            .passthrough()
            .optional(),
        }),
      })
      .passthrough();
    async function invoke(body: unknown, headers?: Record<string, string>) {
      const response = await ctx.rawRequest({
        path: "/__test/server-dispatch-cache/call",
        method: "POST",
        json: { operation: "deleteUser", body, headers },
      });
      expect(response.status).toBe(200);
      return schema.parse(response.body);
    }
    async function state() {
      return {
        owner: await readUserState(ctx, owner.result.data!.user.id),
        foreign: await readUserState(ctx, foreign.result.data!.user.id),
      };
    }
    const before = await state();
    expect(before.owner.sessions).toHaveLength(2);
    const malformed = [];
    for (const body of [null, [], { password: 7 }, { token: null }, { callbackURL: null }]) {
      const rejected = await invoke(body, owner.headers);
      expect(rejected.result.status).toBe(400);
      expect(rejected.result.body).toMatchObject({ code: "VALIDATION_ERROR" });
      malformed.push(rejected);
    }
    const guest = await invoke({});
    expect(guest.result.status).toBe(401);
    const wrong = await invoke({ password: "wrong-password" }, owner.headers);
    expect(wrong.result.status).toBe(400);
    expect(wrong.result.body).toEqual({ code: "INVALID_PASSWORD", message: "Invalid password" });
    const wrongHeaders = new Headers();
    for (const cookie of splitSetCookieHeader(wrong.result.headers!["set-cookie"]!)) {
      wrongHeaders.append("set-cookie", cookie);
    }
    const wrongPublication = await cacheReceipt(wrongHeaders);
    expect(wrongPublication.compactSessionCache.decoded!.user.id).toBe(owner.result.data!.user.id);
    expect(wrongPublication.compactSessionCache.decoded!.session.token).toBe(
      z.string().parse(owner.result.data!.token),
    );
    expect(await state()).toEqual(before);
    const deleted = await invoke(
      { password: "Correct-Horse-Password-205", userId: foreign.result.data!.user.id },
      owner.headers,
    );
    expect(deleted.result.ok).toBe(true);
    expect(deleted.result.value!.response).toEqual({ success: true, message: "User deleted" });
    for (const name of ["session_token", "session_data", "dont_remember"]) {
      expect(deleted.result.value!.headers["set-cookie"]).toContain(`better-auth.${name}=`);
      expect(deleted.result.value!.headers["set-cookie"]).toContain("Max-Age=0");
    }
    const hook = deleted.events.find((e) => e.stage === "user-after")!;
    expect(hook.path).toBe("/delete-user");
    expect(hook.request).toBeNull();
    expect(hook.session!.user.id).toBe(owner.result.data!.user.id);
    const after = await state();
    expect(after.owner.user).toBeNull();
    expect(after.owner.accounts).toEqual([]);
    expect(after.owner.sessions).toEqual([]);
    expect(after.foreign).toEqual(before.foreign);
    const replay = [];
    for (const headers of [owner.headers, second.headers]) {
      const rejected = await invoke({}, headers);
      expect(rejected.result.status).toBe(401);
      replay.push(rejected);
    }
    expect(await state()).toEqual(after);
    expect(
      (await ctx.actor("logical-delete-foreign", "server-dispatch-cache").client.getSession()).data!
        .user.id,
    ).toBe(foreign.result.data!.user.id);
    return ctx.snapshot({
      owner,
      second,
      foreign,
      before,
      malformed,
      guest,
      wrong,
      wrongPublication,
      deleted,
      after,
      replay,
    });
  },
  [],
  30_000,
);
