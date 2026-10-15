import { expect } from "vitest";
import { z } from "zod";

import { cacheReceipt } from "../../../support/compact-cache-receipt";
import { compatScenario } from "../../../support/scenario";
import { readUserState } from "../../../support/verification";

const observation = z.object({
  result: z
    .object({
      ok: z.boolean(),
      status: z.number().optional(),
      body: z.object({ code: z.string().optional() }).passthrough().optional(),
      value: z
        .object({
          response: z.object({ status: z.boolean() }),
          headers: z.record(z.string(), z.string()),
        })
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
          .object({ user: z.object({ id: z.string() }) })
          .passthrough()
          .nullable(),
      })
      .passthrough(),
  ),
});
compatScenario(
  "server verifyPassword validates before admission and checks only genuine current owner authority",
  async (ctx) => {
    const profile = "server-dispatch-cache";
    const password = "Correct-Horse-Password-205";
    const foreignPassword = "Foreign-Horse-Password-205";
    async function issue(name: string, password: string) {
      let issuedHeaders = new Headers();
      const actor = ctx.actor(name, profile);
      const result = await actor.client.signUp.email({
        name,
        email: ctx.uniqueEmail(name),
        password,
        fetchOptions: {
          onSuccess({ response }) {
            issuedHeaders = new Headers(response.headers);
          },
        },
      });
      expect(result.error).toBeNull();
      const cookie = issuedHeaders
        .getSetCookie()
        .map((raw) => raw.split(";")[0])
        .join("; ");
      expect(cookie).toContain("better-auth.session_data=");
      return {
        actor,
        result,
        cookie,
        publication: {
          body: result.data,
          headers: Object.fromEntries(
            [...issuedHeaders].filter(([name]) => !["date", "content-length"].includes(name)),
          ),
          ...(await cacheReceipt(issuedHeaders)),
        },
      };
    }
    const owner = await issue("logical-verify-owner", password);
    const foreign = await issue("logical-verify-foreign", foreignPassword);
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
          operation: "verifyPassword",
          body,
          query: { disableRefresh: true },
          ...(cookie === undefined ? {} : { headers: { cookie } }),
        },
      });
      expect(result.status).toBe(200);
      return observation.parse(result.body);
    }
    const before = await state();
    const malformed = [];
    for (const body of [{}, { password: null }, { password: 7 }]) {
      const denial = await invoke(body);
      expect(denial.result.status).toBe(400);
      expect(denial.result.body!.code).toBe("VALIDATION_ERROR");
      malformed.push(denial);
    }
    const guest = await invoke({ password });
    expect(guest.result.status).toBe(401);
    expect(guest.result.body!.code).toBe("UNAUTHORIZED");
    const wrong = [];
    for (const [input, actor] of [
      ["wrong-password", owner],
      [foreignPassword, owner],
      [password, foreign],
    ] as const) {
      const denial = await invoke({ password: input }, actor.cookie);
      expect(denial.result.status).toBe(400);
      expect(denial.result.body!.code).toBe("INVALID_PASSWORD");
      wrong.push(denial);
    }
    const verified = [];
    for (const [input, actor] of [
      [password, owner],
      [foreignPassword, foreign],
    ] as const) {
      const value = await invoke({ password: input }, actor.cookie);
      expect(value.result.ok).toBe(true);
      expect(value.result.value!.response).toEqual({ status: true });
      expect(value.result.value!.headers["set-cookie"]).toBeUndefined();
      const after = value.events.find((event) => event.stage === "user-after")!;
      expect(after.path).toBe("/verify-password");
      expect(after.request).toBeNull();
      expect(after.session!.user.id).toBe(actor.result.data!.user.id);
      verified.push(value);
    }
    expect(await state()).toEqual(before);
    const signout = await owner.actor.client.signOut();
    expect(signout.error).toBeNull();
    const revokedBefore = await state();
    const revoked = await invoke({ password }, owner.cookie);
    expect(revoked.result.status).toBe(401);
    expect(revoked.result.body!.code).toBe("UNAUTHORIZED");
    expect(await state()).toEqual(revokedBefore);
    return {
      owner: {
        result: owner.result,
        publication: owner.publication,
        headers: { cookie: owner.cookie },
      },
      foreign: {
        result: foreign.result,
        publication: foreign.publication,
        headers: { cookie: foreign.cookie },
      },
      before,
      malformed,
      guest,
      wrong,
      verified,
      signout,
      revokedBefore,
      revoked,
    };
  },
);
