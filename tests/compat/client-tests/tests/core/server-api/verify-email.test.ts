import { expect } from "bun:test";

import { z } from "zod";

import { compatScenario } from "../../../support/scenario";
import { issueSession } from "../../../support/server-session-revocation";
import { readUserState } from "../../../support/verification";

compatScenario(
  "server verifyEmail validates and changes only its proof owner without a physical request",
  async (ctx) => {
    const email = ctx.uniqueEmail("logical-verification-owner");
    const owner = await issueSession(ctx, "logical-verification-owner", email);
    const foreign = await issueSession(
      ctx,
      "logical-verification-foreign",
      ctx.uniqueEmail("logical-verification-foreign"),
    );
    const sent = await ctx.actor("verification-delivery").client.sendVerificationEmail({ email });
    expect(sent.error).toBeNull();
    const delivery = await ctx.rawRequest({
      path: `/__test/verification-email?email=${encodeURIComponent(email)}`,
    });
    expect(delivery.status).toBe(200);
    const proof = z.object({ token: z.string(), url: z.string() }).parse(delivery.body);
    async function state() {
      return {
        owner: await readUserState(ctx, owner.result.data!.user.id),
        foreign: await readUserState(ctx, foreign.result.data!.user.id),
      };
    }
    const schema = z
      .object({
        result: z
          .object({
            ok: z.boolean(),
            status: z.number().nullable().optional(),
            body: z.unknown().optional(),
            headers: z.record(z.string(), z.string()).nullable().optional(),
            value: z
              .object({ response: z.unknown(), headers: z.record(z.string(), z.string()) })
              .passthrough()
              .optional(),
          })
          .passthrough(),
        events: z.array(
          z
            .object({
              stage: z.string(),
              path: z.string().nullable(),
              request: z.unknown(),
              session: z.unknown(),
            })
            .passthrough(),
        ),
      })
      .passthrough();
    async function invoke(query: unknown) {
      const response = await ctx.rawRequest({
        path: "/__test/server-dispatch-cache/call",
        method: "POST",
        json: { operation: "verifyEmail", query },
      });
      expect(response.status).toBe(200);
      return schema.parse(response.body);
    }
    const before = await state();
    expect(before.owner.user!.emailVerified).toBe(false);
    const malformed = [];
    for (const query of [
      {},
      null,
      { token: null },
      { token: 7 },
      { token: proof.token, callbackURL: null },
      { token: proof.token, callbackURL: 7 },
    ]) {
      const rejected = await invoke(query);
      expect(rejected.result.status).toBe(400);
      expect(rejected.result.body).toMatchObject({ code: "VALIDATION_ERROR" });
      malformed.push(rejected);
    }
    const invalid = await invoke({ token: "not.a.token" });
    expect(invalid.result.status).toBe(401);
    expect(invalid.result.body).toEqual({ code: "INVALID_TOKEN", message: "Invalid token" });
    expect(await state()).toEqual(before);
    const verified = await invoke({
      token: proof.token,
      callbackURL: "",
      userId: foreign.result.data!.user.id,
    });
    expect(verified.result.ok).toBe(true);
    expect(verified.result.value!.response).toEqual({ status: true, user: null });
    expect(verified.result.value!.headers["set-cookie"]).toBeUndefined();
    const hook = verified.events.find((e) => e.stage === "user-after")!;
    expect(hook.path).toBe("/verify-email");
    expect(hook.request).toBeNull();
    expect(hook.session).toBeNull();
    const after = await state();
    expect(after.owner.user!.emailVerified).toBe(true);
    expect({
      ...after.owner.user,
      emailVerified: false,
      updatedAt: before.owner.user!.updatedAt,
    }).toEqual({ ...before.owner.user!, updatedAt: before.owner.user!.updatedAt });
    expect(after.owner.accounts).toEqual(before.owner.accounts);
    expect(after.owner.sessions).toEqual(before.owner.sessions);
    expect(after.foreign).toEqual(before.foreign);
    const replay = await invoke({ token: proof.token });
    expect(replay.result.value!.response).toEqual({ status: true, user: null });
    expect(replay.result.value!.headers["set-cookie"]).toBeUndefined();
    const redirected = await invoke({
      token: proof.token,
      callbackURL: "https://external.example/done?kept=1#verified",
    });
    expect(redirected.result.status).toBe(302);
    expect(redirected.result.body).toBeNull();
    expect(redirected.result.headers!.location).toBe(
      "https://external.example/done?kept=1#verified",
    );
    const failureRedirect = await invoke({
      token: "not.a.token",
      callbackURL: "/done?kept=1#verified",
    });
    expect(failureRedirect.result.status).toBe(302);
    expect(failureRedirect.result.body).toBeNull();
    expect(failureRedirect.result.headers!.location).toBe(
      "/done?kept=1&error=INVALID_TOKEN#verified",
    );
    expect(await state()).toEqual(after);
    return ctx.snapshot({
      owner,
      foreign,
      sent,
      delivery,
      before,
      malformed,
      invalid,
      verified,
      after,
      replay,
      redirected,
      failureRedirect,
    });
  },
  [],
  30_000,
);
