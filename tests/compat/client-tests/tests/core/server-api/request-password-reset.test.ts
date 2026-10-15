import { expect } from "vitest";
import { z } from "zod";

import { compatScenario } from "../../../support/scenario";
import { issueSession, revocationObservation } from "../../../support/server-session-revocation";
import { readUserState, storedVerification } from "../../../support/verification";

compatScenario(
  "server requestPasswordReset delivers owned proofs without requiring session or physical request",
  async (ctx) => {
    await ctx.setResetPasswordMode("capture");
    const email = ctx.uniqueEmail("logical-delivery-owner");
    const missingEmail = ctx.uniqueEmail("logical-delivery-missing");
    const owner = await issueSession(ctx, "logical-delivery-owner", email);
    const foreign = await issueSession(
      ctx,
      "logical-delivery-foreign",
      ctx.uniqueEmail("logical-delivery-foreign"),
    );
    async function state() {
      return {
        owner: await readUserState(ctx, owner.result.data!.user.id),
        foreign: await readUserState(ctx, foreign.result.data!.user.id),
      };
    }
    const schema = revocationObservation
      .extend({
        result: revocationObservation.shape.result.extend({
          value: revocationObservation.shape.result.shape.value
            .unwrap()
            .extend({
              response: z.object({ status: z.boolean(), message: z.string() }).passthrough(),
            })
            .passthrough()
            .optional(),
        }),
      })
      .passthrough();
    async function invoke(body: unknown) {
      const response = await ctx.rawRequest({
        path: "/__test/server-dispatch-cache/call",
        method: "POST",
        json: { operation: "requestPasswordReset", body },
      });
      expect(response.status).toBe(200);
      return schema.parse(response.body);
    }
    const before = await state();
    const malformed = [];
    for (const body of [
      {},
      { email: null },
      { email: 7 },
      { email: "invalid" },
      { email, redirectTo: null },
      { email, redirectTo: 7 },
    ]) {
      const denied = await invoke(body);
      expect(denied.result.status).toBe(400);
      expect(denied.result.body!.code).toBe("VALIDATION_ERROR");
      malformed.push(denied);
    }
    const missing = await invoke({
      email: missingEmail,
      redirectTo: "https://external.example/reset",
    });
    expect(missing.result.ok).toBe(true);
    expect(missing.result.value!.response).toEqual({
      status: true,
      message: "If this email exists in our system, check your email for the reset link",
    });
    const noDelivery = await ctx.rawRequest({
      path: `/__test/reset-password-token?email=${encodeURIComponent(missingEmail)}`,
    });
    expect(noDelivery.status).toBe(404);
    expect(await state()).toEqual(before);
    const redirectTo = "https://external.example/reset?a=1#step";
    const sent = await invoke({ email, redirectTo, userId: foreign.result.data!.user.id });
    expect(sent.result.ok).toBe(true);
    expect(sent.result.value!.response).toEqual(missing.result.value!.response);
    expect(sent.result.value!.headers["set-cookie"]).toBeUndefined();
    const observed = sent.events.find((e) => e.stage === "user-after")!;
    expect(observed.path).toBe("/request-password-reset");
    expect(observed.request).toBeNull();
    expect(observed.session).toBeNull();
    const delivery = await ctx.rawRequest({
      path: `/__test/reset-password-token?email=${encodeURIComponent(email)}`,
    });
    expect(delivery.status).toBe(200);
    const proof = z
      .object({ token: z.string().length(24), url: z.string().url() })
      .parse(delivery.body);
    const link = new URL(proof.url);
    expect(link.pathname).toBe(
      `/__test/profiles/server-dispatch-cache/api/auth/reset-password/${proof.token}`,
    );
    expect(link.searchParams.get("callbackURL")).toBe(redirectTo);
    const rows = await storedVerification(ctx, `reset-password:${proof.token}`);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.value).toBe(owner.result.data!.user.id);
    expect(rows[0]!.identifier).toBe(`reset-password:${proof.token}`);
    const after = await state();
    expect(after).toEqual(before);
    const reset = await ctx
      .actor("logical-delivery-reset", "server-dispatch-cache")
      .client.resetPassword({
        token: proof.token,
        newPassword: "logical-delivery-replacement-205",
      });
    expect(reset.error).toBeNull();
    expect(await storedVerification(ctx, `reset-password:${proof.token}`)).toEqual([]);
    const login = await ctx
      .actor("logical-delivery-login", "server-dispatch-cache")
      .client.signIn.email({ email, password: "logical-delivery-replacement-205" });
    expect(login.error).toBeNull();
    expect(login.data!.user.id).toBe(owner.result.data!.user.id);
    expect(await readUserState(ctx, foreign.result.data!.user.id)).toEqual(before.foreign);
    return ctx.snapshot({
      owner,
      foreign,
      before,
      malformed,
      missing,
      noDelivery,
      sent,
      delivery,
      rows: rows.map((row) => ({
        ...row,
        identifier: {
          namespace: "reset-password:",
          token: row.identifier.slice("reset-password:".length),
        },
        value: { userId: row.value },
      })),
      after,
      reset,
      login,
    });
  },
  [],
  30_000,
);
