import { expect } from "bun:test";

import { z } from "zod";

import { compatScenario } from "../../../support/scenario";

const delivery = z.object({ token: z.string().min(1), url: z.string().url() });

compatScenario(
  "reset password prefers a nonempty body proof over another owner's live query proof",
  async (ctx) => {
    await ctx.setResetPasswordMode("capture");
    const original = "originalPassword123!";
    const replacement = "bodyReplacement123!";
    const bodyOwner = ctx.actor("body-owner");
    const queryOwner = ctx.actor("query-owner");
    const bodyEmail = ctx.uniqueEmail("reset-body-owner");
    const queryEmail = ctx.uniqueEmail("reset-query-owner");
    const bodySignup = await bodyOwner.client.signUp.email({
      email: bodyEmail,
      password: original,
      name: "Body owner",
    });
    const querySignup = await queryOwner.client.signUp.email({
      email: queryEmail,
      password: original,
      name: "Query owner",
    });
    expect(bodySignup.error).toBeNull();
    expect(querySignup.error).toBeNull();
    async function delivered(email: string) {
      const requested = await ctx.actor("reset-guest").client.requestPasswordReset({ email });
      expect(requested.error).toBeNull();
      const response = await ctx.rawRequest({
        path: `/__test/reset-password-token?email=${encodeURIComponent(email)}`,
      });
      expect(response.status).toBe(200);
      return delivery.parse(response.body);
    }
    const bodyProof = await delivered(bodyEmail);
    const queryProof = await delivered(queryEmail);
    const queryBefore = await ctx.readUserState({ userId: querySignup.data!.user.id });
    const proofBefore = await ctx.readVerificationState({
      identifier: `reset-password:${queryProof.token}`,
    });
    const reset = await ctx.rawRequest({
      path: `/api/auth/reset-password?token=${encodeURIComponent(queryProof.token)}`,
      method: "POST",
      json: { token: bodyProof.token, newPassword: replacement },
    });
    expect(reset.status).toBe(200);
    expect(reset.body).toEqual({ status: true });
    expect(await ctx.readUserState({ userId: querySignup.data!.user.id })).toEqual(queryBefore);
    expect(
      await ctx.readVerificationState({ identifier: `reset-password:${queryProof.token}` }),
    ).toEqual(proofBefore);
    expect(
      await ctx.readVerificationState({ identifier: `reset-password:${bodyProof.token}` }),
    ).toEqual([]);
    expect((await bodyOwner.client.getSession()).data?.user.id).toBe(bodySignup.data!.user.id);
    expect((await queryOwner.client.getSession()).data?.user.id).toBe(querySignup.data!.user.id);
    const oldLogin = await ctx
      .actor("body-old-login")
      .client.signIn.email({ email: bodyEmail, password: original });
    expect(oldLogin.error?.status).toBe(401);
    const newLogin = await ctx
      .actor("body-new-login")
      .client.signIn.email({ email: bodyEmail, password: replacement });
    expect(newLogin.error).toBeNull();
    expect(newLogin.data?.user.id).toBe(bodySignup.data!.user.id);
    const queryLogin = await ctx
      .actor("query-old-login")
      .client.signIn.email({ email: queryEmail, password: original });
    expect(queryLogin.error).toBeNull();
    expect(queryLogin.data?.user.id).toBe(querySignup.data!.user.id);
    const queryReset = await ctx
      .actor("query-reset-guest")
      .client.resetPassword({ token: queryProof.token, newPassword: "queryReplacement123!" });
    expect(queryReset.error).toBeNull();
    const queryNewLogin = await ctx
      .actor("query-new-login")
      .client.signIn.email({ email: queryEmail, password: "queryReplacement123!" });
    expect(queryNewLogin.error).toBeNull();
    expect(queryNewLogin.data?.user.id).toBe(querySignup.data!.user.id);
    return ctx.snapshot({
      bodySignup,
      querySignup,
      bodyProof,
      queryProof,
      reset,
      queryBefore,
      proofBefore: z
        .array(z.object({ identifier: z.string(), value: z.string() }).passthrough())
        .parse(proofBefore)
        .map((row) => ({
          ...row,
          identifier: {
            namespace: "reset-password:",
            token: row.identifier.slice("reset-password:".length),
          },
          value: { userId: row.value },
        })),
      oldLogin,
      newLogin,
      queryLogin,
      queryReset,
      queryNewLogin,
    });
  },
  ["POST /reset-password", "POST /request-password-reset", "POST /sign-in/email"],
);
