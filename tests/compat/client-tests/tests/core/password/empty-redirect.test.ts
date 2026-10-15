import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "empty reset redirect delivers a redeemable proof and masks unknown email without weakening trust checks",
  async (ctx) => {
    const email = ctx.uniqueEmail("empty-reset-redirect-owner");
    const owner = ctx.actor("owner");
    const signup = await owner.client.signUp.email({
      email,
      password: "password123",
      name: "Owner",
    });
    expect(signup.error).toBeNull();
    const foreign = ctx.actor("foreign");
    const foreignSignup = await foreign.client.signUp.email({
      email: ctx.uniqueEmail("empty-reset-redirect-foreign"),
      password: "password123",
      name: "Foreign",
    });
    expect(foreignSignup.error).toBeNull();
    const before = await ctx.readUserState({ userId: signup.data!.user.id });
    const foreignBefore = await ctx.readUserState({ userId: foreignSignup.data!.user.id });
    const missingEmail = ctx.uniqueEmail("empty-reset-redirect-missing");
    const missing = await owner.client.requestPasswordReset({
      email: missingEmail,
      redirectTo: "",
    });
    expect(missing.error).toBeNull();
    const undelivered = await ctx.rawRequest({
      path: `/__test/reset-password-token?email=${encodeURIComponent(missingEmail)}`,
    });
    expect(undelivered.status).toBe(404);
    const sent = await owner.client.requestPasswordReset({ email, redirectTo: "" });
    expect(sent.error).toBeNull();
    expect(sent.data).toEqual(missing.data);
    const delivery = await ctx.rawRequest({
      path: `/__test/reset-password-token?email=${encodeURIComponent(email)}`,
    });
    expect(delivery.status).toBe(200);
    const proof = delivery.body as { url: string; token: string };
    expect(proof.token).toBeTypeOf("string");
    expect(new URL(proof.url).searchParams.get("callbackURL")).toBe("");
    const identifier = `reset-password:${proof.token}`;
    const proofBefore = await ctx.readVerificationState({ identifier });
    expect(proofBefore).toMatchObject([{ identifier, value: signup.data!.user.id }]);
    expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(before);
    const denied = await owner.client.requestPasswordReset({
      email,
      redirectTo: "https://foreign.fixture.test/reset",
    });
    expect(denied.error).toMatchObject({ status: 403, code: "INVALID_REDIRECT_URL" });
    expect(await ctx.readVerificationState({ identifier })).toEqual(proofBefore);
    expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(before);
    const reset = await owner.client.resetPassword({
      token: proof.token,
      newPassword: "replacementPassword123",
    });
    expect(reset.error).toBeNull();
    expect(await ctx.readVerificationState({ identifier })).toEqual([]);
    const replay = await owner.client.resetPassword({
      token: proof.token,
      newPassword: "neverInstalled123",
    });
    expect(replay.error).toMatchObject({ status: 400, code: "INVALID_TOKEN" });
    const oldPassword = await ctx
      .actor("old-password")
      .client.signIn.email({ email, password: "password123" });
    expect(oldPassword.error?.status).toBe(401);
    const newPassword = await ctx
      .actor("new-password")
      .client.signIn.email({ email, password: "replacementPassword123" });
    expect(newPassword.error).toBeNull();
    expect(newPassword.data!.user.id).toBe(signup.data!.user.id);
    expect(await ctx.readUserState({ userId: foreignSignup.data!.user.id })).toEqual(foreignBefore);
    const current = await owner.client.getSession();
    expect(signup.data!.token).toBeTypeOf("string");
    expect(current.data!.session.token).toBe(signup.data!.token!);
    return ctx.snapshot({
      signup,
      foreignSignup,
      missing,
      undelivered,
      sent,
      delivery,
      denied,
      reset,
      replay,
      oldPassword,
      newPassword,
      current,
    });
  },
  ["POST /request-password-reset", "POST /reset-password", "POST /sign-in/email"],
);
