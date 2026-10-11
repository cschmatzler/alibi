import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "missing reset callback query fails the required string schema before redirect or proof use",
  async (ctx) => {
    const email = ctx.uniqueEmail("required-reset-callback");
    const owner = ctx.actor("owner");
    const signup = await owner.client.signUp.email({
      email,
      password: "password123",
      name: "Owner",
    });
    expect(signup.error).toBeNull();
    const foreign = ctx.actor("foreign");
    const foreignSignup = await foreign.client.signUp.email({
      email: ctx.uniqueEmail("required-reset-callback-foreign"),
      password: "password123",
      name: "Foreign",
    });
    expect(foreignSignup.error).toBeNull();
    expect(
      (
        await owner.client.requestPasswordReset({
          email,
          redirectTo: "/reset?application=retained#details",
        })
      ).error,
    ).toBeNull();
    const delivery = await ctx.rawRequest({
      path: `/__test/reset-password-token?email=${encodeURIComponent(email)}`,
    });
    expect(delivery.status).toBe(200);
    const proof = delivery.body as { token: string; url: string };
    expect(proof.token).toBeString();
    const identifier = `reset-password:${proof.token}`;
    const proofBefore = await ctx.readVerificationState({ identifier });
    const before = await ctx.readUserState({ userId: signup.data!.user.id });
    const foreignBefore = await ctx.readUserState({ userId: foreignSignup.data!.user.id });
    const withoutCallback = new URL(proof.url);
    withoutCallback.searchParams.delete("callbackURL");
    const denied = await ctx.rawRequest({ path: withoutCallback.href, redirect: "manual" });
    expect(denied.status).toBe(400);
    expect(denied.body).toEqual({
      code: "VALIDATION_ERROR",
      message: "[query.callbackURL] Invalid input: expected string, received undefined",
    });
    expect(denied.location).toBeNull();
    expect(await ctx.readVerificationState({ identifier })).toEqual(proofBefore);
    expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(before);
    expect(await ctx.readUserState({ userId: foreignSignup.data!.user.id })).toEqual(foreignBefore);
    const accepted = await ctx.rawRequest({ path: proof.url, redirect: "manual" });
    const expected = new URL("/reset?application=retained#details", ctx.baseURL);
    expected.searchParams.set("token", proof.token);
    expect(accepted.status).toBe(302);
    expect(accepted.location).toBe(expected.href);
    expect(await ctx.readVerificationState({ identifier })).toEqual(proofBefore);
    expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(before);
    expect(await ctx.readUserState({ userId: foreignSignup.data!.user.id })).toEqual(foreignBefore);
    const current = await owner.client.getSession();
    expect(signup.data!.token).toBeString();
    expect(current.data!.session.token).toBe(signup.data!.token!);
    return ctx.snapshot({ signup, foreignSignup, delivery, denied, accepted, current });
  },
  ["POST /request-password-reset", "GET /reset-password/{}"],
);
