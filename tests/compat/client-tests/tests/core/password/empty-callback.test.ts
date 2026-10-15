import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "delivered empty reset callback rejects without consuming proof before a trusted callback retry",
  async (ctx) => {
    const owner = ctx.actor("owner");
    const email = ctx.uniqueEmail("empty-reset-callback-owner");
    const signup = await owner.client.signUp.email({
      email,
      password: "password123",
      name: "Owner",
    });
    expect(signup.error).toBeNull();
    const foreign = ctx.actor("foreign");
    const foreignSignup = await foreign.client.signUp.email({
      email: ctx.uniqueEmail("empty-reset-callback-foreign"),
      password: "password123",
      name: "Foreign",
    });
    expect(foreignSignup.error).toBeNull();
    expect((await owner.client.requestPasswordReset({ email })).error).toBeNull();
    const delivery = await ctx.rawRequest({
      path: `/__test/reset-password-token?email=${encodeURIComponent(email)}`,
    });
    expect(delivery.status).toBe(200);
    const proof = delivery.body as { url: string; token: string };
    expect(proof.token).toBeTypeOf("string");
    const delivered = new URL(proof.url);
    expect(delivered.searchParams.get("callbackURL")).toBe("");
    const identifier = `reset-password:${proof.token}`;
    const before = await ctx.readUserState({ userId: signup.data!.user.id });
    const foreignBefore = await ctx.readUserState({ userId: foreignSignup.data!.user.id });
    const proofBefore = await ctx.readVerificationState({ identifier });
    const denied = await ctx.rawRequest({ path: proof.url, redirect: "manual" });
    expect(denied.status).toBe(302);
    expect(denied.location).toBe(`${ctx.baseURL}/api/auth/error?error=INVALID_TOKEN`);
    expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(before);
    expect(await ctx.readUserState({ userId: foreignSignup.data!.user.id })).toEqual(foreignBefore);
    expect(await ctx.readVerificationState({ identifier })).toEqual(proofBefore);
    const callback = "/reset?application=retained#details";
    delivered.searchParams.set("callbackURL", callback);
    const accepted = await ctx.rawRequest({ path: delivered.href, redirect: "manual" });
    const expected = new URL(callback, ctx.baseURL);
    expected.searchParams.set("token", proof.token);
    expect(accepted.status).toBe(302);
    expect(accepted.location).toBe(expected.href);
    expect(await ctx.readVerificationState({ identifier })).toEqual(proofBefore);
    expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(before);
    expect(await ctx.readUserState({ userId: foreignSignup.data!.user.id })).toEqual(foreignBefore);
    const current = await owner.client.getSession();
    expect(signup.data!.token).toBeTypeOf("string");
    expect(current.data!.session.token).toBe(signup.data!.token!);
    const foreignCurrent = await foreign.client.getSession();
    expect(foreignSignup.data!.token).toBeTypeOf("string");
    expect(foreignCurrent.data!.session.token).toBe(foreignSignup.data!.token!);
    return ctx.snapshot({
      signup,
      foreignSignup,
      delivery,
      denied,
      accepted,
      current,
      foreignCurrent,
    });
  },
  ["POST /request-password-reset", "GET /reset-password/{}"],
);
