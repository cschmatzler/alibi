import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { phoneClient, readPhoneOtp, readPhoneState, uniquePhone } from "./helpers";
compatScenario(
  "phone reset callback rejects after password commit before configured session revocation",
  async (ctx) => {
    const profile = "phone-reset-callback";
    const owner = phoneClient(ctx, profile, "owner");
    const second = phoneClient(ctx, profile, "second");
    const email = ctx.uniqueEmail("reset-callback-owner");
    const phoneNumber = uniquePhone(ctx, "reset-callback-phone");
    const signup = await owner.signUp.email({
      email,
      password: "original-password123",
      name: "Reset owner",
      phoneNumber,
    });
    expect(signup.error).toBeNull();
    expect((await owner.phoneNumber.sendOtp({ phoneNumber })).error).toBeNull();
    const verified = await owner.phoneNumber.verify({
      phoneNumber,
      code: await readPhoneOtp(ctx, phoneNumber),
      disableSession: true,
    });
    expect(verified.error).toBeNull();
    expect(
      (await second.signIn.email({ email, password: "original-password123" })).error,
    ).toBeNull();
    const userId = signup.data!.user.id;
    const before = await readPhoneState(ctx, profile, userId);
    expect(before.sessions).toHaveLength(2);
    const control = async (mode?: string) => {
      const r = await ctx.rawRequest({
        path: "/__test/phone-reset-control",
        method: "POST",
        json: { mode },
      });
      expect(r.status).toBe(200);
      return r.body as any;
    };
    await control("reject");
    expect((await owner.phoneNumber.requestPasswordReset({ phoneNumber })).error).toBeNull();
    const otp = await readPhoneOtp(ctx, phoneNumber, "password-reset");
    const denied = await owner.phoneNumber.resetPassword(
      { phoneNumber, otp, newPassword: "changed-password123" },
      { headers: { "x-reset-marker": "rejected" } },
    );
    expect(denied.error).toMatchObject({
      status: 403,
      code: "PHONE_RESET_REJECTED",
      message: "Application reset callback rejected",
    });
    const receipt = await control();
    expect(receipt.events).toHaveLength(1);
    expect(receipt.events[0]).toMatchObject({
      userId,
      request: { method: "POST", marker: "rejected" },
    });
    expect(new URL(receipt.events[0].request.url).pathname).toBe(
      `/__test/profiles/${profile}/api/auth/phone-number/reset-password`,
    );
    expect(
      await ctx.readVerificationState({ identifier: `${phoneNumber}-request-password-reset` }),
    ).toEqual([]);
    const afterFailure = await readPhoneState(ctx, profile, userId);
    expect(afterFailure.user).toEqual(before.user);
    expect(afterFailure.accounts).toEqual(before.accounts);
    expect(afterFailure.sessions).toEqual(before.sessions);
    expect((await owner.getSession()).data!.user.id).toBe(userId);
    expect((await second.getSession()).data!.user.id).toBe(userId);
    const fresh = phoneClient(ctx, profile, "fresh");
    const oldPassword = await fresh.signIn.email({ email, password: "original-password123" });
    expect(oldPassword.error!.code).toBe("INVALID_EMAIL_OR_PASSWORD");
    const newPassword = await fresh.signIn.email({ email, password: "changed-password123" });
    expect(newPassword.error).toBeNull();
    expect(newPassword.data!.user.id).toBe(userId);
    await control("success");
    expect((await owner.phoneNumber.requestPasswordReset({ phoneNumber })).error).toBeNull();
    const reset = await owner.phoneNumber.resetPassword(
      {
        phoneNumber,
        otp: await readPhoneOtp(ctx, phoneNumber, "password-reset"),
        newPassword: "final-password123",
      },
      { headers: { "x-reset-marker": "recovered" } },
    );
    expect(reset.error).toBeNull();
    const after = await readPhoneState(ctx, profile, userId);
    expect(after.sessions).toEqual([]);
    for (const client of [owner, second, fresh])
      expect((await client.getSession()).data).toBeNull();
    const receipts = await control();
    expect(receipts.events).toHaveLength(2);
    expect(receipts.events[1]).toMatchObject({
      userId,
      request: { method: "POST", marker: "recovered" },
    });
    return ctx.snapshot({
      signup,
      verified,
      before,
      denied,
      receipt,
      afterFailure,
      oldPassword,
      newPassword,
      reset,
      after,
      receipts,
    });
  },
  ["POST /phone-number/reset-password"],
);
