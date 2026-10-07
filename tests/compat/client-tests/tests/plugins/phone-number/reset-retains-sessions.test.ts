import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { phoneClient, readPhoneOtp, readPhoneState, uniquePhone } from "./helpers";
compatScenario(
  "phone password reset retains all established sessions by default while changing credential authority",
  async (ctx) => {
    const profile = "phone-signup";
    const owner = phoneClient(ctx, profile, "owner");
    const second = phoneClient(ctx, profile, "second");
    const foreign = phoneClient(ctx, profile, "foreign");
    const email = ctx.uniqueEmail("phone-reset-owner");
    const phoneNumber = uniquePhone(ctx, "retained-phone");
    const oldPassword = "original-password123";
    const signup = await owner.signUp.email({
      email,
      name: "Retained owner",
      password: oldPassword,
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
    const login = await second.signIn.email({ email, password: oldPassword });
    expect(login.error).toBeNull();
    const other = await foreign.signUp.email({
      email: ctx.uniqueEmail("phone-reset-foreign"),
      name: "Foreign",
      password: oldPassword,
    });
    expect(other.error).toBeNull();
    const userId = signup.data!.user.id;
    const before = await readPhoneState(ctx, profile, userId);
    expect(before.user!.phoneNumberVerified).toBe(true);
    expect(before.sessions).toHaveLength(2);
    const foreignBefore = await readPhoneState(ctx, profile, other.data!.user.id);
    const issued = await owner.phoneNumber.requestPasswordReset({ phoneNumber });
    expect(issued.error).toBeNull();
    const otp = await readPhoneOtp(ctx, phoneNumber, "password-reset");
    const identifier = `${phoneNumber}-request-password-reset`;
    expect(await ctx.readVerificationState({ identifier })).toHaveLength(1);
    const reset = await owner.phoneNumber.resetPassword({
      phoneNumber,
      otp,
      newPassword: "changed-password123",
    });
    expect(reset.error).toBeNull();
    expect(await ctx.readVerificationState({ identifier })).toEqual([]);
    const after = await readPhoneState(ctx, profile, userId);
    expect(after.user).toEqual(before.user);
    expect(after.accounts).toEqual(before.accounts);
    expect(after.sessions).toEqual(before.sessions);
    expect(await readPhoneState(ctx, profile, other.data!.user.id)).toEqual(foreignBefore);
    const ownerSession = await owner.getSession();
    const secondSession = await second.getSession();
    expect(ownerSession.data!.user.id).toBe(userId);
    expect(secondSession.data!.user.id).toBe(userId);
    const fresh = phoneClient(ctx, profile, "fresh");
    const rejected = await fresh.signIn.email({ email, password: oldPassword });
    expect(rejected.error).toMatchObject({ code: "INVALID_EMAIL_OR_PASSWORD", status: 401 });
    const accepted = await fresh.signIn.email({ email, password: "changed-password123" });
    expect(accepted.error).toBeNull();
    expect(accepted.data!.user.id).toBe(userId);
    const replay = await owner.phoneNumber.resetPassword({
      phoneNumber,
      otp,
      newPassword: "must-not-commit123",
    });
    expect(replay.error!.code).toBe("OTP_NOT_FOUND");
    return ctx.snapshot({
      signup,
      verified,
      login,
      before,
      foreignBefore,
      issued,
      reset,
      after,
      ownerSession,
      secondSession,
      rejected,
      accepted,
      replay,
    });
  },
  ["POST /phone-number/reset-password"],
);
