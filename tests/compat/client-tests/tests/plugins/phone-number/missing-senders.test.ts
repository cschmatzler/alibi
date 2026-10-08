import { expect } from "bun:test";

import { z } from "zod";

import { compatScenario } from "../../../support/scenario";
import { phoneClient, readPhoneOtp, readPhoneState, uniquePhone } from "./helpers";

compatScenario(
  "phone required OTP sender guards before validation while an omitted reset sender still issues a usable proof",
  async (ctx) => {
    const physical = async () => {
      const response = await fetch(`${ctx.baseURL}/__test/provider-batch/sql-state`);
      expect(response.status).toBe(200);
      return response.json();
    };
    const before = await physical();
    const missing = phoneClient(ctx, "phone-no-otp-sender", "missing-sender");
    let deniedCookies: string[] = [];
    const denied = await missing.phoneNumber.sendOtp(
      { phoneNumber: "not-a-phone" },
      {
        onResponse: ({ response }) => {
          deniedCookies = response.headers.getSetCookie();
        },
      },
    );
    expect(denied.data).toBeNull();
    expect(denied.error).toEqual({
      status: 501,
      statusText: "Not Implemented",
      code: "SEND_OTP_NOT_IMPLEMENTED",
      message: "sendOTP not implemented",
    });
    expect(deniedCookies).toEqual([]);
    expect(await physical()).toEqual(before);
    const validatorResponse = await fetch(`${ctx.baseURL}/__test/phone-validator-events`);
    expect(validatorResponse.status).toBe(200);
    const validatorEvents = await validatorResponse.json();
    expect(validatorEvents).toEqual([]);
    expect(await ctx.readVerificationState({ identifier: "not-a-phone" })).toEqual([]);
    const foreign = await ctx
      .actor("missing-sender-foreign")
      .client.signUp.email({
        email: ctx.uniqueEmail("missing-sender-foreign"),
        password: "password123",
        name: "Foreign Sender Owner",
      });
    expect(foreign.error).toBeNull();
    const foreignBefore = await ctx.readUserState({ userId: foreign.data!.user.id });
    const profile = "phone-no-reset-sender";
    const owner = phoneClient(ctx, profile, "optional-sender-owner");
    const phoneNumber = uniquePhone(ctx, "optional-sender-owner");
    const email = ctx.uniqueEmail("optional-sender-owner");
    const signup = await owner.signUp.email({
      email,
      password: "original-password123",
      name: "Optional Sender Owner",
      phoneNumber,
    });
    expect(signup.error).toBeNull();
    expect(signup.data?.user.id).toBeString();
    const issued = await owner.phoneNumber.sendOtp({ phoneNumber });
    expect(issued.error).toBeNull();
    const enrollment = await readPhoneOtp(ctx, phoneNumber);
    const verified = await owner.phoneNumber.verify({
      phoneNumber,
      code: enrollment,
      disableSession: true,
    });
    expect(verified.error).toBeNull();
    expect(verified.data?.user.phoneNumberVerified).toBe(true);
    const ownerBefore = await readPhoneState(ctx, profile, signup.data!.user.id);
    const reset = await owner.phoneNumber.requestPasswordReset({ phoneNumber });
    expect(reset.data).toEqual({ status: true });
    expect(reset.error).toBeNull();
    const identifier = `${phoneNumber}-request-password-reset`;
    const proof = z
      .array(z.object({ identifier: z.string(), value: z.string() }).passthrough())
      .parse(await ctx.readVerificationState({ identifier }));
    expect(proof).toHaveLength(1);
    expect(proof[0]!.identifier).toBe(identifier);
    expect(proof[0]!.value).toMatch(/^\d{6}:0$/);
    const otp = proof[0]!.value.split(":")[0]!;
    const delivery = await fetch(
      `${ctx.baseURL}/__test/phone-otp?phoneNumber=${encodeURIComponent(phoneNumber)}&type=password-reset`,
    );
    expect(delivery.status).toBe(200);
    expect(await delivery.json()).toBeNull();
    expect(await readPhoneState(ctx, profile, signup.data!.user.id)).toEqual(ownerBefore);
    const changed = await owner.phoneNumber.resetPassword({
      phoneNumber,
      otp,
      newPassword: "recovered-password123",
    });
    expect(changed.error).toBeNull();
    expect(changed.data).toEqual({ status: true });
    expect(await ctx.readVerificationState({ identifier })).toEqual([]);
    const after = await readPhoneState(ctx, profile, signup.data!.user.id);
    expect(after.sessions).toEqual(ownerBefore.sessions);
    expect(after.user).toEqual(ownerBefore.user);
    expect(after.accounts).toEqual(ownerBefore.accounts);
    const login = phoneClient(ctx, profile, "optional-sender-new-browser");
    const oldPassword = await login.signIn.phoneNumber({
      phoneNumber,
      password: "original-password123",
    });
    expect(oldPassword.error?.code).toBe("INVALID_PHONE_NUMBER_OR_PASSWORD");
    const accepted = await login.signIn.phoneNumber({
      phoneNumber,
      password: "recovered-password123",
    });
    expect(accepted.error).toBeNull();
    expect(accepted.data?.user.id).toBe(signup.data!.user.id);
    const replay = await owner.phoneNumber.resetPassword({
      phoneNumber,
      otp,
      newPassword: "replay-password123",
    });
    expect(replay.error?.code).toBe("OTP_NOT_FOUND");
    expect(await ctx.readUserState({ userId: foreign.data!.user.id })).toEqual(foreignBefore);
    expect((await ctx.actor("missing-sender-foreign").client.getSession()).data?.user.id).toBe(
      foreign.data!.user.id,
    );
    return ctx.snapshot({
      denied,
      validatorEvents,
      foreign,
      signup,
      issued,
      verified,
      reset,
      changed,
      after,
      oldPassword,
      accepted,
      replay,
    });
  },
  [
    "POST /phone-number/send-otp",
    "POST /phone-number/request-password-reset",
    "POST /phone-number/reset-password",
    "POST /sign-in/phone-number",
  ],
);
