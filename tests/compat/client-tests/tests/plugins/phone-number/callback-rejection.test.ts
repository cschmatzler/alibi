import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { phoneClient, readPhoneOtp, readPhoneState, uniquePhone } from "./helpers";
compatScenario(
  "phone completion callback rejects after verified owner commit and before creating a session",
  async (ctx) => {
    const profile = "phone-callback-reject";
    const client = phoneClient(ctx, profile, "owner");
    const foreignClient = phoneClient(ctx, "phone-signup", "foreign");
    const foreign = await foreignClient.signUp.email({
      email: ctx.uniqueEmail("callback-foreign"),
      name: "Foreign",
      password: "password123",
    });
    expect(foreign.error).toBeNull();
    const foreignBefore = await readPhoneState(ctx, "phone-signup", foreign.data!.user.id);
    const phoneNumber = uniquePhone(ctx, "callback-phone");
    const sent = await client.phoneNumber.sendOtp({ phoneNumber });
    expect(sent.error).toBeNull();
    const code = await readPhoneOtp(ctx, phoneNumber);
    expect(await ctx.readVerificationState({ identifier: phoneNumber })).toHaveLength(1);
    const denied = await client.phoneNumber.verify({ phoneNumber, code });
    expect(denied.error).toMatchObject({
      status: 403,
      code: "PHONE_CALLBACK_REJECTED",
      message: "Application verification callback rejected",
    });
    const callbacks = (await ctx.rawRequest({ path: "/__test/phone-callbacks" })).body as any[];
    expect(callbacks).toHaveLength(1);
    expect(callbacks[0].phoneNumber).toBe(phoneNumber);
    const userId = callbacks[0].userId;
    const committed = await readPhoneState(ctx, profile, userId);
    expect(committed.user).toMatchObject({ id: userId, phoneNumber, phoneNumberVerified: true });
    expect(committed.accounts).toEqual([]);
    expect(committed.sessions).toEqual([]);
    expect((await client.getSession()).data).toBeNull();
    expect(await ctx.readVerificationState({ identifier: phoneNumber })).toEqual([]);
    expect(await readPhoneState(ctx, "phone-signup", foreign.data!.user.id)).toEqual(foreignBefore);
    const replay = await client.phoneNumber.verify({ phoneNumber, code });
    expect(replay.error!.code).toBe("OTP_NOT_FOUND");
    expect(await readPhoneState(ctx, profile, userId)).toEqual(committed);
    expect((await ctx.rawRequest({ path: "/__test/phone-callbacks" })).body).toEqual(callbacks);
    const recovery = phoneClient(ctx, "phone-signup", "recovery");
    expect((await recovery.phoneNumber.sendOtp({ phoneNumber })).error).toBeNull();
    const verified = await recovery.phoneNumber.verify({
      phoneNumber,
      code: await readPhoneOtp(ctx, phoneNumber),
    });
    expect(verified.error).toBeNull();
    expect(verified.data!.user.id).toBe(userId);
    expect((await readPhoneState(ctx, profile, userId)).sessions).toHaveLength(1);
    return ctx.snapshot({ foreignBefore, sent, denied, callbacks, committed, replay, verified });
  },
  ["POST /phone-number/verify"],
);
