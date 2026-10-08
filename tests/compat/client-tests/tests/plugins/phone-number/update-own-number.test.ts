import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { phoneClient, readPhoneOtp, readPhoneState, uniquePhone } from "./helpers";
compatScenario(
  "phone update to the current owned number rejects after burning proof without callbacks or session changes",
  async (ctx) => {
    const profile = "phone-signup";
    const owner = phoneClient(ctx, profile, "owner");
    const phoneNumber = uniquePhone(ctx, "same-phone");
    expect((await owner.phoneNumber.sendOtp({ phoneNumber })).error).toBeNull();
    const created = await owner.phoneNumber.verify({
      phoneNumber,
      code: await readPhoneOtp(ctx, phoneNumber),
    });
    expect(created.error).toBeNull();
    const userId = created.data!.user.id;
    const before = await readPhoneState(ctx, profile, userId);
    const callbacks = (await ctx.rawRequest({ path: "/__test/phone-callbacks" })).body;
    expect((await owner.phoneNumber.sendOtp({ phoneNumber })).error).toBeNull();
    const code = await readPhoneOtp(ctx, phoneNumber);
    expect(await ctx.readVerificationState({ identifier: phoneNumber })).toHaveLength(1);
    const denied = await owner.phoneNumber.verify({ phoneNumber, code, updatePhoneNumber: true });
    expect(denied.error).toMatchObject({ status: 400, code: "PHONE_NUMBER_EXIST" });
    expect(await ctx.readVerificationState({ identifier: phoneNumber })).toEqual([]);
    expect(await readPhoneState(ctx, profile, userId)).toEqual(before);
    expect((await ctx.rawRequest({ path: "/__test/phone-callbacks" })).body).toEqual(callbacks);
    const session = await owner.getSession();
    expect(session.data!.session.token).toBe(created.data!.token!);
    const replay = await owner.phoneNumber.verify({ phoneNumber, code, updatePhoneNumber: true });
    expect(replay.error!.code).toBe("OTP_NOT_FOUND");
    const nextNumber = uniquePhone(ctx, "replacement-phone");
    expect((await owner.phoneNumber.sendOtp({ phoneNumber: nextNumber })).error).toBeNull();
    const updated = await owner.phoneNumber.verify({
      phoneNumber: nextNumber,
      code: await readPhoneOtp(ctx, nextNumber),
      updatePhoneNumber: true,
    });
    expect(updated.error).toBeNull();
    expect(updated.data!.user).toMatchObject({
      id: userId,
      phoneNumber: nextNumber,
      phoneNumberVerified: true,
    });
    expect(updated.data!.token).toBe(created.data!.token!);
    const after = await readPhoneState(ctx, profile, userId);
    expect(after.sessions).toEqual(before.sessions);
    expect(after.accounts).toEqual(before.accounts);
    expect(after.user!.phoneNumber).toBe(nextNumber);
    return ctx.snapshot({ created, before, callbacks, denied, session, replay, updated, after });
  },
  ["POST /phone-number/verify"],
);
