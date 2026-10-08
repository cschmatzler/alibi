import { expect } from "bun:test";

import { raceOneTimeProof } from "../../../support/one-time-race";
import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import { phoneClient, readPhoneOtp, readPhoneState, uniquePhone } from "./helpers";
compatScenario(
  "overlapping local phone OTP redemption commits one session and authenticates only one browser",
  async (ctx) => {
    const profile = "phone-signup";
    const owner = phoneClient(ctx, profile, "owner");
    const phoneNumber = uniquePhone(ctx, "race-phone");
    expect((await owner.phoneNumber.sendOtp({ phoneNumber })).error).toBeNull();
    const created = await owner.phoneNumber.verify({
      phoneNumber,
      code: await readPhoneOtp(ctx, phoneNumber),
    });
    expect(created.error).toBeNull();
    const userId = created.data!.user.id;
    const foreign = await phoneClient(ctx, profile, "foreign").signUp.email({
      email: ctx.uniqueEmail("race-foreign"),
      name: "Foreign",
      password: "password123",
    });
    expect(foreign.error).toBeNull();
    const before = await readPhoneState(ctx, profile, userId);
    const foreignBefore = await readPhoneState(ctx, profile, foreign.data!.user.id);
    expect(before.sessions).toHaveLength(1);
    expect((await owner.phoneNumber.sendOtp({ phoneNumber })).error).toBeNull();
    const code = await readPhoneOtp(ctx, phoneNumber);
    expect(await ctx.readVerificationState({ identifier: phoneNumber })).toHaveLength(1);
    const responses = await raceOneTimeProof(
      ctx,
      authProfilePath(profile) + "/phone-number/verify",
      { phoneNumber, code },
    );
    expect(responses.map((r) => r.status)).toEqual([200, 400]);
    const [winner, loser] = responses;
    expect(winner!.body.user.id).toBe(userId);
    expect(winner!.session.user.id).toBe(userId);
    expect(winner!.session.session.token).toBe(winner!.body.token);
    expect(loser!.session).toBeNull();
    expect(loser!.cookies).toEqual([]);
    const after = await readPhoneState(ctx, profile, userId);
    expect(after.user).toEqual(before.user);
    expect(after.accounts).toEqual(before.accounts);
    expect(after.sessions).toHaveLength(2);
    expect(after.sessions).toContainEqual(before.sessions[0]!);
    expect(await readPhoneState(ctx, profile, foreign.data!.user.id)).toEqual(foreignBefore);
    expect(await ctx.readVerificationState({ identifier: phoneNumber })).toEqual([]);
    const replay = await owner.phoneNumber.verify({ phoneNumber, code });
    expect(replay.error!.code).toBe("OTP_NOT_FOUND");
    expect(await readPhoneState(ctx, profile, userId)).toEqual(after);
    expect(loser!.body.code).toBe("OTP_NOT_FOUND");
    return ctx.snapshot({ created, before, foreignBefore, responses, after, replay });
  },
  ["POST /phone-number/verify"],
);
