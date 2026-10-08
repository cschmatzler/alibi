import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { phoneClient, readPhoneOtp, readPhoneState, uniquePhone } from "./helpers";
for (const mode of ["coded", "ordinary"] as const) {
  compatScenario(
    `phone external ${mode} verifier rejection preserves proof and owner until successful retry`,
    async (ctx) => {
      const profile = "phone-custom-errors";
      const client = phoneClient(ctx, profile, "owner");
      const configure = async (mode: string) => {
        const r = await ctx.rawRequest({
          path: "/__test/phone-verifier-control",
          method: "POST",
          json: { mode },
        });
        expect(r.status).toBe(200);
      };
      await configure("success");
      const phoneNumber = uniquePhone(ctx, "external-phone");
      const signup = await client.signUp.email({
        email: ctx.uniqueEmail("external-owner"),
        password: "password123",
        name: "External owner",
        phoneNumber,
      });
      expect(signup.error).toBeNull();
      const userId = signup.data!.user.id;
      const before = await readPhoneState(ctx, profile, userId);
      expect(before.user!.phoneNumberVerified).not.toBe(true);
      expect((await client.phoneNumber.sendOtp({ phoneNumber })).error).toBeNull();
      const code = await readPhoneOtp(ctx, phoneNumber);
      const proof = (await ctx.readVerificationState({ identifier: phoneNumber })) as any[];
      expect(proof).toHaveLength(1);
      expect(proof[0].value).toBe(`${code}:0`);
      await configure(mode);
      const denied = await client.phoneNumber.verify({ phoneNumber, code });
      expect(denied.error!.status).toBe(mode === "coded" ? 403 : 500);
      expect(await ctx.readVerificationState({ identifier: phoneNumber })).toEqual(proof);
      expect(await readPhoneState(ctx, profile, userId)).toEqual(before);
      expect((await ctx.rawRequest({ path: "/__test/phone-callbacks" })).body).toEqual([]);
      await configure("success");
      const verified = await client.phoneNumber.verify({ phoneNumber, code });
      expect(verified.error).toBeNull();
      expect(verified.data!.user).toMatchObject({
        id: userId,
        phoneNumber,
        phoneNumberVerified: true,
      });
      const after = await readPhoneState(ctx, profile, userId);
      expect(after.accounts).toEqual(before.accounts);
      expect(after.sessions).toHaveLength(before.sessions.length + 1);
      expect(await ctx.readVerificationState({ identifier: phoneNumber })).toEqual([]);
      const replay = await client.phoneNumber.verify({ phoneNumber, code });
      expect(replay.error!.code).toBe("INVALID_OTP");
      if (mode === "coded")
        expect(denied.error).toMatchObject({
          code: "PHONE_VERIFIER_REJECTED",
          message: "Application verifier rejected",
        });
      return ctx.snapshot({
        signup,
        before,
        proof: proof.map((r) => ({ ...r, value: { token: r.value } })),
        denied,
        verified,
        after,
        replay,
      });
    },
    ["POST /phone-number/verify"],
  );
}
