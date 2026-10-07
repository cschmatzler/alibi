import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { emailOTPClient } from "better-auth/client/plugins";
import { z } from "zod";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import { readOtp, deliveredOtpCount } from "./helpers";

compatScenario(
  "email OTP signup verification delivers a scoped code without verifying the password signup prematurely",
  async (ctx) => {
    const profile = "otp-signup-verification" as const;
    const client = createAuthClient({
      baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
      plugins: [emailOTPClient()],
      fetchOptions: { customFetchImpl: ctx.actor("signup-otp-owner", profile).fetch },
    });
    const email = ctx.uniqueEmail("signup-otp-owner");
    const signup = await client.signUp.email({
      email,
      name: "OTP signup owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    expect(signup.data?.user.emailVerified).toBe(false);
    const identifier = `email-verification-otp-${email}`;
    const otp = await readOtp(ctx, email, "email-verification");
    expect(await deliveredOtpCount(ctx, email, "sign-in")).toBe(0);
    const stored = z
      .array(z.object({ value: z.string() }).passthrough())
      .parse(await ctx.readVerificationState({ identifier }));
    expect(stored).toEqual([expect.objectContaining({ identifier, value: `${otp}:0` })]);
    const before = await client.getSession();
    expect(before.data?.user.id).toBe(signup.data!.user.id);
    expect(before.data?.user.emailVerified).toBe(false);
    const verified = await client.emailOtp.verifyEmail({ email, otp });
    expect(verified.error).toBeNull();
    const after = await client.getSession();
    expect(after.data?.user.emailVerified).toBe(true);
    expect(after.data?.user.id).toBe(signup.data!.user.id);
    expect(await ctx.readVerificationState({ identifier })).toEqual([]);
    const replay = await client.emailOtp.verifyEmail({ email, otp });
    expect(replay.error).toMatchObject({ status: 400, code: "INVALID_OTP" });
    return ctx.snapshot({
      signup,
      stored: stored.map((row) => ({
        ...row,
        value: { token: row.value.split(":")[0], attempts: Number(row.value.split(":")[1]) },
      })),
      before,
      verified,
      after,
      replay,
    });
  },
  ["POST /sign-up/email", "POST /email-otp/verify-email"],
);
