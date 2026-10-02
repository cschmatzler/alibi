import { createAuthClient } from "better-auth/client";
import { emailOTPClient } from "better-auth/client/plugins";
import { z } from "zod";
import { fixtureValue, type ScenarioContext } from "../../support/verification";

export type OtpType = "email-verification" | "sign-in" | "forget-password" | "change-email";

const otpDelivery = z.object({ otp: z.string().min(1) });

export function passwordlessClient(ctx: ScenarioContext, actor = "primary") {
  return createAuthClient({
    baseURL: ctx.baseURL,
    plugins: [emailOTPClient()],
    fetchOptions: { customFetchImpl: ctx.actor(actor).fetch },
  });
}

export async function readOtp(ctx: ScenarioContext, email: string, type: OtpType) {
  const parsed = otpDelivery.safeParse(
    await fixtureValue(ctx, "/__test/email-otp", { email, type }),
  );
  if (!parsed.success) throw new Error("Successful OTP issuance must deliver a parseable code");
  return parsed.data.otp;
}

export async function deliveredOtpCount(ctx: ScenarioContext, email: string, type: OtpType) {
  const value = await fixtureValue(ctx, "/__test/email-otp", { email, type });
  return value === null ? 0 : 1;
}
