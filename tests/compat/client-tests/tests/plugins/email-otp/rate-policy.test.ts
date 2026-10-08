import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { readOtp } from "./helpers";

compatScenario(
  "email-otp configured plugin quota stops delivery and resets after its window",
  async (ctx) => {
    const actor = ctx.actor("limited", "passwordless-rate-policy");
    const email = ctx.uniqueEmail("otp-rate");
    const send = () =>
      actor.client.emailOtp.sendVerificationOtp({
        email,
        type: "sign-in",
        fetchOptions: { headers: { "x-forwarded-for": "198.51.100.218" } },
      });
    const first = await send();
    const second = await send();
    expect(first.error).toBeNull();
    expect(second.error).toBeNull();
    const otp = await readOtp(ctx, email, "sign-in");
    const identifier = `sign-in-otp-${email}`;
    const before = (await ctx.readVerificationState({ identifier })) as any[];
    expect(before).toHaveLength(2);
    expect(before.some((row) => row.value === `${otp}:0`)).toBe(true);
    const denied = await send();
    expect(denied.error).toMatchObject({
      status: 429,
      message: "Too many requests. Please try again later.",
    });
    expect(await readOtp(ctx, email, "sign-in")).toBe(otp);
    expect(await ctx.readVerificationState({ identifier })).toEqual(before);
    await Bun.sleep(1200);
    const reset = await send();
    expect(reset.error).toBeNull();
    const latest = await readOtp(ctx, email, "sign-in");
    const after = (await ctx.readVerificationState({ identifier })) as any[];
    expect(after).toHaveLength(3);
    expect(after.some((row) => row.value === `${latest}:0`)).toBe(true);
    const project = (rows: unknown[]) =>
      rows.map((row: any) => ({
        ...row,
        value: { token: row.value.split(":")[0], attempts: Number(row.value.split(":")[1]) },
      }));
    return ctx.snapshot({
      first,
      second,
      denied,
      reset,
      before: project(before),
      after: project(after),
    });
  },
  ["POST /email-otp/send-verification-otp"],
);
