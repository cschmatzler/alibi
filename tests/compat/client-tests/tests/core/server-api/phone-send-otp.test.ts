import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { storedVerification, verificationCount } from "../../../support/verification";
import { readPhoneOtp, uniquePhone } from "../../plugins/phone-number/helpers";

compatScenario(
  "server phone OTP delivery persists a consumable proof without browser authority",
  async (ctx) => {
    const phoneNumber = uniquePhone(ctx, "server-send-phone");
    async function send(profile: string, body: unknown) {
      return ctx.rawRequest({
        path: "/__test/server-api/phone-send-otp",
        method: "POST",
        json: { profile, body },
      });
    }
    const sent = await send("phone-default", { phoneNumber, ignored: true });
    expect(sent.status).toBe(200);
    expect(sent.body).toEqual({ message: "code sent" });
    const code = await readPhoneOtp(ctx, phoneNumber);
    expect(code).toMatch(/^\d{6}$/);
    const proof = await storedVerification(ctx, phoneNumber);
    expect(proof).toHaveLength(1);
    expect(proof[0]!.value).toBe(`${code}:0`);
    const malformed = await send("phone-default", { phoneNumber: 42 });
    expect(malformed.status).toBe(400);
    expect((malformed.body as { code: string }).code).toBe("VALIDATION_ERROR");
    const invalid = await send("phone-custom", { phoneNumber: "+000" });
    expect(invalid.status).toBe(400);
    expect((invalid.body as { code: string }).code).toBe("INVALID_PHONE_NUMBER");
    expect(await storedVerification(ctx, phoneNumber)).toEqual(proof);
    const consumed = await ctx.rawRequest({
      path: "/__test/phone-consume-otp",
      method: "POST",
      json: { profile: "phone-default", phoneNumber, code },
    });
    expect(consumed.status).toBe(200);
    expect(consumed.body).toEqual({ status: true });
    expect(await verificationCount(ctx, phoneNumber)).toBe(0);
    const missing = await send("phone-no-otp-sender", { phoneNumber: "+err" });
    expect(missing.status).toBe(501);
    expect((missing.body as { code: string }).code).toBe("SEND_OTP_NOT_IMPLEMENTED");
    expect(await verificationCount(ctx, "+err")).toBe(0);
    const session = await ctx
      .actor("observer", "phone-default")
      .fetch(`${ctx.baseURL}/__test/profiles/phone-default/api/auth/get-session`);
    expect(await session.json()).toBeNull();
    return ctx.snapshot({ sent, malformed, invalid, consumed, missing });
  },
);
