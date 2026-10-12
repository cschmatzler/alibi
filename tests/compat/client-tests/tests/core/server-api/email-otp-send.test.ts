import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { storedVerification, verificationCount } from "../../../support/verification";
import { passwordlessClient, readOtp, deliveredOtpCount } from "../../plugins/email-otp/helpers";

compatScenario("server email OTP sending preserves scope and delivery admission", async (ctx) => {
  const client = passwordlessClient(ctx, "owner");
  const email = ctx.uniqueEmail("server-otp-owner");
  const owner = await client.signUp.email({ email, password: "password123", name: "OTP Owner" });
  expect(owner.error).toBeNull();
  async function invoke(
    body: unknown,
    profile?: string,
    headers?: Record<string, string>,
    physicalRequest = false,
  ) {
    return ctx.rawRequest({
      path: "/__test/server-api/email-otp-send",
      method: "POST",
      ...(physicalRequest
        ? {
            headers: {
              origin: "https://untrusted.example.test",
              "sec-fetch-site": "cross-site",
              "sec-fetch-mode": "navigate",
            },
          }
        : {}),
      json: {
        body,
        ...(profile ? { profile } : {}),
        ...(headers ? { headers } : {}),
        ...(physicalRequest ? { physicalRequest: true } : {}),
      },
    });
  }
  const denied = [];
  for (const [body, expected] of [
    [
      { email: 42, type: "sign-in" },
      {
        code: "VALIDATION_ERROR",
        message: "[body.email] Invalid input: expected string, received number",
      },
    ],
    [
      { email: "not-an-email", type: "sign-in" },
      { code: "INVALID_EMAIL", message: "Invalid email" },
    ],
    [{ email, type: "change-email" }, { message: "Invalid OTP type" }],
  ] as const) {
    const result = await invoke(body);
    expect(result.status).toBe(400);
    expect(result.body).toEqual(expected);
    denied.push(result);
  }
  const crossSite = await invoke({ email, type: "sign-in" }, undefined, undefined, true);
  expect(crossSite.status).toBe(403);
  expect((crossSite.body as { code: string }).code).toBe("CROSS_SITE_NAVIGATION_LOGIN_BLOCKED");
  expect(await verificationCount(ctx, `sign-in-otp-${email}`)).toBe(0);
  expect(await deliveredOtpCount(ctx, email, "sign-in")).toBe(0);
  const scoped = [];
  for (const type of ["email-verification", "forget-password"] as const) {
    const result = await invoke({ email: email.toUpperCase(), type, ignored: true });
    expect(result.status).toBe(200);
    expect(result.body).toEqual({ success: true });
    const otp = await readOtp(ctx, email, type);
    expect(otp).toMatch(/^\d{6}$/);
    const proof = await storedVerification(ctx, `${type}-otp-${email}`);
    expect(proof).toHaveLength(1);
    expect(proof[0]!.value).toBe(`${otp}:0`);
    const retrieved = await ctx.rawRequest({
      path: "/__test/server-api/email-otp-get",
      method: "POST",
      json: { query: { email, type } },
    });
    expect(retrieved.status).toBe(200);
    expect(retrieved.body).toEqual({ otp });
    scoped.push({ result, retrieved: { ...retrieved, body: { otp: { token: otp } } } });
  }
  const absent = ctx.uniqueEmail("server-otp-absent");
  const hidden = [];
  for (const type of ["email-verification", "forget-password"] as const) {
    const result = await invoke({ email: absent, type });
    expect(result.status).toBe(200);
    expect(result.body).toEqual({ success: true });
    expect(await verificationCount(ctx, `${type}-otp-${absent}`)).toBe(0);
    expect(await deliveredOtpCount(ctx, absent, type)).toBe(0);
    hidden.push(result);
  }
  const guest = ctx.uniqueEmail("server-otp-guest");
  const sent = await invoke({ email: guest.toUpperCase(), type: "sign-in" }, undefined, {
    origin: "https://untrusted.example.test",
    "sec-fetch-site": "cross-site",
    "sec-fetch-mode": "navigate",
  });
  expect(sent.status).toBe(200);
  expect(sent.body).toEqual({ success: true });
  const otp = await readOtp(ctx, guest, "sign-in");
  expect(otp).toMatch(/^\d{6}$/);
  const browser = passwordlessClient(ctx, "guest");
  const signedIn = await browser.signIn.emailOtp({ email: guest, otp });
  expect(signedIn.error).toBeNull();
  expect((await browser.getSession()).data!.user.email).toBe(guest);
  expect(await verificationCount(ctx, `sign-in-otp-${guest}`)).toBe(0);
  expect((await client.getSession()).data!.user.id).toBe(owner.data!.user.id);
  const missing = await invoke(
    { email: "not-an-email", type: "sign-in" },
    "passwordless-no-sender",
  );
  expect(missing.status).toBe(400);
  expect(missing.body).toEqual({ message: "send email verification is not implemented" });
  return ctx.snapshot({ denied, crossSite, scoped, hidden, sent, signedIn, missing });
});
