import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { twoFactorClient } from "better-auth/client/plugins";

import { compatScenario } from "../../../support/scenario";
import { generateCurrentTotp } from "../../../support/totp";
compatScenario(
  "renamed two-factor table and fields own enrollment, TOTP, OTP, backup, trust and disable",
  async (ctx) => {
    const actor = ctx.actor("owner", "two-factor-custom-table");
    const owner = createAuthClient({
      baseURL: ctx.baseURL,
      plugins: [twoFactorClient()],
      fetchOptions: { customFetchImpl: actor.fetch },
    });
    const email = ctx.uniqueEmail("custom-factor");
    const signup = await owner.signUp.email({
      email,
      password: "password123",
      name: "Custom storage",
    });
    expect(signup.error).toBeNull();
    const userId = signup.data!.user.id;
    const state = async () =>
      (await ctx.rawRequest({ path: `/__test/two-factor-custom-table/state?userId=${userId}` }))
        .body as any;
    const enable = await owner.twoFactor.enable({ password: "password123" });
    expect(enable.error).toBeNull();
    const enrollment = enable.data!;
    if (!("totpURI" in enrollment))
      throw new Error("Custom-table enrollment must provide a TOTP URI");
    expect(enrollment.backupCodes).toHaveLength(10);
    const enrolled = await state();
    expect(enrolled.customTableExists).toBe(true);
    expect(enrolled.defaultTableExists).toBe(false);
    expect(enrolled.rows).toHaveLength(1);
    expect(enrolled.rows[0]).toMatchObject({ userId, secretPresent: true, backupPresent: true });
    const activate = await owner.twoFactor.verifyTotp({
      code: await generateCurrentTotp(enrollment.totpURI),
    });
    expect(activate.error).toBeNull();
    expect((await owner.getSession()).data!.user.twoFactorEnabled).toBe(true);
    await owner.signOut();
    const pendingOtp = await owner.signIn.email({ email, password: "password123" });
    expect(pendingOtp.data).toMatchObject({ twoFactorRedirect: true });
    const sent = await owner.twoFactor.sendOtp({});
    expect(sent.error).toBeNull();
    const delivered = await ctx.rawRequest({
      path: `/__test/two-factor-custom-table/otp?email=${encodeURIComponent(email)}`,
    });
    const otp = (delivered.body as any).otp;
    expect(otp).toMatch(/^\d{6}$/);
    const verifiedOtp = await owner.twoFactor.verifyOtp({ code: otp });
    expect(verifiedOtp.error).toBeNull();
    await owner.signOut();
    const pendingBackup = await owner.signIn.email({ email, password: "password123" });
    expect(pendingBackup.data).toMatchObject({ twoFactorRedirect: true });
    const backup = await owner.twoFactor.verifyBackupCode({
      code: enrollment.backupCodes[0]!,
      trustDevice: true,
    });
    expect(backup.error).toBeNull();
    await owner.signOut();
    const trusted = await owner.signIn.email({ email, password: "password123" });
    expect(trusted.error).toBeNull();
    expect(trusted.data).not.toHaveProperty("twoFactorRedirect");
    expect((await owner.getSession()).data!.user.id).toBe(userId);
    const disabled = await owner.twoFactor.disable({ password: "password123" });
    expect(disabled.error).toBeNull();
    const removed = await state();
    expect(removed.rows).toEqual([]);
    expect((await owner.getSession()).data!.user.twoFactorEnabled).toBe(false);
    return ctx.snapshot({
      signup,
      enrolled,
      activate,
      pendingOtp,
      sent,
      verifiedOtp,
      pendingBackup,
      backup,
      trusted,
      disabled,
      removed,
    });
  },
  [
    "POST /two-factor/enable",
    "POST /two-factor/verify-totp",
    "POST /two-factor/send-otp",
    "POST /two-factor/verify-otp",
    "POST /two-factor/verify-backup-code",
    "POST /two-factor/disable",
  ],
);
