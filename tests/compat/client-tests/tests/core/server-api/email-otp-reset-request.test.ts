import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
import {
  storedVerification,
  verificationCount,
  readUserState,
} from "../../../support/verification";
import { passwordlessClient, readOtp, deliveredOtpCount } from "../../plugins/email-otp/helpers";

for (const operation of ["requestPasswordResetEmailOTP", "forgetPasswordEmailOTP"] as const) {
  compatScenario(
    `server ${operation} preserves reset delivery and hidden mailboxes`,
    async (ctx) => {
      const client = passwordlessClient(ctx, "owner");
      const email = ctx.uniqueEmail("server-otp-reset-owner");
      const password = "password123";
      const owner = await client.signUp.email({ email, password, name: "Reset Owner" });
      expect(owner.error).toBeNull();
      const before = await readUserState(ctx, owner.data!.user.id);
      async function invoke(body: unknown, profile?: string) {
        return ctx.rawRequest({
          path: "/__test/server-api/email-otp-reset-request",
          method: "POST",
          json: { operation, body, ...(profile ? { profile } : {}) },
        });
      }
      const invalid = await invoke({ email: 42 });
      expect(invalid.status).toBe(400);
      expect((invalid.body as { code: string }).code).toBe("VALIDATION_ERROR");
      const malformedEmail = "not-an-email";
      const malformed = await invoke({ email: malformedEmail });
      expect(malformed.status).toBe(400);
      expect(malformed.body).toMatchObject({ code: "INVALID_EMAIL" });
      const absent = ctx.uniqueEmail("server-otp-reset-absent");
      const hidden = await invoke({ email: absent });
      expect(hidden.status).toBe(200);
      expect(hidden.body).toEqual({ success: true });
      for (const address of [malformedEmail, absent]) {
        expect(await deliveredOtpCount(ctx, address, "forget-password")).toBe(0);
        expect(await verificationCount(ctx, `forget-password-otp-${address}`)).toBe(0);
      }
      const sent = await invoke({ email: email.toUpperCase(), ignored: true });
      expect(sent.status).toBe(200);
      expect(sent.body).toEqual({ success: true });
      const otp = await readOtp(ctx, email, "forget-password");
      expect(otp).toMatch(/^\d{6}$/);
      const identifier = `forget-password-otp-${email}`;
      const proof = await storedVerification(ctx, identifier);
      expect(proof).toHaveLength(1);
      expect(proof[0]!.value).toBe(`${otp}:0`);
      expect(await readUserState(ctx, owner.data!.user.id)).toEqual(before);
      const reset = await client.emailOtp.resetPassword({
        email,
        otp,
        password: "changed-reset-password123",
      });
      expect(reset.error).toBeNull();
      expect(await verificationCount(ctx, identifier)).toBe(0);
      const browser = passwordlessClient(ctx, "fresh");
      const rejected = await browser.signIn.email({ email, password });
      expect(rejected.error?.code).toBe("INVALID_EMAIL_OR_PASSWORD");
      const accepted = await browser.signIn.email({ email, password: "changed-reset-password123" });
      expect(accepted.error).toBeNull();
      expect(accepted.data!.user.id).toBe(owner.data!.user.id);
      const identities = await readUserState(ctx, owner.data!.user.id);
      const missing = await invoke({ email }, "passwordless-no-sender");
      expect(missing.status).toBe(500);
      expect(missing.body).toEqual({ message: "Internal server error" });
      const retained = await storedVerification(ctx, identifier);
      expect(retained).toHaveLength(1);
      expect(retained[0]!.value).toMatch(/^\d{6}:0$/);
      expect(await readUserState(ctx, owner.data!.user.id)).toEqual(identities);
      return ctx.snapshot({
        before,
        invalid,
        malformed,
        hidden,
        sent,
        reset,
        rejected,
        accepted,
        missing,
      });
    },
    [],
    30000,
    {
      oracle: {
        collapsedFixtureErrors:
          "The reset-request SDK throws when its configured sender is absent, after issuing a proof. The fixture host renders the ordinary error as a generic 500; retained proof and identity state are asserted independently.",
      },
    },
  );
}
