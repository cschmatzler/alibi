import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { twoFactorClient } from "better-auth/client/plugins";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import { generateCurrentTotp } from "../../../support/totp";

for (const profile of [
  "two-factor-otp-missing-options",
  "two-factor-otp-missing-sender",
] as const) {
  compatScenario(
    `missing OTP delivery ${profile} preserves password and challenge guard ordering`,
    async (ctx) => {
      const actorFor = (name: string) => {
        const actor = ctx.actor(name, profile);
        return {
          ...actor,
          client: createAuthClient({
            baseURL: ctx.baseURL + authProfilePath(profile),
            plugins: [twoFactorClient()],
            fetchOptions: { customFetchImpl: actor.fetch },
          }),
        };
      };
      const owner = actorFor("missing-owner");
      const foreign = actorFor("missing-foreign");
      const guest = actorFor("missing-guest");
      const email = ctx.uniqueEmail("missing-owner");
      const password = "password123";
      const signup = await owner.client.signUp.email({
        email,
        password,
        name: "Missing sender owner",
      });
      expect(signup.error).toBeNull();
      const userId = signup.data!.user.id;
      const other = await foreign.client.signUp.email({
        email: ctx.uniqueEmail("missing-foreign"),
        password,
        name: "Foreign owner",
      });
      expect(other.error).toBeNull();
      const foreignBefore = await ctx.readUserState({ userId: other.data!.user.id });
      // Compare complete physical rows within each backend; SQL table/column names differ.
      const sql = async () => {
        const response = await fetch(ctx.baseURL + "/__test/provider-batch/sql-state");
        expect(response.status).toBe(200);
        return response.json();
      };
      const before = await sql();
      const outcomes = [];
      for (const actor of [guest, owner]) {
        const denied = await actor.client.twoFactor.sendOtp({});
        expect(denied.error).toMatchObject({
          status: 400,
          code: "OTP_NOT_CONFIGURED",
          message: "otp isn't configured",
        });
        expect(await sql()).toEqual(before);
        outcomes.push(ctx.snapshot(denied));
      }
      for (const value of [undefined, "", "wrong-password", password]) {
        const denied = await owner.client.twoFactor.enable({
          method: "otp",
          ...(value === undefined ? {} : { password: value }),
        });
        expect(denied.error?.status).toBe(400);
        expect(denied.error?.code).toBe(
          value === undefined
            ? "VALIDATION_ERROR"
            : value === password
              ? "OTP_NOT_CONFIGURED"
              : "INVALID_PASSWORD",
        );
        expect(await sql()).toEqual(before);
        expect(((await ctx.readUserState({ userId })) as any).twoFactorExists).toBe(false);
        outcomes.push(ctx.snapshot(denied));
      }
      const enrolled = await owner.client.twoFactor.enable({ password, method: "totp" });
      expect(enrolled.error).toBeNull();
      if (!enrolled.data || enrolled.data.method !== "totp") {
        throw new Error("Actual TOTP enrollment required");
      }
      const uri = enrolled.data.totpURI;
      expect(
        (await owner.client.twoFactor.verifyTotp({ code: await generateCurrentTotp(uri) })).error,
      ).toBeNull();
      const pending = actorFor("missing-pending");
      const signin = await pending.client.signIn.email({ email, password });
      expect(signin.error).toBeNull();
      expect(signin.data).toHaveProperty("twoFactorRedirect", true);
      const pendingBefore = await sql();
      expect(
        ((pendingBefore as any).verification ?? (pendingBefore as any).verifications).length,
      ).toBeGreaterThan(0);
      const denied = await pending.client.twoFactor.sendOtp({});
      expect(denied.error).toMatchObject({
        status: 400,
        code: "OTP_NOT_CONFIGURED",
        message: "otp isn't configured",
      });
      expect(await sql()).toEqual(pendingBefore);
      const saved = await owner.client.twoFactor.getTotpUri({ password });
      expect(saved.error).toBeNull();
      expect(saved.data?.totpURI).toBe(uri);
      const control: any = (
        await ctx.rawRequest({
          path: "/__test/two-factor-otp-config",
          method: "POST",
          json: { profile, email },
        })
      ).body;
      expect(control.delivery).toBeNull();
      expect(control.receipts).toEqual([]);
      const resumed = await pending.client.twoFactor.verifyTotp({
        code: await generateCurrentTotp(uri),
      });
      expect(resumed.error).toBeNull();
      expect((await pending.client.getSession()).data?.user.id).toBe(userId);
      expect((await owner.client.getSession()).data?.user.id).toBe(userId);

      const configured = createAuthClient({
        baseURL: ctx.baseURL + authProfilePath("two-factor-otp-plain"),
        plugins: [twoFactorClient()],
        fetchOptions: { customFetchImpl: owner.fetch },
      });
      const sent = await configured.twoFactor.sendOtp({});
      expect(sent.error).toBeNull();
      const delivered: any = (
        await ctx.rawRequest({
          path: "/__test/two-factor-otp-config",
          method: "POST",
          json: { profile: "two-factor-otp-plain", email },
        })
      ).body;
      expect(delivered.delivery.userId).toBe(userId);
      expect(delivered.delivery.otp).toMatch(/^\d{6}$/);
      expect(delivered.row).not.toBeNull();
      expect(delivered.receipts).toEqual([{ phase: "send", input: delivered.delivery.otp }]);
      expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(foreignBefore);
      return {
        outcomes,
        pendingDenied: ctx.snapshot(denied),
        resumed: ctx.snapshot(resumed),
        sent: ctx.snapshot(sent),
        owner: ctx.snapshot(await owner.client.getSession()),
        foreign: ctx.snapshot(foreignBefore),
      };
    },
    ["POST /two-factor/send-otp", "POST /two-factor/enable", "POST /two-factor/verify-totp"],
  );
}
