import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { readOtp } from "./helpers";

for (const profile of ["otp-change-disabled-omitted", "otp-change-disabled-false"] as const) {
  compatScenario(
    `disabled OTP email change: ${profile} guards before proof access and callbacks`,
    async (ctx) => {
      async function physical() {
        const response = await fetch(`${ctx.baseURL}/__test/provider-batch/sql-state`);
        expect(response.status).toBe(200);
        return response.json();
      }
      async function delivery(email: string, type: string) {
        const response = await fetch(
          `${ctx.baseURL}/__test/email-otp?email=${encodeURIComponent(email)}&type=${type}`,
        );
        expect(response.status).toBe(200);
        return response.json();
      }
      const owner = ctx.actor("disabled-otp-owner", profile);
      const guest = ctx.actor("disabled-otp-guest", profile);
      const email = ctx.uniqueEmail("disabled-otp-owner");
      const newEmail = ctx.uniqueEmail("disabled-otp-target");
      const signup = await owner.client.signUp.email({
        email,
        password: "password123",
        name: "Disabled OTP Owner",
      });
      expect(signup.error).toBeNull();
      const issuer = ctx.actor("enabled-otp-issuer");
      const login = await issuer.client.signIn.email({ email, password: "password123" });
      expect(login.error).toBeNull();
      const issued = await issuer.client.emailOtp.requestEmailChange(
        { newEmail },
        { headers: { "x-callback-probe": "issue207" } },
      );
      expect(issued.error).toBeNull();
      const targetOtp = await readOtp(ctx, newEmail, "change-email");
      const currentIssued = await issuer.client.emailOtp.sendVerificationOtp({
        email,
        type: "email-verification",
      });
      expect(currentIssued.error).toBeNull();
      const currentOtp = await readOtp(ctx, email, "email-verification");
      expect(
        await ctx.readVerificationState({ identifier: `change-email-otp-${email}-${newEmail}` }),
      ).toHaveLength(1);
      expect(
        await ctx.readVerificationState({ identifier: `email-verification-otp-${email}` }),
      ).toHaveLength(1);
      const before = await physical();
      const receipt = await delivery(newEmail, "change-email");
      const denied = [];
      for (const kind of ["request", "change"] as const) {
        const result =
          kind === "request"
            ? await owner.client.emailOtp.requestEmailChange(
                { newEmail, otp: currentOtp },
                { headers: { "x-callback-probe": "issue207" } },
              )
            : await owner.client.emailOtp.changeEmail(
                { newEmail, otp: targetOtp },
                { headers: { "x-callback-probe": "issue207" } },
              );
        expect(result.error?.status).toBe(400);
        expect(result.error?.message).toBe("Change email with OTP is disabled");
        expect(result.error?.code).toBeUndefined();
        expect(await physical()).toEqual(before);
        expect(await delivery(newEmail, "change-email")).toEqual(receipt);
        const unauthenticated =
          kind === "request"
            ? await guest.client.emailOtp.requestEmailChange({ newEmail, otp: currentOtp })
            : await guest.client.emailOtp.changeEmail({ newEmail, otp: targetOtp });
        expect(unauthenticated.error).toMatchObject({
          status: 401,
          code: "UNAUTHORIZED",
          message: "Unauthorized",
        });
        const malformed = await guest.fetch(
          `${ctx.baseURL}/__test/profiles/${profile}/api/auth/email-otp/${kind === "request" ? "request-email-change" : "change-email"}`,
          {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ newEmail: 55, otp: targetOtp }),
          },
        );
        expect(malformed.status).toBe(400);
        const malformedBody = await malformed.json();
        expect(await physical()).toEqual(before);
        denied.push({
          kind,
          result: ctx.snapshot(result),
          unauthenticated: ctx.snapshot(unauthenticated),
          malformed: { status: malformed.status, body: malformedBody },
        });
      }
      expect((await owner.client.getSession()).data?.user.email).toBe(email);
      const control = await issuer.client.emailOtp.changeEmail({ newEmail, otp: targetOtp });
      expect(control.error).toBeNull();
      expect((await owner.client.getSession()).data?.user.email).toBe(newEmail);
      expect(
        await ctx.readVerificationState({ identifier: `change-email-otp-${email}-${newEmail}` }),
      ).toEqual([]);
      expect(
        await ctx.readVerificationState({ identifier: `email-verification-otp-${email}` }),
      ).toHaveLength(1);
      return {
        signup: ctx.snapshot(signup),
        login: ctx.snapshot(login),
        issued: ctx.snapshot(issued),
        currentIssued: ctx.snapshot(currentIssued),
        denied,
        control: ctx.snapshot(control),
      };
    },
    ["POST /email-otp/request-email-change", "POST /email-otp/change-email"],
  );
}
