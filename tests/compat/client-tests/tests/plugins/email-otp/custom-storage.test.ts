import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { emailOTPClient } from "better-auth/client/plugins";

import { compatScenario } from "../../../support/scenario";
import { storedVerification, verificationCount } from "../../../support/verification";
import { readOtp } from "./helpers";
for (const mode of ["hash", "cipher", "cipher-failure"] as const) {
  compatScenario(
    `email OTP custom ${mode} transforms real proofs and composes reuse, errors and admission`,
    async (ctx) => {
      const profile = `passwordless-custom-${mode}` as const;
      const actor = ctx.actor("owner", profile);
      const owner = createAuthClient({
        baseURL: ctx.baseURL,
        plugins: [emailOTPClient()],
        fetchOptions: {
          customFetchImpl: actor.fetch,
          headers: {
            "x-forwarded-for":
              "198.51.100." + (["hash", "cipher", "cipher-failure"].indexOf(mode) + 20),
          },
        },
      });
      const email = ctx.uniqueEmail("custom-otp");
      const send = () => owner.emailOtp.sendVerificationOtp({ email, type: "sign-in" });
      const first = await send();
      expect(first.error).toBeNull();
      const otp = await readOtp(ctx, email, "sign-in");
      const initial = await storedVerification(ctx, `sign-in-otp-${email}`);
      expect(initial).toHaveLength(1);
      const encoded =
        mode === "hash"
          ? `application:${new Bun.CryptoHasher("sha256").update(otp).digest("hex")}`
          : `application:${Buffer.from([...Buffer.from(otp)].map((byte) => byte ^ 0x5a)).toString("hex")}`;
      expect(initial[0]!.value).toBe(`${encoded}:0`);
      const retrieve = await ctx.rawRequest({
        path: "/__test/server-api",
        method: "POST",
        json: { operation: "get-email-otp", profile, email, type: "sign-in" },
      });
      if (mode === "hash") expect(retrieve.status).toBe(400);
      else if (mode === "cipher-failure") expect(retrieve.status).toBe(500);
      else {
        expect(retrieve.status).toBe(200);
        expect(retrieve.body).toEqual({ otp });
      }
      if (mode === "cipher-failure") {
        expect((await storedVerification(ctx, `sign-in-otp-${email}`))[0]!.value).toBe(
          initial[0]!.value,
        );
        const resend = await send();
        expect(resend.error?.status).toBe(500);
        expect((await storedVerification(ctx, `sign-in-otp-${email}`))[0]!.value).toBe(
          initial[0]!.value,
        );
        const denied = await owner.signIn.emailOtp({ email, otp });
        expect(denied.error?.status).toBe(500);
        expect(await storedVerification(ctx, `sign-in-otp-${email}`)).toEqual([]);
        const recovery = await send();
        expect(recovery.error).toBeNull();
        const replacement = await readOtp(ctx, email, "sign-in");
        expect(await verificationCount(ctx, `sign-in-otp-${email}`)).toBe(1);
        const retry = await owner.signIn.emailOtp({ email, otp: replacement });
        expect(retry.error?.status).toBe(500);
        expect(await verificationCount(ctx, `sign-in-otp-${email}`)).toBe(0);
        expect((await owner.getSession()).data).toBeNull();
        return ctx.snapshot({ first, retrieve, resend, denied, recovery, retry });
      }
      const wrong = await owner.signIn.emailOtp({ email, otp: "wrong-code" });
      expect(wrong.error?.code).toBe("INVALID_OTP");
      const second = await send();
      expect(second.error).toBeNull();
      const nextOtp = await readOtp(ctx, email, "sign-in");
      const resent = await storedVerification(ctx, `sign-in-otp-${email}`);
      if (mode === "cipher") {
        expect(nextOtp).toBe(otp);
        expect(resent[0]!.value).toBe(`${encoded}:1`);
      } else {
        expect(resent[0]!.value).toBe(
          `application:${new Bun.CryptoHasher("sha256").update(nextOtp).digest("hex")}:0`,
        );
      }
      const third = await send();
      expect(third.error).toBeNull();
      const currentOtp = await readOtp(ctx, email, "sign-in");
      const admitted = await storedVerification(ctx, `sign-in-otp-${email}`);
      const blocked = await send();
      expect(blocked.error?.status).toBe(429);
      expect((await storedVerification(ctx, `sign-in-otp-${email}`))[0]!.value).toBe(
        admitted[0]!.value,
      );
      const signIn = await owner.signIn.emailOtp({ email, otp: currentOtp });
      expect(signIn.error).toBeNull();
      expect(await verificationCount(ctx, `sign-in-otp-${email}`)).toBe(0);
      const replay = await owner.signIn.emailOtp({ email, otp: currentOtp });
      expect(replay.error?.status).toBe(400);
      expect((await owner.getSession()).data!.user.email).toBe(email);
      return ctx.snapshot({
        first,
        retrieve:
          mode === "cipher"
            ? { ...retrieve, body: { otp: { token: (retrieve.body as any).otp } } }
            : retrieve,
        wrong,
        second,
        third,
        blocked,
        signIn,
        replay,
      });
    },
    ["POST /email-otp/send-verification-otp", "POST /sign-in/email-otp"],
  );
}
