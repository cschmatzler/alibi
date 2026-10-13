import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { storedVerification, expireVerification } from "../../../support/verification";

for (const profile of [undefined, "passwordless-hashed"] as const) {
  compatScenario(
    `server email OTP checks retain live proofs and retire exhausted attempts with ${profile ?? "plain"} storage`,
    async (ctx) => {
      const owner = await ctx.actor("owner").client.signUp.email({
        email: ctx.uniqueEmail("server-check-owner"),
        password: "password123",
        name: "Check Owner",
      });
      expect(owner.error).toBeNull();
      const email = owner.data!.user.email;
      async function create(email: string, type: string) {
        const result = await ctx.rawRequest({
          path: "/__test/server-api",
          method: "POST",
          json: { operation: "create-email-otp", ...(profile ? { profile } : {}), email, type },
        });
        expect(result.status).toBe(200);
        expect(typeof result.body).toBe("string");
        return result.body as string;
      }
      async function check(body: unknown) {
        return ctx.rawRequest({
          path: "/__test/server-api/email-otp-check",
          method: "POST",
          json: { ...(profile ? { profile } : {}), body },
        });
      }
      const observations = [];
      for (const type of [
        "email-verification",
        "sign-in",
        "forget-password",
        "change-email",
      ] as const) {
        const otp = await create(email, type);
        const identifier = `${type}-otp-${email}`;
        const proof = await storedVerification(ctx, identifier);
        expect(proof).toHaveLength(1);
        const malformed = await check({ email, type, otp: 42 });
        expect(malformed.status).toBe(400);
        expect((malformed.body as { code: string }).code).toBe("VALIDATION_ERROR");
        expect(await storedVerification(ctx, identifier)).toEqual(proof);
        const success = await check({ email: email.toUpperCase(), type, otp, ignored: true });
        expect(success.status).toBe(200);
        expect(success.body).toEqual({ success: true });
        expect(await storedVerification(ctx, identifier)).toEqual(proof);
        const wrong = [];
        for (let attempt = 1; attempt <= 3; attempt++) {
          const result = await check({ email, type, otp: "wrong" });
          expect(result.status).toBe(400);
          expect((result.body as { code: string }).code).toBe("INVALID_OTP");
          const stored = await storedVerification(ctx, identifier);
          expect(stored).toHaveLength(1);
          expect(stored[0]!.value.endsWith(`:${attempt}`)).toBe(true);
          if (!profile) expect(stored[0]!.value).toBe(`${otp}:${attempt}`);
          wrong.push(result);
        }
        const exhausted = await check({ email, type, otp });
        expect(exhausted.status).toBe(403);
        expect((exhausted.body as { code: string }).code).toBe("TOO_MANY_ATTEMPTS");
        expect(await storedVerification(ctx, identifier)).toEqual([]);
        expect((await ctx.actor("owner").client.getSession()).data!.user.id).toBe(
          owner.data!.user.id,
        );
        observations.push({ malformed, success, wrong, exhausted });
      }
      const guest = ctx.uniqueEmail("server-check-absent");
      const otp = await create(guest, "sign-in");
      const identifier = `sign-in-otp-${guest}`;
      const proof = await storedVerification(ctx, identifier);
      const missing = await check({ email: guest, type: "sign-in", otp });
      expect(missing.status).toBe(400);
      expect((missing.body as { code: string }).code).toBe("USER_NOT_FOUND");
      expect(await storedVerification(ctx, identifier)).toEqual(proof);
      await expireVerification(ctx, identifier);
      const expired = await check({ email: guest, type: "sign-in", otp });
      expect(expired.status).toBe(400);
      expect((expired.body as { code: string }).code).toBe("OTP_EXPIRED");
      expect(await storedVerification(ctx, identifier)).toEqual([]);
      const replay = await check({ email: guest, type: "sign-in", otp });
      expect(replay.status).toBe(400);
      expect((replay.body as { code: string }).code).toBe("INVALID_OTP");
      return ctx.snapshot({ observations, missing, expired, replay });
    },
  );
}
