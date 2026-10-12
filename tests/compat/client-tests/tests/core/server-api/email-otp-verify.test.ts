import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import {
  storedVerification,
  verificationCount,
  readUserState,
} from "../../../support/verification";

for (const profile of [undefined, "passwordless-proof"] as const) {
  compatScenario(
    `server email OTP verification consumes proofs with auto sign-in ${profile ? "enabled" : "disabled"}`,
    async (ctx) => {
      const actor = ctx.actor("owner", profile);
      const owner = await actor.client.signUp.email({
        email: ctx.uniqueEmail("server-verify-owner"),
        password: "password123",
        name: "Verify Owner",
      });
      expect(owner.error).toBeNull();
      expect(owner.data!.user.emailVerified).toBe(false);
      const foreign = await ctx.actor("foreign", profile).client.signUp.email({
        email: ctx.uniqueEmail("server-verify-foreign"),
        password: "password123",
        name: "Foreign",
      });
      expect(foreign.error).toBeNull();
      const email = owner.data!.user.email;
      const before = await readUserState(ctx, owner.data!.user.id);
      const foreignBefore = await readUserState(ctx, foreign.data!.user.id);
      async function create(email: string) {
        const result = await ctx.rawRequest({
          path: "/__test/server-api",
          method: "POST",
          json: {
            operation: "create-email-otp",
            ...(profile ? { profile } : {}),
            email,
            type: "email-verification",
          },
        });
        expect(result.status).toBe(200);
        expect(typeof result.body).toBe("string");
        return result.body as string;
      }
      async function invoke(body: unknown) {
        const response = await ctx
          .actor("verification-sdk", profile)
          .fetch(`${ctx.baseURL}/__test/server-api/email-otp-verify`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              ...(profile ? { profile } : {}),
              body,
              headers: { "user-agent": "server-email-otp-sdk", "x-forwarded-for": "198.51.100.31" },
            }),
          });
        return {
          status: response.status,
          body: (await response.json()) as any,
          cookieCount: response.headers.getSetCookie().length,
        };
      }
      const otp = await create(email);
      const identifier = `email-verification-otp-${email}`;
      const proof = await storedVerification(ctx, identifier);
      const invalid = await invoke({ email, otp: 42 });
      expect(invalid.status).toBe(400);
      expect(invalid.body.code).toBe("VALIDATION_ERROR");
      expect(await storedVerification(ctx, identifier)).toEqual(proof);
      const wrong = await invoke({ email, otp: "wrong" });
      expect(wrong.status).toBe(400);
      expect(wrong.body.code).toBe("INVALID_OTP");
      expect((await storedVerification(ctx, identifier))[0]!.value).toBe(`${otp}:1`);
      expect(await readUserState(ctx, owner.data!.user.id)).toEqual(before);
      const verified = await invoke({
        email: email.toUpperCase(),
        otp,
        userId: foreign.data!.user.id,
      });
      expect(verified.status).toBe(200);
      expect(verified.body).toMatchObject({
        status: true,
        user: { id: owner.data!.user.id, emailVerified: true },
      });
      expect(await verificationCount(ctx, identifier)).toBe(0);
      const after = await readUserState(ctx, owner.data!.user.id);
      expect(after.user).toEqual({ ...before.user!, emailVerified: true });
      expect(after.accounts).toEqual(before.accounts);
      expect(after.sessions).toHaveLength(profile ? 2 : 1);
      const session = await ctx.actor("verification-sdk", profile).client.getSession();
      if (profile) {
        expect(verified.cookieCount).toBeGreaterThan(0);
        expect(session.data!.user.id).toBe(owner.data!.user.id);
        expect(session.data!.session.token).toBe(verified.body.token);
        expect(session.data!.session.userAgent).toBe("server-email-otp-sdk");
        expect(session.data!.session.ipAddress).toBe("198.51.100.31");
      } else {
        expect(verified.body.token).toBeNull();
        expect(verified.cookieCount).toBe(0);
        expect(session.data).toBeNull();
        expect(after.sessions).toEqual(before.sessions);
      }
      expect((await actor.client.getSession()).data!.user.id).toBe(owner.data!.user.id);
      expect(await readUserState(ctx, foreign.data!.user.id)).toEqual(foreignBefore);
      const replay = await invoke({ email, otp });
      expect(replay.status).toBe(400);
      expect(replay.body.code).toBe("INVALID_OTP");
      expect(await readUserState(ctx, owner.data!.user.id)).toEqual(after);
      const guest = ctx.uniqueEmail("server-verify-absent");
      const missing = await invoke({ email: guest, otp: await create(guest) });
      expect(missing.status).toBe(400);
      expect(missing.body.code).toBe("USER_NOT_FOUND");
      expect(await verificationCount(ctx, `email-verification-otp-${guest}`)).toBe(0);
      expect(await readUserState(ctx, owner.data!.user.id)).toEqual(after);
      expect(await readUserState(ctx, foreign.data!.user.id)).toEqual(foreignBefore);
      return ctx.snapshot({ before, invalid, wrong, verified, session, after, replay, missing });
    },
  );
}
