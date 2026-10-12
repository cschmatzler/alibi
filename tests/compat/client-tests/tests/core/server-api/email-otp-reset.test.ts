import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import {
  readUserState,
  storedVerification,
  verificationCount,
} from "../../../support/verification";

for (const credential of [true, false]) {
  compatScenario(
    `server email OTP reset ${credential ? "replaces" : "creates"} credentials without reissuing authority`,
    async (ctx) => {
      const email = ctx.uniqueEmail("server-reset-owner");
      async function create(email: string, type: string) {
        const response = await ctx.rawRequest({
          path: "/__test/server-api",
          method: "POST",
          json: { operation: "create-email-otp", email, type },
        });
        expect(response.status).toBe(200);
        return response.body as string;
      }
      let ownerId: string;
      if (credential) {
        const owner = await ctx
          .actor("owner")
          .client.signUp.email({ email, password: "password123", name: "Reset Owner" });
        expect(owner.error).toBeNull();
        ownerId = owner.data!.user.id;
      } else {
        const response = await ctx
          .actor("owner")
          .fetch(`${ctx.baseURL}/__test/server-api/email-otp-sign-in`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              body: { email, otp: await create(email, "sign-in"), name: "OTP Owner" },
            }),
          });
        expect(response.status).toBe(200);
        ownerId = ((await response.json()) as { user: { id: string } }).user.id;
      }
      const foreign = await ctx
        .actor("foreign")
        .client.signUp.email({
          email: ctx.uniqueEmail("server-reset-foreign"),
          password: "password123",
          name: "Foreign",
        });
      expect(foreign.error).toBeNull();
      const before = await readUserState(ctx, ownerId);
      const foreignBefore = await readUserState(ctx, foreign.data!.user.id);
      const otp = await create(email, "forget-password");
      const identifier = `forget-password-otp-${email}`;
      const proof = await storedVerification(ctx, identifier);
      async function invoke(body: unknown) {
        return ctx.rawRequest({
          path: "/__test/server-api/email-otp-reset",
          method: "POST",
          json: { body },
        });
      }
      const denied = [];
      for (const [body, code] of [
        [{ email, otp, password: 42 }, "VALIDATION_ERROR"],
        [{ email, otp, password: "short" }, "PASSWORD_TOO_SHORT"],
      ] as const) {
        const result = await invoke(body);
        expect(result.status).toBe(400);
        expect((result.body as { code: string }).code).toBe(code);
        expect(await storedVerification(ctx, identifier)).toEqual(proof);
        expect(await readUserState(ctx, ownerId)).toEqual(before);
        denied.push(result);
      }
      const wrong = await invoke({ email, otp: "wrong", password: "replacement-password123" });
      expect(wrong.status).toBe(400);
      expect((wrong.body as { code: string }).code).toBe("INVALID_OTP");
      expect((await storedVerification(ctx, identifier))[0]!.value).toBe(`${otp}:1`);
      const reset = await invoke({
        email: email.toUpperCase(),
        otp,
        password: "replacement-password123",
        userId: foreign.data!.user.id,
      });
      expect(reset.status).toBe(200);
      expect(reset.body).toEqual({ success: true });
      expect(await verificationCount(ctx, identifier)).toBe(0);
      const after = await readUserState(ctx, ownerId);
      expect(after.user).toEqual({ ...before.user!, emailVerified: true });
      expect(after.sessions).toEqual(before.sessions);
      expect(after.accounts).toHaveLength(1);
      expect(after.accounts[0]!.providerId).toBe("credential");
      expect(after.accounts[0]!.userId).toBe(ownerId);
      if (credential) expect(after.accounts).toEqual(before.accounts);
      expect((await ctx.actor("owner").client.getSession()).data!.user.id).toBe(ownerId);
      expect(await readUserState(ctx, foreign.data!.user.id)).toEqual(foreignBefore);
      const replay = await invoke({ email, otp, password: "must-not-commit123" });
      expect(replay.status).toBe(400);
      expect((replay.body as { code: string }).code).toBe("INVALID_OTP");
      expect(await readUserState(ctx, ownerId)).toEqual(after);
      const client = ctx.actor("fresh").client;
      let rejected;
      if (credential) {
        rejected = await client.signIn.email({ email, password: "password123" });
        expect(rejected.error?.code).toBe("INVALID_EMAIL_OR_PASSWORD");
      }
      const accepted = await client.signIn.email({ email, password: "replacement-password123" });
      expect(accepted.error).toBeNull();
      expect(accepted.data!.user.id).toBe(ownerId);
      expect(await readUserState(ctx, foreign.data!.user.id)).toEqual(foreignBefore);
      return ctx.snapshot({
        before,
        denied,
        wrong,
        reset,
        after,
        replay,
        ...(rejected ? { rejected } : {}),
        accepted,
      });
    },
  );
}
