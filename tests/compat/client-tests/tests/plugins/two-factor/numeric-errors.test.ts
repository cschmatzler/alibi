import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { twoFactorClient } from "better-auth/client/plugins";
import { z } from "zod";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import { redactTwoFactorPayload } from "../../../support/totp";

for (const profile of [
  "two-factor-totp-invalid-digits",
  "two-factor-totp-infinite-digits",
  "two-factor-totp-tiny-period",
] as const) {
  compatScenario(
    `invalid terminating TOTP ${profile} restores its real pending attempt without swallowing callback identity`,
    async (ctx) => {
      const owner = createAuthClient({
        baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
        plugins: [twoFactorClient()],
        fetchOptions: { customFetchImpl: ctx.actor("owner", profile).fetch },
      });
      const password = "password123";
      const email = ctx.uniqueEmail(profile);
      const signup = await owner.signUp.email({ email, password, name: "Invalid TOTP" });
      expect(signup.error).toBeNull();
      if (!signup.data) throw new Error("owner required");
      const userId = signup.data.user.id;
      const enabled = await owner.twoFactor.enable({ password });
      expect(enabled.error).toBeNull();
      const factor = await ctx.rawRequest({
        path: "/__test/two-factor-policy",
        method: "POST",
        json: { userId },
      });
      await owner.signOut();
      expect((await owner.signIn.email({ email, password })).data).toHaveProperty(
        "twoFactorRedirect",
        true,
      );
      const before = await ctx.readUserState({ userId });
      const pending = async () =>
        (
          await ctx.rawRequest({
            path: "/__test/two-factor-policy",
            method: "POST",
            json: { userId, pendingState: true },
          })
        ).body;
      const initial = z
        .object({
          key: z.string(),
          challenge: z.boolean(),
          attempts: z.string().nullable(),
          otpExists: z.boolean(),
          trustCount: z.number(),
        })
        .passthrough()
        .parse(await pending());
      expect(initial).toHaveProperty("attempts", "0");
      expect(initial).toHaveProperty("challenge", true);
      const rejected = await owner.twoFactor.verifyTotp({ code: "wrong🔑" });
      expect(rejected.error?.status).toBe(500);
      expect(rejected.error).not.toHaveProperty("code");
      expect(await pending()).toEqual(initial);
      expect(await ctx.readUserState({ userId })).toEqual(before);
      expect(
        (
          await ctx.rawRequest({
            path: "/__test/two-factor-policy",
            method: "POST",
            json: { userId },
          })
        ).body,
      ).toEqual(factor.body);
      return ctx.snapshot({
        signup,
        enabled: redactTwoFactorPayload(enabled),
        rejected,
        before,
        pending: { ...initial, identifier: { token: initial.key }, key: undefined },
      });
    },
    ["POST /two-factor/verify-totp"],
  );
}
