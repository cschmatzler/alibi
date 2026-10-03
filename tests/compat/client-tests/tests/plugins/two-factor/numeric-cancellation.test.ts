import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { twoFactorClient } from "better-auth/client/plugins";
import { z } from "zod";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import { generateCurrentTotp, redactTwoFactorPayload } from "../../../support/totp";

for (const failure of ["cancel", "forbidden"] as const) {
  compatScenario(
    `fractional TOTP authenticated ${failure} retains stage-specific factor state and real retry`,
    async (ctx) => {
      const profile = "two-factor-totp-fraction";
      const client = createAuthClient({
        baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
        plugins: [twoFactorClient()],
        fetchOptions: { customFetchImpl: ctx.actor("owner", profile).fetch },
      });
      const signup = await client.signUp.email({
        email: ctx.uniqueEmail(failure),
        password: "password123",
        name: "Fractional Cancellation",
      });
      expect(signup.error).toBeNull();
      if (!signup.data) throw new Error("owner required");
      if (!signup.data.token) throw new Error("issued signup token required");
      const userId = signup.data.user.id;
      const enabled = await client.twoFactor.enable({ password: "password123" });
      expect(enabled.error).toBeNull();
      const uri = z.object({ totpURI: z.string() }).parse(enabled.data).totpURI;
      const factor = async () =>
        (
          await ctx.rawRequest({
            path: "/__test/two-factor-policy",
            method: "POST",
            json: { userId },
          })
        ).body;
      const before = await ctx.readUserState({ userId });
      const initial = await factor();
      expect(initial).toHaveProperty("verified", false);
      const wrong = await client.twoFactor.verifyTotp(
        { code: "wrong🔑" },
        { headers: { "x-two-factor-session": failure } },
      );
      expect(wrong.error?.code).toBe("INVALID_CODE");
      expect(await ctx.readUserState({ userId })).toEqual(before);
      expect(await factor()).toEqual(initial);
      const rejected = await client.twoFactor.verifyTotp(
        { code: await generateCurrentTotp(uri), trustDevice: true },
        { headers: { "x-two-factor-session": failure } },
      );
      if (failure === "cancel") {
        expect(rejected.error?.status).toBe(500);
        expect(rejected.error).not.toHaveProperty("code");
      } else {
        expect(rejected.error).toMatchObject({
          status: 403,
          message: "session creation cancelled by database hook",
        });
      }
      const after = z
        .object({
          user: z.object({ twoFactorEnabled: z.boolean() }).passthrough(),
          sessions: z.array(z.unknown()),
        })
        .passthrough()
        .parse(await ctx.readUserState({ userId }));
      expect(after.user.twoFactorEnabled).toBe(true);
      expect(after.sessions).toEqual(
        z.object({ sessions: z.array(z.unknown()) }).parse(before).sessions,
      );
      expect(await factor()).toEqual(initial);
      const trust = await ctx.rawRequest({
        path: "/__test/two-factor-policy",
        method: "POST",
        json: { userId, pendingState: true },
      });
      expect(trust.body).toHaveProperty("trustCount", 0);
      // Source has already enabled the user. Retry marks the factor without rotating the old session.
      const retry = await client.twoFactor.verifyTotp({ code: await generateCurrentTotp(uri) });
      expect(retry.error).toBeNull();
      const final = await factor();
      expect(final).toEqual({ ...(initial as object), verified: true });
      const session = await client.getSession();
      expect(session.data?.session.token).toBe(signup.data.token);
      expect(session.data?.user.id).toBe(userId);
      await ctx.resetServerState();
      expect((await client.getSession()).data).toBeNull();
      expect(await ctx.readUserState({ userId })).toEqual({
        user: null,
        accounts: [],
        sessions: [],
        twoFactorExists: false,
      });
      return ctx.snapshot({
        signup,
        enabled: redactTwoFactorPayload(enabled),
        before,
        wrong,
        rejected,
        after,
        retry,
        session,
      });
    },
    ["POST /two-factor/verify-totp"],
  );
}
