import { expect } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { twoFactorClient } from "better-auth/client/plugins";
import { z } from "zod";
import { compatScenario } from "../../support/scenario";
import { authProfilePath } from "../../support/profiles";

const stateSchema = z
  .object({
    user: z
      .object({ id: z.string(), twoFactorEnabled: z.boolean() })
      .passthrough(),
    sessions: z.array(
      z
        .object({ id: z.string(), token: z.string(), userId: z.string() })
        .passthrough(),
    ),
    twoFactorExists: z.boolean(),
  })
  .passthrough();
const rowsSchema = z.array(
  z
    .object({ id: z.string(), identifier: z.string(), value: z.string() })
    .passthrough(),
);

for (const profile of [
  "two-factor-pending-session-cancel",
  "two-factor-pending-session-forbidden",
  "two-factor-passwordless",
] as const) {
  compatScenario(
    `two-factor authenticated OTP ${profile.endsWith("cancel") ? "session cancellation returns an empty 500" : profile.endsWith("forbidden") ? "retains a same-message application Forbidden" : "success rotates its real owner session"} after code consumption`,
    async (ctx) => {
      const client = (name: string) =>
        createAuthClient({
          baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
          plugins: [twoFactorClient()],
          fetchOptions: { customFetchImpl: ctx.actor(name, profile).fetch },
        });
      const owner = client("owner"),
        foreign = client("foreign"),
        guest = client("guest");
      const email = ctx.uniqueEmail("authenticated-otp"),
        password = "password123";
      const signup = await owner.signUp.email({
        email,
        password,
        name: "OTP Cancellation Owner",
      });
      expect(signup.error).toBeNull();
      if (!signup.data) throw new Error("actual owner required");
      const other = await foreign.signUp.email({
        email: ctx.uniqueEmail("foreign"),
        password,
        name: "Foreign Owner",
      });
      expect(other.error).toBeNull();
      if (!other.data) throw new Error("actual foreign owner required");
      const userId = signup.data.user.id;
      const before = stateSchema.parse(await ctx.readUserState({ userId }));
      const foreignBefore = await ctx.readUserState({
        userId: other.data.user.id,
      });
      expect(before.user.twoFactorEnabled).toBe(false);
      expect(before.twoFactorExists).toBe(false);
      expect(before.sessions).toHaveLength(1);
      const original = before.sessions[0]!;
      if (!signup.data.token) throw new Error("actual signup token required");
      expect(original.token).toBe(signup.data.token);
      const identifier = `2fa-otp-${userId}!${original.id}`;
      const readOtp = async () =>
        rowsSchema.parse(await ctx.readVerificationState({ identifier }));
      const sent = await owner.twoFactor.sendOtp({});
      expect(sent.error).toBeNull();
      const delivery = await ctx.rawRequest({
        path: "/__test/two-factor-policy",
        method: "POST",
        json: { deliveryEmail: email },
      });
      const code = z.object({ otp: z.string() }).parse(delivery.body).otp;
      const issued = await readOtp();
      expect(issued).toHaveLength(1);
      expect(issued[0]?.value).toBe(`${code}:0`);
      const guestDenied = await guest.twoFactor.verifyOtp({ code });
      expect(guestDenied.error?.code).toBe("INVALID_TWO_FACTOR_COOKIE");
      const foreignDenied = await foreign.twoFactor.verifyOtp({ code });
      expect(foreignDenied.error?.code).toBe("OTP_HAS_EXPIRED");
      expect(await readOtp()).toEqual(issued);
      expect(await ctx.readUserState({ userId })).toEqual(before);
      const wrong = await owner.twoFactor.verifyOtp({ code: "wrong" });
      expect(wrong.error?.code).toBe("INVALID_CODE");
      const counted = await readOtp();
      expect(counted).toHaveLength(1);
      expect(counted[0]?.value).toBe(`${code}:1`);
      expect(await ctx.readUserState({ userId })).toEqual(before);
      const completed = await owner.twoFactor.verifyOtp({
        code,
        trustDevice: true,
      });
      if (profile.endsWith("cancel")) {
        expect(completed.error?.status).toBe(500);
        expect(completed.error).not.toHaveProperty("code");
      } else if (profile.endsWith("forbidden")) {
        expect(completed.error).toMatchObject({
          status: 403,
          message: "session creation cancelled by database hook",
        });
      } else {
        expect(completed.error).toBeNull();
        expect(completed.data?.user.id).toBe(userId);
        expect(completed.data?.token).not.toBe(original.token);
      }
      expect(await readOtp()).toEqual([]);
      const after = stateSchema.parse(await ctx.readUserState({ userId }));
      expect(after.user.twoFactorEnabled).toBe(true);
      expect(after.twoFactorExists).toBe(false);
      expect(after.sessions).toHaveLength(1);
      if (profile === "two-factor-passwordless") {
        expect(after.sessions[0]?.token).toBe(completed.data?.token);
        expect(after.sessions[0]?.id).not.toBe(original.id);
      } else {
        expect(after.sessions).toEqual(before.sessions);
      }
      const current = await owner.getSession();
      expect(current.data?.user.twoFactorEnabled).toBe(true);
      expect(current.data?.session.token).toBe(after.sessions[0]?.token);
      const trust = await ctx.rawRequest({
        path: "/__test/two-factor-policy",
        method: "POST",
        json: {
          userId,
          pendingState: true,
          pendingKey: `${userId}!${original.id}`,
        },
      });
      expect(
        z.object({ trustCount: z.number() }).parse(trust.body).trustCount,
      ).toBe(0);
      const retry = await owner.twoFactor.verifyOtp({ code });
      expect(retry.error?.code).toBe("OTP_HAS_EXPIRED");
      expect(await readOtp()).toEqual([]);
      expect(await ctx.readUserState({ userId })).toEqual(after);
      expect(await ctx.readUserState({ userId: other.data.user.id })).toEqual(
        foreignBefore,
      );
      expect((await foreign.getSession()).data?.user.id).toBe(
        other.data.user.id,
      );
      return ctx.snapshot({
        signup,
        other,
        before,
        foreignBefore,
        sent,
        guestDenied,
        foreignDenied,
        wrong,
        completed,
        after,
        current,
        retry,
        consumed: await readOtp(),
        trust: {
          count: z.object({ trustCount: z.number() }).parse(trust.body)
            .trustCount,
        },
      });
    },
    ["POST /two-factor/send-otp", "POST /two-factor/verify-otp"],
  );
}
