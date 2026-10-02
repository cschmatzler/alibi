import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { twoFactorClient } from "better-auth/client/plugins";
import { z } from "zod";

import { authProfilePath } from "../../support/profiles";
import { compatScenario } from "../../support/scenario";
import { generateCurrentTotp, redactTwoFactorPayload } from "../../support/totp";

const factorSchema = z.object({
  secret: z.string(),
  backupCodes: z.string(),
  verified: z.boolean(),
  failedVerificationCount: z.number(),
  lockedUntil: z.null(),
});

const pendingSchema = z.object({
  key: z.string().nullable(),
  challenge: z.boolean(),
  attempts: z.string().nullable(),
  otpExists: z.boolean(),
  trustCount: z.number(),
});

for (const profile of [
  "two-factor-pending-session-cancel",
  "two-factor-pending-session-forbidden",
] as const) {
  for (const factor of ["totp", "otp", "backup"] as const) {
    compatScenario(
      `two-factor pending ${factor} ${profile.endsWith("cancel") ? "session cancellation returns FAILED_TO_CREATE_SESSION" : "preserves an identical-message application Forbidden"} after consumption`,
      async (ctx) => {
        const actor = (name: string) =>
          createAuthClient({
            baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
            plugins: [twoFactorClient()],
            fetchOptions: { customFetchImpl: ctx.actor(name, profile).fetch },
          });
        const owner = actor("owner");
        const foreign = actor("foreign");
        const guest = actor("guest");
        const email = ctx.uniqueEmail(`pending-${factor}`);
        const password = "password123";
        const signup = await owner.signUp.email({ email, password, name: "Pending Owner" });
        expect(signup.error).toBeNull();

        if (!signup.data) {
          throw new Error("owner required");
        }

        const other = await foreign.signUp.email({
          email: ctx.uniqueEmail("foreign"),
          password,
          name: "Foreign Owner",
        });
        expect(other.error).toBeNull();

        if (!other.data) {
          throw new Error("foreign required");
        }

        const foreignBefore = await ctx.readUserState({ userId: other.data.user.id });
        const enable = await owner.twoFactor.enable({ password });
        expect(enable.error).toBeNull();

        if (!enable.data || !("totpURI" in enable.data)) {
          throw new Error("real enrollment required");
        }

        const [firstBackup, secondBackup] = z
          .tuple([z.string(), z.string()])
          .rest(z.string())
          .parse(enable.data.backupCodes);
        const userId = signup.data.user.id;
        const policy = async (body: Record<string, unknown>) =>
          (
            await ctx.rawRequest({
              path: "/__test/two-factor-policy",
              method: "POST",
              json: { userId, ...body },
            })
          ).body;
        const initial = factorSchema.parse(await policy({ count: 0.5 }));
        expect(initial.verified).toBe(true);

        await owner.signOut();
        const badPassword = await owner.signIn.email({ email, password: "wrong-password" });
        expect(badPassword.error?.code).toBe("INVALID_EMAIL_OR_PASSWORD");

        const signIn = await owner.signIn.email({ email, password });
        expect(signIn.data).toMatchObject({ twoFactorRedirect: true });

        let code =
          factor === "backup"
            ? firstBackup
            : factor === "totp"
              ? await generateCurrentTotp(enable.data.totpURI)
              : "";

        if (factor === "otp") {
          const sent = await owner.twoFactor.sendOtp({});
          expect(sent.error).toBeNull();
          code = z.object({ otp: z.string() }).parse(await policy({ deliveryEmail: email })).otp;
        }

        const verify = (client: typeof owner, value: string) =>
          factor === "totp"
            ? client.twoFactor.verifyTotp({ code: value, trustDevice: true })
            : factor === "otp"
              ? client.twoFactor.verifyOtp({ code: value, trustDevice: true })
              : client.twoFactor.verifyBackupCode({ code: value, trustDevice: true });
        const deniedGuest = await verify(guest, code);
        expect(deniedGuest.error?.code).toBe("INVALID_TWO_FACTOR_COOKIE");
        expect(factorSchema.parse(await policy({}))).toEqual(initial);

        const before = pendingSchema.parse(await policy({ pendingState: true }));
        expect(before).toMatchObject({
          challenge: true,
          attempts: "0",
          otpExists: factor === "otp",
          trustCount: 0,
        });

        if (!before.key) {
          throw new Error("persisted challenge required");
        }

        const rejected = await verify(owner, code);
        expect(rejected.error).toMatchObject(
          profile.endsWith("cancel")
            ? { status: 500, code: "FAILED_TO_CREATE_SESSION", message: "failed to create session" }
            : { status: 403, message: "session creation cancelled by database hook" },
        );

        const after = pendingSchema.parse(
          await policy({ pendingState: true, pendingKey: before.key }),
        );
        expect(after).toMatchObject({
          challenge: false,
          attempts: factor === "otp" ? "0" : null,
          otpExists: false,
          trustCount: 0,
        });

        const stored = factorSchema.parse(await policy({}));
        expect(stored.secret).toBe(initial.secret);
        expect(stored.verified).toBe(true);
        expect(stored.failedVerificationCount).toBe(0);
        expect(stored.lockedUntil).toBeNull();

        if (factor === "backup") {
          expect(stored.backupCodes).not.toBe(initial.backupCodes);
        } else {
          expect(stored.backupCodes).toBe(initial.backupCodes);
        }

        const state = z
          .object({
            sessions: z.array(z.unknown()),
            user: z.object({ twoFactorEnabled: z.boolean() }),
          })
          .parse(await ctx.readUserState({ userId }));
        expect(state.sessions).toHaveLength(0);
        expect(state.user.twoFactorEnabled).toBe(true);

        const replay = await verify(owner, code);
        expect(replay.error?.code).toBe("INVALID_TWO_FACTOR_COOKIE");
        expect(await foreign.getSession()).toMatchObject({
          data: { user: { id: other.data.user.id } },
        });
        expect(await ctx.readUserState({ userId: other.data.user.id })).toEqual(foreignBefore);

        let backupReplay: unknown = null;

        if (factor === "backup") {
          await owner.signIn.email({ email, password });
          const old = await verify(owner, code);
          expect(old.error?.code).toBe("INVALID_BACKUP_CODE");

          const fresh = await verify(owner, secondBackup);
          expect(fresh.error?.status).toBe(profile.endsWith("cancel") ? 500 : 403);

          backupReplay = { old, fresh };
          expect(
            z.object({ sessions: z.array(z.unknown()) }).parse(await ctx.readUserState({ userId }))
              .sessions,
          ).toHaveLength(0);
        }

        expect(after.key).toBe(before.key);

        const beforeState = { ...before, key: before.key === null ? null : { token: before.key } };
        const afterState = { ...after, key: after.key === null ? null : { token: after.key } };
        return ctx.snapshot({
          signup,
          other,
          foreignBefore,
          enable: redactTwoFactorPayload(enable),
          badPassword,
          signIn,
          deniedGuest,
          before: beforeState,
          rejected,
          after: afterState,
          state,
          replay,
          backupReplay,
        });
      },
      [
        "POST /two-factor/enable",
        `POST /two-factor/verify-${factor === "backup" ? "backup-code" : factor}`,
      ],
    );
  }
}
