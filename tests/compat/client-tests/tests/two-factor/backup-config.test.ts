import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { twoFactorClient } from "better-auth/client/plugins";
import { symmetricDecrypt } from "better-auth/crypto";
import { z } from "zod";

import { authProfilePath } from "../../support/profiles";
import { compatScenario } from "../../support/scenario";

const codesSchema = z.object({ backupCodes: z.array(z.string()) });

const factorSchema = z
  .object({
    id: z.string(),
    userId: z.string(),
    secret: z.string(),
    backupCodes: z.string(),
  })
  .passthrough();

const viewSchema = z.object({
  status: z.literal(true),
  backupCodes: z.array(z.string()),
  receipts: z.array(z.object({ phase: z.string(), input: z.string() })),
});

const secret = ["compat", "test", "only", "key", "not", "real", "minimum", "32chars"].join("-");

function redactCodes(result: unknown) {
  const copy = structuredClone(result) as {
    data?: Record<string, unknown> | null;
  };
  if (copy.data) {
    if (typeof copy.data.totpURI === "string") {
      copy.data.totpURI = "<authenticator-URI>";
    }
    if (Array.isArray(copy.data.backupCodes)) {
      copy.data.backupCodes = copy.data.backupCodes.map(() => "<backup-code>");
    }
  }
  return copy;
}

for (const profile of [
  "two-factor-backup-plain",
  "two-factor-backup-zero",
  "two-factor-backup-negative",
  "two-factor-backup-encrypted",
  "two-factor-backup-custom",
] as const) {
  compatScenario(
    `two-factor ${profile} applies configured generation and storage through enrollment, server-only view, consumption and regeneration`,
    async (ctx) => {
      const client = (name: string) =>
        createAuthClient({
          baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
          plugins: [twoFactorClient()],
          fetchOptions: { customFetchImpl: ctx.actor(name, profile).fetch },
        });
      const owner = client("owner");
      const email = ctx.uniqueEmail(profile);
      const password = "password123";
      const signup = await owner.signUp.email({
        email,
        password,
        name: "Backup Owner",
      });
      expect(signup.error).toBeNull();

      if (!signup.data) {
        throw new Error("owner required");
      }

      const userId = signup.data.user.id;
      const before = await ctx.readUserState({ userId });
      const missing = await owner.twoFactor.generateBackupCodes({ password });
      expect(missing.error?.code).toBe("TWO_FACTOR_NOT_ENABLED");
      expect(await ctx.readUserState({ userId })).toEqual(before);

      const enabled = await owner.twoFactor.enable({ password });
      expect(enabled.error).toBeNull();

      const codes = codesSchema.parse(enabled.data).backupCodes;
      const count = profile.endsWith("plain")
        ? 2
        : profile.endsWith("zero") || profile.endsWith("negative")
          ? 0
          : 3;
      expect(codes).toHaveLength(count);

      for (const code of codes) {
        if (profile.endsWith("plain")) {
          expect(code).toMatch(/^[a-zA-Z0-9]{4}-$/);
        } else if (profile.endsWith("encrypted")) {
          expect(code).toMatch(/^[a-zA-Z0-9]{5}-[a-zA-Z0-9]$/);
        }
      }

      if (profile.endsWith("custom")) {
        expect(codes).toEqual(["same-1", "same-1", "other-1"]);
      }

      const control = async (view = false) => {
        const result = await ctx.rawRequest({
          path: "/__test/two-factor-policy",
          method: "POST",
          json: {
            userId,
            ...(view ? { backupProfile: profile, viewBackupCodes: true } : {}),
          },
        });
        expect(result.status).toBe(200);
        return result.body;
      };
      const initial = factorSchema.parse(await control());
      const decoded = profile.endsWith("encrypted")
        ? await symmetricDecrypt({ key: secret, data: initial.backupCodes })
        : profile.endsWith("custom")
          ? initial.backupCodes.slice(7)
          : initial.backupCodes;
      expect(JSON.parse(decoded)).toEqual(codes);

      const viewed = viewSchema.parse(await control(true));
      expect(viewed.backupCodes).toEqual(codes);

      if (profile.endsWith("custom")) {
        expect(viewed.receipts).toEqual([
          { phase: "generate", input: "" },
          { phase: "encrypt", input: JSON.stringify(codes) },
          { phase: "decrypt", input: initial.backupCodes },
        ]);
      }

      const foreign = client("foreign");
      const other = await foreign.signUp.email({
        email: ctx.uniqueEmail(`${profile}-other`),
        password,
        name: "Other Owner",
      });
      expect(other.error).toBeNull();

      if (!other.data) {
        throw new Error("other required");
      }

      const otherEnabled = await foreign.twoFactor.enable({ password });
      expect(otherEnabled.error).toBeNull();

      const otherCodes = codesSchema.parse(otherEnabled.data).backupCodes;
      const attempted = codes[0] ?? "absent-backup";
      expect(otherCodes).not.toContain(attempted);

      const otherBefore = await ctx.readUserState({
        userId: other.data.user.id,
      });
      const wrongOwner = await foreign.twoFactor.verifyBackupCode({
        code: attempted,
        disableSession: true,
      });
      expect(wrongOwner.error?.code).toBe("INVALID_BACKUP_CODE");
      expect(await control()).toEqual(initial);
      expect(await ctx.readUserState({ userId: other.data.user.id })).toEqual(otherBefore);

      const current = await owner.getSession();
      const ownerBefore = await ctx.readUserState({ userId });
      const wrong = await owner.twoFactor.verifyBackupCode({
        code: "invalid-backup",
        disableSession: true,
      });
      expect(wrong.error?.code).toBe("INVALID_BACKUP_CODE");
      expect(await control()).toEqual(initial);

      let verified: unknown = null;
      let replay: unknown = null;

      if (codes.length) {
        const result = await owner.twoFactor.verifyBackupCode({
          code: codes[0]!,
          disableSession: true,
          trustDevice: true,
        });
        expect(result.error).toBeNull();
        expect(result.data?.user.id).toBe(userId);
        expect(result.data?.token).toBe(current.data?.session.token);

        verified = result;
        const remaining = viewSchema.parse(await control(true));
        expect(remaining.backupCodes).toEqual(codes.filter((code) => code !== codes[0]));

        const consumed = factorSchema.parse(await control());
        expect(consumed.id).toBe(initial.id);
        expect(consumed.secret).toBe(initial.secret);

        const denied = await owner.twoFactor.verifyBackupCode({
          code: codes[0]!,
        });
        expect(denied.error?.code).toBe("INVALID_BACKUP_CODE");
        expect(await control()).toEqual(consumed);

        replay = denied;
      }

      expect(await ctx.readUserState({ userId })).toEqual(ownerBefore);

      const wrongPassword = await owner.twoFactor.generateBackupCodes({
        password: "wrong-password",
      });
      expect(wrongPassword.error?.code).toBe("INVALID_PASSWORD");

      const regenerated = await owner.twoFactor.generateBackupCodes({
        password,
      });
      expect(regenerated.error).toBeNull();

      const updated = codesSchema.parse(regenerated.data).backupCodes;
      expect(updated).toHaveLength(count);

      const after = factorSchema.parse(await control());
      expect(after.id).toBe(initial.id);
      expect(after.secret).toBe(initial.secret);
      expect(viewSchema.parse(await control(true)).backupCodes).toEqual(updated);

      if (codes.length) {
        const old = await owner.twoFactor.verifyBackupCode({
          code: codes[codes.length - 1]!,
        });
        expect(old.error?.code).toBe("INVALID_BACKUP_CODE");
        expect(await control()).toEqual(after);
      }

      expect((await owner.getSession()).data?.session.token).toBe(current.data?.session.token);

      let repeated = null;

      if (profile === "two-factor-backup-custom") {
        // The same callback remains alive while the existing reset boundary
        // clears fixture state. A second real enrollment must start at one and
        // return only the new owner's actual generation/cipher receipts.
        const reset = await ctx.rawRequest({
          path: "/__test/reset-state",
          method: "POST",
        });
        expect(reset.status).toBe(200);
        expect(reset.body).toEqual({ status: true });

        const secondSignup = await owner.signUp.email({
          email,
          password,
          name: "Backup Owner",
        });
        expect(secondSignup.error).toBeNull();

        if (!secondSignup.data) {
          throw new Error("second owner required");
        }

        expect(secondSignup.data.user.id).not.toBe(userId);

        const secondEnabled = await owner.twoFactor.enable({ password });
        expect(secondEnabled.error).toBeNull();

        const secondCodes = codesSchema.parse(secondEnabled.data).backupCodes;
        expect(secondCodes).toEqual(["same-1", "same-1", "other-1"]);

        const secondStorage = await ctx.rawRequest({
          path: "/__test/two-factor-policy",
          method: "POST",
          json: { userId: secondSignup.data.user.id },
        });
        expect(secondStorage.status).toBe(200);

        const secondFactor = factorSchema.parse(secondStorage.body);
        expect(secondFactor.userId).toBe(secondSignup.data.user.id);
        expect(secondFactor.backupCodes).toBe("backup-" + JSON.stringify(secondCodes));

        const secondView = await ctx.rawRequest({
          path: "/__test/two-factor-policy",
          method: "POST",
          json: {
            userId: secondSignup.data.user.id,
            backupProfile: profile,
            viewBackupCodes: true,
          },
        });
        expect(secondView.status).toBe(200);
        expect(viewSchema.parse(secondView.body)).toEqual({
          status: true,
          backupCodes: secondCodes,
          receipts: [
            { phase: "generate", input: "" },
            { phase: "encrypt", input: JSON.stringify(secondCodes) },
            { phase: "decrypt", input: secondFactor.backupCodes },
          ],
        });

        repeated = {
          reset,
          signup: secondSignup,
          enabled: redactCodes(secondEnabled),
          owner: { userId: secondSignup.data.user.id },
        };
      }

      return ctx.snapshot({
        signup,
        repeated,
        before,
        missing,
        enabled: redactCodes(enabled),
        wrongOwner,
        wrong,
        current,
        verified,
        replay,
        wrongPassword,
        regenerated: redactCodes(regenerated),
        storage: {
          mode: profile,
          initial: codes.length,
          regenerated: updated.length,
        },
      });
    },
    [
      "POST /two-factor/enable",
      "POST /two-factor/generate-backup-codes",
      "POST /two-factor/verify-backup-code",
    ],
  );
}

compatScenario(
  "two-factor invalid backup generation preserves validation and credentials while OTP-only enrollment has no backup factor",
  async (ctx) => {
    const profile = "two-factor-backup-invalid-length";
    const client = (name: string) =>
      createAuthClient({
        baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
        plugins: [twoFactorClient()],
        fetchOptions: { customFetchImpl: ctx.actor(name, profile).fetch },
      });
    const owner = client("owner");
    const guest = client("guest");
    const password = "password123";
    const guestEnable = await guest.twoFactor.enable({ password });
    expect(guestEnable.error?.code).toBe("UNAUTHORIZED");

    const created = await owner.signUp.email({
      email: ctx.uniqueEmail("invalid-backup-length"),
      password,
      name: "Invalid Length Owner",
    });
    expect(created.error).toBeNull();

    if (!created.data) {
      throw new Error("owner required");
    }

    const userId = created.data.user.id;
    const original = await owner.getSession();
    const before = await ctx.readUserState({ userId });
    const wrong = await owner.twoFactor.enable({ password: "wrong-password" });
    expect(wrong.error?.code).toBe("INVALID_PASSWORD");

    const failed = await owner.twoFactor.enable({ password });
    expect(failed.error?.status).toBe(500);
    expect(await ctx.readUserState({ userId })).toEqual(before);
    expect((await owner.getSession()).data?.session.token).toBe(original.data?.session.token);

    const noFactor = await ctx.rawRequest({
      path: "/__test/two-factor-policy",
      method: "POST",
      json: { userId },
    });
    expect(noFactor.status).toBe(200);
    expect(noFactor.body).toBeNull();

    const otpEnabled = await owner.twoFactor.enable({
      password,
      method: "otp",
    });
    expect(otpEnabled.error).toBeNull();
    expect(otpEnabled.data).toEqual({ method: "otp" });

    const current = await owner.getSession();
    expect(current.data?.user.twoFactorEnabled).toBe(true);

    const otpState = await ctx.readUserState({ userId });
    const wrongRegeneration = await owner.twoFactor.generateBackupCodes({
      password: "wrong-password",
    });
    expect(wrongRegeneration.error?.code).toBe("INVALID_PASSWORD");

    const absent = await owner.twoFactor.generateBackupCodes({ password });
    expect(absent.error?.code).toBe("TWO_FACTOR_NOT_ENABLED");
    expect(await ctx.readUserState({ userId })).toEqual(otpState);

    return ctx.snapshot({
      created,
      guestEnable,
      original,
      before,
      wrong,
      failed,
      otpEnabled,
      current,
      wrongRegeneration,
      absent,
      otpState,
    });
  },
  ["POST /two-factor/enable", "POST /two-factor/generate-backup-codes"],
);

compatScenario(
  "two-factor pending backup disableSession consumes duplicates and attempt state without issuing a session or trusting the device",
  async (ctx) => {
    const profile = "two-factor-backup-custom";
    const owner = createAuthClient({
      baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
      plugins: [twoFactorClient()],
      fetchOptions: { customFetchImpl: ctx.actor("owner", profile).fetch },
    });
    const email = ctx.uniqueEmail("pending-backup-disable");
    const password = "password123";
    const created = await owner.signUp.email({
      email,
      password,
      name: "Pending Backup Owner",
    });
    expect(created.error).toBeNull();

    if (!created.data) {
      throw new Error("owner required");
    }

    const userId = created.data.user.id;
    const enabled = await owner.twoFactor.enable({ password });
    expect(enabled.error).toBeNull();

    const codes = codesSchema.parse(enabled.data).backupCodes;
    expect(codes[0]).toBe(codes[1]);
    expect((await owner.signOut()).error).toBeNull();

    const pending = await owner.signIn.email({
      email,
      password,
      rememberMe: false,
    });
    expect(pending.data).toMatchObject({ twoFactorRedirect: true });

    const pendingSchema = z.object({
      key: z.string(),
      challenge: z.boolean(),
      attempts: z.string().nullable(),
      otpExists: z.boolean(),
      trustCount: z.number(),
    });
    const state = async (key?: string) => {
      const result = await ctx.rawRequest({
        path: "/__test/two-factor-policy",
        method: "POST",
        json: {
          userId,
          pendingState: true,
          ...(key ? { pendingKey: key } : {}),
        },
      });
      expect(result.status).toBe(200);
      return pendingSchema.parse(result.body);
    };
    const before = await state();
    expect(before).toMatchObject({
      challenge: true,
      attempts: "0",
      otpExists: false,
      trustCount: 0,
    });

    const ownerBefore = await ctx.readUserState({ userId });
    expect(z.object({ sessions: z.array(z.unknown()) }).parse(ownerBefore).sessions).toEqual([]);

    const verified = await owner.twoFactor.verifyBackupCode({
      code: codes[0]!,
      disableSession: true,
      trustDevice: true,
    });
    expect(verified.error).toBeNull();
    expect(verified.data?.user.id).toBe(userId);
    expect(verified.data).not.toHaveProperty("token");

    const after = await state(before.key);
    expect(after).toEqual({ ...before, attempts: null });
    expect(await ctx.readUserState({ userId })).toEqual(ownerBefore);
    expect((await owner.getSession()).data).toBeNull();

    const view = await ctx.rawRequest({
      path: "/__test/two-factor-policy",
      method: "POST",
      json: { userId, backupProfile: profile, viewBackupCodes: true },
    });
    expect(view.status).toBe(200);
    expect(viewSchema.parse(view.body).backupCodes).toEqual(
      codes.filter((code) => code !== codes[0]),
    );

    const replay = await owner.twoFactor.verifyBackupCode({ code: codes[0]! });
    expect(replay.error?.code).toBe("INVALID_TWO_FACTOR_COOKIE");
    expect(await state(before.key)).toEqual(after);

    // OTP has its separate budget and can complete the retained real challenge.
    const sent = await owner.twoFactor.sendOtp({});
    expect(sent.error).toBeNull();

    const delivery = await ctx.rawRequest({
      path: "/__test/two-factor-policy",
      method: "POST",
      json: { deliveryEmail: email },
    });
    expect(delivery.status).toBe(200);

    const otp = z.object({ otp: z.string() }).parse(delivery.body).otp;
    const completed = await owner.twoFactor.verifyOtp({ code: otp });
    expect(completed.error).toBeNull();
    expect(completed.data?.user.id).toBe(userId);

    const final = await state(before.key);
    expect(final).toMatchObject({
      key: before.key,
      challenge: false,
      attempts: null,
      otpExists: false,
      trustCount: 0,
    });

    const persisted = await ctx.readUserState({ userId });
    const sessions = z
      .object({
        sessions: z.array(z.object({ token: z.string(), userId: z.string() })),
      })
      .parse(persisted).sessions;
    expect(sessions).toHaveLength(1);
    expect(sessions[0]).toMatchObject({ token: completed.data?.token, userId });

    return ctx.snapshot({
      created,
      enabled: redactCodes(enabled),
      pending,
      before: { ...before, key: { token: before.key } },
      verified,
      after: { ...after, key: { token: after.key } },
      ownerBefore,
      replay,
      sent,
      completed,
      final: { ...final, key: { token: final.key } },
      persisted,
    });
  },
  [
    "POST /two-factor/enable",
    "POST /two-factor/verify-backup-code",
    "POST /two-factor/send-otp",
    "POST /two-factor/verify-otp",
  ],
);
