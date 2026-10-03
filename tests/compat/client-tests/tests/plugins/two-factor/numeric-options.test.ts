import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { twoFactorClient } from "better-auth/client/plugins";
import { z } from "zod";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import { generateCurrentTotp, hotpAtCounter, redactTwoFactorPayload } from "../../../support/totp";

const factorSchema = z
  .object({
    id: z.string(),
    userId: z.string(),
    secret: z.string(),
    backupCodes: z.string(),
    verified: z.boolean(),
    failedVerificationCount: z.number().nullable(),
    lockedUntil: z.string().nullable(),
  })
  .passthrough();

compatScenario(
  "raw TOTP numbers use Source HMAC, truthy defaults and wrapped counters",
  async (ctx) => {
    const results = [];
    for (const [profile, digits, period, valid] of [
      ["two-factor-totp-fraction", 3.5, 30.5, true],
      ["two-factor-totp-negative-period", 6, -30, true],
      ["two-factor-totp-infinite-period", 6, Infinity, true],
      ["two-factor-totp-negative-infinite-period", 6, -Infinity, true],
      ["two-factor-totp-large-period", 6, 1e30, true],
      ["two-factor-totp-nan", 6, 30, true],
      ["two-factor-totp-invalid-digits", -1, 30, false],
      ["two-factor-totp-infinite-digits", Infinity, 30, false],
      ["two-factor-totp-tiny-period", 6, Number.MIN_VALUE, false],
    ] as const) {
      const first = Math.floor(Date.now() / (period * 1000));
      const response = await ctx.rawRequest({
        path: "/__test/two-factor-totp",
        method: "POST",
        json: { profile, secret: "密钥🔑" },
      });
      const last = Math.floor(Date.now() / (period * 1000));
      expect(response.status).toBe(valid ? 200 : 500);
      if (valid) {
        const code = z.object({ code: z.string() }).parse(response.body).code;
        const expected = await Promise.all(
          [...new Set([first, last])].map((counter) =>
            hotpAtCounter(new TextEncoder().encode("密钥🔑"), digits, counter),
          ),
        );
        expect(expected).toContain(code);
        if (digits === 3.5) expect(code).toContain(".");
      }
      results.push({ profile, status: response.status });
    }
    return results;
  },
  [],
  30000,
  {
    oracle: {
      collapsedFixtureErrors:
        "the server-only control maps genuine generation exceptions to generic 500",
    },
  },
);

for (const [profile, digits, period] of [
  ["two-factor-totp-fraction", 3.5, 30.5],
  ["two-factor-totp-negative-period", 6, -30],
  ["two-factor-totp-infinite-period", 6, Infinity],
  ["two-factor-totp-negative-infinite-period", 6, -Infinity],
  ["two-factor-totp-large-period", 6, 1e30],
  ["two-factor-totp-nan", 6, 30],
] as const) {
  compatScenario(
    `raw TOTP ${profile} authenticates only its owner and records complete challenge state`,
    async (ctx) => {
      const client = (name: string) =>
        createAuthClient({
          baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
          plugins: [twoFactorClient()],
          fetchOptions: { customFetchImpl: ctx.actor(name, profile).fetch },
        });
      const owner = client("owner");
      const foreign = client("foreign");
      const password = "password123";
      const email = ctx.uniqueEmail(profile);
      const signup = await owner.signUp.email({ email, password, name: "Numeric Owner" });
      expect(signup.error).toBeNull();
      if (!signup.data) throw new Error("owner required");
      const userId = signup.data.user.id;
      const other = await foreign.signUp.email({
        email: ctx.uniqueEmail("foreign"),
        password,
        name: "Foreign",
      });
      expect(other.error).toBeNull();
      if (!other.data) throw new Error("foreign required");
      const foreignBefore = await ctx.readUserState({ userId: other.data.user.id });
      const enabled = await owner.twoFactor.enable({ password });
      expect(enabled.error).toBeNull();
      const uri = z.object({ totpURI: z.string() }).parse(enabled.data).totpURI;
      expect(new URL(uri).searchParams.get("digits")).toBe(String(digits));
      expect(new URL(uri).searchParams.get("period")).toBe(
        profile.endsWith("nan") ? "NaN" : String(period),
      );
      const saved = await owner.twoFactor.getTotpUri({ password });
      expect(saved.error).toBeNull();
      const savedUri = z.object({ totpURI: z.string() }).parse(saved.data).totpURI;
      expect(new URL(savedUri).searchParams.get("period")).toBe(String(period));
      const factor = async () =>
        factorSchema.parse(
          (
            await ctx.rawRequest({
              path: "/__test/two-factor-policy",
              method: "POST",
              json: { userId },
            })
          ).body,
        );
      if (profile === "two-factor-totp-fraction") {
        expect(
          (await owner.twoFactor.verifyTotp({ code: await generateCurrentTotp(savedUri) })).error,
        ).toBeNull();
      }
      const enrolled = await factor();
      expect(enrolled.verified).toBe(true);
      const wrongUser = await foreign.twoFactor.verifyTotp({
        code: await generateCurrentTotp(savedUri),
      });
      expect(wrongUser.error?.code).toBe("TOTP_NOT_ENABLED");
      expect(await ctx.readUserState({ userId: other.data.user.id })).toEqual(foreignBefore);
      expect(await factor()).toEqual(enrolled);
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
      const rowsBefore = z
        .object({ key: z.string(), attempts: z.string().nullable(), challenge: z.boolean() })
        .parse(await pending());
      expect(rowsBefore.challenge).toBe(true);
      expect(rowsBefore.attempts).toBe("0");
      const wrong = await owner.twoFactor.verifyTotp({ code: "wrong🔑" });
      expect(wrong.error?.code).toBe("INVALID_CODE");
      expect(await ctx.readUserState({ userId })).toEqual(before);
      const failed = await factor();
      expect(failed).toEqual({ ...enrolled, failedVerificationCount: 1 });
      const rowsFailed = z
        .object({ key: z.string(), attempts: z.string(), challenge: z.boolean() })
        .parse(await pending());
      expect(rowsFailed).toEqual({ ...rowsBefore, attempts: "1" });
      const completed = await owner.twoFactor.verifyTotp({
        code: await generateCurrentTotp(savedUri),
      });
      expect(completed.error).toBeNull();
      const session = await owner.getSession();
      expect(session.data?.user.id).toBe(userId);
      const state = z
        .object({ sessions: z.array(z.object({ token: z.string(), userId: z.string() })) })
        .passthrough()
        .parse(await ctx.readUserState({ userId }));
      expect(state.sessions).toHaveLength(1);
      expect(state.sessions[0]?.token).toBe(session.data?.session.token);
      const reset = await factor();
      expect(reset).toEqual({ ...enrolled, failedVerificationCount: 0, lockedUntil: null });
      expect(z.object({ key: z.null() }).parse(await pending()).key).toBeNull();
      expect(await ctx.readUserState({ userId: other.data.user.id })).toEqual(foreignBefore);
      return {
        signup: ctx.snapshot(signup),
        other: ctx.snapshot(other),
        enabled: ctx.snapshot(redactTwoFactorPayload(enabled)),
        saved: ctx.snapshot(redactTwoFactorPayload(saved)),
        wrongUser: ctx.snapshot(wrongUser),
        before: ctx.snapshot(before),
        wrong: ctx.snapshot(wrong),
        failed: ctx.snapshot({ ...failed, secret: "<cipher>", backupCodes: "<codes>" }),
        completed: ctx.snapshot(completed),
        session: ctx.snapshot(session),
        state: ctx.snapshot(state),
        reset: ctx.snapshot({ ...reset, secret: "<cipher>", backupCodes: "<codes>" }),
      };
    },
    ["POST /two-factor/enable", "POST /two-factor/verify-totp"],
  );
}

for (const [profile, count, length] of [
  ["two-factor-backup-nan-count", 0, 0],
  ["two-factor-backup-negative-infinite-count", 0, 0],
  ["two-factor-backup-nan-length", 1, 0],
  ["two-factor-backup-half-length", 1, 1],
  ["two-factor-backup-large-length", 1, 32770],
  ["two-factor-backup-large-count", 1024, 12],
] as const) {
  compatScenario(
    `raw backup ${profile} stores actual rounded codes and preserves owner boundaries`,
    async (ctx) => {
      const client = (name: string) =>
        createAuthClient({
          baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
          plugins: [twoFactorClient()],
          fetchOptions: { customFetchImpl: ctx.actor(name, profile).fetch },
        });
      const owner = client("owner");
      const foreign = client("foreign");
      const password = "password123";
      const signup = await owner.signUp.email({
        email: ctx.uniqueEmail(profile),
        password,
        name: "Backup Owner",
      });
      expect(signup.error).toBeNull();
      if (!signup.data) throw new Error("owner required");
      const userId = signup.data.user.id;
      const other = await foreign.signUp.email({
        email: ctx.uniqueEmail("foreign"),
        password,
        name: "Foreign",
      });
      expect(other.error).toBeNull();
      if (!other.data) throw new Error("foreign required");
      const foreignBefore = await ctx.readUserState({ userId: other.data.user.id });
      const enabled = await owner.twoFactor.enable({ password });
      expect(enabled.error).toBeNull();
      const codes = z.object({ backupCodes: z.array(z.string()) }).parse(enabled.data).backupCodes;
      expect(codes).toHaveLength(count);
      for (const code of codes) {
        expect(code.length).toBe(length + 1);
        expect(code).toMatch(length > 5 ? /^[a-zA-Z0-9]{5}-[a-zA-Z0-9]+$/ : /^[a-zA-Z0-9]*-$/);
      }
      const factor = async () =>
        factorSchema.parse(
          (
            await ctx.rawRequest({
              path: "/__test/two-factor-policy",
              method: "POST",
              json: { userId },
            })
          ).body,
        );
      const initial = await factor();
      expect(JSON.parse(initial.backupCodes)).toEqual(codes);
      const denied = await foreign.twoFactor.verifyBackupCode({ code: codes[0] ?? "missing" });
      expect(denied.error?.code).toBe("BACKUP_CODES_NOT_ENABLED");
      expect(await ctx.readUserState({ userId: other.data.user.id })).toEqual(foreignBefore);
      expect(await factor()).toEqual(initial);
      const wrong = await owner.twoFactor.verifyBackupCode({ code: "wrong🔑" });
      expect(wrong.error?.code).toBe("INVALID_BACKUP_CODE");
      expect(await factor()).toEqual(initial);
      if (codes.length) {
        const verified = await owner.twoFactor.verifyBackupCode({ code: codes[0]! });
        expect(verified.error).toBeNull();
        expect(JSON.parse((await factor()).backupCodes)).toEqual(
          codes.filter((c) => c !== codes[0]),
        );
        expect((await owner.twoFactor.verifyBackupCode({ code: codes[0]! })).error?.code).toBe(
          "INVALID_BACKUP_CODE",
        );
      }
      const regenerated = await owner.twoFactor.generateBackupCodes({ password });
      expect(regenerated.error).toBeNull();
      const fresh = z
        .object({ backupCodes: z.array(z.string()) })
        .parse(regenerated.data).backupCodes;
      expect(fresh).toHaveLength(count);
      const final = await factor();
      expect(final).toEqual({ ...initial, backupCodes: JSON.stringify(fresh) });
      const session = await owner.getSession();
      expect(session.data?.user.id).toBe(userId);
      expect(await ctx.readUserState({ userId: other.data.user.id })).toEqual(foreignBefore);
      return {
        signup: ctx.snapshot(signup),
        other: ctx.snapshot(other),
        enabled: ctx.snapshot(redactTwoFactorPayload(enabled)),
        denied: ctx.snapshot(denied),
        wrong: ctx.snapshot(wrong),
        regenerated: ctx.snapshot(redactTwoFactorPayload(regenerated)),
        session: ctx.snapshot(session),
        count,
        length,
      };
    },
    [
      "POST /two-factor/enable",
      "POST /two-factor/verify-backup-code",
      "POST /two-factor/generate-backup-codes",
    ],
  );
}

for (const [profile, units, minutes] of [
  ["two-factor-otp-nan", 0, 3],
  ["two-factor-otp-half", 1, 0.5],
  ["two-factor-otp-large", 32770, 1e8],
  ["two-factor-otp-infinite-digits", null, 3],
  ["two-factor-otp-infinite-expiry", null, Infinity],
  ["two-factor-otp-negative-expiry", 6, -1],
] as const) {
  compatScenario(
    `raw OTP ${profile} preserves generated data, expiry and authentication state`,
    async (ctx) => {
      const client = (name: string) =>
        createAuthClient({
          baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
          plugins: [twoFactorClient()],
          fetchOptions: { customFetchImpl: ctx.actor(name, profile).fetch },
        });
      const owner = client("owner");
      const foreign = client("foreign");
      const password = "password123";
      const email = ctx.uniqueEmail(profile);
      const signup = await owner.signUp.email({ email, password, name: "Numeric OTP" });
      expect(signup.error).toBeNull();
      if (!signup.data) throw new Error("owner required");
      const userId = signup.data.user.id;
      const other = await foreign.signUp.email({
        email: ctx.uniqueEmail("foreign"),
        password,
        name: "Foreign",
      });
      expect(other.error).toBeNull();
      if (!other.data) throw new Error("foreign required");
      const foreignBefore = await ctx.readUserState({ userId: other.data.user.id });
      const before = z
        .object({
          sessions: z.array(z.object({ id: z.string(), token: z.string() }).passthrough()),
        })
        .passthrough()
        .parse(await ctx.readUserState({ userId }));
      const identifier = `2fa-otp-${userId}!${before.sessions[0]!.id}`;
      const control = async () =>
        z
          .object({
            delivery: z.object({ otp: z.string(), userId: z.string() }).nullable(),
            row: z
              .object({
                id: z.string(),
                identifier: z.string(),
                value: z.string(),
                expiresAt: z.string(),
              })
              .nullable(),
            generations: z.number(),
            receipts: z.array(z.object({ phase: z.string(), input: z.string() })),
          })
          .parse(
            (
              await ctx.rawRequest({
                path: "/__test/two-factor-otp-config",
                method: "POST",
                json: { profile, email, identifier },
              })
            ).body,
          );
      const start = Date.now();
      const sent = await owner.twoFactor.sendOtp({});
      const end = Date.now();
      const issued = await control();
      if (units === null) {
        expect(sent.error?.status).toBe(500);
        expect(sent.error).not.toHaveProperty("code");
        expect(issued).toEqual({ delivery: null, row: null, generations: 0, receipts: [] });
        expect(await ctx.readUserState({ userId })).toEqual(before);
        return ctx.snapshot({ signup, other, sent, before, issued });
      }
      expect(sent.error).toBeNull();
      if (!issued.row || !issued.delivery) throw new Error("actual delivered row required");
      const code = issued.delivery.otp;
      expect(code).toHaveLength(units);
      expect(code).toMatch(/^\d*$/);
      expect(issued.delivery.userId).toBe(userId);
      expect(issued.row.value).toBe(`${code}:0`);
      expect(issued.receipts).toEqual([{ phase: "send", input: code }]);
      expect(Date.parse(issued.row.expiresAt)).toBeGreaterThanOrEqual(start + minutes * 60000);
      expect(Date.parse(issued.row.expiresAt)).toBeLessThanOrEqual(end + minutes * 60000);
      const wrongOwner = await foreign.twoFactor.verifyOtp({ code });
      expect(wrongOwner.error?.code).toBe("OTP_HAS_EXPIRED");
      expect((await control()).row).toEqual(issued.row);
      expect(await ctx.readUserState({ userId: other.data.user.id })).toEqual(foreignBefore);
      if (minutes < 0) {
        const expired = await owner.twoFactor.verifyOtp({ code });
        expect(expired.error?.code).toBe("OTP_HAS_EXPIRED");
        expect(await ctx.readUserState({ userId })).toEqual(before);
        return ctx.snapshot({ signup, other, sent, expired, before });
      }
      const wrong = await owner.twoFactor.verifyOtp({ code: "wrong🔑" });
      expect(wrong.error?.code).toBe("INVALID_CODE");
      expect((await control()).row?.value).toBe(`${code}:1`);
      expect(await ctx.readUserState({ userId })).toEqual(before);
      const verified = await owner.twoFactor.verifyOtp({ code });
      expect(verified.error).toBeNull();
      expect(verified.data?.user.id).toBe(userId);
      expect(verified.data?.token).not.toBe(before.sessions[0]!.token);
      expect((await control()).row).toBeNull();
      const after = z
        .object({
          user: z.object({ twoFactorEnabled: z.boolean() }).passthrough(),
          sessions: z.array(z.object({ token: z.string(), userId: z.string() }).passthrough()),
          twoFactorExists: z.boolean(),
        })
        .passthrough()
        .parse(await ctx.readUserState({ userId }));
      expect(after.sessions).toHaveLength(1);
      expect(after.sessions[0]?.token).toBe(verified.data?.token);
      expect(after.user.twoFactorEnabled).toBe(true);
      expect(after.twoFactorExists).toBe(false);
      const replay = await owner.twoFactor.verifyOtp({ code });
      expect(replay.error?.code).toBe("OTP_HAS_EXPIRED");
      expect(await ctx.readUserState({ userId })).toEqual(after);
      expect(await ctx.readUserState({ userId: other.data.user.id })).toEqual(foreignBefore);
      return ctx.snapshot({
        signup,
        other,
        sent,
        wrongOwner,
        wrong,
        verified,
        replay,
        before,
        after,
        units,
        minutes,
      });
    },
    ["POST /two-factor/send-otp", "POST /two-factor/verify-otp"],
  );
}
