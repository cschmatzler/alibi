import { expect } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { twoFactorClient } from "better-auth/client/plugins";
import { z } from "zod";
import { authProfilePath, type FixtureProfile } from "../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { generateCurrentTotp } from "../../support/totp";

function clientFor(ctx: ScenarioContext, name = "primary", profile?: FixtureProfile) {
  return createAuthClient({
    baseURL: profile ? `${ctx.baseURL}${authProfilePath(profile)}` : ctx.baseURL,
    plugins: [twoFactorClient()],
    fetchOptions: { customFetchImpl: ctx.actor(name, profile).fetch },
  });
}

async function enroll(ctx: ScenarioContext, name: string, profile?: FixtureProfile) {
  const client = clientFor(ctx, name, profile);
  const email = ctx.uniqueEmail(name);
  const password = "password123";
  const signup = await client.signUp.email({ email, password, name });
  expect(signup.error).toBeNull();
  if (!signup.data) throw new Error("factor owner required");
  const enable = await client.twoFactor.enable({ password });
  expect(enable.error).toBeNull();
  const { totpURI, backupCodes } = z
    .object({ totpURI: z.string(), backupCodes: z.array(z.string()) })
    .parse(enable.data);
  const verified = await client.twoFactor.verifyTotp({ code: await generateCurrentTotp(totpURI) });
  expect(verified.error).toBeNull();
  expect((await client.getSession()).data?.user.twoFactorEnabled).toBe(true);
  return { client, email, password, userId: signup.data.user.id, totpURI, backupCodes };
}

const factorSchema = z.object({
  id: z.string(),
  userId: z.string(),
  secret: z.string(),
  backupCodes: z.string(),
  verified: z.boolean().nullable(),
  failedVerificationCount: z.number().nullable(),
  lockedUntil: z.string().nullable(),
});
async function factorState(
  ctx: ScenarioContext,
  userId: string,
  mutation: { count?: number | null; verified?: boolean; expireLock?: boolean } = {},
) {
  const response = await ctx.rawRequest({
    path: "/__test/two-factor-policy",
    method: "POST",
    json: { userId, ...mutation },
  });
  expect(response.status).toBe(200);
  return factorSchema.parse(response.body);
}
function publicFactorState(state: z.infer<typeof factorSchema>) {
  const { secret, backupCodes, lockedUntil, ...safe } = state;
  // Each runtime's real deadline is asserted against its request clock below.
  return { ...safe, locked: lockedUntil !== null };
}

compatScenario(
  "two-factor challenge budget spans factors and invalidates the exhausted challenge before a valid code",
  async (ctx) => {
    const owner = await enroll(ctx, "challenge-budget");
    await owner.client.signOut();
    const signIn = await owner.client.signIn.email({
      email: owner.email,
      password: owner.password,
    });
    expect(signIn.data).toHaveProperty("twoFactorRedirect", true);
    const failures = [];
    for (let index = 0; index < 5; index++) {
      const result =
        index % 2 === 0
          ? await owner.client.twoFactor.verifyTotp({ code: "invalid-code" })
          : await owner.client.twoFactor.verifyBackupCode({ code: "invalid-backup-code" });
      expect(result.error).toMatchObject({
        status: 401,
        code: index % 2 === 0 ? "INVALID_CODE" : "INVALID_BACKUP_CODE",
      });
      failures.push(ctx.snapshot(result));
    }
    const exhausted = await owner.client.twoFactor.verifyTotp({
      code: await generateCurrentTotp(owner.totpURI),
      trustDevice: true,
    });
    expect(exhausted.error).toMatchObject({
      status: 400,
      code: "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE",
    });
    const replay = await owner.client.twoFactor.verifyBackupCode({ code: owner.backupCodes[0]! });
    expect(replay.error).toMatchObject({ status: 401, code: "INVALID_TWO_FACTOR_COOKIE" });
    const deniedState = z
      .object({ twoFactorExists: z.literal(true), sessions: z.array(z.unknown()) })
      .parse(await ctx.readUserState({ userId: owner.userId }));
    expect(deniedState.sessions).toHaveLength(0);
    expect((await owner.client.getSession()).data).toBeNull();
    const renewed = await owner.client.signIn.email({
      email: owner.email,
      password: owner.password,
    });
    const completed = await owner.client.twoFactor.verifyBackupCode({
      code: owner.backupCodes[0]!,
    });
    expect(completed.error).toBeNull();
    const session = await owner.client.getSession();
    expect(session.data?.user.id).toBe(owner.userId);
    const persisted = z
      .object({ sessions: z.array(z.object({ token: z.string(), userId: z.string() })) })
      .parse(await ctx.readUserState({ userId: owner.userId }));
    expect(persisted.sessions).toHaveLength(1);
    expect(persisted.sessions[0]).toMatchObject({
      token: session.data?.session.token,
      userId: owner.userId,
    });
    return {
      signIn: ctx.snapshot(signIn),
      failures,
      exhausted: ctx.snapshot(exhausted),
      replay: ctx.snapshot(replay),
      deniedState,
      renewed: ctx.snapshot(renewed),
      completed: ctx.snapshot(completed),
      session: ctx.snapshot(session),
      persisted: ctx.snapshot(persisted),
    };
  },
  [
    "POST /two-factor/enable",
    "POST /two-factor/verify-totp",
    "POST /two-factor/verify-backup-code",
    "POST /two-factor/verify-otp",
    "POST /two-factor/send-otp",
  ],
);

compatScenario(
  "two-factor default account lock spans renewed challenges while authenticated and foreign owners retain their sessions",
  async (ctx) => {
    const owner = await enroll(ctx, "account-budget");
    const foreign = await enroll(ctx, "foreign-budget");
    const pending = clientFor(ctx, "pending-owner");
    const failures = [];
    for (let generation = 0; generation < 2; generation++) {
      const redirect = await pending.signIn.email({ email: owner.email, password: owner.password });
      expect(redirect.data).toHaveProperty("twoFactorRedirect", true);
      for (let index = 0; index < 5; index++) {
        const result =
          index % 2 === 0
            ? await pending.twoFactor.verifyTotp({ code: "invalid-code" })
            : await pending.twoFactor.verifyBackupCode({ code: "invalid-backup-code" });
        expect(result.error?.status).toBe(401);
        failures.push(ctx.snapshot(result));
      }
    }
    const locked = await pending.twoFactor.verifyTotp({
      code: await generateCurrentTotp(owner.totpURI),
    });
    expect(locked.error).toMatchObject({ status: 429, code: "ACCOUNT_TEMPORARILY_LOCKED" });
    const lockedBackup = await pending.twoFactor.verifyBackupCode({ code: owner.backupCodes[0]! });
    expect(lockedBackup.error).toMatchObject({ status: 429, code: "ACCOUNT_TEMPORARILY_LOCKED" });
    const before = await ctx.readUserState({ userId: owner.userId });
    expect((await pending.getSession()).data).toBeNull();
    const existing = await owner.client.twoFactor.verifyTotp({
      code: await generateCurrentTotp(owner.totpURI),
    });
    expect(existing.error).toBeNull();
    expect(await ctx.readUserState({ userId: owner.userId })).toEqual(before);
    const remainsLocked = await pending.twoFactor.verifyTotp({
      code: await generateCurrentTotp(owner.totpURI),
    });
    expect(remainsLocked.error?.status).toBe(429);
    await foreign.client.signOut();
    await foreign.client.signIn.email({ email: foreign.email, password: foreign.password });
    const foreignCompletion = await foreign.client.twoFactor.verifyTotp({
      code: await generateCurrentTotp(foreign.totpURI),
    });
    expect(foreignCompletion.error).toBeNull();
    const foreignSession = await foreign.client.getSession();
    expect(foreignSession.data?.user.id).toBe(foreign.userId);
    const ownerSession = await owner.client.getSession();
    expect(ownerSession.data?.user.id).toBe(owner.userId);
    return {
      failures,
      locked: ctx.snapshot(locked),
      lockedBackup: ctx.snapshot(lockedBackup),
      existing: ctx.snapshot(existing),
      remainsLocked: ctx.snapshot(remainsLocked),
      before: ctx.snapshot(before),
      foreignCompletion: ctx.snapshot(foreignCompletion),
      foreignSession: ctx.snapshot(foreignSession),
      ownerSession: ctx.snapshot(ownerSession),
    };
  },
  [
    "POST /two-factor/enable",
    "POST /two-factor/verify-totp",
    "POST /two-factor/verify-backup-code",
    "POST /two-factor/verify-otp",
    "POST /two-factor/send-otp",
  ],
);

compatScenario(
  "two-factor lockout settings preserve fractional thresholds, zero defaults, disabled budgets and successful resets in persisted state",
  async (ctx) => {
    const results = [];
    for (const profile of [
      "two-factor-lockout-fractional",
      "two-factor-lockout-zero",
      "two-factor-lockout-disabled",
    ] as const) {
      const owner = await enroll(ctx, profile, profile);
      await owner.client.signOut();
      const redirect = await owner.client.signIn.email({
        email: owner.email,
        password: owner.password,
      });
      expect(redirect.data).toHaveProperty("twoFactorRedirect", true);
      expect((await owner.client.getSession()).data).toBeNull();
      const seedCount = profile === "two-factor-lockout-zero" ? null : 0.5;
      const seeded = await factorState(ctx, owner.userId, { count: seedCount });
      expect(seeded.failedVerificationCount).toBe(seedCount);
      const failures = [];
      const failureCount = profile === "two-factor-lockout-fractional" ? 2 : 1;
      let lastFailureStarted = 0,
        lastFailureFinished = 0;
      for (let index = 0; index < failureCount; index++) {
        lastFailureStarted = Date.now();
        const failure = await owner.client.twoFactor.verifyTotp({ code: "invalid-code" });
        lastFailureFinished = Date.now();
        expect(failure.error).toMatchObject({ status: 401, code: "INVALID_CODE" });
        failures.push(ctx.snapshot(failure));
      }
      const failed = await factorState(ctx, owner.userId);
      expect(failed.failedVerificationCount).toBe(
        profile === "two-factor-lockout-disabled"
          ? 0.5
          : profile === "two-factor-lockout-zero"
            ? null
            : 2.5,
      );
      if (profile === "two-factor-lockout-fractional") {
        const until = Date.parse(failed.lockedUntil!);
        expect(until).toBeGreaterThanOrEqual(lastFailureStarted + 600_250);
        expect(until).toBeLessThanOrEqual(lastFailureFinished + 600_250);
        const locked = await owner.client.twoFactor.verifyBackupCode({
          code: owner.backupCodes[0]!,
        });
        expect(locked.error).toMatchObject({ status: 429, code: "ACCOUNT_TEMPORARILY_LOCKED" });
        expect(await factorState(ctx, owner.userId)).toEqual(failed);
        await factorState(ctx, owner.userId, { expireLock: true });
        const completed = await owner.client.twoFactor.verifyBackupCode({
          code: owner.backupCodes[0]!,
        });
        expect(completed.error).toBeNull();
        const reset = await factorState(ctx, owner.userId);
        expect(reset.failedVerificationCount).toBe(0);
        expect(reset.lockedUntil).toBeNull();
        expect(reset.id).toBe(seeded.id);
        expect(reset.secret).toBe(seeded.secret);
        expect(reset.backupCodes).not.toBe(seeded.backupCodes);
        results.push({
          profile,
          failures,
          failed: publicFactorState(failed),
          locked: ctx.snapshot(locked),
          completed: ctx.snapshot(completed),
          reset: publicFactorState(reset),
        });
      } else {
        const completed = await owner.client.twoFactor.verifyTotp({
          code: await generateCurrentTotp(owner.totpURI),
        });
        expect(completed.error).toBeNull();
        const reset = await factorState(ctx, owner.userId);
        expect(reset.failedVerificationCount).toBe(
          profile === "two-factor-lockout-disabled" ? 0.5 : 0,
        );
        expect(reset.lockedUntil).toBeNull();
        expect(reset.id).toBe(seeded.id);
        expect(reset.secret).toBe(seeded.secret);
        expect(reset.backupCodes).toBe(seeded.backupCodes);
        results.push({
          profile,
          failures,
          failed: publicFactorState(failed),
          completed: ctx.snapshot(completed),
          reset: publicFactorState(reset),
        });
        if (profile === "two-factor-lockout-zero") {
          await owner.client.signOut();
          expect(
            (await owner.client.signIn.email({ email: owner.email, password: owner.password }))
              .data,
          ).toHaveProperty("twoFactorRedirect", true);
          const zeroFailure = await owner.client.twoFactor.verifyTotp({ code: "invalid-code" });
          expect(zeroFailure.error?.code).toBe("INVALID_CODE");
          const zeroLock = await factorState(ctx, owner.userId);
          expect(zeroLock.failedVerificationCount).toBe(1);
          expect(zeroLock.lockedUntil).not.toBeNull();
          const expired = await owner.client.twoFactor.verifyTotp({
            code: await generateCurrentTotp(owner.totpURI),
          });
          expect(expired.error).toBeNull();
          const cleared = await factorState(ctx, owner.userId);
          expect(cleared.failedVerificationCount).toBe(0);
          expect(cleared.lockedUntil).toBeNull();
          results.push({
            profile: "zero-expired-lock",
            zeroFailure: ctx.snapshot(zeroFailure),
            zeroLock: publicFactorState(zeroLock),
            expired: ctx.snapshot(expired),
            cleared: publicFactorState(cleared),
          });
        }
      }
      expect((await owner.client.getSession()).data?.user.id).toBe(owner.userId);
    }
    return ctx.snapshot(results);
  },
  [
    "POST /two-factor/enable",
    "POST /two-factor/verify-totp",
    "POST /two-factor/verify-backup-code",
    "POST /two-factor/verify-otp",
    "POST /two-factor/send-otp",
  ],
);

compatScenario(
  "two-factor enrollment reuses only an unverified factor generation and protects established secrets from re-enrollment",
  async (ctx) => {
    const client = clientFor(ctx);
    const email = ctx.uniqueEmail("verified-generation");
    const password = "password123";
    const signup = await client.signUp.email({ email, password, name: "Generation Owner" });
    expect(signup.error).toBeNull();
    if (!signup.data) throw new Error("owner required");
    const first = await client.twoFactor.enable({ password });
    expect(first.error).toBeNull();
    const firstState = await factorState(ctx, signup.data.user.id);
    expect(firstState.verified).toBe(false);
    await factorState(ctx, signup.data.user.id, { count: 0.5 });
    const second = await client.twoFactor.enable({ password });
    expect(second.error).toBeNull();
    const secondState = await factorState(ctx, signup.data.user.id);
    expect(secondState.id).toBe(firstState.id);
    expect(secondState.verified).toBe(false);
    expect(secondState.failedVerificationCount).toBe(0.5);
    expect(secondState.secret).not.toBe(firstState.secret);
    expect(secondState.backupCodes).not.toBe(firstState.backupCodes);
    const uri = z.object({ totpURI: z.string() }).parse(second.data).totpURI;
    const beforeWrongPassword = await factorState(ctx, signup.data.user.id);
    const wrongPassword = await client.twoFactor.enable({ password: "wrong-password" });
    expect(wrongPassword.error?.code).toBe("INVALID_PASSWORD");
    expect(await factorState(ctx, signup.data.user.id)).toEqual(beforeWrongPassword);
    const verified = await client.twoFactor.verifyTotp({ code: await generateCurrentTotp(uri) });
    expect(verified.error).toBeNull();
    const established = await factorState(ctx, signup.data.user.id);
    expect(established.verified).toBe(true);
    expect(established.failedVerificationCount).toBe(0.5);
    const denied = await client.twoFactor.enable({ password });
    expect(denied.error).toMatchObject({ status: 400, code: "TOTP_ALREADY_ENABLED" });
    expect(await factorState(ctx, signup.data.user.id)).toEqual(established);
    const foreign = await enroll(ctx, "generation-foreign");
    const foreignWrong = await foreign.client.twoFactor.verifyTotp({ code: "invalid-code" });
    expect(foreignWrong.error?.status).toBe(401);
    expect(await factorState(ctx, signup.data.user.id)).toEqual(established);
    await factorState(ctx, signup.data.user.id, { verified: false });
    await client.signOut();
    const pending = await client.signIn.email({ email, password });
    expect(pending.data).toMatchObject({ twoFactorRedirect: true, twoFactorMethods: ["otp"] });
    const unverified = await factorState(ctx, signup.data.user.id);
    const deniedTotp = await client.twoFactor.verifyTotp({ code: await generateCurrentTotp(uri) });
    expect(deniedTotp.error).toMatchObject({ status: 400, code: "TOTP_NOT_ENABLED" });
    expect(await factorState(ctx, signup.data.user.id)).toEqual(unverified);
    const backup = z.object({ backupCodes: z.array(z.string()) }).parse(second.data)
      .backupCodes[0]!;
    const completion = await client.twoFactor.verifyBackupCode({ code: backup });
    expect(completion.error).toBeNull();
    expect((await client.getSession()).data?.user.id).toBe(signup.data.user.id);
    const final = await factorState(ctx, signup.data.user.id);
    expect(final.failedVerificationCount).toBe(0);
    expect(final.verified).toBe(false);
    const replay = await client.twoFactor.verifyBackupCode({ code: backup });
    expect(replay.error).toMatchObject({ status: 401, code: "INVALID_BACKUP_CODE" });
    expect(await factorState(ctx, signup.data.user.id)).toEqual(final);
    return ctx.snapshot({
      signup,
      firstState: publicFactorState(firstState),
      secondState: publicFactorState(secondState),
      wrongPassword,
      verified,
      established: publicFactorState(established),
      denied,
      foreignWrong,
      pending,
      unverified: publicFactorState(unverified),
      deniedTotp,
      completion,
      replay,
      final: publicFactorState(final),
    });
  },
  [
    "POST /two-factor/enable",
    "POST /two-factor/verify-totp",
    "POST /two-factor/verify-backup-code",
    "POST /two-factor/verify-otp",
    "POST /two-factor/send-otp",
  ],
);

compatScenario(
  "two-factor OTP failures share the pending account budget and successful OTP resets it without consuming a backup code",
  async (ctx) => {
    const profile = "two-factor-lockout-fractional";
    const owner = await enroll(ctx, "otp-account-budget", profile);
    const authenticatedBefore = await factorState(ctx, owner.userId);
    expect((await owner.client.twoFactor.sendOtp({})).error).toBeNull();
    const authenticatedWrong = await owner.client.twoFactor.verifyOtp({ code: "invalid-code" });
    expect(authenticatedWrong.error?.status).toBe(401);
    expect(await factorState(ctx, owner.userId)).toEqual(authenticatedBefore);
    await owner.client.signOut();
    expect(
      (await owner.client.signIn.email({ email: owner.email, password: owner.password })).data,
    ).toHaveProperty("twoFactorRedirect", true);
    await factorState(ctx, owner.userId, { count: 1.5 });
    expect((await owner.client.twoFactor.sendOtp({})).error).toBeNull();
    const delivery = await ctx.rawRequest({
      path: "/__test/two-factor-policy",
      method: "POST",
      json: { deliveryEmail: owner.email },
    });
    expect(delivery.status).toBe(200);
    const otp = z.object({ otp: z.string() }).parse(delivery.body).otp;
    const wrong = await owner.client.twoFactor.verifyOtp({ code: "invalid-code" });
    expect(wrong.error?.code).toBe("INVALID_CODE");
    const lockedState = await factorState(ctx, owner.userId);
    expect(lockedState.failedVerificationCount).toBe(2.5);
    expect(lockedState.lockedUntil).not.toBeNull();
    const locked = await owner.client.twoFactor.verifyOtp({ code: otp });
    expect(locked.error?.status).toBe(429);
    const lockedTotp = await owner.client.twoFactor.verifyTotp({
      code: await generateCurrentTotp(owner.totpURI),
    });
    expect(lockedTotp.error?.status).toBe(429);
    expect(await factorState(ctx, owner.userId)).toEqual(lockedState);
    await factorState(ctx, owner.userId, { expireLock: true });
    const completed = await owner.client.twoFactor.verifyOtp({ code: otp });
    expect(completed.error).toBeNull();
    const current = await owner.client.getSession();
    expect(current.data?.user.id).toBe(owner.userId);
    expect(current.data?.session.token).toBe(completed.data?.token);
    const reset = await factorState(ctx, owner.userId);
    expect(reset.failedVerificationCount).toBe(0);
    expect(reset.lockedUntil).toBeNull();
    expect(reset.id).toBe(authenticatedBefore.id);
    expect(reset.secret).toBe(authenticatedBefore.secret);
    expect(reset.backupCodes).toBe(authenticatedBefore.backupCodes);
    const replay = await clientFor(ctx, "otp-replay", profile).twoFactor.verifyOtp({ code: otp });
    expect(replay.error?.code).toBe("INVALID_TWO_FACTOR_COOKIE");
    return ctx.snapshot({
      authenticatedWrong,
      wrong,
      lockedState: publicFactorState(lockedState),
      locked,
      lockedTotp,
      completed,
      current,
      reset: publicFactorState(reset),
      replay,
    });
  },
  [
    "POST /two-factor/enable",
    "POST /two-factor/verify-totp",
    "POST /two-factor/verify-backup-code",
    "POST /two-factor/verify-otp",
    "POST /two-factor/send-otp",
  ],
);

compatScenario(
  "two-factor skip-verification enrollment persists verified state and rotates only the owner's session",
  async (ctx) => {
    const profile = "two-factor-skip-verification";
    const client = clientFor(ctx, "skip-owner", profile);
    const email = ctx.uniqueEmail("skip-owner"),
      password = "password123";
    const signup = await client.signUp.email({ email, password, name: "Skip Owner" });
    expect(signup.error).toBeNull();
    if (!signup.data) throw new Error("owner required");
    const originalToken = z.string().parse(signup.data.token);
    const original = await client.getSession();
    expect(original.data?.session.token).toBe(originalToken);
    const wrong = await client.twoFactor.enable({ password: "wrong-password" });
    expect(wrong.error?.code).toBe("INVALID_PASSWORD");
    const before = z
      .object({ twoFactorExists: z.boolean(), sessions: z.array(z.object({ token: z.string() })) })
      .parse(await ctx.readUserState({ userId: signup.data.user.id }));
    expect(before.twoFactorExists).toBe(false);
    expect(before.sessions.map((row) => row.token)).toEqual([originalToken]);
    const enabled = await client.twoFactor.enable({ password });
    expect(enabled.error).toBeNull();
    const state = await factorState(ctx, signup.data.user.id);
    expect(state.verified).toBe(true);
    expect(state.failedVerificationCount).toBe(0);
    const current = await client.getSession();
    expect(current.data?.user.id).toBe(signup.data.user.id);
    expect(current.data?.user.twoFactorEnabled).toBe(true);
    expect(current.data?.session.token).not.toBe(originalToken);
    const persisted = z
      .object({ sessions: z.array(z.object({ token: z.string(), userId: z.string() })) })
      .parse(await ctx.readUserState({ userId: signup.data.user.id }));
    expect(persisted.sessions).toHaveLength(1);
    expect(persisted.sessions[0]).toMatchObject({
      token: current.data?.session.token,
      userId: signup.data.user.id,
    });
    const reenroll = await client.twoFactor.enable({ password });
    expect(reenroll.error?.code).toBe("TOTP_ALREADY_ENABLED");
    expect(await factorState(ctx, signup.data.user.id)).toEqual(state);
    await client.signOut();
    expect((await client.signIn.email({ email, password })).data).toHaveProperty(
      "twoFactorRedirect",
      true,
    );
    const backup = z.object({ backupCodes: z.array(z.string()) }).parse(enabled.data)
      .backupCodes[0]!;
    const completion = await client.twoFactor.verifyBackupCode({ code: backup });
    expect(completion.error).toBeNull();
    expect((await client.getSession()).data?.user.id).toBe(signup.data.user.id);
    const afterCompletion = await factorState(ctx, signup.data.user.id);
    const replay = await client.twoFactor.verifyBackupCode({ code: backup });
    expect(replay.error).toMatchObject({ status: 401, code: "INVALID_BACKUP_CODE" });
    expect(await factorState(ctx, signup.data.user.id)).toEqual(afterCompletion);
    return ctx.snapshot({
      signup,
      original,
      wrong,
      before,
      enrollment: {
        error: enabled.error,
        backupCount: z.object({ backupCodes: z.array(z.string()) }).parse(enabled.data).backupCodes
          .length,
      },
      state: publicFactorState(state),
      current,
      persisted,
      reenroll,
      completion,
      replay,
      afterCompletion: publicFactorState(afterCompletion),
    });
  },
  [
    "POST /two-factor/enable",
    "POST /two-factor/verify-totp",
    "POST /two-factor/verify-backup-code",
    "POST /two-factor/verify-otp",
    "POST /two-factor/send-otp",
  ],
);
