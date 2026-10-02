import { expect } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { twoFactorClient } from "better-auth/client/plugins";
import { z } from "zod";
import { authProfilePath, type FixtureProfile } from "../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { generateCurrentTotp } from "../../support/totp";
import { disableGuestValidation } from "./disable-validation";

function clientFor(ctx: ScenarioContext, profile: FixtureProfile, name = "owner") {
  return createAuthClient({
    baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
    plugins: [twoFactorClient()],
    fetchOptions: { customFetchImpl: ctx.actor(name, profile).fetch },
  });
}
const enrollment = z.object({ totpURI: z.string(), backupCodes: z.array(z.string()) });
const credentialState = z.array(
  z.object({ userId: z.string(), providerId: z.string(), hasPassword: z.boolean() }),
);
function redactFactor(value: unknown): unknown {
  const copy = structuredClone(value) as { data?: Record<string, unknown> | null };
  if (copy.data) {
    if (typeof copy.data.totpURI === "string") copy.data.totpURI = "<authenticator-URI>";
    if (Array.isArray(copy.data.backupCodes))
      copy.data.backupCodes = copy.data.backupCodes.map(() => "<backup-code>");
  }
  return copy;
}
async function credentials(ctx: ScenarioContext, userId: string, empty = false) {
  const result = await ctx.rawRequest({
    path: "/__test/two-factor-policy",
    method: "POST",
    json: { userId, credentialState: true, emptyCredentialPassword: empty },
  });
  expect(result.status).toBe(200);
  return credentialState.parse(result.body);
}
async function signup(ctx: ScenarioContext, profile: FixtureProfile, name = "owner") {
  const client = clientFor(ctx, profile, name),
    email = ctx.uniqueEmail(`${profile}-${name}`),
    password = "password123";
  const result = await client.signUp.email({ email, password, name });
  expect(result.error).toBeNull();
  if (!result.data) throw new Error("owner required");
  await ctx.seedOAuthAccount({
    email,
    providerId: "social-fixture",
    accountId: `${profile}-${name}-social-account`,
  });
  return { client, email, password, userId: result.data.user.id, result };
}
async function body(ctx: ScenarioContext, profile: FixtureProfile, path: string, json: unknown) {
  const response = await ctx
    .actor("owner", profile)
    .fetch(`${ctx.baseURL}${authProfilePath(profile)}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(json),
    });
  return { status: response.status, body: await response.json() };
}

compatScenario(
  "two-factor passwordless social owner completes real enrollment, URI retrieval, backup regeneration and disable without a credential password",
  async (ctx) => {
    const profile = "two-factor-passwordless",
      owner = await signup(ctx, profile);
    const mixed = await credentials(ctx, owner.userId);
    expect(mixed).toEqual([
      { userId: owner.userId, providerId: "credential", hasPassword: true },
      { userId: owner.userId, providerId: "social-fixture", hasPassword: false },
    ]);
    await ctx.removeCredentialAccount({ email: owner.email });
    const social = await credentials(ctx, owner.userId);
    expect(social).toEqual([
      { userId: owner.userId, providerId: "social-fixture", hasPassword: false },
    ]);
    const enabled = await owner.client.twoFactor.enable({});
    expect(enabled.error).toBeNull();
    const factor = enrollment.parse(enabled.data);
    const verified = await owner.client.twoFactor.verifyTotp({
      code: await generateCurrentTotp(factor.totpURI),
    });
    expect(verified.error).toBeNull();
    const current = await owner.client.getSession();
    expect(current.data?.user.id).toBe(owner.userId);
    expect(current.data?.user.twoFactorEnabled).toBe(true);
    const uri = await owner.client.twoFactor.getTotpUri({ password: "ignored".repeat(30) });
    expect(uri.error).toBeNull();
    expect(z.object({ totpURI: z.string() }).parse(uri.data).totpURI).toBe(factor.totpURI);
    const regenerated = await owner.client.twoFactor.generateBackupCodes({});
    expect(regenerated.error).toBeNull();
    const codes = z
      .object({ backupCodes: z.array(z.string()) })
      .parse(regenerated.data).backupCodes;
    expect(codes).toHaveLength(10);
    expect(codes).not.toEqual(factor.backupCodes);
    const oldCode = await owner.client.twoFactor.verifyBackupCode({ code: factor.backupCodes[0]! });
    expect(oldCode.error?.code).toBe("INVALID_BACKUP_CODE");
    const foreign = await signup(ctx, profile, "foreign");
    const foreignEnrollment = await foreign.client.twoFactor.enable({ password: foreign.password });
    expect(foreignEnrollment.error).toBeNull();
    expect(
      (
        await foreign.client.twoFactor.verifyTotp({
          code: await generateCurrentTotp(enrollment.parse(foreignEnrollment.data).totpURI),
        })
      ).error,
    ).toBeNull();
    const foreignBefore = await ctx.readUserState({ userId: foreign.userId });
    const foreignCode = await foreign.client.twoFactor.verifyBackupCode({ code: codes[0]! });
    expect(foreignCode.error?.code).toBe("INVALID_BACKUP_CODE");
    expect(await ctx.readUserState({ userId: foreign.userId })).toEqual(foreignBefore);
    const backup = await owner.client.twoFactor.verifyBackupCode({ code: codes[0]! });
    expect(backup.error).toBeNull();
    expect(backup.data?.user.id).toBe(owner.userId);
    const beforeGuests = await ctx.readUserState({ userId: owner.userId });
    const guestValidation = await disableGuestValidation(ctx, profile);
    expect(await ctx.readUserState({ userId: owner.userId })).toEqual(beforeGuests);
    const disabled = await owner.client.twoFactor.disable({});
    expect(disabled.error).toBeNull();
    const final = await owner.client.getSession();
    expect(final.data?.user.id).toBe(owner.userId);
    expect(final.data?.user.twoFactorEnabled).toBe(false);
    expect(final.data?.session.token).not.toBe(current.data?.session.token);
    const persisted = z
      .object({
        twoFactorExists: z.boolean(),
        sessions: z.array(z.object({ token: z.string(), userId: z.string() })),
      })
      .parse(await ctx.readUserState({ userId: owner.userId }));
    expect(persisted.twoFactorExists).toBe(false);
    expect(persisted.sessions).toHaveLength(1);
    expect(persisted.sessions[0]).toMatchObject({
      token: final.data?.session.token,
      userId: owner.userId,
    });
    return ctx.snapshot({
      signup: owner.result,
      mixed,
      social,
      enrollment: redactFactor(enabled),
      verified,
      current,
      uri: redactFactor(uri),
      regenerated: redactFactor(regenerated),
      oldCode,
      foreignCode,
      backup,
      guestValidation,
      disabled,
      final,
      persisted,
    });
  },
  [
    "POST /two-factor/enable",
    "POST /two-factor/disable",
    "POST /two-factor/get-totp-uri",
    "POST /two-factor/generate-backup-codes",
    "POST /two-factor/verify-totp",
    "POST /two-factor/verify-backup-code",
  ],
);

compatScenario(
  "two-factor passwordless option retains password ownership for mixed social and credential accounts",
  async (ctx) => {
    const owner = await signup(ctx, "two-factor-passwordless");
    const before = await ctx.readUserState({ userId: owner.userId });
    const missing = await owner.client.twoFactor.enable({});
    expect(missing.error?.code).toBe("INVALID_PASSWORD");
    const wrong = await owner.client.twoFactor.enable({ password: "wrong-password" });
    expect(wrong.error?.code).toBe("INVALID_PASSWORD");
    const long = await owner.client.twoFactor.enable({ password: "x".repeat(129) });
    expect(long.error?.code).toBe("PASSWORD_TOO_LONG");
    expect(await ctx.readUserState({ userId: owner.userId })).toEqual(before);
    const enabled = await owner.client.twoFactor.enable({ password: owner.password });
    expect(enabled.error).toBeNull();
    const factor = enrollment.parse(enabled.data);
    expect(
      (await owner.client.twoFactor.verifyTotp({ code: await generateCurrentTotp(factor.totpURI) }))
        .error,
    ).toBeNull();
    const established = await ctx.readUserState({ userId: owner.userId });
    const uri = await owner.client.twoFactor.getTotpUri({}),
      backup = await owner.client.twoFactor.generateBackupCodes({}),
      disable = await owner.client.twoFactor.disable({ password: "" });
    for (const result of [uri, backup, disable])
      expect(result.error?.code).toBe("INVALID_PASSWORD");
    expect(await ctx.readUserState({ userId: owner.userId })).toEqual(established);
    expect((await owner.client.getSession()).data?.user.id).toBe(owner.userId);
    return ctx.snapshot({
      signup: owner.result,
      before,
      missing,
      wrong,
      long,
      enrollment: redactFactor(enabled),
      established,
      uri,
      backup,
      disable,
    });
  },
  [
    "POST /two-factor/enable",
    "POST /two-factor/disable",
    "POST /two-factor/get-totp-uri",
    "POST /two-factor/generate-backup-codes",
    "POST /two-factor/verify-totp",
    "POST /two-factor/verify-backup-code",
  ],
);

compatScenario(
  "two-factor passwordless child overrides preserve required schemas and independently permit social URI and backup operations",
  async (ctx) => {
    const observations = [];
    for (const profile of [
      "two-factor-passwordless-child-required",
      "two-factor-passwordless-child-optional",
    ] as const) {
      const owner = await signup(ctx, profile),
        enabled = await owner.client.twoFactor.enable({ password: owner.password });
      expect(enabled.error).toBeNull();
      const factor = enrollment.parse(enabled.data);
      expect(
        (
          await owner.client.twoFactor.verifyTotp({
            code: await generateCurrentTotp(factor.totpURI),
          })
        ).error,
      ).toBeNull();
      await ctx.removeCredentialAccount({ email: owner.email });
      const before = await ctx.readUserState({ userId: owner.userId });
      const uri = await owner.client.twoFactor.getTotpUri({}),
        backup = await owner.client.twoFactor.generateBackupCodes({});
      const malformed = await body(ctx, profile, "/two-factor/get-totp-uri", { password: null });
      expect(malformed).toMatchObject({
        status: 400,
        body: {
          code: "VALIDATION_ERROR",
          message: "[body.password] Invalid input: expected string, received null",
        },
      });
      if (profile === "two-factor-passwordless-child-required") {
        for (const result of [uri, backup]) expect(result.error?.code).toBe("VALIDATION_ERROR");
        const supplied = await owner.client.twoFactor.getTotpUri({ password: owner.password });
        expect(supplied.error?.code).toBe("INVALID_PASSWORD");
        expect(await ctx.readUserState({ userId: owner.userId })).toEqual(before);
        const disabled = await owner.client.twoFactor.disable({});
        expect(disabled.error).toBeNull();
        expect(
          z
            .object({ twoFactorExists: z.boolean() })
            .parse(await ctx.readUserState({ userId: owner.userId })).twoFactorExists,
        ).toBe(false);
        observations.push({ profile, uri, backup, malformed, supplied, disabled });
      } else {
        expect(uri.error).toBeNull();
        expect(backup.error).toBeNull();
        expect(z.object({ totpURI: z.string() }).parse(uri.data).totpURI).toBe(factor.totpURI);
        const regenerated = z
          .object({ backupCodes: z.array(z.string()) })
          .parse(backup.data).backupCodes;
        const consumed = await owner.client.twoFactor.verifyBackupCode({ code: regenerated[0]! });
        expect(consumed.error).toBeNull();
        const disable = await owner.client.twoFactor.disable({});
        expect(disable.error?.code).toBe("VALIDATION_ERROR");
        const supplied = await owner.client.twoFactor.disable({ password: owner.password });
        expect(supplied.error?.code).toBe("INVALID_PASSWORD");
        expect((await owner.client.getSession()).data?.user.twoFactorEnabled).toBe(true);
        observations.push({
          profile,
          uri: redactFactor(uri),
          backup: redactFactor(backup),
          malformed,
          consumed,
          disable,
          supplied,
        });
      }
    }
    return ctx.snapshot(observations);
  },
  [
    "POST /two-factor/enable",
    "POST /two-factor/disable",
    "POST /two-factor/get-totp-uri",
    "POST /two-factor/generate-backup-codes",
    "POST /two-factor/verify-totp",
    "POST /two-factor/verify-backup-code",
  ],
);

compatScenario(
  "two-factor passwordless treats a retained empty credential hash as absent and rejects explicit null before mutation",
  async (ctx) => {
    const profile = "two-factor-passwordless",
      owner = await signup(ctx, profile);
    const empty = await credentials(ctx, owner.userId, true);
    expect(empty).toEqual([
      { userId: owner.userId, providerId: "credential", hasPassword: false },
      { userId: owner.userId, providerId: "social-fixture", hasPassword: false },
    ]);
    const nullPassword = await body(ctx, profile, "/two-factor/enable", { password: null });
    expect(nullPassword).toMatchObject({ status: 400, body: { code: "VALIDATION_ERROR" } });
    expect(
      z
        .object({ twoFactorExists: z.boolean() })
        .parse(await ctx.readUserState({ userId: owner.userId })).twoFactorExists,
    ).toBe(false);
    const enabled = await owner.client.twoFactor.enable({ password: "ignored-wrong-password" });
    expect(enabled.error).toBeNull();
    const factor = enrollment.parse(enabled.data);
    const verified = await owner.client.twoFactor.verifyTotp({
      code: await generateCurrentTotp(factor.totpURI),
    });
    expect(verified.error).toBeNull();
    const saved = await owner.client.twoFactor.getTotpUri({});
    expect(saved.error).toBeNull();
    expect(z.object({ totpURI: z.string() }).parse(saved.data).totpURI).toBe(factor.totpURI);
    const disabled = await owner.client.twoFactor.disable({ password: "ignored-wrong-password" });
    expect(disabled.error).toBeNull();
    const current = await owner.client.getSession();
    expect(current.data?.user.id).toBe(owner.userId);
    expect(current.data?.user.twoFactorEnabled).toBe(false);
    expect(await credentials(ctx, owner.userId)).toEqual(empty);
    return ctx.snapshot({
      empty,
      nullPassword,
      enrollment: redactFactor(enabled),
      verified,
      saved: redactFactor(saved),
      disabled,
      current,
    });
  },
  [
    "POST /two-factor/enable",
    "POST /two-factor/disable",
    "POST /two-factor/get-totp-uri",
    "POST /two-factor/generate-backup-codes",
    "POST /two-factor/verify-totp",
    "POST /two-factor/verify-backup-code",
  ],
);

compatScenario(
  "two-factor passwordless OTP enrollment rotates the social owner's session and preserves OTP owner and replay boundaries",
  async (ctx) => {
    const profile = "two-factor-passwordless";
    let originalCookie = "";
    const owner = createAuthClient({
      baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
      plugins: [twoFactorClient()],
      fetchOptions: {
        customFetchImpl: async (input, init) => {
          const response = await ctx.actor("owner", profile).fetch(input, init);
          const url = input instanceof Request ? input.url : input.toString();
          if (url.endsWith("/sign-up/email")) {
            originalCookie =
              response.headers
                .getSetCookie()
                .find((value) => value.split("=")[0]?.endsWith(".session_token"))
                ?.split(";")[0] ?? "";
          }
          return response;
        },
      },
    });
    const email = ctx.uniqueEmail("passwordless-otp"),
      password = "password123";
    const created = await owner.signUp.email({ email, password, name: "Social OTP Owner" });
    expect(created.error).toBeNull();
    if (!created.data) throw new Error("owner required");
    const userId = created.data.user.id;
    await ctx.seedOAuthAccount({
      email,
      providerId: "social-fixture",
      accountId: "passwordless-otp-social-account",
    });
    const mixed = await credentials(ctx, userId);
    expect(mixed).toEqual([
      { userId, providerId: "credential", hasPassword: true },
      { userId, providerId: "social-fixture", hasPassword: false },
    ]);
    const initial = await owner.getSession(),
      before = await ctx.readUserState({ userId });
    const wrongPassword = await owner.twoFactor.enable({
      password: "wrong-password",
      method: "otp",
    });
    expect(wrongPassword.error?.code).toBe("INVALID_PASSWORD");
    expect(await ctx.readUserState({ userId })).toEqual(before);

    await ctx.removeCredentialAccount({ email });
    const social = await credentials(ctx, userId);
    expect(social).toEqual([{ userId, providerId: "social-fixture", hasPassword: false }]);
    const socialBefore = await ctx.readUserState({ userId });
    const nullPassword = await body(ctx, profile, "/two-factor/enable", {
      password: null,
      method: "otp",
    });
    expect(nullPassword).toMatchObject({
      status: 400,
      body: {
        code: "VALIDATION_ERROR",
        message: "[body.password] Invalid input: expected string, received null",
      },
    });
    const invalidMethod = await body(ctx, profile, "/two-factor/enable", {
      method: "invalid",
      issuer: null,
    });
    expect(invalidMethod.status).toBe(400);
    expect(invalidMethod.body).toMatchObject({ code: "VALIDATION_ERROR" });
    expect(z.object({ message: z.string() }).parse(invalidMethod.body).message).toStartWith(
      "[body.method]",
    );
    const nullIssuer = await body(ctx, profile, "/two-factor/enable", {
      method: "otp",
      issuer: null,
    });
    expect(nullIssuer).toMatchObject({
      status: 400,
      body: {
        code: "VALIDATION_ERROR",
        message: "[body.issuer] Invalid input: expected string, received null",
      },
    });
    expect(await ctx.readUserState({ userId })).toEqual(socialBefore);

    const enabled = await owner.twoFactor.enable({ method: "otp" });
    expect(enabled.error).toBeNull();
    expect(enabled.data).toEqual({ method: "otp" });
    const current = await owner.getSession();
    expect(current.data?.user.id).toBe(userId);
    expect(current.data?.user.twoFactorEnabled).toBe(true);
    expect(current.data?.session.token).not.toBe(initial.data?.session.token);
    const stateSchema = z.object({
      user: z.object({ twoFactorEnabled: z.boolean() }),
      twoFactorExists: z.boolean(),
      sessions: z.array(z.object({ id: z.string(), token: z.string(), userId: z.string() })),
    });
    const enabledRaw = await ctx.readUserState({ userId });
    const enabledState = stateSchema.parse(enabledRaw);
    expect(enabledState.user.twoFactorEnabled).toBe(true);
    expect(enabledState.twoFactorExists).toBe(false);
    expect(enabledState.sessions).toHaveLength(1);
    expect(enabledState.sessions[0]).toMatchObject({ token: current.data?.session.token, userId });
    expect(originalCookie).not.toBe("");
    const oldSession = await clientFor(ctx, profile, "old-session").getSession({
      fetchOptions: { headers: { cookie: originalCookie } },
    });
    expect(oldSession.data).toBeNull();

    const foreign = await signup(ctx, profile, "foreign"),
      foreignBefore = await ctx.readUserState({ userId: foreign.userId });
    const sent = await owner.twoFactor.sendOtp({});
    expect(sent.error).toBeNull();
    const delivery = await ctx.rawRequest({
      path: "/__test/two-factor-policy",
      method: "POST",
      json: { deliveryEmail: email },
    });
    expect(delivery.status).toBe(200);
    const code = z.object({ otp: z.string().regex(/^\d{6}$/) }).parse(delivery.body).otp;
    const identifier = `2fa-otp-${userId}!${current.data!.session.id}`;
    const rows = await ctx.readVerificationState({ identifier });
    const rowSchema = z.array(
      z.object({ id: z.string(), identifier: z.string(), value: z.string() }),
    );
    expect(rowSchema.parse(rows)).toHaveLength(1);
    expect(rowSchema.parse(rows)[0]).toMatchObject({ identifier, value: `${code}:0` });
    const wrongOwner = await foreign.client.twoFactor.verifyOtp({ code });
    expect(wrongOwner.error?.code).toBe("OTP_HAS_EXPIRED");
    expect(await ctx.readVerificationState({ identifier })).toEqual(rows);
    expect(await ctx.readUserState({ userId })).toEqual(enabledRaw);
    expect(await ctx.readUserState({ userId: foreign.userId })).toEqual(foreignBefore);
    const wrongCode = await owner.twoFactor.verifyOtp({ code: "wrong-code" });
    expect(wrongCode.error?.code).toBe("INVALID_CODE");
    expect(rowSchema.parse(await ctx.readVerificationState({ identifier }))[0]?.value).toBe(
      `${code}:1`,
    );
    const verified = await owner.twoFactor.verifyOtp({ code });
    expect(verified.error).toBeNull();
    expect(verified.data?.user.id).toBe(userId);
    expect(verified.data?.token).toBe(current.data?.session.token);
    expect(await ctx.readVerificationState({ identifier })).toEqual([]);
    const replay = await owner.twoFactor.verifyOtp({ code });
    expect(replay.error?.code).toBe("OTP_HAS_EXPIRED");
    const final = await owner.getSession(),
      persisted = stateSchema.parse(await ctx.readUserState({ userId }));
    expect(persisted).toEqual(enabledState);
    expect(final.data?.session.token).toBe(current.data?.session.token);
    expect(await ctx.readUserState({ userId })).toEqual(enabledRaw);
    expect(await credentials(ctx, userId)).toEqual(social);
    expect(await ctx.readUserState({ userId: foreign.userId })).toEqual(foreignBefore);
    return ctx.snapshot({
      created,
      mixed,
      initial,
      before,
      wrongPassword,
      social,
      nullPassword,
      invalidMethod,
      nullIssuer,
      enabled,
      current,
      enabledState,
      oldSession,
      sent,
      wrongOwner,
      wrongCode,
      verified,
      replay,
      final,
      persisted,
      foreignBefore,
    });
  },
  ["POST /two-factor/enable", "POST /two-factor/send-otp", "POST /two-factor/verify-otp"],
);
