import { expect } from "bun:test";
import { createHmac } from "node:crypto";
import { createAuthClient } from "better-auth/client";
import { twoFactorClient } from "better-auth/client/plugins";
import { Cookie } from "tough-cookie";
import { z } from "zod";
import { compatScenario } from "../../support/scenario";
import { authProfilePath } from "../../support/profiles";
import { expireVerification } from "../../support/verification";

type Context = Parameters<Parameters<typeof compatScenario>[1]>[0];
const rowsSchema = z.array(
  z
    .object({
      id: z.string(),
      identifier: z.string(),
      value: z.string(),
      createdAt: z.string(),
      expiresAt: z.string(),
    })
    .passthrough(),
);
function projectRows(rows: z.infer<typeof rowsSchema>) {
  return rows.map((row) => ({
    ...row,
    identifier: { token: row.identifier },
    value: { userId: row.value },
  }));
}
function lifetime(row: z.infer<typeof rowsSchema>[number], seconds: number) {
  const difference = Date.parse(row.expiresAt) - Date.parse(row.createdAt);
  expect(difference).toBeGreaterThanOrEqual(seconds * 1000 - 100);
  expect(difference).toBeLessThanOrEqual(seconds * 1000 + 100);
}
function payload(cookie: Cookie) {
  const decoded = decodeURIComponent(cookie.value);
  return decoded.slice(0, decoded.lastIndexOf("."));
}
function cookieAttributes(cookie: Cookie, seconds: number) {
  expect(cookie.httpOnly).toBe(true);
  expect(cookie.path).toBe("/");
  expect(cookie.sameSite).toBe("lax");
  expect(cookie.maxAge).toBe(seconds < 0 ? null : Math.floor(seconds));
  expect(cookie.expires).toBe("Infinity");
}
async function readRows(ctx: Context, identifier: string) {
  return rowsSchema.parse(await ctx.readVerificationState({ identifier }));
}
for (const [profile, challengeAge, trustAge] of [
  ["two-factor-trust-fractional", 600.75, 1200.875],
  ["two-factor-trust-zero-challenge", 0, 1200.875],
  ["two-factor-trust-negative-challenge", -0.25, 1200.875],
  ["two-factor-trust-zero", 600.75, 0],
  ["two-factor-trust-negative", 600.75, -0.25],
  ["two-factor-trust-cleanup-disabled", 600.75, 1200.875],
] as const) {
  compatScenario(
    `two-factor ${profile} retains configured cookie and database lifetimes through real trust and challenge state`,
    async (ctx) => {
      const captured = new Map<string, Cookie>();
      const client = (name: string) =>
        createAuthClient({
          baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
          plugins: [twoFactorClient()],
          fetchOptions: {
            customFetchImpl: ctx.actor(name, profile).fetch,
            onSuccess: (context) => {
              for (const header of context.response.headers.getSetCookie()) {
                const parsed = Cookie.parse(header);
                if (parsed) captured.set(`${name}:${parsed.key}`, parsed);
              }
            },
          },
        });
      const owner = client("owner"),
        email = ctx.uniqueEmail(profile),
        password = "password123";
      const created = await owner.signUp.email({
        email,
        password,
        name: "Trust TTL Owner",
      });
      expect(created.error).toBeNull();
      if (!created.data) throw new Error("owner required");
      const userId = created.data.user.id;
      const enabled = await owner.twoFactor.enable({ password });
      expect(enabled.error).toBeNull();
      const enrollment = z
        .object({
          method: z.literal("totp"),
          totpURI: z.string(),
          backupCodes: z.array(z.string()),
        })
        .parse(enabled.data);
      const setup = await ctx.readUserState({ userId });
      expect((await owner.signOut()).error).toBeNull();
      const signin = await owner.signIn.email({ email, password });
      expect(signin.data).toMatchObject({ twoFactorRedirect: true });
      const challengeCookie = [...captured.values()].find((cookie) =>
        cookie.key.endsWith(".two_factor"),
      );
      if (!challengeCookie) throw new Error("actual challenge cookie required");
      const key = payload(challengeCookie),
        challenge = await readRows(ctx, key),
        attempts = await readRows(ctx, `2fa-attempts-${key}`);
      expect(challenge).toHaveLength(1);
      expect(attempts).toHaveLength(1);
      if (!challenge[0] || !attempts[0])
        throw new Error("actual challenge records required");
      expect(challenge[0].value).toBe(userId);
      expect(attempts[0].value).toBe("0");
      expect(attempts[0].expiresAt).toBe(challenge[0].expiresAt);
      lifetime(challenge[0], challengeAge);
      cookieAttributes(challengeCookie, challengeAge);
      expect(
        z
          .object({ sessions: z.array(z.unknown()) })
          .parse(await ctx.readUserState({ userId })).sessions,
      ).toEqual([]);
      if (challengeAge <= 0) {
        // Zero expires the browser cookie immediately. Negative cookie ages
        // intentionally remain session cookies; the source expired-challenge
        // snapshot/cleanup quirk is a separate request-policy boundary.
        const denied =
          challengeAge === 0 ? await owner.twoFactor.sendOtp({}) : null;
        if (denied) {
          expect(denied.error?.code).toBe("INVALID_TWO_FACTOR_COOKIE");
          const delivery = await ctx.rawRequest({
            path: "/__test/two-factor-policy",
            method: "POST",
            json: { deliveryEmail: email },
          });
          expect(delivery.body).toBeNull();
        }
        return ctx.snapshot({
          created,
          enabled: {
            error: enabled.error,
            method: enrollment.method,
            backupCount: enrollment.backupCodes.length,
          },
          setup,
          signin,
          challenge: projectRows(challenge),
          attempts: attempts.map((row) => ({
            ...row,
            identifier: { token: row.identifier },
          })),
          denied,
        });
      }
      expect((await owner.twoFactor.sendOtp({})).error).toBeNull();
      const delivery = await ctx.rawRequest({
        path: "/__test/two-factor-policy",
        method: "POST",
        json: { deliveryEmail: email },
      });
      const otp = z.object({ otp: z.string() }).parse(delivery.body).otp;
      const verified = await owner.twoFactor.verifyOtp({
        code: otp,
        trustDevice: true,
      });
      expect(verified.error).toBeNull();
      expect(verified.data?.user.id).toBe(userId);
      const trustCookie = [...captured.values()].find((cookie) =>
        cookie.key.endsWith(".trust_device"),
      );
      if (!trustCookie) throw new Error("actual trust cookie required");
      cookieAttributes(trustCookie, trustAge);
      const identifier = payload(trustCookie).split("!")[1];
      if (!identifier)
        throw new Error("actual persisted trust identifier required");
      const trust = await readRows(ctx, identifier);
      expect(trust).toHaveLength(1);
      if (!trust[0]) throw new Error("actual trust record required");
      expect(trust[0].value).toBe(userId);
      lifetime(trust[0], trustAge);
      expect(await readRows(ctx, key)).toEqual([]);
      const state = await ctx.readUserState({ userId });
      expect(
        z
          .object({
            sessions: z.array(
              z.object({ token: z.string(), userId: z.string() }),
            ),
          })
          .parse(state).sessions,
      ).toEqual([
        expect.objectContaining({ token: verified.data?.token, userId }),
      ]);
      const pair = `${trustCookie.key}=${trustCookie.value}`;
      let foreign: unknown = null;
      if (profile === "two-factor-trust-fractional") {
        const other = client("foreign"),
          otherEmail = ctx.uniqueEmail("foreign-trust");
        const signup = await other.signUp.email({
          email: otherEmail,
          password,
          name: "Foreign Trust Owner",
        });
        expect(signup.error).toBeNull();
        if (!signup.data) throw new Error("foreign owner required");
        expect((await other.twoFactor.enable({ password })).error).toBeNull();
        expect((await other.signOut()).error).toBeNull();
        const wrong = await other.signIn.email(
          { email: otherEmail, password },
          { headers: { cookie: pair } },
        );
        expect(wrong.data).toMatchObject({ twoFactorRedirect: true });
        expect(await ctx.readUserState({ userId })).toEqual(state);
        expect(await readRows(ctx, identifier)).toEqual(trust);
        const otherState = await ctx.readUserState({
          userId: signup.data.user.id,
        });
        expect(
          z.object({ sessions: z.array(z.unknown()) }).parse(otherState)
            .sessions,
        ).toEqual([]);
        foreign = { signup, wrong, otherState };
      }
      const expiredIdentifier = ctx.uniqueToken("expired-trust-control");
      const seed = await ctx.rawRequest({
        path: "/__test/verification-state",
        method: "POST",
        json: {
          action: "seed",
          identifier: expiredIdentifier,
          value: userId,
          expiresAt: "2020-01-01T00:00:00.000Z",
        },
      });
      expect(seed.status).toBe(200);
      const beforeExpired = await readRows(ctx, expiredIdentifier);
      expect((await owner.signOut()).error).toBeNull();
      const later = await owner.signIn.email(
        { email, password },
        { headers: { cookie: pair } },
      );
      const cleanup = await readRows(ctx, expiredIdentifier);
      expect(cleanup).toEqual(
        profile.endsWith("cleanup-disabled") ? beforeExpired : [],
      );
      let rotation: unknown = null,
        replay: unknown = null,
        expired: unknown = null;
      if (trustAge > 0) {
        expect(later.error).toBeNull();
        expect(later.data?.user.id).toBe(userId);
        expect(later.data).not.toHaveProperty("twoFactorRedirect");
        const next = [...captured.values()].find((cookie) =>
          cookie.key.endsWith(".trust_device"),
        );
        if (!next) throw new Error("rotated cookie required");
        expect(next.value).not.toBe(trustCookie.value);
        cookieAttributes(next, trustAge);
        const nextIdentifier = payload(next).split("!")[1]!;
        expect(nextIdentifier).not.toBe(identifier);
        expect(await readRows(ctx, identifier)).toEqual([]);
        const nextRows = await readRows(ctx, nextIdentifier);
        expect(nextRows).toHaveLength(1);
        expect(nextRows[0]?.value).toBe(userId);
        if (!nextRows[0]) throw new Error("rotated row required");
        lifetime(nextRows[0], trustAge);
        const ownerBefore = await ctx.readUserState({ userId });
        const old = await owner.signIn.email(
          { email, password },
          { headers: { cookie: pair } },
        );
        expect(old.data).toMatchObject({ twoFactorRedirect: true });
        expect(await ctx.readUserState({ userId })).toEqual(ownerBefore);
        expect(await readRows(ctx, nextIdentifier)).toEqual(nextRows);
        replay = old;
        await expireVerification(ctx, nextIdentifier);
        const beforeExpiry = await readRows(ctx, nextIdentifier);
        const denied = await owner.signIn.email(
          { email, password },
          { headers: { cookie: `${next.key}=${next.value}` } },
        );
        expect(denied.data).toMatchObject({ twoFactorRedirect: true });
        expect(await ctx.readUserState({ userId })).toEqual(ownerBefore);
        expect(await readRows(ctx, nextIdentifier)).toEqual(
          profile.endsWith("cleanup-disabled") ? beforeExpiry : [],
        );
        expired = denied;
        rotation = { rows: projectRows(nextRows), current: later, ownerBefore };
      } else {
        expect(later.data).toMatchObject({ twoFactorRedirect: true });
        expect(await readRows(ctx, identifier)).toEqual([]);
        expect(
          z
            .object({ sessions: z.array(z.unknown()) })
            .parse(await ctx.readUserState({ userId })).sessions,
        ).toEqual([]);
      }
      return ctx.snapshot({
        created,
        enabled: {
          error: enabled.error,
          method: enrollment.method,
          backupCount: enrollment.backupCodes.length,
        },
        setup,
        signin,
        challenge: projectRows(challenge),
        verified,
        trust: projectRows(trust),
        state,
        foreign,
        later,
        cleanup: projectRows(cleanup),
        rotation,
        replay,
        expired,
      });
    },
    ["POST /sign-in/email", "POST /two-factor/verify-otp"],
  );
}

// The key belongs only to the equivalent fixture applications. Public handlers
// issue the original proofs; independent crypto changes their authenticated
// syntax without giving the production owner a test-only proof generator.
const fixtureSecret = [
  "compat",
  "test",
  "only",
  "key",
  "not",
  "real",
  "minimum",
  "32chars",
].join("-");
const signedTrustValue = (value: string) =>
  encodeURIComponent(
    `${value}.${createHmac("sha256", fixtureSecret).update(value).digest("base64")}`,
  );
const userBoundTrustToken = (userId: string, identifier: string) =>
  createHmac("sha256", fixtureSecret)
    .update(`${userId}!${identifier}`)
    .digest("base64url");

for (const profile of [
  "two-factor-skip-verification",
  "two-factor-trust-cleanup-disabled",
] as const) {
  const exercise = async (
    ctx: Context,
    stage: "syntax" | "lookup" | "rotation",
  ) => {
    const history: Cookie[] = [];
    const client = (actor: string) =>
      createAuthClient({
        baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
        plugins: [twoFactorClient()],
        fetchOptions: {
          customFetchImpl: ctx.actor(actor, profile).fetch,
          onSuccess: (context) => {
            for (const header of context.response.headers.getSetCookie()) {
              const cookie = Cookie.parse(header);
              if (cookie) history.push(cookie);
            }
          },
        },
      });
    const owner = client("trust-owner"),
      foreign = client("trust-foreign"),
      password = "password123";
    const email = ctx.uniqueEmail("invalid-trust"),
      foreignEmail = ctx.uniqueEmail("invalid-trust-foreign");
    const created = await owner.signUp.email({
      email,
      password,
      name: "Trust Owner",
    });
    const other = await foreign.signUp.email({
      email: foreignEmail,
      password,
      name: "Foreign Trust Owner",
    });
    expect(created.error).toBeNull();
    expect(other.error).toBeNull();
    if (!created.data || !other.data) throw new Error("real owners required");
    const userId = created.data.user.id,
      foreignId = other.data.user.id;
    const enroll = async (selected: typeof owner) => {
      const result = await selected.twoFactor.enable({ password });
      expect(result.error).toBeNull();
      const data = z
        .object({
          method: z.literal("totp"),
          totpURI: z.string(),
          backupCodes: z.array(z.string()),
        })
        .parse(result.data);
      return {
        error: result.error,
        method: data.method,
        backupCount: data.backupCodes.length,
      };
    };
    const enabled = await enroll(owner),
      foreignEnabled = await enroll(foreign);
    expect((await owner.signOut()).error).toBeNull();
    expect((await foreign.signOut()).error).toBeNull();
    const initialState = await ctx.readUserState({ userId }),
      foreignState = await ctx.readUserState({ userId: foreignId });
    expect(
      z.object({ sessions: z.array(z.unknown()) }).parse(initialState)
        .sessions,
    ).toEqual([]);
    expect(
      z.object({ sessions: z.array(z.unknown()) }).parse(foreignState)
        .sessions,
    ).toEqual([]);
    const latest = (suffix: string) => {
      const cookie = history.findLast((cookie) =>
        cookie.key.endsWith(suffix),
      );
      if (!cookie || !cookie.value)
        throw new Error(`actual ${suffix} cookie required`);
      return cookie;
    };
    const expiredCookie = (cookie: Cookie) => {
      expect(cookie.value).toBe("");
      expect(cookie.secure).toBe(false);
      expect(cookie.domain).toBeNull();
      cookieAttributes(cookie, 0);
    };
    const pendingRows = async (
      selected: typeof owner,
      expectedUserId: string,
    ) => {
      const cookie = latest(".two_factor"),
        key = payload(cookie);
      const challenge = await readRows(ctx, key),
        attempts = await readRows(ctx, `2fa-attempts-${key}`);
      expect(challenge).toHaveLength(1);
      expect(attempts).toHaveLength(1);
      expect(challenge[0]?.value).toBe(expectedUserId);
      expect(attempts[0]?.value).toBe("0");
      expect(attempts[0]?.expiresAt).toBe(challenge[0]?.expiresAt);
      expect(await readRows(ctx, `2fa-otp-${key}`)).toEqual([]);
      return { key, selected, challenge, attempts };
    };
    const complete = async (
      pending: Awaited<ReturnType<typeof pendingRows>>,
    ) => {
      expect((await pending.selected.twoFactor.sendOtp({})).error).toBeNull();
      const delivery = await ctx.rawRequest({
        path: "/__test/two-factor-policy",
        method: "POST",
        json: { deliveryEmail: email },
      });
      const code = z.object({ otp: z.string() }).parse(delivery.body).otp;
      const verified = await pending.selected.twoFactor.verifyOtp({
        code,
        trustDevice: true,
      });
      expect(verified.error).toBeNull();
      expect(verified.data?.user.id).toBe(userId);
      expect(await readRows(ctx, pending.key)).toEqual([]);
      const afterAttempts = await readRows(
        ctx,
        `2fa-attempts-${pending.key}`,
      );
      expect(afterAttempts).toHaveLength(1);
      expect(afterAttempts[0]?.value).toBe("0");
      expect(afterAttempts[0]?.expiresAt).toBe(
        pending.challenge[0]?.expiresAt,
      );
      expect(await readRows(ctx, `2fa-otp-${pending.key}`)).toEqual([]);
      const cookie = latest(".trust_device"),
        value = payload(cookie),
        identifier = value.split("!")[1];
      if (!identifier) throw new Error("actual trust identifier required");
      expect(value.split("!")[0]).toBe(
        userBoundTrustToken(userId, identifier),
      );
      const rows = await readRows(ctx, identifier);
      expect(rows).toHaveLength(1);
      expect(rows[0]?.value).toBe(userId);
      cookieAttributes(
        cookie,
        profile.endsWith("cleanup-disabled") ? 1200.875 : 2592000,
      );
      const state = await ctx.readUserState({ userId });
      expect(
        z
          .object({
            sessions: z.array(
              z.object({ token: z.string(), userId: z.string() }),
            ),
          })
          .parse(state).sessions,
      ).toEqual([
        expect.objectContaining({ token: verified.data?.token, userId }),
      ]);
      expect(await ctx.readUserState({ userId: foreignId })).toEqual(
        foreignState,
      );
      expect((await owner.signOut()).error).toBeNull();
      return {
        verified,
        cookie,
        value,
        identifier,
        rows,
        state,
        afterAttempts,
      };
    };
    const initialCookieOffset = history.length;
    const signin = await owner.signIn.email({ email, password });
    expect(
      history
        .slice(initialCookieOffset)
        .filter((cookie) => cookie.key.endsWith(".trust_device")),
    ).toEqual([]);
    expect(signin.data).toMatchObject({ twoFactorRedirect: true });
    const firstPending = await pendingRows(owner, userId),
      issued = await complete(firstPending);
    const ownerBaseline = await ctx.readUserState({ userId });
    const expiredIdentifier = ctx.uniqueToken("invalid-trust-cleanup");
    expect(
      (
        await ctx.rawRequest({
          path: "/__test/verification-state",
          method: "POST",
          json: {
            action: "seed",
            identifier: expiredIdentifier,
            value: foreignId,
            expiresAt: "2020-01-01T00:00:00.000Z",
          },
        })
      ).status,
    ).toBe(200);
    const expiredBaseline = await readRows(ctx, expiredIdentifier);
    const trustPair = (value: string) => `${issued.cookie.key}=${value}`;
    const common = {
      created,
      other,
      enabled,
      foreignEnabled,
      initialState,
      foreignState,
      signin,
      verified: issued.verified,
      originalTrust: projectRows(issued.rows),
      ownerBaseline,
    };
    const observations: unknown[] = [];
    let lastPending: Awaited<ReturnType<typeof pendingRows>> | undefined;
    const rejected = async (
      name: string,
      value: string,
      shouldClear: boolean,
      expectedRows = issued.rows,
    ) => {
      const start = history.length;
      const result = await owner.signIn.email(
        { email, password },
        { headers: { cookie: trustPair(value) } },
      );
      expect(result.error).toBeNull();
      expect(result.data).toMatchObject({
        twoFactorRedirect: true,
        twoFactorMethods: ["totp", "otp"],
      });
      const deletion = history
        .slice(start)
        .filter((cookie) => cookie.key === issued.cookie.key);
      expect(deletion).toHaveLength(shouldClear ? 1 : 0);
      if (deletion[0]) {
        expiredCookie(deletion[0]);
      }
      lastPending = await pendingRows(owner, userId);
      expect(await ctx.readUserState({ userId })).toEqual(ownerBaseline);
      expect(await ctx.readUserState({ userId: foreignId })).toEqual(
        foreignState,
      );
      expect(await readRows(ctx, issued.identifier)).toEqual(expectedRows);
      observations.push({
        name,
        result,
        challenge: projectRows(lastPending.challenge),
        attempts: lastPending.attempts.map((row) => ({
          ...row,
          identifier: { token: row.identifier },
        })),
      });
      return lastPending;
    };
    if (stage === "syntax") {
      const decoded = decodeURIComponent(issued.cookie.value),
        signatureOffset = decoded.lastIndexOf("."),
        signature = decoded.slice(signatureOffset + 1);
      const badSignature = encodeURIComponent(
        `${issued.value}.${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`,
      );
      for (const [name, value, clear] of [
        ["invalid-outer-hmac", badSignature, false],
        ["missing-outer-signature", encodeURIComponent(issued.value), false],
        ["signed-empty-payload", signedTrustValue(""), false],
        [
          "invalid-inner-hmac",
          signedTrustValue(`wrong!${issued.identifier}`),
          true,
        ],
        ["missing-components", signedTrustValue("unstructured"), true],
        ["empty-token", signedTrustValue(`!${issued.identifier}`), true],
        [
          "empty-identifier",
          signedTrustValue(`${userBoundTrustToken(userId, "")}!`),
          true,
        ],
      ] as const) {
        await rejected(name, value, clear);
        expect(await readRows(ctx, expiredIdentifier)).toEqual(expiredBaseline);
      }
      return ctx.snapshot({ ...common, observations });
    }
    const startForeign = history.length;
    const wrongOwner = await foreign.signIn.email(
      { email: foreignEmail, password },
      { headers: { cookie: trustPair(issued.cookie.value) } },
    );
    expect(wrongOwner.data).toMatchObject({ twoFactorRedirect: true });
    const foreignDeletion = history
      .slice(startForeign)
      .filter((cookie) => cookie.key === issued.cookie.key);
    expect(foreignDeletion).toHaveLength(1);
    if (!foreignDeletion[0])
      throw new Error("real foreign deletion required");
    expiredCookie(foreignDeletion[0]);
    const foreignPending = await pendingRows(foreign, foreignId);
    expect(await ctx.readUserState({ userId })).toEqual(ownerBaseline);
    expect(await ctx.readUserState({ userId: foreignId })).toEqual(
      foreignState,
    );
    expect(await readRows(ctx, issued.identifier)).toEqual(issued.rows);
    expect(await readRows(ctx, expiredIdentifier)).toEqual(expiredBaseline);
    if (stage === "lookup") {
      const mutateOwner = async (ownerId: string) => {
        expect(
          (
            await ctx.rawRequest({
              path: "/__test/two-factor-policy",
              method: "POST",
              json: { userId: ownerId, trustIdentifier: issued.identifier },
            })
          ).status,
        ).toBe(200);
      };
      await mutateOwner(foreignId);
      const changedOwner = await readRows(ctx, issued.identifier);
      expect(changedOwner).toEqual(
        issued.rows.map((row) => ({ ...row, value: foreignId })),
      );
      await rejected(
        "changed-stored-owner",
        issued.cookie.value,
        true,
        changedOwner,
      );
      expect(await readRows(ctx, expiredIdentifier)).toEqual(
        profile.endsWith("cleanup-disabled") ? expiredBaseline : [],
      );
      await mutateOwner(userId);
      const absent = ctx.uniqueToken("missing-issued-trust");
      const missing = await rejected(
        "authenticated-missing-record",
        signedTrustValue(`${userBoundTrustToken(userId, absent)}!${absent}`),
        true,
      );
      expect(await readRows(ctx, absent)).toEqual([]);
      expect(await readRows(ctx, expiredIdentifier)).toEqual(
        profile.endsWith("cleanup-disabled") ? expiredBaseline : [],
      );
      const second = await complete(missing);
      const expiryStartedAt = Date.now();
      await expireVerification(ctx, second.identifier);
      const expiryFinishedAt = Date.now();
      const expiredTrust = await readRows(ctx, second.identifier);
      // The Source adapter's updateMany applies updatedAt onUpdate. The expiry
      // control must mirror that write while retaining every other stored field.
      expect(expiredTrust).toHaveLength(second.rows.length);
      for (const row of expiredTrust) {
        const original = second.rows.find(original => original.id === row.id);
        if (!original) throw new Error("Expiring a proof must preserve its physical row identity");
        expect(Date.parse(String(row.updatedAt))).toBeGreaterThanOrEqual(expiryStartedAt);
        expect(Date.parse(String(row.updatedAt))).toBeLessThanOrEqual(expiryFinishedAt);
        expect(row).toEqual({...original,
          expiresAt: "2020-01-01T00:00:00.000Z", updatedAt: row.updatedAt});
      }
      await rejected("expired-real-issued-proof", second.cookie.value, true);
      const expiryRows = await readRows(ctx, second.identifier);
      expect(expiryRows).toEqual(
        profile.endsWith("cleanup-disabled") ? expiredTrust : [],
      );
      expect(await readRows(ctx, foreignPending.key)).toEqual(
        foreignPending.challenge,
      );
      return ctx.snapshot({
        ...common,
        observations,
        wrongOwner,
        foreignChallenge: projectRows(foreignPending.challenge),
        changedOwner: projectRows(changedOwner),
        secondVerified: second.verified,
        completedAttempts: second.afterAttempts.map((row) => ({
          ...row,
          identifier: { token: row.identifier },
        })),
        expiryRows: projectRows(expiryRows),
      });
    }
    // Preserve a genuine preceding owner challenge independently of the
    // foreign challenge while the original issued proof rotates twice.
    await rejected(
      "preceding-owner-challenge",
      signedTrustValue(`wrong!${issued.identifier}`),
      true,
    );
    expect(await readRows(ctx, expiredIdentifier)).toEqual(expiredBaseline);
    const extra = await owner.signIn.email(
      { email, password },
      {
        headers: {
          cookie: trustPair(
            signedTrustValue(`${issued.value}!ignored!components`),
          ),
        },
      },
    );
    expect(extra.error).toBeNull();
    expect(extra.data).not.toHaveProperty("twoFactorRedirect");
    expect(extra.data?.user.id).toBe(userId);
    const rotatedCookie = latest(".trust_device"),
      rotatedKey = payload(rotatedCookie).split("!")[1];
    if (!rotatedKey) throw new Error("real rotated identifier required");
    expect(rotatedKey).not.toBe(issued.identifier);
    expect(await readRows(ctx, issued.identifier)).toEqual([]);
    const rotation = await readRows(ctx, rotatedKey);
    expect(rotation).toHaveLength(1);
    expect(rotation[0]?.value).toBe(userId);
    cookieAttributes(
      rotatedCookie,
      profile.endsWith("cleanup-disabled") ? 1200.875 : 2592000,
    );
    const rotatedSession = await owner.getSession();
    expect(rotatedSession.error).toBeNull();
    expect(rotatedSession.data).toMatchObject({
      session: {token: extra.data?.token, userId}, user: {id: userId},
    });
    const publicSessionRow = (result: typeof rotatedSession) => {
      const session = z.object({id: z.string(), token: z.string(), userId: z.string(), expiresAt: z.date()}).parse(result.data?.session);
      return {...session, expiresAt: session.expiresAt.toISOString()};
    };
    const finalState = await ctx.readUserState({ userId });
    expect(
      z
        .object({
          sessions: z.array(
            z.object({ id: z.string(), token: z.string(), userId: z.string(), expiresAt: z.string() }),
          ),
        })
        .parse(finalState).sessions,
    ).toEqual([
      publicSessionRow(rotatedSession),
    ]);
    // Better Call's actual atob accepts unused trailing Base64 bits while
    // requiring the outer signature's exact 44-character padded shape.
    const rotatedRaw = decodeURIComponent(rotatedCookie.value);
    const alphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const signaturePosition = rotatedRaw.length - 2;
    const character = rotatedRaw[signaturePosition];
    if (!character) throw new Error("actual padded signature required");
    const aliasCharacter = alphabet[alphabet.indexOf(character) + 1];
    if (!aliasCharacter) throw new Error("actual unused-bit alias required");
    const aliasRaw =
      rotatedRaw.slice(0, signaturePosition) +
      aliasCharacter +
      rotatedRaw.slice(signaturePosition + 1);
    const signatureOf = (value: string) =>
      value.slice(value.lastIndexOf(".") + 1);
    expect(signatureOf(aliasRaw)).toHaveLength(44);
    expect(signatureOf(aliasRaw).endsWith("=")).toBe(true);
    expect(Buffer.from(signatureOf(aliasRaw), "base64")).toEqual(
      Buffer.from(signatureOf(rotatedRaw), "base64"),
    );
    const aliasValue = encodeURIComponent(aliasRaw);
    const alias = await owner.signIn.email(
      { email, password },
      { headers: { cookie: trustPair(aliasValue) } },
    );
    expect(alias.error).toBeNull();
    expect(alias.data).not.toHaveProperty("twoFactorRedirect");
    expect(alias.data?.user.id).toBe(userId);
    expect(await readRows(ctx, rotatedKey)).toEqual([]);
    const aliasCookie = latest(".trust_device"),
      aliasKey = payload(aliasCookie).split("!")[1];
    if (!aliasKey) throw new Error("actual alias rotation required");
    expect(aliasKey).not.toBe(rotatedKey);
    const aliasRows = await readRows(ctx, aliasKey);
    expect(aliasRows).toHaveLength(1);
    expect(aliasRows[0]?.value).toBe(userId);
    cookieAttributes(
      aliasCookie,
      profile.endsWith("cleanup-disabled") ? 1200.875 : 2592000,
    );
    const aliasSession = await owner.getSession();
    expect(aliasSession.error).toBeNull();
    expect(aliasSession.data).toMatchObject({
      session: {token: alias.data?.token, userId}, user: {id: userId},
    });
    const aliasState = await ctx.readUserState({ userId });
    expect(
      z
        .object({
          sessions: z.array(
            z.object({ id: z.string(), token: z.string(), userId: z.string(), expiresAt: z.string() }),
          ),
        })
        .parse(aliasState).sessions,
    ).toEqual([
      publicSessionRow(rotatedSession),
      publicSessionRow(aliasSession),
    ]);
    const replayStart = history.length;
    const aliasReplay = await owner.signIn.email(
      { email, password },
      { headers: { cookie: trustPair(aliasValue) } },
    );
    expect(aliasReplay.data).toMatchObject({ twoFactorRedirect: true });
    const replayCookies = history
      .slice(replayStart)
      .filter((cookie) => cookie.key === issued.cookie.key);
    expect(replayCookies).toHaveLength(1);
    if (!replayCookies[0]) throw new Error("actual replay deletion required");
    expiredCookie(replayCookies[0]);
    const replayPending = await pendingRows(owner, userId);
    expect(await ctx.readUserState({ userId })).toEqual(aliasState);
    expect(await readRows(ctx, aliasKey)).toEqual(aliasRows);
    expect(await ctx.readUserState({ userId: foreignId })).toEqual(
      foreignState,
    );
    expect(await readRows(ctx, foreignPending.key)).toEqual(
      foreignPending.challenge,
    );
    if (!lastPending)
      throw new Error("actual last pending challenge required");
    expect(await readRows(ctx, lastPending.key)).toEqual(
      lastPending.challenge,
    );
    return ctx.snapshot({
      ...common,
      observations,
      wrongOwner,
      foreignChallenge: projectRows(foreignPending.challenge),
      extra,
      rotation: projectRows(rotation),
      finalState,
      rotatedSession,
      alias,
      aliasSession,
      aliasRows: projectRows(aliasRows),
      aliasState,
      aliasReplay,
      replayChallenge: projectRows(replayPending.challenge),
    });
  };
  for (const [stage, behavior] of [
    ["syntax", "checks outer and inner trust syntax before deletion and cleanup"],
    ["lookup", "checks authenticated trust ownership missing rows expiry and cleanup"],
    ["rotation", "rotates real trust proofs accepts HMAC aliases and rejects replay"],
  ] as const) {
    compatScenario(
      `two-factor ${profile} ${behavior}`,
      (ctx) => exercise(ctx, stage),
      ["POST /sign-in/email", "POST /two-factor/verify-otp"],
    );
  }
}
