import { expect } from "bun:test";
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
