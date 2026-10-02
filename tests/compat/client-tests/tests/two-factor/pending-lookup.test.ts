import { expect } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { twoFactorClient } from "better-auth/client/plugins";
import { Cookie } from "tough-cookie";
import { z } from "zod";
import { authProfilePath, type FixtureProfile } from "../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { generateCurrentTotp } from "../../support/totp";

const verification = z.object({
  id: z.string(),
  identifier: z.string(),
  value: z.string(),
  expiresAt: z.string(),
  createdAt: z.string(),
  updatedAt: z.string(),
});
const factorRow = z.object({
  id: z.string(),
  userId: z.string(),
  secret: z.string(),
  backupCodes: z.string(),
  verified: z.boolean().nullable(),
  failedVerificationCount: z.number().nullable(),
  lockedUntil: z.string().nullable(),
});
const stateSchema = z.object({
  receipts: z.array(z.string()),
  snapshot: z.object({
    verifications: z.array(verification),
    factors: z.array(factorRow),
  }),
});
type State = z.infer<typeof stateSchema>;
async function control(
  ctx: ScenarioContext,
  profile: FixtureProfile,
  body: Record<string, unknown>,
) {
  const result = await ctx.rawRequest({
    path: "/__test/two-factor-pending-lookup",
    method: "POST",
    json: { profile, ...body },
  });
  expect(result.status).toBe(200);
  return result.body;
}
async function state(ctx: ScenarioContext, profile: FixtureProfile) {
  return stateSchema.parse(await control(ctx, profile, { action: "snapshot" }));
}
function project(value: State) {
  return {
    receipts: value.receipts,
    snapshot: {
      verifications: value.snapshot.verifications.map((row) => ({
        ...row,
        identifier: { token: row.identifier },
        value: row.identifier.startsWith("2fa-attempts-")
          ? row.value
          : row.identifier.startsWith("2fa-otp-")
            ? { token: row.value }
            : { userId: row.value },
      })),
      factors: value.snapshot.factors.map((row) => ({
        ...row,
        secret: { token: row.secret },
        backupCodes: { token: row.backupCodes },
        codes: z
          .array(z.string())
          .parse(JSON.parse(row.backupCodes))
          .map((token) => ({ token })),
      })),
    },
  };
}
for (const cleanup of [true, false] as const)
  for (const kind of ["totp", "otp", "backup"] as const)
    for (const mode of ["expired", "missing-user", "newest-expired"] as const) {
      compatScenario(
        `two-factor pending ${kind} ${mode} ${cleanup ? "default" : "disabled"} cleanup preserves the actual lookup snapshot and failure stage`,
        async (ctx) => {
          const profile: FixtureProfile =
            mode === "expired"
              ? cleanup
                ? "two-factor-pending-lookup-zero"
                : "two-factor-pending-lookup-zero-disabled"
              : cleanup
                ? "two-factor-pending-lookup"
                : "two-factor-pending-lookup-disabled";
          const positive: FixtureProfile = cleanup
            ? "two-factor-pending-lookup"
            : "two-factor-pending-lookup-disabled";
          await control(ctx, profile, { action: "clear" });
          const cookies = new Map<string, Cookie>();
          const actor = (name: string, selected: FixtureProfile = profile) =>
            createAuthClient({
              baseURL: `${ctx.baseURL}${authProfilePath(selected)}`,
              plugins: [twoFactorClient()],
              fetchOptions: {
                customFetchImpl: ctx.actor(name, selected).fetch,
                onResponse: ({ response }) => {
                  for (const header of response.headers.getSetCookie()) {
                    const cookie = Cookie.parse(header);
                    if (cookie?.key.endsWith(".two_factor") && cookie.value)
                      cookies.set(name, cookie);
                  }
                },
              },
            });
          const owner = actor("owner"),
            sibling = actor("sibling"),
            foreign = actor("foreign"),
            raw = actor("raw");
          const email = ctx.uniqueEmail("pending-owner"),
            password = "password123";
          const signup = await owner.signUp.email({
            email,
            password,
            name: "Pending Owner",
          });
          expect(signup.error).toBeNull();
          if (!signup.data) throw new Error("actual owner required");
          expect((await sibling.signIn.email({ email, password })).error).toBeNull();
          const other = await foreign.signUp.email({
            email: ctx.uniqueEmail("foreign"),
            password,
            name: "Foreign Owner",
          });
          expect(other.error).toBeNull();
          if (!other.data) throw new Error("actual foreign owner required");
          const enrollment = await owner.twoFactor.enable({ password });
          expect(enrollment.error).toBeNull();
          const enabled = z
            .object({
              method: z.literal("totp"),
              totpURI: z.string(),
              backupCodes: z.array(z.string()),
            })
            .parse(enrollment.data);
          expect((await foreign.twoFactor.enable({ password })).error).toBeNull();
          const userId = signup.data.user.id,
            foreignId = other.data.user.id;
          expect((await owner.signOut()).error).toBeNull();
          const signIn = await owner.signIn.email({ email, password });
          expect(signIn.data).toMatchObject({ twoFactorRedirect: true });
          const cookie = cookies.get("owner");
          if (!cookie) throw new Error("actual issued pending cookie required");
          if (mode === "expired") expect(cookie.maxAge).toBe(0);
          const decoded = decodeURIComponent(cookie.value),
            key = decoded.slice(0, decoded.lastIndexOf("."));
          const rawCookie = cookie.cookieString();
          const setup = await state(ctx, profile);
          expect(setup.snapshot.verifications.find((row) => row.identifier === key)?.value).toBe(
            userId,
          );
          expect(
            setup.snapshot.verifications.find((row) => row.identifier === `2fa-attempts-${key}`)
              ?.value,
          ).toBe("0");
          const unrelated = ctx.uniqueToken("unrelated-expired");
          await control(ctx, profile, {
            action: "seed",
            identifier: unrelated,
            value: foreignId,
            expiresAt: "2020-01-01T00:00:00.000Z",
            createdAt: "2019-01-01T00:00:00.000Z",
          });
          await ctx.rawRequest({
            path: "/__test/two-factor-policy",
            method: "POST",
            json: { userId, count: 3 },
          });
          await control(ctx, profile, {
            action: "user",
            userId,
            name: "Changed Pending Owner",
          });
          let code =
            kind === "backup"
              ? enabled.backupCodes[0]!
              : kind === "totp"
                ? await generateCurrentTotp(enabled.totpURI)
                : "";
          const verify = async (client: typeof owner, headers?: Record<string, string>) =>
            kind === "totp"
              ? client.twoFactor.verifyTotp(
                  { code: await generateCurrentTotp(enabled.totpURI) },
                  { headers },
                )
              : kind === "otp"
                ? client.twoFactor.verifyOtp({ code }, { headers })
                : client.twoFactor.verifyBackupCode({ code }, { headers });
          const guardState = await state(ctx, profile);
          const guards = [];
          const dot = decoded.lastIndexOf(".");
          const signature = decoded.slice(dot + 1);
          const wrongSignature = encodeURIComponent(
            `${decoded.slice(0, dot + 1)}${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`,
          );
          for (const header of ["", `${cookie.key}=${wrongSignature}`]) {
            await control(ctx, profile, { action: "arm" });
            const guard = await verify(raw, { cookie: header });
            expect(guard.error?.code).toBe("INVALID_TWO_FACTOR_COOKIE");
            const guarded = await state(ctx, profile);
            expect(guarded.receipts).toEqual([]);
            expect(guarded.snapshot).toEqual(guardState.snapshot);
            let sendGuard;
            if (kind === "otp") {
              await control(ctx, profile, { action: "arm" });
              sendGuard = await raw.twoFactor.sendOtp({}, { headers: { cookie: header } });
              expect(sendGuard.error).toMatchObject({
                status: 401,
                code: "INVALID_TWO_FACTOR_COOKIE",
              });
              const afterSend = await state(ctx, profile);
              expect(afterSend.receipts).toEqual([]);
              expect(afterSend.snapshot).toEqual(guardState.snapshot);
            }
            guards.push({ verify: guard, send: sendGuard });
          }
          let negative: unknown = null,
            delivery: unknown = null,
            deliveredCode: string | null = null;
          if (mode === "expired") {
            const beforeJar = await state(ctx, profile);
            negative = await verify(owner);
            expect(
              z
                .object({
                  error: z.object({
                    code: z.literal("INVALID_TWO_FACTOR_COOKIE"),
                  }),
                })
                .parse(negative),
            ).toBeDefined();
            expect((await state(ctx, profile)).snapshot).toEqual(beforeJar.snapshot);
          }
          if (kind === "otp") {
            await control(ctx, profile, { action: "arm" });
            const sent = await raw.twoFactor.sendOtp({}, { headers: { cookie: rawCookie } });
            expect(sent.error).toBeNull();
            delivery = await control(ctx, profile, {
              action: "delivery",
              email,
            });
            code = z.object({ otp: z.string() }).parse(delivery).otp;
            deliveredCode = code;
            expect((await state(ctx, profile)).receipts).toEqual(
              cleanup ? ["lookup", "cleanup-read", "cleanup-delete", "user"] : ["lookup", "user"],
            );
          }
          const ghost = ctx.uniqueToken("missing-user");
          if (mode === "missing-user")
            await control(ctx, profile, {
              action: "patch",
              identifier: key,
              value: ghost,
            });
          if (mode === "newest-expired")
            await control(ctx, profile, {
              action: "seed",
              identifier: key,
              value: ghost,
              expiresAt: "2020-01-01T00:00:00.000Z",
              createdAt: "2030-01-01T00:00:00.000Z",
            });
          const before = await state(ctx, profile),
            ownerBefore = await ctx.readUserState({ userId }),
            foreignBefore = await ctx.readUserState({ userId: foreignId });
          await control(ctx, profile, { action: "arm" });
          const rejected = await verify(raw, { cookie: rawCookie });
          expect(rejected.error?.code).toBe("INVALID_TWO_FACTOR_COOKIE");
          const after = await state(ctx, profile);
          const expectedReceipts = cleanup
            ? [
                "lookup",
                "cleanup-read",
                "cleanup-delete",
                ...(mode === "expired" && kind === "otp" ? [] : ["user"]),
              ]
            : ["lookup", "user"];
          expect(after.receipts).toEqual(expectedReceipts);
          expect(after.snapshot.verifications.some((row) => row.identifier === unrelated)).toBe(
            !cleanup,
          );
          const ownerFactorBefore = before.snapshot.factors.find((row) => row.userId === userId)!;
          const ownerFactorAfter = after.snapshot.factors.find((row) => row.userId === userId)!;
          expect(ownerFactorAfter).toEqual({
            ...ownerFactorBefore,
            failedVerificationCount: mode === "expired" && kind === "otp" && !cleanup ? 0 : 3,
          });
          expect(after.snapshot.factors.find((row) => row.userId === foreignId)).toEqual(
            before.snapshot.factors.find((row) => row.userId === foreignId),
          );
          expect(await ctx.readUserState({ userId })).toEqual(ownerBefore);
          expect(await ctx.readUserState({ userId: foreignId })).toEqual(foreignBefore);
          if (mode === "expired") {
            expect(after.snapshot.verifications.some((row) => row.identifier === key)).toBe(
              !cleanup && kind !== "otp",
            );
            expect(
              after.snapshot.verifications.some((row) => row.identifier === `2fa-attempts-${key}`),
            ).toBe(!cleanup && kind === "otp");
            expect(
              after.snapshot.verifications.some((row) => row.identifier === `2fa-otp-${key}`),
            ).toBe(cleanup && kind === "otp");
          } else {
            expect(
              after.snapshot.verifications.find((row) => row.identifier === `2fa-attempts-${key}`)
                ?.value,
            ).toBe("0");
            if (kind === "otp")
              expect(
                after.snapshot.verifications.find((row) => row.identifier === `2fa-otp-${key}`),
              ).toEqual(
                before.snapshot.verifications.find((row) => row.identifier === `2fa-otp-${key}`),
              );
          }
          const replay = await verify(raw, { cookie: rawCookie });
          if (mode === "newest-expired" && cleanup) {
            expect(replay.error).toBeNull();
            expect(replay.data?.user.id).toBe(userId);
            if (kind === "backup") code = enabled.backupCodes[1]!;
          } else expect(replay.error?.code).toBe("INVALID_TWO_FACTOR_COOKIE");
          let fresh = actor("fresh", positive),
            retryCookie = rawCookie;
          if (mode === "expired" || (mode === "newest-expired" && cleanup)) {
            const freshSignIn = await fresh.signIn.email({ email, password });
            expect(freshSignIn.data).toMatchObject({ twoFactorRedirect: true });
            const issued = cookies.get("fresh");
            if (!issued) throw new Error("real positive-lifetime retry cookie required");
            retryCookie = issued.cookieString();
          } else {
            // Restore installed state through the real adapter; no factor credential is removed.
            await control(ctx, profile, {
              action: "patch",
              identifier: key,
              value: userId,
              expiresAt: "2031-01-01T00:00:00.000Z",
            });
          }
          if (kind === "otp") {
            expect(
              (await fresh.twoFactor.sendOtp({}, { headers: { cookie: retryCookie } })).error,
            ).toBeNull();
            code = z
              .object({ otp: z.string() })
              .parse(await control(ctx, positive, { action: "delivery", email })).otp;
          }
          const retry = await verify(fresh, { cookie: retryCookie });
          expect(retry.error).toBeNull();
          expect(retry.data?.user.id).toBe(userId);
          expect(retry.data?.user.name).toBe("Changed Pending Owner");
          const finished = await state(ctx, positive);
          expect(
            finished.snapshot.factors.find((row) => row.userId === userId)?.failedVerificationCount,
          ).toBe(0);
          expect(await ctx.readUserState({ userId: foreignId })).toEqual(foreignBefore);
          const finalReplay = await verify(raw, { cookie: retryCookie });
          if (mode !== "newest-expired" || cleanup)
            expect(finalReplay.error?.code).toBe("INVALID_TWO_FACTOR_COOKIE");
          // With cleanup disabled, a retained older installed identifier is a genuine
          // second generation. Its exact replay behavior is observed, not normalized.
          const final = await state(ctx, positive),
            ownerAfter = await ctx.readUserState({ userId });
          return ctx.snapshot({
            signup,
            other,
            enrollment: {
              ...enabled,
              totpURI: { token: enabled.totpURI },
              backupCodes: enabled.backupCodes.map((token) => ({ token })),
            },
            signIn,
            guards,
            negative,
            delivery: deliveredCode ? { token: deliveredCode } : null,
            before: project(before),
            ownerBefore,
            foreignBefore,
            rejected,
            after: project(after),
            replay,
            retry,
            finished: project(finished),
            finalReplay,
            final: project(final),
            ownerAfter,
          });
        },
        [
          "POST /two-factor/enable",
          ...(kind === "otp" ? ["POST /two-factor/send-otp"] : []),
          `POST /two-factor/verify-${kind === "backup" ? "backup-code" : kind}`,
        ],
      );
    }
