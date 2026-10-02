import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { phoneNumberClient } from "better-auth/client/plugins";
import { z } from "zod";

import { authProfilePath, type FixtureProfile } from "./profiles";
import { compatScenario } from "./scenario";
import { fixtureValue, readUserState, storedVerification, verificationCount } from "./verification";

const modes = [
  "length-zero",
  "length-fraction",
  "length-negative",
  "length-nan",
  "length-negative-infinity",
  "attempts-zero",
  "attempts-fraction",
  "attempts-negative",
  "attempts-nan",
  "attempts-infinity",
  "attempts-negative-infinity",
  "lifetime-zero",
  "lifetime-fraction",
  "lifetime-negative",
  "lifetime-nan",
  "lifetime-infinity",
  "lifetime-negative-infinity",
] as const;

/** Each row exercises actual delivery, proof persistence, and the public consumer. */
export function passwordlessNumericScenarios(plugin: "passwordless" | "phone" | "magic-link") {
  for (const mode of modes) {
    if (plugin === "magic-link" && !mode.startsWith("lifetime-")) {
      continue;
    }
    compatScenario(
      `${plugin} raw numeric ${mode} governs delivered proof and consumption`,
      async (ctx) => {
        const profile = `${plugin}-numeric-${mode}` as FixtureProfile;
        const actor = ctx.actor("primary", profile);
        const client = actor.client;
        const phoneClient = createAuthClient({
          baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
          plugins: [phoneNumberClient()],
          fetchOptions: { customFetchImpl: actor.fetch },
        });
        const email = ctx.uniqueEmail("numeric-owner");
        const phoneNumber = `+1${String(Bun.hash(ctx.uniqueToken("number")))
          .padStart(10, "0")
          .slice(-10)}`;
        const issue = () =>
          plugin === "phone"
            ? phoneClient.phoneNumber.sendOtp({ phoneNumber })
            : plugin === "passwordless"
              ? client.emailOtp.sendVerificationOtp({ email, type: "sign-in" })
              : client.signIn.magicLink({ email });
        const identifier = plugin === "phone" ? phoneNumber : `sign-in-otp-${email}`;
        const generationFails =
          mode === "length-zero" ||
          mode === "length-negative" ||
          mode === "length-negative-infinity";
        const invalidDate =
          mode === "lifetime-infinity" ||
          mode === "lifetime-negative-infinity" ||
          (mode === "lifetime-nan" && plugin !== "magic-link");
        let predecessor:
          | {
              issued: unknown;
              delivery: unknown;
              code: string;
              key: string;
              rows: Awaited<ReturnType<typeof storedVerification>>;
              consume: () => Promise<unknown>;
            }
          | undefined;

        if (generationFails || invalidDate) {
          const priorActor =
            plugin === "phone" ? ctx.actor("prior", "phone-signup") : ctx.actor("prior");
          const priorPhone = createAuthClient({
            baseURL: `${ctx.baseURL}${authProfilePath("phone-signup")}`,
            plugins: [phoneNumberClient()],
            fetchOptions: { customFetchImpl: priorActor.fetch },
          });
          const priorIssued =
            plugin === "phone"
              ? await priorPhone.phoneNumber.sendOtp({ phoneNumber })
              : plugin === "passwordless"
                ? await priorActor.client.emailOtp.sendVerificationOtp({ email, type: "sign-in" })
                : await priorActor.client.signIn.magicLink({ email });
          expect(priorIssued.error).toBeNull();

          const priorDelivery = z
            .record(z.string(), z.unknown())
            .parse(
              await fixtureValue(
                ctx,
                plugin === "phone"
                  ? "/__test/phone-otp"
                  : plugin === "passwordless"
                    ? "/__test/email-otp"
                    : "/__test/magic-link",
                plugin === "phone" ? { phoneNumber } : { email, type: "sign-in" },
              ),
            );
          const priorCode = z
            .string()
            .parse(
              priorDelivery[
                plugin === "phone" ? "code" : plugin === "passwordless" ? "otp" : "token"
              ],
            );
          const priorKey = plugin === "magic-link" ? priorCode : identifier;
          predecessor = {
            issued: priorIssued,
            delivery: priorDelivery,
            code: priorCode,
            key: priorKey,
            rows: await storedVerification(ctx, priorKey),
            consume: () =>
              plugin === "phone"
                ? priorPhone.phoneNumber.verify({ phoneNumber, code: priorCode })
                : plugin === "passwordless"
                  ? priorActor.client.signIn.emailOtp({ email, otp: priorCode })
                  : priorActor.client.magicLink.verify({ query: { token: priorCode } }),
          };
        }

        const issuanceStartedAt = Date.now();
        const issued = await issue();
        const issuanceFinishedAt = Date.now();

        if (generationFails || invalidDate) {
          expect(issued.error?.status).toBe(500);

          if (!predecessor) {
            throw new Error("Failed issuance must have an independently delivered predecessor");
          }

          expect(
            await fixtureValue(
              ctx,
              plugin === "phone"
                ? "/__test/phone-otp"
                : plugin === "passwordless"
                  ? "/__test/email-otp"
                  : "/__test/magic-link",
              plugin === "phone" ? { phoneNumber } : { email, type: "sign-in" },
            ),
          ).toEqual(predecessor.delivery);

          const remaining = await storedVerification(ctx, predecessor.key);
          const deletedByRetry = plugin === "passwordless" && invalidDate;
          expect(remaining).toEqual(deletedByRetry ? [] : predecessor.rows);
          expect((await client.getSession()).data).toBeNull();

          const predecessorResult = await predecessor.consume();

          if (deletedByRetry) {
            expect(
              z
                .object({ error: z.object({ code: z.literal("INVALID_OTP") }) })
                .passthrough()
                .parse(predecessorResult).error.code,
            ).toBe("INVALID_OTP");
          } else {
            expect(
              z.object({ error: z.null() }).passthrough().parse(predecessorResult).error,
            ).toBeNull();
          }

          expect(await verificationCount(ctx, predecessor.key)).toBe(0);

          return {
            issued,
            priorIssued: predecessor.issued,
            rowsAfterFailure: remaining.length,
            priorExpiresAt: predecessor.rows[0]?.expiresAt,
            predecessorResult,
          };
        }

        expect(issued.error).toBeNull();

        const delivery = z
          .object(
            plugin === "phone"
              ? { code: z.string() }
              : plugin === "passwordless"
                ? { otp: z.string() }
                : { token: z.string(), url: z.string(), metadata: z.unknown() },
          )
          .passthrough()
          .parse(
            await fixtureValue(
              ctx,
              plugin === "phone"
                ? "/__test/phone-otp"
                : plugin === "passwordless"
                  ? "/__test/email-otp"
                  : "/__test/magic-link",
              plugin === "phone" ? { phoneNumber } : { email, type: "sign-in" },
            ),
          );
        const code = z
          .string()
          .parse(
            delivery[plugin === "phone" ? "code" : plugin === "passwordless" ? "otp" : "token"],
          );
        expect(code.length).toBe(
          plugin === "magic-link"
            ? 32
            : mode === "length-fraction"
              ? 2
              : mode === "length-nan"
                ? 0
                : 6,
        );

        const key = plugin === "magic-link" ? code : identifier;
        const stored = await storedVerification(ctx, key);
        expect(stored).toHaveLength(1);
        expect(stored[0]?.value).toBe(
          plugin === "magic-link" ? JSON.stringify({ email, name: undefined }) : `${code}:0`,
        );

        const ttl =
          mode === "lifetime-fraction"
            ? 30_000
            : mode === "lifetime-negative"
              ? -1_000
              : mode === "lifetime-zero" && plugin !== "magic-link"
                ? 0
                : 300_000;
        expect(Date.parse(stored[0]!.expiresAt)).toBeGreaterThanOrEqual(issuanceStartedAt + ttl);
        expect(Date.parse(stored[0]!.expiresAt)).toBeLessThanOrEqual(issuanceFinishedAt + ttl);

        const consume = (provided: string, recipient = plugin === "phone" ? phoneNumber : email) =>
          plugin === "phone"
            ? phoneClient.phoneNumber.verify({ phoneNumber: recipient, code: provided })
            : plugin === "passwordless"
              ? client.signIn.emailOtp({ email: recipient, otp: provided })
              : client.magicLink.verify({ query: { token: provided } });

        if (ttl <= 0) {
          await new Promise((resolve) => setTimeout(resolve, 20));
          const expired =
            plugin === "magic-link"
              ? await actor
                  .fetch(z.string().parse(delivery.url), { redirect: "manual" })
                  .then(async (response) => ({
                    status: response.status,
                    location: response.headers.get("location"),
                    body: await response.text(),
                  }))
              : await consume(code);
          expect(await verificationCount(ctx, key)).toBe(0);
          expect((await client.getSession()).data).toBeNull();

          return { issued, expiresAt: stored[0]?.expiresAt, codeLength: code.length, expired };
        }

        const foreign =
          plugin === "magic-link"
            ? await consume("unissued-foreign-token")
            : await consume(code, plugin === "phone" ? "+19999999999" : ctx.uniqueEmail("foreign"));
        expect(foreign.error).not.toBeNull();
        expect(await storedVerification(ctx, key)).toEqual(stored);

        const budget =
          mode === "attempts-negative" ||
          mode === "attempts-negative-infinity" ||
          (mode === "attempts-zero" && plugin === "phone")
            ? 0
            : mode === "attempts-fraction"
              ? 2
              : (mode === "attempts-nan" && plugin === "phone") || mode === "attempts-infinity"
                ? Infinity
                : 3;
        const wrong = [];

        if (plugin !== "magic-link") {
          for (
            let attempt = 0;
            attempt < (budget === Infinity ? 4 : Math.max(1, budget));
            attempt++
          ) {
            const denied = await consume("incorrect");
            expect(denied.error?.code).toBe(
              attempt >= budget ? "TOO_MANY_ATTEMPTS" : "INVALID_OTP",
            );

            const remaining = await storedVerification(ctx, key);

            if (attempt >= budget) {
              expect(remaining).toHaveLength(0);
            } else {
              expect(remaining).toHaveLength(1);
              expect(remaining[0]?.value).toBe(`${code}:${attempt + 1}`);
              expect(remaining[0]?.expiresAt).toBe(stored[0]?.expiresAt);
            }

            wrong.push({
              denied,
              rows: remaining.length,
              expiresAt: remaining[0]?.expiresAt,
              attempts: remaining[0] ? Number(remaining[0].value.split(":").at(-1)) : null,
            });
          }
          if (budget !== Infinity && budget > 0) {
            const exhausted = await consume(code);
            expect(exhausted.error?.code).toBe("TOO_MANY_ATTEMPTS");
            expect(await verificationCount(ctx, key)).toBe(0);

            wrong.push({ exhausted });
          }
        }

        const reissued = await issue();
        expect(reissued.error).toBeNull();

        const nextDelivery = z
          .record(z.string(), z.unknown())
          .parse(
            await fixtureValue(
              ctx,
              plugin === "phone"
                ? "/__test/phone-otp"
                : plugin === "passwordless"
                  ? "/__test/email-otp"
                  : "/__test/magic-link",
              plugin === "phone" ? { phoneNumber } : { email, type: "sign-in" },
            ),
          );
        const nextCode = z
          .string()
          .parse(
            nextDelivery[plugin === "phone" ? "code" : plugin === "passwordless" ? "otp" : "token"],
          );
        const nextKey = plugin === "magic-link" ? nextCode : key;
        const nextStored = await storedVerification(ctx, nextKey);
        expect(nextStored).toHaveLength(plugin !== "magic-link" && budget === Infinity ? 2 : 1);
        expect(nextStored[0]?.id).not.toBe(stored[0]?.id);

        // Rotation appends a row when a live proof remains; consumption clears the identifier.
        const verified = await consume(nextCode);

        if (budget === 0) {
          expect(verified.error?.code).toBe("TOO_MANY_ATTEMPTS");
          expect((await client.getSession()).data).toBeNull();
          return {
            issued,
            expiresAt: stored[0]?.expiresAt,
            codeLength: code.length,
            foreign,
            wrong,
            reissued,
            rowsAfterReissue: nextStored.length,
            verified,
          };
        }

        expect(verified.error).toBeNull();

        const user = z.object({ id: z.string() }).parse(verified.data?.user);
        const state =
          plugin === "phone"
            ? z
                .object({
                  user: z
                    .object({
                      id: z.string(),
                      phoneNumber: z.string(),
                      phoneNumberVerified: z.boolean(),
                    })
                    .passthrough(),
                  accounts: z.array(z.unknown()),
                  sessions: z.array(
                    z.object({ token: z.string(), expiresAt: z.string() }).passthrough(),
                  ),
                })
                .passthrough()
                .parse(await fixtureValue(ctx, "/__test/user-state", { userId: user.id, profile }))
            : await readUserState(ctx, user.id);
        expect(state.sessions).toHaveLength(1);
        expect(state.accounts).toHaveLength(0);
        expect(state.user?.[plugin === "phone" ? "phoneNumberVerified" : "emailVerified"]).toBe(
          true,
        );
        expect(await verificationCount(ctx, nextKey)).toBe(0);

        const replay = await consume(nextCode);
        expect(replay.error).not.toBeNull();
        expect(
          plugin === "phone"
            ? await fixtureValue(ctx, "/__test/user-state", { userId: user.id, profile })
            : await readUserState(ctx, user.id),
        ).toEqual(state);

        return {
          issued,
          expiresAt: stored[0]?.expiresAt,
          codeLength: code.length,
          foreign,
          wrong,
          reissued,
          rowsAfterReissue: nextStored.length,
          verified,
          state,
          replay,
        };
      },
    );
  }
}
