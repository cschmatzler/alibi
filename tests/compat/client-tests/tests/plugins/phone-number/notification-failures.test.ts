import { expect } from "bun:test";

import { z } from "zod";

import { compatScenario } from "../../../support/scenario";
import { phoneClient, readPhoneOtp, readPhoneState, uniquePhone } from "./helpers";

compatScenario(
  "phone delivery failures retain endpoint-specific awaited and background policies and usable proofs",
  async (ctx) => {
    type Receipt = {
      stage: string;
      purpose: string;
      phoneNumber: string;
      code: string;
      request: { path: string; method: string; marker: string | null };
    };
    const control = async (operation?: string) => {
      const response = await fetch(
        `${ctx.baseURL}/__test/phone-notifications`,
        operation
          ? {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({ operation }),
            }
          : undefined,
      );
      expect(response.status).toBe(200);
      return (await response.json()) as { events: Receipt[]; scheduled: number };
    };
    const waitFor = async (predicate: (state: Awaited<ReturnType<typeof control>>) => boolean) => {
      const deadline = Date.now() + 5000;
      while (true) {
        const state = await control();
        if (predicate(state)) return state;
        if (Date.now() > deadline) throw new Error("Actual notification receipt did not arrive");
        await Bun.sleep(10);
      }
    };
    const settle = async <T>(promise: Promise<T>) =>
      Promise.race([
        promise,
        Bun.sleep(5000).then(() => {
          throw new Error("Phone HTTP request did not finish after callback gate");
        }),
      ]);
    const foreign = await ctx.actor("notification-foreign").client.signUp.email({
      email: ctx.uniqueEmail("notification-foreign"),
      password: "password123",
      name: "Foreign Notification Owner",
    });
    expect(foreign.error).toBeNull();
    const foreignBefore = await ctx.readUserState({ userId: foreign.data!.user.id });
    const observations = [];
    const mismatches = [];
    for (const mode of ["awaited", "background", "schedule-error"] as const) {
      const profile = `phone-notification-${mode}` as const;
      for (const endpoint of ["send-otp", "unverified-signin", "password-reset"] as const) {
        await control("restore");
        const name = `notification-${mode}-${endpoint}`;
        const owner = phoneClient(ctx, profile, name);
        const phoneNumber = uniquePhone(ctx, name);
        const signup = await owner.signUp.email({
          email: ctx.uniqueEmail(name),
          password: "password123",
          name: "Notification Owner",
          phoneNumber,
        });
        expect(signup.error).toBeNull();
        if (endpoint === "password-reset") {
          const enrollment = await owner.phoneNumber.sendOtp({ phoneNumber });
          expect(enrollment.error).toBeNull();
          await waitFor((state) => state.events.at(-1)?.stage === "completed");
          const code = await readPhoneOtp(ctx, phoneNumber);
          const verified = await owner.phoneNumber.verify({
            phoneNumber,
            code,
            disableSession: true,
          });
          expect(verified.data?.user.phoneNumberVerified).toBe(true);
        }
        const before = await readPhoneState(ctx, profile, signup.data!.user.id);
        const identifier =
          endpoint === "password-reset" ? `${phoneNumber}-request-password-reset` : phoneNumber;
        await control("arm");
        const marker = `${name}-marker`;
        let cookies: string[] = [];
        let settled = false;
        const fetchOptions = {
          headers: { "x-phone-delivery-marker": marker },
          onResponse: ({ response }: { response: Response }) => {
            cookies = response.headers.getSetCookie();
          },
        };
        const request = (
          endpoint === "send-otp"
            ? owner.phoneNumber.sendOtp({ phoneNumber }, fetchOptions)
            : endpoint === "unverified-signin"
              ? owner.signIn.phoneNumber({ phoneNumber, password: "password123" }, fetchOptions)
              : owner.phoneNumber.requestPasswordReset({ phoneNumber }, fetchOptions)
        ).then((result) => {
          settled = true;
          return result;
        });
        const started = await waitFor((state) => state.events.length === 1);
        expect(started.events[0]).toMatchObject({
          stage: "started",
          purpose: endpoint === "password-reset" ? "password-reset" : "verification",
          phoneNumber,
          request: {
            path: `/__test/profiles/${profile}/api/auth/${endpoint === "unverified-signin" ? "sign-in/phone-number" : `phone-number/${endpoint === "password-reset" ? "request-password-reset" : "send-otp"}`}`,
            method: "POST",
            marker,
          },
        });
        const issued = started.events[0]!.code;
        expect(issued).toMatch(/^\d{6}$/);
        const proof = z
          .array(z.object({ identifier: z.string(), value: z.string() }).passthrough())
          .parse(await ctx.readVerificationState({ identifier }));
        expect(proof).toHaveLength(1);
        expect(proof[0]!.value).toBe(endpoint === "unverified-signin" ? issued : `${issued}:0`);
        expect(await readPhoneState(ctx, profile, signup.data!.user.id)).toEqual(before);
        if (mode === "awaited") expect(settled).toBe(false);
        else {
          await settle(request);
          expect((await control()).scheduled).toBe(1);
          expect((await control()).events).toEqual(started.events);
        }
        await control("release");
        const result = await settle(request);
        const finished = await waitFor((state) => state.events.length === 2);
        expect(finished.events).toEqual([
          started.events[0]!,
          { ...started.events[0]!, stage: "rejected" },
        ]);
        expect(finished.scheduled).toBe(mode === "awaited" ? 0 : 1);
        expect(cookies).toEqual([]);
        if (endpoint === "send-otp" && mode === "awaited") {
          expect(result.error?.status).toBe(500);
          if (
            JSON.stringify(result.error) !==
            JSON.stringify({ status: 500, statusText: "Internal Server Error" })
          ) {
            mismatches.push({ mode, endpoint, error: result.error });
          }
        } else if (endpoint === "unverified-signin") {
          expect(result.error).toMatchObject({
            status: 401,
            code: "PHONE_NUMBER_NOT_VERIFIED",
            message: "Phone number not verified",
          });
        } else {
          expect(result.error).toBeNull();
          expect(result.data).toEqual(
            endpoint === "send-otp" ? { message: "code sent" } : { status: true },
          );
        }
        expect(await ctx.readVerificationState({ identifier })).toEqual(proof);
        expect(await readPhoneState(ctx, profile, signup.data!.user.id)).toEqual(before);
        await control("restore");
        const consumed =
          endpoint === "password-reset"
            ? await owner.phoneNumber.resetPassword({
                phoneNumber,
                otp: issued,
                newPassword: "notification-recovered123",
              })
            : await owner.phoneNumber.verify({ phoneNumber, code: issued, disableSession: true });
        expect(consumed.error).toBeNull();
        expect(await ctx.readVerificationState({ identifier })).toEqual([]);
        const replay =
          endpoint === "password-reset"
            ? await owner.phoneNumber.resetPassword({
                phoneNumber,
                otp: issued,
                newPassword: "replay-password123",
              })
            : await owner.phoneNumber.verify({ phoneNumber, code: issued, disableSession: true });
        expect(replay.error?.status).toBe(400);
        const authenticated = await phoneClient(
          ctx,
          profile,
          `${name}-recovery`,
        ).signIn.phoneNumber({
          phoneNumber,
          password: endpoint === "password-reset" ? "notification-recovered123" : "password123",
        });
        expect(authenticated.error).toBeNull();
        expect(authenticated.data?.user.id).toBe(signup.data!.user.id);
        expect((await owner.getSession()).data?.session.token).toBe(signup.data!.token!);
        expect(await ctx.readUserState({ userId: foreign.data!.user.id })).toEqual(foreignBefore);
        observations.push({
          mode,
          endpoint,
          signup,
          // Receipts carry random OTPs; preserve their relationships as typed
          // tokens after asserting the exact delivered proof and replay behavior.
          started: {
            ...started,
            events: started.events.map((event) => ({ ...event, code: { token: event.code } })),
          },
          finished: {
            ...finished,
            events: finished.events.map((event) => ({ ...event, code: { token: event.code } })),
          },
          result,
          consumed,
          replay,
          authenticated,
        });
      }
    }
    expect((await ctx.actor("notification-foreign").client.getSession()).data?.user.id).toBe(
      foreign.data!.user.id,
    );
    expect(mismatches).toEqual([]);
    return ctx.snapshot({ foreign, observations });
  },
  [
    "POST /phone-number/send-otp",
    "POST /sign-in/phone-number",
    "POST /phone-number/request-password-reset",
    "POST /phone-number/verify",
    "POST /phone-number/reset-password",
  ],
);
