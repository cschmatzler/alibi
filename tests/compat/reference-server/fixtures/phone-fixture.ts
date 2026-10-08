import { type BetterAuthOptions, betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import { getMigrations } from "better-auth/db/migration";
import { phoneNumber, twoFactor } from "better-auth/plugins";

import { callbackSnapshot } from "./passwordless-context";
import { numericModes, numericOptions } from "./passwordless-numeric";

/** Real delivery callbacks and independently configured pinned phone runtimes. */
export async function createPhoneFixture(
  base: BetterAuthOptions,
  twoFactorOutbox: Map<string, { otp: string }>,
) {
  const outbox = new Map<string, { code?: string; context?: unknown }>();
  let resetMode = "success";
  const notification = {
    events: [] as unknown[],
    scheduled: 0,
    held: false,
    gate: Promise.resolve(),
    release: () => {},
  };
  async function notify(purpose: string, phoneNumber: string, code: string, ctx: any) {
    const receipt = {
      purpose,
      phoneNumber,
      code,
      request: ctx?.request
        ? {
            path: new URL(ctx.request.url).pathname,
            method: ctx.request.method,
            marker: ctx.request.headers.get("x-phone-delivery-marker"),
          }
        : null,
    };
    const gate = notification.gate;
    const held = notification.held;
    notification.events.push({ stage: "started", ...receipt });
    await gate;
    notification.events.push({ stage: held ? "rejected" : "completed", ...receipt });
    if (held) throw new Error("Application SMS delivery rejected");
  }
  const validatorEvents: string[] = [];
  const resetEvents: unknown[] = [];
  const challenges = new Map<string, string>();
  const callbacks: {
    phoneNumber: string;
    userId: string;
    context?: unknown;
    verifiedOwner?: boolean;
  }[] = [];

  function options(name: string) {
    return {
      ...base,
      basePath: `/__test/profiles/${name}/api/auth`,
      ...(name.startsWith("phone-notification-") && name !== "phone-notification-awaited"
        ? {
            advanced: {
              ...base.advanced,
              backgroundTasks: {
                handler: (promise: Promise<unknown>) => {
                  notification.scheduled++;
                  void promise.catch(() => {});
                  if (name === "phone-notification-schedule-error")
                    throw new Error("Application scheduling observation rejected");
                },
              },
            },
          }
        : {}),
      emailAndPassword: {
        ...base.emailAndPassword,
        enabled: true,
        revokeSessionsOnPasswordReset: name === "phone-proof" || name === "phone-reset-callback",
        ...(name === "phone-reset-callback"
          ? {
              onPasswordReset: async ({ user }: { user: { id: string } }, request?: Request) => {
                resetEvents.push({
                  userId: user.id,
                  request: request
                    ? {
                        method: request.method,
                        url: request.url,
                        marker: request.headers.get("x-reset-marker"),
                      }
                    : null,
                });
                if (resetMode === "reject")
                  throw new APIError("FORBIDDEN", {
                    code: "PHONE_RESET_REJECTED",
                    message: "Application reset callback rejected",
                  });
              },
            }
          : {}),
      },
      emailVerification: { ...base.emailVerification, sendOnSignUp: false },
      plugins: [
        twoFactor({
          otpOptions: {
            async sendOTP({ user, otp }) {
              twoFactorOutbox.set(user.email, { otp });
            },
          },
        }),
        phoneNumber({
          ...numericOptions(name),
          async sendOTP({ phoneNumber, code }, ctx) {
            const context = await callbackSnapshot(ctx, phoneNumber);
            outbox.set(`verification:${phoneNumber}`, { code, ...(context ? { context } : {}) });
            if (name.startsWith("phone-notification-"))
              await notify("verification", phoneNumber, code, ctx);
            if (name === "phone-custom") {
              challenges.set(phoneNumber, code);
            }
          },
          async sendPasswordResetOTP({ phoneNumber, code }, ctx) {
            const context = await callbackSnapshot(ctx, `${phoneNumber}-request-password-reset`);
            outbox.set(`password-reset:${phoneNumber}`, { code, ...(context ? { context } : {}) });
            if (name.startsWith("phone-notification-"))
              await notify("password-reset", phoneNumber, code, ctx);
          },
          ...(name === "phone-no-otp-sender"
            ? {
                sendOTP: undefined!,
                phoneNumberValidator: (phone: string) => {
                  validatorEvents.push(phone);
                  throw new Error("Validator must not run before required sender guard");
                },
              }
            : {}),
          ...(name === "phone-no-reset-sender" ? { sendPasswordResetOTP: undefined } : {}),
          requireVerification: name === "phone-proof" || name.startsWith("phone-notification-"),
          ...(name !== "phone-default"
            ? {
                signUpOnVerification: {
                  getTempEmail: (phone: string) => `${phone}@phone.fixture.test`,
                  getTempName: (phone: string) => phone,
                },
              }
            : {}),
          ...(name === "phone-custom"
            ? {
                phoneNumberValidator: (phone: string) => /^\+[0-9]{8,15}$/.test(phone),
                async verifyOTP(
                  { phoneNumber, code }: { phoneNumber: string; code: string },
                  ctx: Parameters<typeof callbackSnapshot>[0],
                ) {
                  const context = await callbackSnapshot(ctx, phoneNumber);

                  if (context) {
                    outbox.set(`verifier:${phoneNumber}`, { context });
                  }

                  if (challenges.get(phoneNumber) !== code) {
                    return false;
                  }

                  challenges.delete(phoneNumber);
                  return true;
                },
              }
            : {}),
          async callbackOnVerification({ phoneNumber, user }, ctx) {
            const context = await callbackSnapshot(ctx, phoneNumber);
            const owner = context
              ? await ctx.context.internalAdapter.findUserById(user.id)
              : undefined;
            callbacks.push({
              phoneNumber,
              userId: user.id,
              ...(context ? { context, verifiedOwner: owner?.phoneNumberVerified === true } : {}),
            });
            if (name === "phone-callback-reject")
              throw new APIError("FORBIDDEN", {
                code: "PHONE_CALLBACK_REJECTED",
                message: "Application verification callback rejected",
              });
          },
        }),
      ],
    };
  }

  const profiles = new Map<string, ReturnType<typeof betterAuth<ReturnType<typeof options>>>>();

  for (const name of [
    "phone-notification-awaited",
    "phone-notification-background",
    "phone-notification-schedule-error",
    "phone-no-otp-sender",
    "phone-no-reset-sender",
    "phone-default",
    "phone-signup",
    "phone-proof",
    "phone-custom",
    "phone-callback-reject",
    "phone-reset-callback",
    ...numericModes.map((mode) => `phone-numeric-${mode}`),
  ]) {
    const config = options(name);
    await (await getMigrations(config)).runMigrations();
    profiles.set(name, betterAuth(config));
  }

  return {
    profiles,
    notificationControl(operation?: string) {
      if (operation === "arm") {
        notification.events.length = 0;
        notification.scheduled = 0;
        notification.held = true;
        notification.gate = new Promise<void>((resolve) => {
          notification.release = resolve;
        });
      }
      if (operation === "release") notification.release();
      if (operation === "restore") {
        notification.release();
        notification.held = false;
        notification.gate = Promise.resolve();
      }
      return { events: [...notification.events], scheduled: notification.scheduled };
    },
    validatorEvents,
    outbox,
    callbacks,
    resetControl(mode?: string) {
      if (mode) resetMode = mode;
      return { mode: resetMode, events: resetEvents };
    },
    reset() {
      resetMode = "success";
      resetEvents.length = 0;
      outbox.clear();
      challenges.clear();
      callbacks.length = 0;
    },
    async consume(body: unknown) {
      if (!body || typeof body !== "object" || Array.isArray(body)) {
        return Response.json({ message: "invalid server operation" }, { status: 400 });
      }

      const record = body as Record<string, unknown>;
      const selected =
        typeof record.profile === "string" ? profiles.get(record.profile) : undefined;

      if (!selected || typeof record.phoneNumber !== "string" || typeof record.code !== "string") {
        return Response.json({ message: "invalid server operation" }, { status: 400 });
      }

      try {
        return Response.json(
          await selected.api.consumePhoneNumberOTP({
            body: { phoneNumber: record.phoneNumber, code: record.code },
          }),
        );
      } catch (error) {
        if (error instanceof APIError) {
          return Response.json(error.body, {
            status:
              typeof error.status === "number"
                ? error.status
                : error.status === "BAD_REQUEST"
                  ? 400
                  : error.status === "FORBIDDEN"
                    ? 403
                    : 500,
          });
        }
        throw error;
      }
    },
  };
}
