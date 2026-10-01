import { betterAuth, type BetterAuthOptions } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { phoneNumber, twoFactor } from "better-auth/plugins";
import { APIError } from "better-auth/api";

/** Real delivery callbacks and independently configured pinned phone runtimes. */
export async function createPhoneFixture(base: BetterAuthOptions, twoFactorOutbox: Map<string, { otp: string }>) {
  const outbox = new Map<string, { code: string }>();
  const challenges = new Map<string, string>();
  const callbacks: { phoneNumber: string; userId: string }[] = [];
  function options(name: string) {
    return {
      ...base,
      basePath: `/__test/profiles/${name}/api/auth`,
      emailAndPassword: { ...base.emailAndPassword, enabled: true, revokeSessionsOnPasswordReset: name === "phone-proof" },
      emailVerification: { ...base.emailVerification, sendOnSignUp: false },
      plugins: [
        twoFactor({ otpOptions: { async sendOTP({ user, otp }) { twoFactorOutbox.set(user.email, { otp }); } } }),
        phoneNumber({
          async sendOTP({ phoneNumber, code }) {
            outbox.set(`verification:${phoneNumber}`, { code });
            if (name === "phone-custom") challenges.set(phoneNumber, code);
          },
          async sendPasswordResetOTP({ phoneNumber, code }) { outbox.set(`password-reset:${phoneNumber}`, { code }); },
          requireVerification: name === "phone-proof",
          ...(name !== "phone-default" ? { signUpOnVerification: { getTempEmail: (phone: string) => `${phone}@phone.fixture.test`, getTempName: (phone: string) => phone } } : {}),
          ...(name === "phone-custom" ? {
            phoneNumberValidator: (phone: string) => /^\+[0-9]{8,15}$/.test(phone),
            async verifyOTP({ phoneNumber, code }: { phoneNumber: string; code: string }) {
              if (challenges.get(phoneNumber) !== code) return false;
              challenges.delete(phoneNumber);
              return true;
            },
          } : {}),
          async callbackOnVerification({ phoneNumber, user }) { callbacks.push({ phoneNumber, userId: user.id }); },
        }),
      ],
    };
  }
  const profiles = new Map<string, ReturnType<typeof betterAuth<ReturnType<typeof options>>>>();
  for (const name of ["phone-default", "phone-signup", "phone-proof", "phone-custom"]) {
    const config = options(name);
    await (await getMigrations(config)).runMigrations();
    profiles.set(name, betterAuth(config));
  }
  return {
    profiles, outbox, callbacks,
    reset() { outbox.clear(); challenges.clear(); callbacks.length = 0; },
    async consume(body: unknown) {
      if (!body || typeof body !== "object" || Array.isArray(body)) return Response.json({ message: "invalid server operation" }, { status: 400 });
      const record = body as Record<string, unknown>;
      const selected = typeof record.profile === "string" ? profiles.get(record.profile) : undefined;
      if (!selected || typeof record.phoneNumber !== "string" || typeof record.code !== "string") return Response.json({ message: "invalid server operation" }, { status: 400 });
      try { return Response.json(await selected.api.consumePhoneNumberOTP({ body: { phoneNumber: record.phoneNumber, code: record.code } })); }
      catch (error) {
        if (error instanceof APIError) return Response.json(error.body, { status: typeof error.status === "number" ? error.status : error.status === "BAD_REQUEST" ? 400 : error.status === "FORBIDDEN" ? 403 : 500 });
        throw error;
      }
    },
  };
}
