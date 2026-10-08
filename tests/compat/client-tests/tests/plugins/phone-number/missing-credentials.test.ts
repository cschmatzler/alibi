import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { phoneClient, phoneUser, readPhoneOtp, readPhoneState, uniquePhone } from "./helpers";

compatScenario(
  "phone password login distinguishes absent credential account from null and empty hashes",
  async (ctx) => {
    async function physical() {
      const response = await fetch(`${ctx.baseURL}/__test/provider-batch/sql-state`);
      expect(response.status).toBe(200);
      return response.json() as Promise<Record<string, Record<string, unknown>[]>>;
    }
    const profile = "phone-proof";
    const owner = phoneClient(ctx, profile, "otp-only");
    const phoneNumber = uniquePhone(ctx, "otp-only-credential");
    expect((await owner.phoneNumber.sendOtp({ phoneNumber })).error).toBeNull();
    const verified = await owner.phoneNumber.verify({
      phoneNumber,
      code: await readPhoneOtp(ctx, phoneNumber),
    });
    expect(verified.error).toBeNull();
    const user = phoneUser(verified.data?.user);
    const otpState = await readPhoneState(ctx, profile, user.id);
    expect(otpState.accounts).toEqual([]);
    expect(otpState.sessions).toHaveLength(1);
    const foreign = phoneClient(ctx, profile, "foreign-credential");
    const foreignSignup = await foreign.signUp.email({
      email: ctx.uniqueEmail("phone-foreign"),
      password: "password123",
      name: "Foreign Phone",
    });
    expect(foreignSignup.error).toBeNull();
    const foreignId = foreignSignup.data!.user.id;
    const foreignBefore = await readPhoneState(ctx, profile, foreignId);
    const guest = phoneClient(ctx, profile, "password-denied");
    const absent = await guest.signIn.phoneNumber({
      phoneNumber,
      password: "arbitrary-password123",
    });
    expect(absent.error).toMatchObject({ status: 401, code: "INVALID_PHONE_NUMBER_OR_PASSWORD" });
    expect(await readPhoneState(ctx, profile, user.id)).toEqual(otpState);
    expect((await owner.getSession()).data?.user.id).toBe(user.id);
    const credentialOwner = phoneClient(ctx, profile, "credential-owner");
    const credentialPhone = uniquePhone(ctx, "credential-phone");
    const signup = await credentialOwner.signUp.email({
      email: ctx.uniqueEmail("phone-credential"),
      name: "Credential Phone",
      password: "password123",
      phoneNumber: credentialPhone,
    });
    expect(signup.error).toBeNull();
    expect(
      (await credentialOwner.phoneNumber.sendOtp({ phoneNumber: credentialPhone })).error,
    ).toBeNull();
    expect(
      (
        await credentialOwner.phoneNumber.verify({
          phoneNumber: credentialPhone,
          code: await readPhoneOtp(ctx, credentialPhone),
          disableSession: true,
        })
      ).error,
    ).toBeNull();
    const credentialUser = phoneUser(signup.data!.user);
    const initial = await readPhoneState(ctx, profile, credentialUser.id);
    const account = initial.accounts.find((account) => account.providerId === "credential")!;
    expect(account).toBeDefined();
    const observations = [];
    const mismatches = [];
    for (const shape of ["null", "empty"] as const) {
      const changed = await ctx.rawRequest({
        path: "/__test/signup-policy",
        method: "POST",
        json: {
          operation: "clear-password",
          profile: "signup-standard",
          accountId: account.id,
          ...(shape === "empty" ? { password: "" } : {}),
        },
      });
      expect(changed.status).toBe(200);
      const completeBefore = await physical();
      const stored = (completeBefore.account ?? completeBefore.accounts)!.find(
        (row) => row.id === account.id,
      )!;
      expect(stored.password).toBe(shape === "null" ? null : "");
      const before = await readPhoneState(ctx, profile, credentialUser.id);
      expect(before.accounts).toEqual(initial.accounts);
      const result = await guest.signIn.phoneNumber({
        phoneNumber: credentialPhone,
        password: "password123",
      });
      expect(result.data).toBeNull();
      expect(await physical()).toEqual(completeBefore);
      expect(await readPhoneState(ctx, profile, credentialUser.id)).toEqual(before);
      expect(await readPhoneState(ctx, profile, foreignId)).toEqual(foreignBefore);
      expect((await credentialOwner.getSession()).data?.user.id).toBe(credentialUser.id);
      if (result.error?.status !== 401 || result.error?.code !== "UNEXPECTED_ERROR") {
        mismatches.push({ shape, result: ctx.snapshot(result) });
      }
      observations.push({ shape, result: ctx.snapshot(result), before });
    }
    expect(await readPhoneState(ctx, profile, user.id)).toEqual(otpState);
    expect(mismatches).toEqual([]);
    return {
      verified: ctx.snapshot(verified),
      absent: ctx.snapshot(absent),
      signup: ctx.snapshot(signup),
      foreignSignup: ctx.snapshot(foreignSignup),
      observations,
    };
  },
  ["POST /sign-in/phone-number"],
);
