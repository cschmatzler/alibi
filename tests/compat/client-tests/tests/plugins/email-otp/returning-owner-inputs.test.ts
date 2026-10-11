import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { emailOTPClient, usernameClient } from "better-auth/client/plugins";
import { z } from "zod";

import { compatScenario } from "../../../support/scenario";
import { readUserState, verificationCount } from "../../../support/verification";
import { passwordlessClient, readOtp } from "./helpers";

compatScenario(
  "verified returning email OTP owner ignores signup-only malformed username fields without changing identity",
  async (ctx) => {
    const owner = createAuthClient({
      baseURL: ctx.baseURL,
      plugins: [emailOTPClient(), usernameClient()],
      fetchOptions: { customFetchImpl: ctx.actor("owner").fetch },
    });
    const foreign = passwordlessClient(ctx, "foreign");
    const guest = passwordlessClient(ctx, "guest");
    const email = ctx.uniqueEmail("returning-input-owner");
    const signup = await owner.signUp.email({
      email,
      name: "Established Owner",
      password: "password123",
      username: "established_owner",
      displayUsername: "Established Owner",
    });
    expect(signup.error).toBeNull();
    const other = await foreign.signUp.email({
      email: ctx.uniqueEmail("returning-input-foreign"),
      name: "Foreign",
      password: "password123",
    });
    expect(other.error).toBeNull();
    expect(
      (await owner.emailOtp.sendVerificationOtp({ email, type: "email-verification" })).error,
    ).toBeNull();
    expect(
      (
        await owner.emailOtp.verifyEmail({
          email,
          otp: await readOtp(ctx, email, "email-verification"),
        })
      ).error,
    ).toBeNull();
    const original = await owner.getSession();
    expect(original.data!.user.emailVerified).toBe(true);
    const foreignBefore = await readUserState(ctx, other.data!.user.id);
    expect((await guest.emailOtp.sendVerificationOtp({ email, type: "sign-in" })).error).toBeNull();
    const otp = await readOtp(ctx, email, "sign-in");
    const before = await readUserState(ctx, signup.data!.user.id);
    const accepted = await guest.$fetch("/sign-in/email-otp", {
      method: "POST",
      body: {
        email,
        otp,
        username: 5,
        displayUsername: { unexpected: true },
        name: "Ignored New Name",
        image: "https://ignored.example.test/image.png",
      },
    });
    expect(accepted.error).toBeNull();
    const payload = z
      .object({
        token: z.string(),
        user: z.object({ id: z.string() }).passthrough(),
      })
      .parse(accepted.data);
    expect(payload.user).toEqual(original.data!.user);
    const current = await guest.getSession();
    expect(current.data!.user).toEqual(original.data!.user);
    expect(current.data!.session.token).toBe(payload.token);
    const after = await readUserState(ctx, signup.data!.user.id);
    expect(after.user).toEqual(before.user);
    expect(after.accounts).toEqual(before.accounts);
    expect(after.sessions).toHaveLength(before.sessions.length + 1);
    for (const session of before.sessions) expect(after.sessions).toContainEqual(session);
    expect(await verificationCount(ctx, `sign-in-otp-${email}`)).toBe(0);
    expect(await readUserState(ctx, other.data!.user.id)).toEqual(foreignBefore);
    const replay = await guest.signIn.emailOtp({ email, otp });
    expect(replay.error).toMatchObject({ status: 400, code: "INVALID_OTP" });
    expect(await readUserState(ctx, signup.data!.user.id)).toEqual(after);
    expect((await owner.getSession()).data!.session.token).toBe(original.data!.session.token);
    const credentials = await passwordlessClient(ctx, "credential-retry").signIn.email({
      email,
      password: "password123",
    });
    expect(credentials.error).toBeNull();
    expect(credentials.data!.user.id).toBe(signup.data!.user.id);
    return ctx.snapshot({ signup, other, original, accepted, current, replay, credentials });
  },
  ["POST /sign-in/email-otp", "POST /email-otp/verify-email", "GET /get-session"],
);
