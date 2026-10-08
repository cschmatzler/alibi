import { expect } from "bun:test";

import { z } from "zod";

import { passwordlessNumericScenarios } from "../../../support/passwordless-numeric";
import { compatScenario } from "../../../support/scenario";
import { expireVerification, verificationCount } from "../../../support/verification";
import {
  phoneClient,
  phoneEnrollmentCode,
  phoneRequest,
  phoneUser,
  readPhoneOtp,
  readPhoneState,
  uniquePhone,
} from "./helpers";

compatScenario(
  "phone signup accepts registered ownership fields and rejects verification spoofing",
  async (ctx) => {
    const profile = "phone-signup";
    const client = phoneClient(ctx, profile);
    const results = [];

    for (const [index, input] of [
      { phoneNumber: 1234 },
      { phoneNumber: true },
      { phoneNumber: null, phoneNumberVerified: false },
      { phoneNumberVerified: 0 },
      { phoneNumberVerified: "" },
      { phoneNumberVerified: true },
      { phoneNumberVerified: [] },
      { phoneNumber: [] },
      { phoneNumber: {} },
    ].entries()) {
      const response = await phoneRequest(ctx, profile, "/sign-up/email", {
        email: ctx.uniqueEmail(`phone-schema-${index}`),
        password: "password123",
        name: "Phone Schema",
        ...input,
      });

      if (index >= 5) {
        expect(response.status).toBe(index >= 7 ? 422 : 400);
        expect(response.body).toEqual(
          index >= 7
            ? { code: "FAILED_TO_CREATE_USER", message: "Failed to create user" }
            : {
                code: "FIELD_NOT_ALLOWED",
                message: "phoneNumberVerified is not allowed to be set",
              },
        );

        results.push({ response });
        continue;
      }

      expect(response.status).toBe(200);

      const payload = z
        .object({
          token: z.string().min(1),
          user: z.object({
            id: z.string(),
            phoneNumber: z.string().nullable(),
            phoneNumberVerified: z.boolean().nullable(),
          }),
        })
        .parse(response.body);
      const state = await readPhoneState(ctx, profile, payload.user.id);
      expect(state.user?.phoneNumber).toBe(index === 0 ? "1234" : index === 1 ? "1" : null);
      expect(state.user?.phoneNumberVerified).toBeNull();
      expect(state.accounts).toHaveLength(1);
      expect(state.accounts[0]?.providerId).toBe("credential");
      expect(state.sessions).toHaveLength(1);
      expect(state.sessions[0]?.token).toBe(payload.token);

      const current = await client.getSession();
      expect(current.data?.user.id).toBe(payload.user.id);
      expect(current.data?.session.token).toBe(payload.token);

      results.push({ response, state, current });
    }

    const existing = ctx.uniqueEmail("phone-schema-0");
    const existingWithInvalidPhone = await phoneRequest(ctx, profile, "/sign-up/email", {
      email: existing,
      password: "password123",
      name: "Duplicate",
      phoneNumber: [],
    });
    expect(existingWithInvalidPhone).toEqual({
      status: 422,
      body: {
        code: "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL",
        message: "User already exists. Use another email.",
      },
    });

    const existingWithSpoof = await phoneRequest(ctx, profile, "/sign-up/email", {
      email: existing,
      password: "password123",
      name: "Duplicate",
      phoneNumberVerified: true,
    });
    expect(existingWithSpoof).toEqual({
      status: 400,
      body: { code: "FIELD_NOT_ALLOWED", message: "phoneNumberVerified is not allowed to be set" },
    });

    const phoneNumber = uniquePhone(ctx, "phone-verification-spoof");
    await client.phoneNumber.sendOtp({ phoneNumber });
    const code = await readPhoneOtp(ctx, phoneNumber);
    const spoof = await phoneRequest(ctx, profile, "/phone-number/verify", {
      phoneNumber,
      code,
      phoneNumberVerified: true,
    });
    expect(spoof.status).toBe(400);
    expect(spoof.body).toEqual({
      code: "FIELD_NOT_ALLOWED",
      message: "phoneNumberVerified is not allowed to be set",
    });
    expect(await verificationCount(ctx, phoneNumber)).toBe(0);

    const replay = await client.phoneNumber.verify({ phoneNumber, code });
    expect(replay.error?.code).toBe("OTP_NOT_FOUND");

    await client.phoneNumber.sendOtp({ phoneNumber });
    const legitimate = await phoneRequest(ctx, profile, "/phone-number/verify", {
      phoneNumber,
      code: await readPhoneOtp(ctx, phoneNumber),
      phoneNumberVerified: false,
    });
    expect(legitimate.status).toBe(200);

    const owner = z.object({ user: z.object({ id: z.string() }) }).parse(legitimate.body).user;
    const stored = await readPhoneState(ctx, profile, owner.id);
    expect(stored.user?.phoneNumber).toBe(phoneNumber);
    expect(stored.user?.phoneNumberVerified).toBe(true);
    expect(stored.accounts).toHaveLength(0);

    return {
      results,
      existingWithInvalidPhone,
      existingWithSpoof,
      spoof,
      replay,
      legitimate,
      stored,
    };
  },
);

// Only values whose stored text is the same on every SQLite version. REAL text
// with 16-17 significant digits is formatted by the engine (3.52+), not the adapter.
const numericPhoneValues = [
  ["1.0", "1"],
  ["1e3", "1000"],
  ["1e-5", "1.0e-05"],
  ["1e20", "1.0e+20"],
  ["2147483648", "2147483648"],
  ["2251799813685247", "2251799813685247"],
  ["-2251799813685248", "-2251799813685248"],
  ["-0.0", "0.0"],
  ["47.49", "47.49"],
  ["1e400", "Inf"],
  ["-1e400", "-Inf"],
] as const;

// Each group owns independent users; collisions stay with their original owner.
// Keeping password hashing bounded lets the default test deadline remain strict.
for (const group of [
  {
    name: "phone signup preserves raw JSON numeric bindings and rounded uniqueness",
    start: 6,
    end: 9,
    // JSON.parse rounds this literal to the owner's 47.49.
    collisions: [["47.490000000000002", 8]],
    extras: false,
  },
  {
    name: "phone signup binds integral and exponential JSON numbers to exact SQLite text",
    start: 0,
    end: 6,
    collisions: [],
    extras: false,
  },
  {
    name: "phone signup binds overflowing JSON numbers without accepting duplicate owners",
    start: 9,
    end: 11,
    collisions: [
      ["1e309", 9],
      ["-1e309", 10],
    ],
    extras: true,
  },
] as const) {
  compatScenario(
    group.name,
    async (ctx) => {
      const profile = "phone-signup";
      const created = [];

      for (const [index, [literal, expected]] of numericPhoneValues.entries()) {
        if (index < group.start || index >= group.end) {
          continue;
        }

        const actor = `numeric-${index}`;
        const email = ctx.uniqueEmail(actor);
        // Preserve the original number spelling: the official client uses
        // JSON.stringify, which cannot send -0.0 or an integer beyond JS precision.
        const raw = await ctx
          .actor(actor, profile)
          .fetch(new URL(`/__test/profiles/${profile}/api/auth/sign-up/email`, ctx.baseURL), {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: `{"email":${JSON.stringify(email)},"password":"password123","name":"Phone Numeric","phoneNumber":${literal}}`,
          });
        const response = { status: raw.status, body: (await raw.json()) as unknown };
        expect(response.status).toBe(200);

        const payload = z
          .object({
            token: z.string().min(1),
            user: z.object({
              id: z.string(),
              phoneNumber: z.string(),
              phoneNumberVerified: z.null(),
            }),
          })
          .parse(response.body);
        expect(payload.user.phoneNumber).toBe(expected);

        const state = await readPhoneState(ctx, profile, payload.user.id);
        expect(state.user?.phoneNumber).toBe(expected);
        expect(state.user?.phoneNumberVerified).toBeNull();
        expect(state.accounts).toHaveLength(1);
        expect(state.accounts[0]?.providerId).toBe("credential");
        expect(state.sessions).toHaveLength(1);
        expect(state.sessions[0]?.token).toBe(payload.token);

        const current = await phoneClient(ctx, profile, actor).getSession();
        expect(current.error).toBeNull();
        expect(current.data?.session.token).toBe(payload.token);
        expect(current.data?.user.id).toBe(payload.user.id);

        created.push({ response, state, current });
      }

      const collisions = [];

      for (const [index, [literal, ownerIndex]] of group.collisions.entries()) {
        const actor = `rounded-collision-${index}`;
        const email = ctx.uniqueEmail(actor);
        const raw = await ctx
          .actor(actor, profile)
          .fetch(new URL(`/__test/profiles/${profile}/api/auth/sign-up/email`, ctx.baseURL), {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: `{"email":${JSON.stringify(email)},"password":"password123","name":"Rounded Collision","phoneNumber":${literal}}`,
          });
        const collision = { status: raw.status, body: (await raw.json()) as unknown };
        expect(collision).toEqual({
          status: 422,
          body: { code: "FAILED_TO_CREATE_USER", message: "Failed to create user" },
        });

        // The colliding applicant must not obtain a credential account or session.
        const applicant = phoneClient(ctx, profile, actor);
        expect((await applicant.getSession()).data).toBeNull();

        const rejectedLogin = await applicant.signIn.email({ email, password: "password123" });
        expect(rejectedLogin.error?.code).toBe("INVALID_EMAIL_OR_PASSWORD");

        const owner = created[Number(ownerIndex) - group.start];

        if (!owner) {
          throw new Error("The rounded phone owner must exist");
        }

        const after = await readPhoneState(ctx, profile, owner.state.user!.id);
        expect(after).toEqual(owner.state);

        collisions.push({ collision, rejectedLogin, after });
      }

      if (!group.extras) {
        return { created, collisions };
      }

      // Without the phone plugin these numeric additional inputs stay ignored.
      const disabledActor = ctx.actor("numeric-phone-disabled");
      const disabledRaw = await disabledActor.fetch(
        new URL("/api/auth/sign-up/email", ctx.baseURL),
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: `{"email":${JSON.stringify(ctx.uniqueEmail("numeric-phone-disabled"))},"password":"password123","name":"Numeric Disabled","phoneNumber":1e400,"metadata":{"rounded":9007199254740993,"overflow":-1e400}}`,
        },
      );
      expect(disabledRaw.status).toBe(200);

      const disabled = z
        .object({ token: z.string(), user: z.object({ id: z.string() }).passthrough() })
        .parse(await disabledRaw.json());
      expect(disabled.user).not.toHaveProperty("phoneNumber");
      expect(disabled.user).not.toHaveProperty("metadata");

      const disabledState = z
        .object({
          user: z.object({ id: z.string() }).passthrough(),
          accounts: z.array(z.unknown()),
          sessions: z.array(z.object({ token: z.string() })),
        })
        .parse(await ctx.readUserState({ userId: disabled.user.id }));
      expect(disabledState.user).not.toHaveProperty("phoneNumber");
      expect(disabledState.user).not.toHaveProperty("metadata");
      expect(disabledState.accounts).toHaveLength(1);
      expect(disabledState.sessions).toHaveLength(1);
      expect(disabledState.sessions[0]?.token).toBe(disabled.token);
      expect((await disabledActor.client.getSession()).data?.user.id).toBe(disabled.user.id);

      // Overflow is a number for schema validation, never an invalid JSON body.
      const client = phoneClient(ctx, profile, "overflow-schema");
      const pendingPhone = uniquePhone(ctx, "overflow-schema");
      await client.phoneNumber.sendOtp({ phoneNumber: pendingPhone });
      const code = await readPhoneOtp(ctx, pendingPhone);
      const invalid = [];

      for (const [path, extra] of [
        ["/phone-number/send-otp", ""],
        ["/phone-number/request-password-reset", ""],
        ["/sign-in/phone-number", ',"password":"password123"'],
        ["/phone-number/verify", `,"code":${JSON.stringify(code)}`],
        ["/phone-number/reset-password", ',"otp":"123456","newPassword":"password123"'],
      ]) {
        const response = await ctx
          .actor("overflow-schema", profile)
          .fetch(new URL(`/__test/profiles/${profile}/api/auth${path}`, ctx.baseURL), {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: `{"phoneNumber":1e400${extra}}`,
          });
        const rejection = { status: response.status, body: (await response.json()) as unknown };
        expect(rejection).toEqual({
          status: 400,
          body: {
            code: "VALIDATION_ERROR",
            message: "[body.phoneNumber] Invalid input: expected string, received Infinity",
          },
        });
        expect(await verificationCount(ctx, pendingPhone)).toBe(1);

        invalid.push(rejection);
      }

      const valid = await client.phoneNumber.verify({ phoneNumber: pendingPhone, code });
      expect(valid.error).toBeNull();
      expect(valid.data?.user.phoneNumber).toBe(pendingPhone);
      expect(await verificationCount(ctx, pendingPhone)).toBe(0);

      return { created, collisions, disabled, disabledState, invalid, valid };
    },
    ["POST /sign-up/email", "GET /get-session"],
  );
}

compatScenario(
  "phone verification signs up a phone owner and preserves identity across new sessions",
  async (ctx) => {
    const profile = "phone-signup";
    const client = phoneClient(ctx, profile);
    const phoneNumber = uniquePhone(ctx, "phone-signup");
    const sent = await client.phoneNumber.sendOtp({ phoneNumber });
    expect(sent.error).toBeNull();

    const code = await readPhoneOtp(ctx, phoneNumber);
    const verified = await client.phoneNumber.verify({ phoneNumber, code });
    expect(verified.error).toBeNull();

    const user = phoneUser(verified.data?.user);
    expect(user.phoneNumber).toBe(phoneNumber);
    expect(user.phoneNumberVerified).toBe(true);
    expect(user.email).toBe(`${phoneNumber}@phone.fixture.test`);
    expect(user.emailVerified).toBe(false);
    expect(user.name).toBe(phoneNumber);

    const token = z.string().min(1).parse(verified.data?.token);
    const current = await client.getSession();
    expect(current.data?.user.id).toBe(user.id);
    expect(current.data?.session.token).toBe(token);

    const before = await readPhoneState(ctx, profile, user.id);
    expect(before.sessions).toHaveLength(1);
    expect(before.accounts).toHaveLength(0);
    expect(before.user?.phoneNumberVerified).toBe(true);

    const replay = await client.phoneNumber.verify({ phoneNumber, code });
    expect(replay.error?.code).toBe("OTP_NOT_FOUND");

    await client.phoneNumber.sendOtp({ phoneNumber });
    const second = await phoneClient(ctx, profile, "second-browser").phoneNumber.verify({
      phoneNumber,
      code: await readPhoneOtp(ctx, phoneNumber),
    });
    expect(second.error).toBeNull();
    expect(second.data?.user.id).toBe(user.id);
    expect(second.data?.token).not.toBe(token);

    const after = await readPhoneState(ctx, profile, user.id);
    expect(after.sessions).toHaveLength(2);
    expect(after.sessions.every((session) => session.userId === user.id)).toBe(true);
    expect(await verificationCount(ctx, phoneNumber)).toBe(0);

    const callbacks = await ctx.rawRequest({ path: "/__test/phone-callbacks", method: "GET" });
    expect(callbacks.status).toBe(200);
    expect(callbacks.body).toEqual([
      { phoneNumber, userId: user.id },
      { phoneNumber, userId: user.id },
    ]);

    return { sent, verified, current, before, replay, second, after, callbacks };
  },
  ["POST /phone-number/send-otp", "POST /phone-number/verify"],
);

compatScenario(
  "phone OTP rejects foreign numbers exhausted attempts expiry and disabled signup",
  async (ctx) => {
    const profile = "phone-default";
    const client = phoneClient(ctx, profile);
    const phoneNumber = uniquePhone(ctx, "phone-reject");
    await client.phoneNumber.sendOtp({ phoneNumber });
    const code = await readPhoneOtp(ctx, phoneNumber);
    const foreign = await client.phoneNumber.verify({
      phoneNumber: uniquePhone(ctx, "phone-foreign"),
      code,
    });
    expect(foreign.error?.code).toBe("OTP_NOT_FOUND");

    const attempts = [];

    for (let index = 0; index < 3; index += 1) {
      const attempt = await client.phoneNumber.verify({ phoneNumber, code: "incorrect" });
      expect(attempt.error?.code).toBe("INVALID_OTP");
      attempts.push(attempt);
    }

    const exhausted = await client.phoneNumber.verify({ phoneNumber, code });
    expect(exhausted.error?.status).toBe(403);
    expect(exhausted.error?.code).toBe("TOO_MANY_ATTEMPTS");
    expect(await verificationCount(ctx, phoneNumber)).toBe(0);

    await client.phoneNumber.sendOtp({ phoneNumber });
    const expiredCode = await readPhoneOtp(ctx, phoneNumber);
    await expireVerification(ctx, phoneNumber);
    const expired = await client.phoneNumber.verify({ phoneNumber, code: expiredCode });
    expect(expired.error?.code).toBe("OTP_EXPIRED");

    await client.phoneNumber.sendOtp({ phoneNumber });
    const cannotCreate = await client.phoneNumber.verify({
      phoneNumber,
      code: await readPhoneOtp(ctx, phoneNumber),
    });
    expect(cannotCreate.error?.status).toBe(500);
    expect(cannotCreate.error?.code).toBe("FAILED_TO_UPDATE_USER");
    expect(await verificationCount(ctx, phoneNumber)).toBe(0);
    expect((await client.getSession()).data).toBeNull();

    return { foreign, attempts, exhausted, expired, cannotCreate };
  },
);

compatScenario(
  "server-only phone proof consumption creates no account or browser session",
  async (ctx) => {
    const profile = "phone-signup";
    const client = phoneClient(ctx, profile);
    const phoneNumber = uniquePhone(ctx, "phone-consume");
    await client.phoneNumber.sendOtp({ phoneNumber });
    const code = await readPhoneOtp(ctx, phoneNumber);
    const wrong = await ctx.rawRequest({
      path: "/__test/phone-consume-otp",
      method: "POST",
      json: { profile, phoneNumber, code: "incorrect" },
    });
    expect(wrong.status).toBe(400);

    const consumed = await ctx.rawRequest({
      path: "/__test/phone-consume-otp",
      method: "POST",
      json: { profile, phoneNumber, code },
    });
    expect(consumed.body).toEqual({ status: true });
    expect(await verificationCount(ctx, phoneNumber)).toBe(0);

    const replay = await ctx.rawRequest({
      path: "/__test/phone-consume-otp",
      method: "POST",
      json: { profile, phoneNumber, code },
    });
    expect(replay.status).toBe(400);

    const publicAttempt = await phoneRequest(ctx, profile, "/phone-number/consume-otp", {
      phoneNumber,
      code,
    });
    expect(publicAttempt.status).toBe(404);

    const session = await client.getSession();
    expect(session.data).toBeNull();

    return { wrong, consumed, replay, publicAttempt, session };
  },
  [],
  30_000,
  {
    oracle: {
      unroutedRequests: "asserts the server-only consume-otp endpoint is not exposed over HTTP",
    },
  },
);

compatScenario(
  "phone updates bind the requester preserve its session and reject occupied numbers",
  async (ctx) => {
    const profile = "phone-signup";
    const client = phoneClient(ctx, profile);
    const signup = await client.signUp.email({
      email: ctx.uniqueEmail("phone-update-owner"),
      password: "password123",
      name: "Phone Owner",
    });
    const user = phoneUser(signup.data?.user);
    const before = await client.getSession();
    const occupied = uniquePhone(ctx, "phone-occupied");
    const other = phoneClient(ctx, profile, "other-owner");
    await other.phoneNumber.sendOtp({ phoneNumber: occupied });
    const occupiedUser = phoneUser(
      (
        await other.phoneNumber.verify({
          phoneNumber: occupied,
          code: await readPhoneOtp(ctx, occupied),
        })
      ).data?.user,
    );
    await client.phoneNumber.sendOtp({ phoneNumber: occupied });
    const collision = await client.phoneNumber.verify({
      phoneNumber: occupied,
      code: await readPhoneOtp(ctx, occupied),
      updatePhoneNumber: true,
    });
    expect(collision.error?.code).toBe("PHONE_NUMBER_EXIST");

    const target = uniquePhone(ctx, "phone-owner-target");
    await client.phoneNumber.sendOtp({ phoneNumber: target });
    const updated = await client.phoneNumber.verify({
      phoneNumber: target,
      code: await readPhoneOtp(ctx, target),
      updatePhoneNumber: true,
    });
    expect(updated.error).toBeNull();
    expect(updated.data?.user.id).toBe(user.id);
    expect(updated.data?.token).toBe(before.data?.session.token);

    const after = await client.getSession();
    expect(after.data?.session.id).toBe(before.data?.session.id);
    expect(after.data?.user.phoneNumber).toBe(target);

    const state = await readPhoneState(ctx, profile, user.id);
    expect(state.user?.phoneNumber).toBe(target);
    expect(state.user?.phoneNumberVerified).toBe(true);
    expect(state.sessions).toHaveLength(1);

    const otherState = await readPhoneState(ctx, profile, occupiedUser.id);
    expect(otherState.user?.phoneNumber).toBe(occupied);

    const visitorTarget = uniquePhone(ctx, "phone-visitor-target");
    const visitor = phoneClient(ctx, profile, "visitor");
    await visitor.phoneNumber.sendOtp({ phoneNumber: visitorTarget });
    const unauthenticated = await visitor.phoneNumber.verify({
      phoneNumber: visitorTarget,
      code: await readPhoneOtp(ctx, visitorTarget),
      updatePhoneNumber: true,
    });
    expect(unauthenticated.error?.status).toBe(401);
    expect(unauthenticated.error?.code).toBe("USER_NOT_FOUND");
    expect(await verificationCount(ctx, visitorTarget)).toBe(0);

    const forbidden = await phoneRequest(ctx, profile, "/update-user", { phoneNumber: occupied });
    expect(forbidden.status).toBe(400);
    expect(forbidden.body).toEqual({
      code: "PHONE_NUMBER_CANNOT_BE_UPDATED",
      message: "Phone number cannot be updated",
    });

    const cleared = await phoneRequest(ctx, profile, "/update-user", { phoneNumber: null });
    expect(cleared.status).toBe(200);

    const clearedState = await readPhoneState(ctx, profile, user.id);
    expect(clearedState.user?.phoneNumber).toBeNull();
    expect(clearedState.user?.phoneNumberVerified).toBe(false);

    return {
      before,
      collision,
      updated,
      after,
      state,
      otherState,
      unauthenticated,
      forbidden,
      cleared,
      clearedState,
    };
  },
  ["POST /phone-number/verify"],
);

compatScenario(
  "phone password sign-in requires ownership proof before credentials and honors rememberMe",
  async (ctx) => {
    const profile = "phone-proof";
    const client = phoneClient(ctx, profile);
    const phoneNumber = uniquePhone(ctx, "phone-password");
    const signup = await client.signUp.email({
      email: ctx.uniqueEmail("phone-password-owner"),
      password: "original-password123",
      name: "Phone Password",
      phoneNumber,
    });
    const user = phoneUser(signup.data?.user);
    const missingProof = await client.signIn.phoneNumber({
      phoneNumber,
      password: "wrong-password123",
    });
    expect(missingProof.error?.code).toBe("PHONE_NUMBER_NOT_VERIFIED");

    const verified = await client.phoneNumber.verify({
      phoneNumber,
      code: await readPhoneOtp(ctx, phoneNumber),
      disableSession: true,
    });
    expect(verified.error).toBeNull();
    expect(verified.data?.token).toBeNull();

    const before = await readPhoneState(ctx, profile, user.id);
    expect(before.sessions).toHaveLength(1);

    const wrong = await client.signIn.phoneNumber({ phoneNumber, password: "wrong-password123" });
    expect(wrong.error?.code).toBe("INVALID_PHONE_NUMBER_OR_PASSWORD");

    const signedIn = await client.signIn.phoneNumber({
      phoneNumber,
      password: "original-password123",
      rememberMe: false,
    });
    expect(signedIn.error).toBeNull();

    const session = await client.getSession();
    expect(session.data?.user.id).toBe(user.id);

    const remaining = Date.parse(String(session.data?.session.expiresAt)) - Date.now();
    expect(remaining).toBeGreaterThan(86_398_000);
    expect(remaining).toBeLessThanOrEqual(86_400_000);

    const state = await readPhoneState(ctx, profile, user.id);
    expect(state.sessions).toHaveLength(2);

    const long = await client.signIn.phoneNumber({ phoneNumber, password: "x".repeat(129) });
    expect(long.error?.code).toBe("PASSWORD_TOO_LONG");

    const remembered = await client.signIn.phoneNumber({
      phoneNumber,
      password: "original-password123",
      rememberMe: true,
    });
    expect(remembered.error).toBeNull();

    const rememberedSession = await client.getSession();
    expect(
      Date.parse(String(rememberedSession.data?.session.expiresAt)) - Date.now(),
    ).toBeGreaterThan(604_798_000);

    return {
      signup,
      missingProof,
      verified,
      before,
      wrong,
      signedIn,
      session,
      state,
      long,
      remembered,
      rememberedSession,
    };
  },
  ["POST /sign-in/phone-number"],
);

compatScenario(
  "phone password sign-in enforces two-factor ownership and trusted-device rotation",
  async (ctx) => {
    const profile = "phone-proof";
    const client = phoneClient(ctx, profile);
    const email = ctx.uniqueEmail("phone-two-factor");
    const phoneNumber = uniquePhone(ctx, "phone-two-factor");
    const password = "phone-second-factor123";
    const signup = await client.signUp.email({
      email,
      password,
      name: "Phone Two Factor",
      phoneNumber,
    });
    const user = phoneUser(signup.data?.user);
    await client.phoneNumber.sendOtp({ phoneNumber });
    const phoneProof = await client.phoneNumber.verify({
      phoneNumber,
      code: await readPhoneOtp(ctx, phoneNumber),
      disableSession: true,
    });
    expect(phoneProof.error).toBeNull();

    const enabled = await client.twoFactor.enable({ password });
    expect(enabled.error).toBeNull();

    const uri = z.object({ totpURI: z.string().min(1) }).parse(enabled.data).totpURI;
    const enrollment = await client.twoFactor.verifyTotp({ code: phoneEnrollmentCode(uri) });
    expect(enrollment.error).toBeNull();

    await client.signOut();
    const before = await readPhoneState(ctx, profile, user.id);
    expect(before.sessions).toHaveLength(0);

    const pending = await client.signIn.phoneNumber({ phoneNumber, password, rememberMe: false });
    expect(pending.error).toBeNull();
    expect(
      z
        .object({ twoFactorRedirect: z.literal(true), twoFactorMethods: z.array(z.string()) })
        .parse(pending.data).twoFactorMethods,
    ).toEqual(["totp", "otp"]);

    const unauthenticated = await client.getSession();
    expect(unauthenticated.data).toBeNull();

    const pendingState = await readPhoneState(ctx, profile, user.id);
    expect(pendingState.sessions).toHaveLength(0);

    const sent = await client.twoFactor.sendOtp({});
    expect(sent.error).toBeNull();

    const code = z
      .object({ otp: z.string().min(1) })
      .parse(await ctx.readTwoFactorOtp({ email })).otp;
    const foreign = await phoneClient(ctx, profile, "wrong-browser").twoFactor.verifyOtp({ code });
    expect(foreign.error).not.toBeNull();

    const wrong = await client.twoFactor.verifyOtp({
      code: code === "111111" ? "222222" : "111111",
    });
    expect(wrong.error?.code).toBe("INVALID_CODE");
    expect((await readPhoneState(ctx, profile, user.id)).sessions).toHaveLength(0);

    const verified = await client.twoFactor.verifyOtp({ code, trustDevice: true });
    expect(verified.error).toBeNull();

    const session = await client.getSession();
    expect(session.data?.user.id).toBe(user.id);
    expect(session.data?.session.token).toBe(verified.data?.token);
    // Trusting this device clears the nonremembered marker. Upstream refreshes
    // the short session to the default lifetime on the following session read.
    expect(Date.parse(String(session.data?.session.expiresAt)) - Date.now()).toBeGreaterThan(
      604_798_000,
    );
    expect(Date.parse(String(session.data?.session.expiresAt)) - Date.now()).toBeLessThanOrEqual(
      604_800_000,
    );

    const replay = await client.twoFactor.verifyOtp({ code });
    expect(replay.error).not.toBeNull();

    await client.signOut();
    const trusted = await client.signIn.phoneNumber({ phoneNumber, password });
    expect(trusted.error).toBeNull();
    expect(trusted.data?.user.id).toBe(user.id);

    const trustedSession = await client.getSession();
    expect(trustedSession.data?.session.token).toBe(trusted.data?.token);

    const state = await readPhoneState(ctx, profile, user.id);
    expect(state.sessions).toHaveLength(1);
    expect(state.sessions.at(0)?.token).toBe(trusted.data?.token);

    return {
      before,
      pending,
      unauthenticated,
      pendingState,
      sent,
      foreign,
      wrong,
      verified,
      session,
      replay,
      trusted,
      trustedSession,
      state,
    };
  },
);

compatScenario(
  "phone password reset consumes rejected proofs creates credentials and revokes configured sessions",
  async (ctx) => {
    const profile = "phone-proof";
    const client = phoneClient(ctx, profile);
    const phoneNumber = uniquePhone(ctx, "phone-reset");
    await client.phoneNumber.sendOtp({ phoneNumber });
    const verified = await client.phoneNumber.verify({
      phoneNumber,
      code: await readPhoneOtp(ctx, phoneNumber),
    });
    const user = phoneUser(verified.data?.user);
    const issued = await client.phoneNumber.requestPasswordReset({ phoneNumber });
    expect(issued.error).toBeNull();

    const otp = await readPhoneOtp(ctx, phoneNumber, "password-reset");
    const foreign = await client.phoneNumber.resetPassword({
      phoneNumber: uniquePhone(ctx, "phone-reset-foreign"),
      otp,
      newPassword: "new-password123",
    });
    expect(foreign.error?.code).toBe("OTP_NOT_FOUND");

    const tooShort = await client.phoneNumber.resetPassword({
      phoneNumber,
      otp,
      newPassword: "short",
    });
    expect(tooShort.error?.code).toBe("PASSWORD_TOO_SHORT");

    const burned = await client.phoneNumber.resetPassword({
      phoneNumber,
      otp,
      newPassword: "new-password123",
    });
    expect(burned.error?.code).toBe("OTP_NOT_FOUND");

    await client.phoneNumber.requestPasswordReset({ phoneNumber });
    const fresh = await readPhoneOtp(ctx, phoneNumber, "password-reset");
    const reset = await client.phoneNumber.resetPassword({
      phoneNumber,
      otp: fresh,
      newPassword: "new-password123",
    });
    expect(reset.error).toBeNull();

    const state = await readPhoneState(ctx, profile, user.id);
    expect(state.accounts).toHaveLength(1);
    expect(state.accounts.at(0)?.providerId).toBe("credential");
    expect(state.accounts.at(0)?.userId).toBe(user.id);
    expect(state.sessions).toHaveLength(0);
    expect(state.user?.emailVerified).toBe(false);

    const revoked = await client.getSession();
    expect(revoked.data).toBeNull();

    const signedIn = await client.signIn.phoneNumber({ phoneNumber, password: "new-password123" });
    expect(signedIn.error).toBeNull();
    expect(signedIn.data?.user.id).toBe(user.id);

    const replay = await client.phoneNumber.resetPassword({
      phoneNumber,
      otp: fresh,
      newPassword: "replay-password123",
    });
    expect(replay.error?.code).toBe("OTP_NOT_FOUND");

    const absent = uniquePhone(ctx, "phone-reset-absent");
    const absentRequest = await client.phoneNumber.requestPasswordReset({ phoneNumber: absent });
    expect(absentRequest.error).toBeNull();
    expect(await verificationCount(ctx, `${absent}-request-password-reset`)).toBe(1);
    const absentProof = z
      .array(z.object({ identifier: z.string(), value: z.string() }))
      .parse(await ctx.readVerificationState({ identifier: `${absent}-request-password-reset` }));
    expect(absentProof).toHaveLength(1);
    const absentOtp = absentProof[0]!.value.split(":")[0]!;
    expect(absentOtp).toMatch(/^\d{6}$/);
    const ownerBefore = await readPhoneState(ctx, profile, user.id);
    const readSql = async () =>
      (await (await fetch(`${ctx.baseURL}/__test/provider-batch/sql-state`)).json()) as Record<
        string,
        any[]
      >;
    const physicalBefore = await readSql();
    const absentReset = await client.phoneNumber.resetPassword({
      phoneNumber: absent,
      otp: absentOtp,
      newPassword: "must-not-create123",
    });
    expect(absentReset.error?.code).toBe("UNEXPECTED_ERROR");
    expect(await verificationCount(ctx, `${absent}-request-password-reset`)).toBe(0);
    const absentReplay = await client.phoneNumber.resetPassword({
      phoneNumber: absent,
      otp: absentOtp,
      newPassword: "must-not-create123",
    });
    expect(absentReplay.error?.code).toBe("OTP_NOT_FOUND");
    const physicalAfter = await readSql();
    const source = "user" in physicalBefore;
    for (const table of source
      ? ["user", "account", "session"]
      : ["users", "accounts", "sessions"]) {
      expect(physicalAfter[table]).toEqual(physicalBefore[table]);
    }
    expect(await readPhoneState(ctx, profile, user.id)).toEqual(ownerBefore);
    expect((await client.getSession()).data?.user.id).toBe(user.id);

    return {
      absentReset,
      absentReplay,
      verified,
      issued,
      foreign,
      tooShort,
      burned,
      reset,
      state,
      revoked,
      signedIn,
      replay,
      absentRequest,
    };
  },
  ["POST /phone-number/request-password-reset", "POST /phone-number/reset-password"],
);

compatScenario(
  "external phone OTP verification enforces provider binding and replaces local expiry policy",
  async (ctx) => {
    const profile = "phone-custom";
    const client = phoneClient(ctx, profile);
    const invalid = await client.phoneNumber.sendOtp({ phoneNumber: "not-a-phone" });
    expect(invalid.error?.code).toBe("INVALID_PHONE_NUMBER");
    expect(await verificationCount(ctx, "not-a-phone")).toBe(0);

    const phoneNumber = uniquePhone(ctx, "phone-provider");
    await client.phoneNumber.sendOtp({ phoneNumber });
    const code = await readPhoneOtp(ctx, phoneNumber);
    const foreign = await client.phoneNumber.verify({
      phoneNumber: uniquePhone(ctx, "phone-provider-foreign"),
      code,
    });
    expect(foreign.error?.code).toBe("INVALID_OTP");

    const wrong = await client.phoneNumber.verify({ phoneNumber, code: "incorrect" });
    expect(wrong.error?.code).toBe("INVALID_OTP");
    expect(await verificationCount(ctx, phoneNumber)).toBe(1);

    await expireVerification(ctx, phoneNumber);
    const verified = await client.phoneNumber.verify({ phoneNumber, code });
    expect(verified.error).toBeNull();
    expect(verified.data?.user.phoneNumber).toBe(phoneNumber);
    expect(await verificationCount(ctx, phoneNumber)).toBe(0);

    const replay = await client.phoneNumber.verify({ phoneNumber, code });
    expect(replay.error?.code).toBe("INVALID_OTP");

    const user = phoneUser(verified.data?.user);
    const state = await readPhoneState(ctx, profile, user.id);
    expect(state.sessions).toHaveLength(1);

    return { invalid, foreign, wrong, verified, replay, state };
  },
  ["POST /phone-number/verify"],
);

compatScenario(
  "phone endpoint schemas reject every malformed field before any state transition",
  async (ctx) => {
    const profile = "phone-signup";
    const client = phoneClient(ctx, profile);
    const phoneNumber = uniquePhone(ctx, "phone-schema-pending");
    const signup = await client.signUp.email({
      email: ctx.uniqueEmail("phone-schema-owner"),
      password: "original-password123",
      name: "Phone Schema",
      phoneNumber,
    });
    const user = phoneUser(signup.data?.user);
    await client.phoneNumber.sendOtp({ phoneNumber });
    const code = await readPhoneOtp(ctx, phoneNumber);
    await client.phoneNumber.requestPasswordReset({ phoneNumber });
    const resetOtp = await readPhoneOtp(ctx, phoneNumber, "password-reset");
    const before = await readPhoneState(ctx, profile, user.id);
    const rejected = [];

    for (const [path, body] of [
      ["/phone-number/send-otp", {}],
      ["/phone-number/request-password-reset", {}],
      ["/sign-in/phone-number", { phoneNumber: 1, password: null, rememberMe: "yes" }],
      [
        "/phone-number/verify",
        { phoneNumber: false, code: 123, disableSession: null, updatePhoneNumber: "yes" },
      ],
      ["/phone-number/reset-password", { otp: false, phoneNumber: null, newPassword: 3 }],
    ] satisfies ReadonlyArray<readonly [string, unknown]>) {
      const response = await phoneRequest(ctx, profile, path, body);
      expect(response.status).toBe(400);

      const parsed = z
        .object({ code: z.literal("VALIDATION_ERROR"), message: z.string() })
        .safeParse(response.body);

      if (!parsed.success) {
        throw new Error("Malformed phone requests must return upstream schema errors");
      }

      expect(await readPhoneState(ctx, profile, user.id)).toEqual(before);
      expect(await verificationCount(ctx, phoneNumber)).toBe(1);
      expect(await verificationCount(ctx, `${phoneNumber}-request-password-reset`)).toBe(1);

      rejected.push(response);
    }

    const verified = await client.phoneNumber.verify({ phoneNumber, code, disableSession: true });
    expect(verified.error).toBeNull();

    const reset = await client.phoneNumber.resetPassword({
      phoneNumber,
      otp: resetOtp,
      newPassword: "new-password123",
    });
    expect(reset.error).toBeNull();

    const state = await readPhoneState(ctx, profile, user.id);
    expect(state.user?.phoneNumberVerified).toBe(true);
    expect(state.accounts).toHaveLength(1);
    expect(state.sessions).toHaveLength(1);

    const signedIn = await client.signIn.phoneNumber({ phoneNumber, password: "new-password123" });
    expect(signedIn.error).toBeNull();
    expect(signedIn.data?.user.id).toBe(user.id);
    expect(await verificationCount(ctx, phoneNumber)).toBe(0);
    expect(await verificationCount(ctx, `${phoneNumber}-request-password-reset`)).toBe(0);

    return { before, rejected, verified, reset, state, signedIn };
  },
);

passwordlessNumericScenarios("phone");

compatScenario(
  "external phone verifier leaves password reset bound to actual local OTP",
  async (ctx) => {
    const profile = "phone-custom";
    const owner = phoneClient(ctx, profile, "owner");
    const phoneNumber = uniquePhone(ctx, "external-reset-owner");
    const email = ctx.uniqueEmail("external-reset-owner");
    const signup = await owner.signUp.email({
      email,
      password: "originalPassword123",
      name: "External reset owner",
      phoneNumber,
    });
    expect(signup.error).toBeNull();
    expect((await owner.phoneNumber.sendOtp({ phoneNumber })).error).toBeNull();
    const providerCode = await readPhoneOtp(ctx, phoneNumber);
    const verified = await owner.phoneNumber.verify(
      { phoneNumber, code: providerCode, disableSession: true },
      { headers: { "x-callback-probe": "issue207" } },
    );
    expect(verified.error).toBeNull();
    const verifierReceipt = await ctx.rawRequest({
      path: `/__test/phone-otp?type=verifier&phoneNumber=${encodeURIComponent(phoneNumber)}`,
    });
    expect(verifierReceipt.body).toMatchObject({ context: { marker: "issue207" } });
    const before = await readPhoneState(ctx, profile, signup.data!.user.id);
    const issued = await owner.phoneNumber.requestPasswordReset({ phoneNumber });
    expect(issued.error).toBeNull();
    const local = await readPhoneOtp(ctx, phoneNumber, "password-reset");
    const identifier = `${phoneNumber}-request-password-reset`;
    const proof = z
      .array(z.object({ id: z.string(), value: z.string(), expiresAt: z.string() }))
      .parse(await ctx.readVerificationState({ identifier }));
    expect(proof).toHaveLength(1);
    expect(proof[0]!.value).toBe(`${local}:0`);
    // Re-arm a genuine provider-approved verification challenge, while retaining the
    // independently issued local password-reset proof.
    expect((await owner.phoneNumber.sendOtp({ phoneNumber })).error).toBeNull();
    const approved = await readPhoneOtp(ctx, phoneNumber);
    expect(approved).not.toBe(local);
    const wrong = await owner.phoneNumber.resetPassword(
      { phoneNumber, otp: approved, newPassword: "replacementPassword123" },
      { headers: { "x-callback-probe": "issue207" } },
    );
    expect(wrong.error).toMatchObject({ code: "INVALID_OTP", status: 400 });
    const restored = z
      .array(z.object({ value: z.string(), expiresAt: z.string() }))
      .parse(await ctx.readVerificationState({ identifier }));
    expect(restored).toHaveLength(1);
    expect(restored[0]).toEqual({ value: `${local}:1`, expiresAt: proof[0]!.expiresAt });
    expect(await readPhoneState(ctx, profile, signup.data!.user.id)).toEqual(before);
    expect(
      (
        await ctx.rawRequest({
          path: `/__test/phone-otp?type=verifier&phoneNumber=${encodeURIComponent(phoneNumber)}`,
        })
      ).body,
    ).toEqual(verifierReceipt.body);
    const reset = await owner.phoneNumber.resetPassword(
      { phoneNumber, otp: local, newPassword: "replacementPassword123" },
      { headers: { "x-callback-probe": "issue207" } },
    );
    expect(reset.error).toBeNull();
    expect(await ctx.readVerificationState({ identifier })).toEqual([]);
    expect(
      (
        await ctx.rawRequest({
          path: `/__test/phone-otp?type=verifier&phoneNumber=${encodeURIComponent(phoneNumber)}`,
        })
      ).body,
    ).toEqual(verifierReceipt.body);
    const replay = await owner.phoneNumber.resetPassword({
      phoneNumber,
      otp: local,
      newPassword: "mustNotCommit123",
    });
    expect(replay.error?.code).toBe("OTP_NOT_FOUND");
    const fresh = phoneClient(ctx, profile, "fresh");
    const login = await fresh.signIn.email({ email, password: "replacementPassword123" });
    expect(login.data?.user.id).toBe(signup.data!.user.id);
    expect((await owner.getSession()).data?.user.id).toBe(signup.data!.user.id);
    return ctx.snapshot({ verified, issued, wrong, reset, replay, login });
  },
  ["POST /phone-number/reset-password", "POST /phone-number/verify"],
);
