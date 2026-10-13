import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { organizationClient, twoFactorClient } from "better-auth/client/plugins";
import { Cookie } from "tough-cookie";
import { z } from "zod";

import { compatScenario } from "../../../support/scenario";
import { generateCurrentTotp, redactTwoFactorPayload } from "../../../support/totp";
import { organizationActor } from "../organization/helpers";
import { disableGuestValidation } from "./disable-validation";

function twoFactorActor(
  ctx: Parameters<Parameters<typeof compatScenario>[1]>[0],
  name = "primary",
) {
  const actor = ctx.actor(name);
  return createAuthClient({
    baseURL: ctx.baseURL,
    plugins: [organizationClient(), twoFactorClient()],
    fetchOptions: {
      customFetchImpl: actor.fetch,
    },
  });
}

compatScenario(
  "two-factor enrollment returns URIs and keeps the user disabled until verification",
  async (ctx) => {
    const client = twoFactorActor(ctx);
    const email = ctx.uniqueEmail("two-factor-enable");
    const password = "password123";

    let ownerCookie = "";
    const signup = await client.signUp.email({
      email,
      password,
      name: "Two Factor Enrollment",
      fetchOptions: {
        onSuccess({ response }) {
          ownerCookie = response.headers
            .getSetCookie()
            .map((cookie) => cookie.split(";")[0])
            .join("; ");
        },
      },
    });

    async function serverURI(body: unknown, cookie?: string) {
      const response = await ctx
        .actor("primary")
        .fetch(`${ctx.baseURL}/__test/server-api/two-factor-uri`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ body, ...(cookie ? { headers: { cookie } } : {}) }),
        });
      expect(response.headers.get("set-cookie")).toBeNull();
      return { status: response.status, body: (await response.json()) as any };
    }
    const missing = await serverURI({ password }, ownerCookie);
    expect(missing.status).toBe(400);
    expect(missing.body.code).toBe("TOTP_NOT_ENABLED");
    const enable = await client.twoFactor.enable({ password });
    const before = await ctx.readUserState({ userId: signup.data!.user.id });
    for (const [body, cookie, status, code] of [
      [{}, ownerCookie, 400, "VALIDATION_ERROR"],
      [{ password: 42 }, ownerCookie, 400, "VALIDATION_ERROR"],
      [{ password: null }, ownerCookie, 400, "VALIDATION_ERROR"],
      [{ password }, undefined, 401, "UNAUTHORIZED"],
      [{ password: "wrong-password" }, ownerCookie, 400, "INVALID_PASSWORD"],
    ] as const) {
      const rejected = await serverURI(body, cookie);
      expect(rejected.status).toBe(status);
      expect(rejected.body.code).toBe(code);
      expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(before);
    }
    const result = await serverURI({ password, userId: "untrusted-selector" }, ownerCookie);
    expect(result.status).toBe(200);
    const totp = { data: result.body, error: null };
    expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(before);
    expect(new URL(totp.data.totpURI).searchParams.get("secret")).toBe(
      new URL(enrollmentUri(enable.data)).searchParams.get("secret"),
    );
    expect((await ctx.readUserState({ userId: signup.data!.user.id })) as any).toHaveProperty(
      "twoFactorExists",
      true,
    );
    const session = await client.getSession();

    return {
      enable: ctx.snapshot(redactTwoFactorPayload(enable)),
      totp: ctx.snapshot(redactTwoFactorPayload(totp)),
      session: ctx.snapshot(session),
    };
  },
);

compatScenario(
  "two-factor totp verification enables the user and later sign-in redirects to second factor",
  async (ctx) => {
    const client = twoFactorActor(ctx);
    const email = ctx.uniqueEmail("two-factor-totp");
    const password = "password123";

    let ownerCookie = "";
    const signup = await client.signUp.email({
      email,
      password,
      name: "Two Factor TOTP",
      fetchOptions: {
        onSuccess({ response }) {
          ownerCookie = response.headers
            .getSetCookie()
            .map((cookie) => cookie.split(";")[0])
            .join("; ");
        },
      },
    });

    async function serverEnable(body: unknown, cookie?: string) {
      return ctx.actor("primary").fetch(`${ctx.baseURL}/__test/server-api/two-factor-enable`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ body, ...(cookie ? { headers: { cookie } } : {}) }),
      });
    }
    const before = await ctx.readUserState({ userId: signup.data!.user.id });
    for (const [body, cookie, status, code] of [
      [{}, ownerCookie, 400, "VALIDATION_ERROR"],
      [{ password: 42 }, ownerCookie, 400, "VALIDATION_ERROR"],
      [{ password, method: "invalid" }, ownerCookie, 400, "VALIDATION_ERROR"],
      [{ password, issuer: null }, ownerCookie, 400, "VALIDATION_ERROR"],
      [{ password }, undefined, 401, "UNAUTHORIZED"],
      [{ password: "wrong-password" }, ownerCookie, 400, "INVALID_PASSWORD"],
    ] as const) {
      const response = await serverEnable(body, cookie);
      expect(response.status).toBe(status);
      expect(((await response.json()) as any).code).toBe(code);
      expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(before);
    }
    const enableResponse = await serverEnable(
      { password, issuer: "Server enrollment", userId: "untrusted-selector" },
      ownerCookie,
    );
    expect(enableResponse.status).toBe(200);
    expect(enableResponse.headers.get("set-cookie")).toBeNull();
    const enable = { data: (await enableResponse.json()) as any, error: null };
    expect(new URL(enable.data.totpURI).searchParams.get("issuer")).toBe("Server enrollment");
    expect(enable.data.method).toBe("totp");
    expect(new Set(enable.data.backupCodes).size).toBe(10);
    expect((await client.getSession()).data?.user.twoFactorEnabled).toBe(false);
    expect((await ctx.readUserState({ userId: signup.data!.user.id })) as any).toHaveProperty(
      "twoFactorExists",
      true,
    );

    if (!enable.data || !("totpURI" in enable.data)) {
      throw new Error("TOTP enrollment must return a URI");
    }

    const code = await generateCurrentTotp(enable.data.totpURI);
    async function serverVerify(body: unknown, cookie: string) {
      const observed = await ctx
        .actor("primary")
        .fetch(`${ctx.baseURL}/__test/server-api/two-factor-verify-totp`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ body, headers: { cookie } }),
        });
      return observed;
    }
    const verifyResponse = await serverVerify({ code }, ownerCookie);
    expect(verifyResponse.status).toBe(200);
    const verifyTotp = { data: (await verifyResponse.json()) as any, error: null };
    const session = await client.getSession();

    await client.signOut();
    let pendingCookie = "";
    const signIn = await client.signIn.email({
      email,
      password,
      rememberMe: false,
      fetchOptions: {
        onSuccess({ response }) {
          pendingCookie = response.headers
            .getSetCookie()
            .filter((raw) => Boolean(Cookie.parse(raw)?.value))
            .map((cookie) => cookie.split(";")[0])
            .join("; ");
        },
      },
    });
    const beforePending = await ctx.readUserState({ userId: signup.data!.user.id });
    for (const body of [{}, { code: 42 }, { code: "012345", trustDevice: null }]) {
      const rejected = await serverVerify(body, pendingCookie);
      expect(rejected.status).toBe(400);
      expect(((await rejected.json()) as any).code).toBe("VALIDATION_ERROR");
      expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(beforePending);
    }
    const pendingCode = await generateCurrentTotp(enable.data.totpURI);
    const invalid = await serverVerify({ code: "" }, pendingCookie);
    expect(invalid.status).toBe(401);
    expect(((await invalid.json()) as any).code).toBe("INVALID_CODE");
    const completedResponse = await serverVerify(
      { code: pendingCode, trustDevice: true, userId: "untrusted-selector" },
      pendingCookie,
    );
    expect(completedResponse.status).toBe(200);
    expect(((await completedResponse.json()) as any).user.id).toBe(signup.data!.user.id);
    expect((await client.getSession()).data?.user.id).toBe(signup.data!.user.id);
    const afterPending = await ctx.readUserState({ userId: signup.data!.user.id });
    const replay = await serverVerify({ code: pendingCode }, pendingCookie);
    expect(replay.status).toBe(401);
    expect(((await replay.json()) as any).code).toBe("INVALID_TWO_FACTOR_COOKIE");
    expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(afterPending);

    return {
      verifyTotp: ctx.snapshot(verifyTotp),
      session: ctx.snapshot(session),
      signIn: ctx.snapshot(signIn),
    };
  },
);

compatScenario(
  "two-factor otp flow completes sign-in and rejects requests without the pending cookie",
  async (ctx) => {
    const client = twoFactorActor(ctx);
    const email = ctx.uniqueEmail("two-factor-otp");
    const password = "password123";

    let ownerCookie = "";
    const signup = await client.signUp.email({
      email,
      password,
      name: "Two Factor OTP",
      fetchOptions: {
        onSuccess({ response }) {
          ownerCookie = response.headers
            .getSetCookie()
            .map((cookie) => cookie.split(";")[0])
            .join("; ");
        },
      },
    });

    const enabled = await ctx
      .actor("primary")
      .fetch(`${ctx.baseURL}/__test/server-api/two-factor-enable`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          body: { password, method: "otp" },
          headers: { cookie: ownerCookie },
        }),
      });
    expect(enabled.status).toBe(200);
    expect(await enabled.json()).toEqual({ method: "otp" });
    const active = await client.getSession();
    expect(active.data?.user.twoFactorEnabled).toBe(true);
    const state = (await ctx.readUserState({ userId: signup.data!.user.id })) as any;
    expect(state.twoFactorExists).toBe(false);
    expect(state.sessions).toHaveLength(1);
    expect(state.sessions[0].token).not.toBe(signup.data!.token);
    await client.signOut();

    let pendingCookie = "";
    const signIn = await client.signIn.email({
      email,
      password,
      rememberMe: false,
      fetchOptions: {
        onSuccess({ response }) {
          pendingCookie = response.headers
            .getSetCookie()
            .filter((raw) => Boolean(Cookie.parse(raw)?.value))
            .map((cookie) => cookie.split(";")[0])
            .join("; ");
        },
      },
    });
    async function serverSend(body: unknown, cookie?: string) {
      return ctx.actor("primary").fetch(`${ctx.baseURL}/__test/server-api/two-factor-send-otp`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ body, ...(cookie ? { headers: { cookie } } : {}) }),
      });
    }
    const beforeSend = await ctx.readUserState({ userId: signup.data!.user.id });
    const beforeDelivery = await ctx.readTwoFactorOtp({ email });
    for (const [body, cookie, status, code] of [
      [{ trustDevice: 42 }, pendingCookie, 400, "VALIDATION_ERROR"],
      [{ trustDevice: null }, pendingCookie, 400, "VALIDATION_ERROR"],
      [{}, undefined, 401, "INVALID_TWO_FACTOR_COOKIE"],
    ] as const) {
      const rejected = await serverSend(body, cookie);
      expect(rejected.status).toBe(status);
      expect(((await rejected.json()) as any).code).toBe(code);
      expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(beforeSend);
      expect(await ctx.readTwoFactorOtp({ email })).toEqual(beforeDelivery);
    }
    const sent = await serverSend(
      { userId: "untrusted-selector", trustDevice: true },
      pendingCookie,
    );
    expect(sent.status).toBe(200);
    expect(sent.headers.get("set-cookie")).toBeNull();
    const sendOtp = { data: (await sent.json()) as any, error: null };
    expect(sendOtp.data).toEqual({ status: true });
    const otpRecord = (await ctx.readTwoFactorOtp({ email })) as { otp: string };
    const verificationStartedAt = Date.now();
    async function serverVerifyOtp(body: unknown, cookie?: string) {
      return ctx.actor("primary").fetch(`${ctx.baseURL}/__test/server-api/two-factor-verify-otp`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ body, ...(cookie ? { headers: { cookie } } : {}) }),
      });
    }
    const beforeVerify = await ctx.readUserState({ userId: signup.data!.user.id });
    for (const [body, cookie, status, code] of [
      [{}, pendingCookie, 400, "VALIDATION_ERROR"],
      [{ code: 42 }, pendingCookie, 400, "VALIDATION_ERROR"],
      [{ code: otpRecord.otp, trustDevice: null }, pendingCookie, 400, "VALIDATION_ERROR"],
      [{ code: otpRecord.otp }, undefined, 401, "INVALID_TWO_FACTOR_COOKIE"],
    ] as const) {
      const rejected = await serverVerifyOtp(body, cookie);
      expect(rejected.status).toBe(status);
      expect(((await rejected.json()) as any).code).toBe(code);
      expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(beforeVerify);
    }
    const wrong = await serverVerifyOtp({ code: "" }, pendingCookie);
    expect(wrong.status).toBe(401);
    expect(((await wrong.json()) as any).code).toBe("INVALID_CODE");
    const verified = await serverVerifyOtp(
      { code: otpRecord.otp, userId: "untrusted-selector" },
      pendingCookie,
    );
    expect(verified.status).toBe(200);
    const verifyOtp = { data: (await verified.json()) as any, error: null };
    const verificationFinishedAt = Date.now();

    if (!verifyOtp.data?.user.id) {
      throw new Error("Second-factor completion must return its owner");
    }

    const persistedBeforeRead = await ctx.readUserState({ userId: verifyOtp.data.user.id });
    const session = await client.getSession();
    expect(session.data?.session.token).toBe(verifyOtp.data.token);
    expect(session.data?.session.userId).toBe(verifyOtp.data.user.id);

    const persistedAfterRead = await ctx.readUserState({ userId: verifyOtp.data.user.id });
    expect(persistedAfterRead).toEqual(persistedBeforeRead);

    if (!session.data) {
      throw new Error("Second-factor session must authenticate");
    }

    expect(session.data.session.expiresAt.getTime()).toBeGreaterThanOrEqual(
      verificationStartedAt + 86_400_000,
    );
    expect(session.data.session.expiresAt.getTime()).toBeLessThanOrEqual(
      verificationFinishedAt + 86_400_000,
    );

    const beforeReplay = await ctx.readUserState({ userId: signup.data!.user.id });
    const replay = await serverVerifyOtp({ code: otpRecord.otp }, pendingCookie);
    expect(replay.status).toBe(401);
    expect(((await replay.json()) as any).code).toBe("INVALID_TWO_FACTOR_COOKIE");
    expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(beforeReplay);

    const missingCookieClient = twoFactorActor(ctx, "missing-cookie");
    const missingCookie = await missingCookieClient.twoFactor.verifyOtp({
      code: otpRecord.otp,
    });

    return {
      signIn: ctx.snapshot(signIn),
      sendOtp: ctx.snapshot(sendOtp),
      verifyOtp: ctx.snapshot(verifyOtp),
      session: ctx.snapshot(session),
      persistedBeforeRead: ctx.snapshot(persistedBeforeRead),
      persistedAfterRead: ctx.snapshot(persistedAfterRead),
      missingCookie: ctx.snapshot(missingCookie),
    };
  },
);

compatScenario(
  "two-factor trusted devices bypass the second-factor challenge on later sign-ins",
  async (ctx) => {
    const client = twoFactorActor(ctx);
    const email = ctx.uniqueEmail("two-factor-trust");
    const password = "password123";

    await client.signUp.email({
      email,
      password,
      name: "Two Factor Trust Device",
    });

    const enable = await client.twoFactor.enable({ password });
    const setupCode = await generateCurrentTotp(enrollmentUri(enable.data));
    await client.twoFactor.verifyTotp({ code: setupCode });
    await client.signOut();

    const signIn = await client.signIn.email({
      email,
      password,
    });
    await client.twoFactor.sendOtp({});
    const otpRecord = (await ctx.readTwoFactorOtp({ email })) as { otp: string };
    const verifyOtp = await client.twoFactor.verifyOtp({
      code: otpRecord.otp,
      trustDevice: true,
    });

    await client.signOut();
    const trustedSignIn = await client.signIn.email({
      email,
      password,
    });

    return {
      signIn: ctx.snapshot(signIn),
      verifyOtp: ctx.snapshot(verifyOtp),
      trustedSignIn: ctx.snapshot(trustedSignIn),
    };
  },
);

function enrollmentUri(value: unknown): string {
  if (
    value &&
    typeof value === "object" &&
    "totpURI" in value &&
    typeof value.totpURI === "string"
  ) {
    return value.totpURI;
  }
  throw new Error("TOTP enrollment must return a URI");
}

compatScenario(
  "two-factor disable deletes factor and trust state and rotates the authoritative session",
  async (ctx) => {
    const client = twoFactorActor(ctx);
    const email = ctx.uniqueEmail("two-factor-disable");
    const password = "password123";
    const signup = await client.signUp.email({ email, password, name: "Disable Two Factor User" });
    expect(signup.error).toBeNull();

    if (!signup.data) {
      throw new Error("two-factor user must be created");
    }

    const userId = signup.data.user.id;
    const enable = await client.twoFactor.enable({ password });
    expect(enable.error).toBeNull();

    const setupCode = await generateCurrentTotp(enrollmentUri(enable.data));
    const enrolled = await client.twoFactor.verifyTotp({ code: setupCode });
    expect(enrolled.error).toBeNull();

    await client.signOut();
    let preferenceCookies: string[] = [];
    const signIn = await client.signIn.email({
      email,
      password,
      rememberMe: false,
      fetchOptions: {
        onSuccess({ response }) {
          preferenceCookies = response.headers
            .getSetCookie()
            .filter((raw) => Cookie.parse(raw)?.key.endsWith(".dont_remember"));
        },
      },
    });
    expect(signIn.error).toBeNull();

    z.object({ twoFactorRedirect: z.literal(true) }).parse(signIn.data);
    await client.twoFactor.sendOtp({});
    const otp = z.object({ otp: z.string().min(6) }).parse(await ctx.readTwoFactorOtp({ email }));
    let disableCookies = "";
    let signedTrustCookie: string | undefined;
    let signedSessionCookie: string | undefined;
    const trusted = await client.twoFactor.verifyOtp({
      code: otp.otp,
      trustDevice: true,
      fetchOptions: {
        onSuccess(context) {
          disableCookies = [
            ...new Map(
              [...preferenceCookies, ...context.response.headers.getSetCookie()].map((raw) => {
                const pair = raw.split(";")[0]!;
                return [pair.slice(0, pair.indexOf("=")), pair];
              }),
            ).values(),
          ].join("; ");
          for (const header of context.response.headers.getSetCookie()) {
            const cookie = Cookie.parse(header);
            if (cookie?.key.endsWith(".trust_device")) {
              signedTrustCookie = cookie.value;
            }
            if (cookie?.key.endsWith(".session_token")) {
              signedSessionCookie = `${cookie.key}=${cookie.value}`;
            }
          }
        },
      },
    });
    expect(trusted.error).toBeNull();

    if (!signedTrustCookie || !signedSessionCookie) {
      throw new Error("trusted verification must set both signed cookies");
    }

    const decodedTrustCookie = decodeURIComponent(signedTrustCookie);
    const trustIdentifier = decodedTrustCookie
      .slice(0, decodedTrustCookie.lastIndexOf("."))
      .split("!")[1];

    if (!trustIdentifier) {
      throw new Error("trust cookie must identify its persisted verification record");
    }

    const trustBeforeRaw = await ctx.readVerificationState({ identifier: trustIdentifier });
    const trustBefore = z.array(z.object({ value: z.string() })).parse(trustBeforeRaw);
    expect(trustBefore).toHaveLength(1);
    expect(trustBefore[0]?.value).toBe(userId);

    const organization = await organizationActor(ctx).orgClient.organization.create({
      name: "Two Factor Org",
      slug: ctx.uniqueToken("two-factor-disable-org"),
    });
    expect(organization.error).toBeNull();

    const before = await client.getSession();
    expect(before.data?.user.twoFactorEnabled).toBe(true);
    expect(before.data?.session.activeOrganizationId).toBe(organization.data?.id);

    const stateBefore = z
      .object({ twoFactorExists: z.boolean() })
      .parse(await ctx.readUserState({ userId }));
    expect(stateBefore.twoFactorExists).toBe(true);

    async function serverDisable(body: unknown, cookie?: string, actorName = "primary") {
      const response = await ctx
        .actor(actorName)
        .fetch(`${ctx.baseURL}/__test/server-api/two-factor-disable`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ body, ...(cookie ? { headers: { cookie } } : {}) }),
        });
      const value = (await response.json()) as any;
      return response.ok
        ? { data: value, error: null }
        : { data: null, error: { ...value, status: response.status } };
    }
    const ownerBeforeRejections = await ctx.readUserState({ userId });
    const guestValidation = await disableGuestValidation(ctx);
    for (const input of [{}, { password: 42 }, { password: null }]) {
      const result = await serverDisable(input, disableCookies);
      expect(result.error).toMatchObject({ status: 400, code: "VALIDATION_ERROR" });
      expect(await ctx.readUserState({ userId })).toEqual(ownerBeforeRejections);
    }
    const unauthenticated = await serverDisable({ password });
    expect(unauthenticated.error).toMatchObject({ status: 401 });

    const wrongPassword = await serverDisable({ password: "incorrect-password" }, disableCookies);
    expect(wrongPassword.error).toMatchObject({ status: 400, code: "INVALID_PASSWORD" });

    const other = twoFactorActor(ctx, "foreign-user");
    let foreignCookie = "";
    const foreignSignup = await other.signUp.email({
      email: ctx.uniqueEmail("foreign-disable"),
      password: "foreign-password123",
      name: "Other User",
      fetchOptions: {
        onSuccess({ response }) {
          foreignCookie = response.headers
            .getSetCookie()
            .map((cookie) => cookie.split(";")[0])
            .join("; ");
        },
      },
    });
    expect(foreignSignup.error).toBeNull();

    const wrongUser = await serverDisable({ password, userId }, foreignCookie);
    expect(wrongUser.error).toMatchObject({ status: 400, code: "INVALID_PASSWORD" });

    const rejectedState = await ctx.readUserState({ userId });
    expect(rejectedState).toEqual(ownerBeforeRejections);
    expect(
      z.object({ twoFactorExists: z.literal(true) }).parse(rejectedState).twoFactorExists,
    ).toBe(true);
    expect(await ctx.readVerificationState({ identifier: trustIdentifier })).toEqual(
      trustBeforeRaw,
    );

    const unchanged = await client.getSession();
    expect(unchanged.data?.session.token).toBe(before.data?.session.token);
    expect(unchanged.data?.user.twoFactorEnabled).toBe(true);

    const disable = await serverDisable(
      { password, userId: foreignSignup.data!.user.id },
      disableCookies,
    );
    expect(disable.data).toEqual({ status: true });

    const after = await client.getSession();
    expect(after.data?.user.id).toBe(userId);
    expect(after.data?.user.twoFactorEnabled).toBe(false);
    expect(after.data?.session.token).not.toBe(before.data?.session.token);
    expect(after.data?.session.activeOrganizationId).toBe(organization.data?.id);

    const afterStateRaw = await ctx.readUserState({ userId });
    const afterState = z
      .object({ twoFactorExists: z.boolean(), sessions: z.array(z.object({ token: z.string() })) })
      .parse(afterStateRaw);
    expect(afterState.twoFactorExists).toBe(false);
    expect(afterState.sessions).toHaveLength(1);
    expect(afterState.sessions[0]?.token).toBe(after.data?.session.token);

    const trustAfter = await ctx.readVerificationState({ identifier: trustIdentifier });
    expect(trustAfter).toEqual([]);

    const revoked = await twoFactorActor(ctx, "old-session").getSession({
      fetchOptions: { headers: { cookie: signedSessionCookie } },
    });
    expect(revoked.data).toBeNull();

    const replayDisable = await serverDisable({ password }, signedSessionCookie, "old-session");
    expect(replayDisable.error).toMatchObject({ status: 401, code: "UNAUTHORIZED" });
    expect(await ctx.readUserState({ userId })).toEqual(afterStateRaw);

    const removedFactor = await client.twoFactor.getTotpUri({ password });
    expect(removedFactor.error).toMatchObject({ status: 400, code: "TOTP_NOT_ENABLED" });

    await client.signOut();
    const passwordOnly = await client.signIn.email({ email, password });
    expect(passwordOnly.error).toBeNull();
    expect(passwordOnly.data).toHaveProperty("token");

    const sessionAfterSignIn = await client.getSession();
    expect(sessionAfterSignIn.data?.user.id).toBe(userId);
    expect(sessionAfterSignIn.data?.user.twoFactorEnabled).toBe(false);

    return {
      enrolled: ctx.snapshot(enrolled),
      signIn: ctx.snapshot(signIn),
      trusted: ctx.snapshot(trusted),
      organization: ctx.snapshot(organization),
      before: ctx.snapshot(before),
      guestValidation,
      unauthenticated: ctx.snapshot(unauthenticated),
      wrongPassword: ctx.snapshot(wrongPassword),
      wrongUser: ctx.snapshot(wrongUser),
      unchanged: ctx.snapshot(unchanged),
      disable: ctx.snapshot(disable),
      after: ctx.snapshot(after),
      factorExistsAfter: afterState.twoFactorExists,
      trustRecordsAfter: trustAfter,
      revoked: ctx.snapshot(revoked),
      replayDisable: ctx.snapshot(replayDisable),
      removedFactor: ctx.snapshot(removedFactor),
      passwordOnly: ctx.snapshot(passwordOnly),
      sessionAfterSignIn: ctx.snapshot(sessionAfterSignIn),
    };
  },
  ["POST /two-factor/disable"],
);

compatScenario(
  "two-factor disable requires a persistent cookie session and rejects API key emulation",
  async (ctx) => {
    const client = twoFactorActor(ctx);
    const password = "password123";
    const signup = await client.signUp.email({
      email: ctx.uniqueEmail("two-factor-sensitive-disable"),
      password,
      name: "Sensitive Factor Owner",
    });
    expect(signup.error).toBeNull();

    if (!signup.data) {
      throw new Error("factor owner requires a session");
    }

    const userId = signup.data.user.id;
    const enable = await client.twoFactor.enable({ password });
    const enrolled = await client.twoFactor.verifyTotp({
      code: await generateCurrentTotp(enrollmentUri(enable.data)),
    });
    expect(enrolled.error).toBeNull();

    const before = await client.getSession();
    expect(before.data?.user.twoFactorEnabled).toBe(true);

    const keyResponse = await ctx.rawRequest({
      path: "/__test/api-key/create",
      method: "POST",
      json: { userId, configId: "session" },
    });
    expect(keyResponse.status).toBe(200);

    const key = z
      .object({ id: z.string(), key: z.string(), referenceId: z.string() })
      .parse(keyResponse.body);
    const machine = await ctx.rawRequest({
      actor: "machine",
      path: "/api/auth/get-session",
      headers: { "x-api-key": key.key },
    });
    expect(machine.status).toBe(200);

    const virtual = z
      .object({
        user: z.object({ id: z.string() }),
        session: z.object({ id: z.string(), token: z.string(), userId: z.string() }),
      })
      .parse(machine.body);
    expect(virtual.user.id).toBe(userId);
    expect(virtual.session.id).toBe(key.id);
    expect(virtual.session.token).toBe(key.key);

    const apiKeyDisable = await ctx.rawRequest({
      actor: "machine",
      path: "/api/auth/two-factor/disable",
      method: "POST",
      headers: { "x-api-key": key.key },
      json: { password },
    });
    expect(apiKeyDisable).toMatchObject({
      status: 401,
      body: { message: "Unauthorized", code: "UNAUTHORIZED" },
    });

    const bearerDisable = await ctx.rawRequest({
      actor: "bare-bearer",
      path: "/api/auth/two-factor/disable",
      method: "POST",
      headers: { authorization: `Bearer ${before.data?.session.token}` },
      json: { password },
    });
    expect(bearerDisable).toMatchObject({
      status: 401,
      body: { message: "Unauthorized", code: "UNAUTHORIZED" },
    });

    const unchanged = await client.getSession();
    expect(unchanged.data?.session.token).toBe(before.data?.session.token);
    expect(unchanged.data?.user.twoFactorEnabled).toBe(true);

    const state = z
      .object({ twoFactorExists: z.boolean() })
      .parse(await ctx.readUserState({ userId }));
    expect(state.twoFactorExists).toBe(true);

    const disable = await client.twoFactor.disable({ password });
    expect(disable.data).toEqual({ status: true });

    return {
      signup: ctx.snapshot(signup),
      enrolled: ctx.snapshot(enrolled),
      before: ctx.snapshot(before),
      machine,
      apiKeyDisable,
      bearerDisable,
      unchanged: ctx.snapshot(unchanged),
      disable: ctx.snapshot(disable),
    };
  },
  ["POST /two-factor/disable"],
);
