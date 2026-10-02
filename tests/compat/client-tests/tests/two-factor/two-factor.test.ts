import { expect } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { organizationClient, twoFactorClient } from "better-auth/client/plugins";
import { Cookie } from "tough-cookie";
import { z } from "zod";
import { compatScenario } from "../../support/scenario";
import { generateCurrentTotp, redactTwoFactorPayload } from "../../support/totp";
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

    await client.signUp.email({
      email,
      password,
      name: "Two Factor Enrollment",
    });

    const enable = await client.twoFactor.enable({ password });
    const totp = await client.twoFactor.getTotpUri({ password });
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

    await client.signUp.email({
      email,
      password,
      name: "Two Factor TOTP",
    });

    const enable = await client.twoFactor.enable({ password });
    if (!enable.data || !("totpURI" in enable.data))
      throw new Error("TOTP enrollment must return a URI");
    const code = await generateCurrentTotp(enable.data.totpURI);
    const verifyTotp = await client.twoFactor.verifyTotp({ code });
    const session = await client.getSession();

    await client.signOut();
    const signIn = await client.signIn.email({
      email,
      password,
      rememberMe: false,
    });

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

    await client.signUp.email({
      email,
      password,
      name: "Two Factor OTP",
    });

    const enable = await client.twoFactor.enable({ password });
    const setupCode = await generateCurrentTotp(enrollmentUri(enable.data));
    await client.twoFactor.verifyTotp({ code: setupCode });
    await client.signOut();

    const signIn = await client.signIn.email({
      email,
      password,
      rememberMe: false,
    });
    const sendOtp = await client.twoFactor.sendOtp({});
    const otpRecord = (await ctx.readTwoFactorOtp({ email })) as { otp: string };
    const verificationStartedAt = Date.now();
    const verifyOtp = await client.twoFactor.verifyOtp({ code: otpRecord.otp });
    const verificationFinishedAt = Date.now();
    if (!verifyOtp.data?.user.id) throw new Error("Second-factor completion must return its owner");
    const persistedBeforeRead = await ctx.readUserState({ userId: verifyOtp.data.user.id });
    const session = await client.getSession();
    expect(session.data?.session.token).toBe(verifyOtp.data.token);
    expect(session.data?.session.userId).toBe(verifyOtp.data.user.id);
    const persistedAfterRead = await ctx.readUserState({ userId: verifyOtp.data.user.id });
    expect(persistedAfterRead).toEqual(persistedBeforeRead);
    if (!session.data) throw new Error("Second-factor session must authenticate");
    expect(session.data.session.expiresAt.getTime()).toBeGreaterThanOrEqual(
      verificationStartedAt + 86_400_000,
    );
    expect(session.data.session.expiresAt.getTime()).toBeLessThanOrEqual(
      verificationFinishedAt + 86_400_000,
    );

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
  if (value && typeof value === "object" && "totpURI" in value && typeof value.totpURI === "string")
    return value.totpURI;
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
    if (!signup.data) throw new Error("two-factor user must be created");
    const userId = signup.data.user.id;
    const enable = await client.twoFactor.enable({ password });
    expect(enable.error).toBeNull();
    const setupCode = await generateCurrentTotp(enrollmentUri(enable.data));
    const enrolled = await client.twoFactor.verifyTotp({ code: setupCode });
    expect(enrolled.error).toBeNull();
    await client.signOut();
    const signIn = await client.signIn.email({ email, password, rememberMe: false });
    expect(signIn.error).toBeNull();
    z.object({ twoFactorRedirect: z.literal(true) }).parse(signIn.data);
    await client.twoFactor.sendOtp({});
    const otp = z.object({ otp: z.string().min(6) }).parse(await ctx.readTwoFactorOtp({ email }));
    let signedTrustCookie: string | undefined;
    let signedSessionCookie: string | undefined;
    const trusted = await client.twoFactor.verifyOtp({
      code: otp.otp,
      trustDevice: true,
      fetchOptions: {
        onSuccess(context) {
          for (const header of context.response.headers.getSetCookie()) {
            const cookie = Cookie.parse(header);
            if (cookie?.key.endsWith(".trust_device")) signedTrustCookie = cookie.value;
            if (cookie?.key.endsWith(".session_token"))
              signedSessionCookie = `${cookie.key}=${cookie.value}`;
          }
        },
      },
    });
    expect(trusted.error).toBeNull();
    if (!signedTrustCookie || !signedSessionCookie)
      throw new Error("trusted verification must set both signed cookies");
    const decodedTrustCookie = decodeURIComponent(signedTrustCookie);
    const trustIdentifier = decodedTrustCookie
      .slice(0, decodedTrustCookie.lastIndexOf("."))
      .split("!")[1];
    if (!trustIdentifier)
      throw new Error("trust cookie must identify its persisted verification record");
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

    const ownerBeforeRejections = await ctx.readUserState({ userId });
    const guestValidation = await disableGuestValidation(ctx);
    const unauthenticated = await twoFactorActor(ctx, "guest").twoFactor.disable({ password });
    expect(unauthenticated.error).toMatchObject({ status: 401 });
    const wrongPassword = await client.twoFactor.disable({ password: "incorrect-password" });
    expect(wrongPassword.error).toMatchObject({ status: 400, code: "INVALID_PASSWORD" });
    const other = twoFactorActor(ctx, "foreign-user");
    const foreignSignup = await other.signUp.email({
      email: ctx.uniqueEmail("foreign-disable"),
      password: "foreign-password123",
      name: "Other User",
    });
    expect(foreignSignup.error).toBeNull();
    const wrongUser = await other.twoFactor.disable({ password });
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

    const disable = await client.twoFactor.disable({ password });
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
    const replayDisable = await twoFactorActor(ctx, "old-session").twoFactor.disable({
      password,
      fetchOptions: { headers: { cookie: signedSessionCookie } },
    });
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
    if (!signup.data) throw new Error("factor owner requires a session");
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
