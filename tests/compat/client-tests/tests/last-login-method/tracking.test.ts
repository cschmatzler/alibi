import { expect } from "bun:test";
import { passkeyClient } from "@better-auth/passkey/client";
import { createAuthClient } from "better-auth/client";
import {
  anonymousClient,
  emailOTPClient,
  lastLoginMethodClient,
  magicLinkClient,
  multiSessionClient,
  siweClient,
  usernameClient,
} from "better-auth/client/plugins";
import { Cookie } from "tough-cookie";
import { z } from "zod";
import { Authenticator } from "../../support/authenticator";
import { authProfilePath, type FixtureProfile } from "../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { message as walletMessage, signature as walletSignature } from "../../support/siwe-wallet";

function actor(ctx: ScenarioContext, name: string, profile: FixtureProfile) {
  const cookies: string[][] = [];
  const transport = ctx.actor(name, profile);
  const client = createAuthClient({
    baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
    plugins: [
      lastLoginMethodClient(),
      anonymousClient(),
      emailOTPClient(),
      magicLinkClient(),
      multiSessionClient(),
      usernameClient(),
      siweClient(),
      passkeyClient(),
    ],
    fetchOptions: {
      customFetchImpl: transport.fetch,
      onResponse: ({ response }) => {
        cookies.push(response.headers.getSetCookie());
      },
    },
  });
  return { client, cookies, fetch: transport.fetch };
}
function tracking(headers: string[], name = "better-auth.last_used_login_method") {
  return headers.map((header) => Cookie.parse(header)).find((cookie) => cookie?.key === name);
}
async function control(ctx: ScenarioContext, body: Record<string, unknown>) {
  const result = await ctx.rawRequest({
    path: "/__test/last-login-method",
    method: "POST",
    json: body,
  });
  expect(result.status).toBe(200);
  return result.body;
}
async function state(ctx: ScenarioContext) {
  const result = await ctx.rawRequest({ path: "/__test/last-login-method" });
  expect(result.status).toBe(200);
  return z
    .object({
      events: z.array(z.record(z.string(), z.unknown())),
      users: z.array(
        z.object({
          id: z.string(),
          email: z.string(),
          name: z.string().nullable(),
          lastLoginMethod: z.string().nullable(),
        }),
      ),
    })
    .parse(result.body);
}
function observed(headers: string[], name: string) {
  const cookie = tracking(headers, name);
  return cookie
    ? {
        name: cookie.key,
        value: cookie.value,
        path: cookie.path ?? null,
        domain: cookie.domain ?? null,
        maxAge: cookie.maxAge ?? null,
        expires: cookie.expires instanceof Date ? cookie.expires.toISOString() : cookie.expires,
        httpOnly: cookie.httpOnly,
        secure: cookie.secure,
        sameSite: cookie.sameSite ?? null,
        extensions: cookie.extensions ?? null,
      }
    : null;
}
function projectEvents(value: Awaited<ReturnType<typeof state>>) {
  return {
    ...value,
    events: value.events.map((event) => {
      const body = event.body as any;
      if (!body?.response?.response)
        return typeof body?.otp === "string"
          ? { ...event, body: { ...body, otp: { token: body.otp } } }
          : event;
      return {
        ...event,
        body: {
          ...body,
          response: {
            ...body.response,
            id: { token: body.response.id },
            rawId: { token: body.response.rawId },
            response: Object.fromEntries(
              Object.entries(body.response.response).map(([key, value]) => [
                key,
                typeof value === "string" ? { token: value } : value,
              ]),
            ),
          },
        },
      };
    }),
  };
}
for (const mode of [
  "default",
  "database",
  "custom",
  "denied",
  "cookie-error",
  "resolver-error",
  "update-error",
  "transform",
  "policy",
  "composition",
  "nan",
  "negative",
] as const) {
  compatScenario(
    `last login ${mode} preserves real cookie consent database updates and failed authentication ownership`,
    async (ctx) => {
      const profile = `last-login-${mode}` as FixtureProfile;
      const owner = actor(ctx, "owner", profile),
        sibling = actor(ctx, "sibling", profile),
        foreign = actor(ctx, "foreign", profile),
        guest = actor(ctx, "guest", profile);
      await control(ctx, { action: "reset" });
      const email = ctx.uniqueEmail("last-login-owner"),
        password = "password123";
      const headers = {
        "x-last-login-probe": "original signup",
        "x-last-login-method": "custom/signup% owner",
      };
      let forged: unknown = null;
      if (mode !== "default") {
        const before = await state(ctx);
        forged = await guest.client.signUp.email({
          email: ctx.uniqueEmail("forged"),
          password,
          name: "Attacker",
          lastLoginMethod: "attacker",
        } as any);
        expect(
          z
            .object({
              error: z.object({ code: z.literal("FIELD_NOT_ALLOWED") }),
            })
            .parse(forged),
        ).toBeDefined();
        expect((await state(ctx)).users).toEqual(before.users);
        await control(ctx, { action: "clear" });
      }
      const signup = await owner.client.signUp.email(
        { email, password, name: "Owner" },
        { headers },
      );
      expect(signup.error).toBeNull();
      if (!signup.data) throw new Error("real owner required");
      const name =
          mode === "custom"
            ? "fixture.last_login_method"
            : mode === "policy"
              ? "policy.last_login_method"
              : "better-auth.last_used_login_method",
        method =
          mode === "custom" || mode === "update-error" ? headers["x-last-login-method"] : "email";
      const cookie = tracking(owner.cookies.at(-1)!, name);
      if (mode === "denied" || mode === "cookie-error") expect(cookie).toBeUndefined();
      else {
        expect(decodeURIComponent(cookie!.value)).toBe(method);
        expect(cookie!.httpOnly).toBe(false);
        expect(cookie!.maxAge).toBe(
          mode === "custom"
            ? 123
            : mode === "policy"
              ? 0
              : mode === "nan" || mode === "negative"
                ? null
                : 2592000,
        );
        expect(cookie!.path).toBe("/");
        expect(cookie!.sameSite).toBe(mode === "policy" ? "strict" : "lax");
        expect(cookie!.expires).toBe("Infinity");
      }
      const afterSignup = await state(ctx);
      expect(
        afterSignup.users.find((row) => row.id === signup.data!.user.id)?.lastLoginMethod,
      ).toBe(mode === "default" ? null : mode === "transform" ? `stored:${method}` : method);
      expect(signup.data.user).toMatchObject(mode === "default" ? {} : { lastLoginMethod: method });
      expect(afterSignup.events.filter((event) => event.kind === "cookie")).toHaveLength(1);
      const other = await foreign.client.signUp.email({
        email: ctx.uniqueEmail("last-login-foreign"),
        password,
        name: "Foreign",
      });
      expect(other.error).toBeNull();
      if (!other.data) throw new Error("real foreign owner required");
      const foreignBefore = await ctx.readUserState({
        userId: other.data.user.id,
      });
      const ownerBefore = await ctx.readUserState({
        userId: signup.data.user.id,
      });
      let injectedUpdate: unknown = null;
      if (mode !== "default") {
        injectedUpdate = await owner.client.updateUser({
          lastLoginMethod: "forged-update",
        } as any);
        expect(
          z
            .object({
              error: z.object({ code: z.literal("FIELD_NOT_ALLOWED") }),
            })
            .parse(injectedUpdate),
        ).toBeDefined();
        expect(await ctx.readUserState({ userId: signup.data.user.id })).toEqual(ownerBefore);
      }

      await control(ctx, { action: "clear" });
      const failed = await guest.client.signIn.email(
        { email, password: "wrong-password" },
        { headers: { "x-last-login-probe": "rejected" } },
      );
      expect(failed.error?.code).toBe("INVALID_EMAIL_OR_PASSWORD");
      expect(tracking(guest.cookies.at(-1)!, name)).toBeUndefined();
      expect(await ctx.readUserState({ userId: signup.data.user.id })).toEqual(ownerBefore);
      const afterFailed = await state(ctx);
      expect(afterFailed.events.filter((event) => event.kind === "cookie")).toHaveLength(0);
      if (mode === "update-error") await control(ctx, { action: "update-error" });
      const secondHeaders = {
        "x-last-login-probe": "sibling sign-in",
        "x-last-login-method": "custom/signin",
      };
      const second = await sibling.client.signIn.email(
        { email, password },
        { headers: secondHeaders },
      );
      expect(second.error).toBeNull();
      expect(second.data?.user.id).toBe(signup.data.user.id);
      if (mode === "update-error") await control(ctx, { action: "restore-updates" });
      const afterSecond = await state(ctx);
      expect(
        afterSecond.users.find((row) => row.id === signup.data!.user.id)?.lastLoginMethod,
      ).toBe(
        mode === "default"
          ? null
          : mode === "custom"
            ? "custom/signin"
            : mode === "update-error"
              ? method
              : mode === "transform"
                ? "stored:email"
                : "email",
      );
      let deviceSessions: unknown = null;
      if (mode === "composition") {
        const another = await owner.client.signUp.email({
          email: ctx.uniqueEmail("retained-device"),
          password,
          name: "Device Owner",
        });
        expect(another.error).toBeNull();
        deviceSessions = await owner.client.multiSession.listDeviceSessions();
        expect(
          z
            .object({ data: z.array(z.unknown()).length(2) })
            .passthrough()
            .parse(deviceSessions),
        ).toBeDefined();
        const active = await owner.client.multiSession.setActive({
          sessionToken: signup.data.token!,
        });
        expect(active.error).toBeNull();
        expect(tracking(owner.cookies.at(-1)!, name)).toBeUndefined();
      }
      const sessions = await owner.client.getSession();
      expect(sessions.error).toBeNull();
      expect(sessions.data?.user.id).toBe(signup.data.user.id);
      const siblingSession = await sibling.client.getSession();
      expect(siblingSession.error).toBeNull();
      expect(siblingSession.data?.user.id).toBe(signup.data.user.id);
      expect(siblingSession.data?.session.token).not.toBe(sessions.data?.session.token);
      const ownerState = await ctx.readUserState({
        userId: signup.data.user.id,
      });
      expect(
        z
          .object({ sessions: z.array(z.unknown()) })
          .passthrough()
          .parse(ownerState).sessions,
      ).toHaveLength(2);
      expect(await ctx.readUserState({ userId: other.data.user.id })).toEqual(foreignBefore);
      let resolverRejected: unknown = null;
      if (mode === "resolver-error") {
        const before = await state(ctx);
        resolverRejected = await guest.client.signIn.email(
          { email, password },
          { headers: { "x-last-login-resolver-error": "true" } },
        );
        expect(
          z.object({ error: z.object({ status: z.literal(500) }) }).parse(resolverRejected),
        ).toBeDefined();
        expect(tracking(guest.cookies.at(-1)!, name)).toBeUndefined();
        const after = await state(ctx);
        expect(after.users).toEqual(before.users);
        const remaining = z
          .object({ sessions: z.array(z.unknown()) })
          .passthrough()
          .parse(await ctx.readUserState({ userId: signup.data.user.id }));
        expect(remaining.sessions).toHaveLength(3);
      }
      let suppressed: unknown = null;
      if (mode === "custom") {
        const before = await state(ctx);
        suppressed = await guest.client.signIn.email(
          { email, password },
          { headers: { "x-last-login-method": "" } },
        );
        expect(z.object({ error: z.null() }).passthrough().parse(suppressed)).toBeDefined();
        expect(tracking(guest.cookies.at(-1)!, name)).toBeUndefined();
        expect((await state(ctx)).users).toEqual(before.users);
      }
      return ctx.snapshot({
        injectedUpdate,
        suppressed,
        forged,
        signup,
        cookie: observed(owner.cookies[0]!, name),
        afterSignup,
        other,
        foreignBefore,
        ownerBefore,
        failed,
        afterFailed,
        second,
        cookieSecond: observed(sibling.cookies[0]!, name),
        afterSecond,
        sessions,
        siblingSession,
        ownerState,
        deviceSessions,
        resolverRejected,
        final: await state(ctx),
        foreignAfter: await ctx.readUserState({ userId: other.data.user.id }),
      });
    },
    [
      "POST /sign-up/email",
      "POST /sign-in/email",
      "GET /get-session",
      ...(mode !== "default" ? ["POST /update-user"] : []),
      ...(mode === "composition"
        ? ["GET /multi-session/list-device-sessions", "POST /multi-session/set-active"]
        : []),
    ],
  );
}
compatScenario(
  "last login actual authentication methods and anonymous upgrade preserve resolver context and original issuance snapshots",
  async (ctx) => {
    const profile: FixtureProfile = "last-login-database";
    await control(ctx, { action: "reset" });
    const owner = actor(ctx, "owner", profile),
      foreign = actor(ctx, "foreign", profile),
      upgrade = actor(ctx, "upgrade", profile);
    const password = "password123",
      email = ctx.uniqueEmail("method-owner"),
      username = "methodowner";
    const signup = await owner.client.signUp.email({
      email,
      password,
      name: "Methods Owner",
      username,
    } as any);
    expect(signup.error).toBeNull();
    if (!signup.data) throw new Error("real owner required");
    const other = await foreign.client.signUp.email({
      email: ctx.uniqueEmail("method-foreign"),
      password,
      name: "Foreign",
    });
    expect(other.error).toBeNull();
    const foreignBefore = await ctx.readUserState({
      userId: other.data!.user.id,
    });
    const outputs = [];
    const check = async (method: string | null) => {
      const current = await state(ctx);
      expect(current.users.find((row) => row.id === signup.data!.user.id)?.lastLoginMethod).toBe(
        method ?? "email",
      );
      const cookie = tracking(owner.cookies.at(-1)!);
      if (method) expect(decodeURIComponent(cookie!.value)).toBe(method);
      else expect(cookie).toBeUndefined();
      expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(foreignBefore);
      return projectEvents(current);
    };
    await owner.client.signOut();
    const signed = await owner.client.signIn.username({ username, password });
    expect(signed.error).toBeNull();
    outputs.push({ signed, state: await check(null) });
    await owner.client.signOut();
    const sent = await owner.client.emailOtp.sendVerificationOtp({
      email,
      type: "sign-in",
    });
    expect(sent.error).toBeNull();
    const delivered = z
      .object({ otp: z.string() })
      .parse(await control(ctx, { action: "delivery", key: `sign-in:${email}` }));
    const otp = await owner.client.signIn.emailOtp({
      email,
      otp: delivered.otp,
    });
    expect(otp.error).toBeNull();
    outputs.push({
      sent,
      delivered: { ...delivered, otp: { token: delivered.otp } },
      otp,
      state: await check("email-otp"),
    });
    const authenticator = new Authenticator();
    const registration = await owner.client.$fetch("/passkey/generate-register-options");
    expect(registration.error).toBeNull();
    const registrationResponse = authenticator.register(registration.data, ctx.baseURL);
    const registered = await owner.client.$fetch("/passkey/verify-registration", {
      method: "POST",
      body: { response: registrationResponse, name: "Owned key" },
    });
    expect(registered.error).toBeNull();
    await owner.client.signOut();
    const authOptions = await owner.client.$fetch("/passkey/generate-authenticate-options");
    expect(authOptions.error).toBeNull();
    const authenticationResponse = authenticator.authenticate(authOptions.data, ctx.baseURL);
    const passkey = await owner.client.$fetch("/passkey/verify-authentication", {
      method: "POST",
      body: { response: authenticationResponse },
    });
    expect(passkey.error).toBeNull();
    const callbackReceipts = await state(ctx);
    expect(
      callbackReceipts.events
        .filter((event) => event.path === "/passkey/verify-registration")
        .every(
          (event) =>
            JSON.stringify(event.body) ===
            JSON.stringify({
              response: registrationResponse,
              name: "Owned key",
            }),
        ),
    ).toBe(true);
    expect(
      callbackReceipts.events
        .filter((event) => event.path === "/passkey/verify-authentication")
        .every(
          (event) =>
            JSON.stringify(event.body) === JSON.stringify({ response: authenticationResponse }),
        ),
    ).toBe(true);
    expect(
      callbackReceipts.events
        .filter((event) => event.path === "/sign-in/email-otp")
        .every((event) => (event.body as any).otp === delivered.otp),
    ).toBe(true);
    outputs.push({
      registration,
      registered,
      authOptions,
      passkey,
      state: await check("passkey"),
    });
    await owner.client.signOut();
    const link = await owner.client.signIn.magicLink({
      email,
      callbackURL: "/dashboard",
    });
    expect(link.error).toBeNull();
    const delivery = z
      .object({ url: z.string(), token: z.string() })
      .passthrough()
      .parse(await control(ctx, { action: "delivery", key: `magic:${email}` }));
    const magic = await owner.fetch(delivery.url, { redirect: "manual" });
    expect(magic.status).toBe(302);
    owner.cookies.push(magic.headers.getSetCookie());
    outputs.push({
      link,
      delivery,
      magic: { status: magic.status, location: magic.headers.get("location") },
      state: await check("magic-link"),
    });
    const social = actor(ctx, "social", profile);
    const socialEmail = ctx.uniqueEmail("social-last-login");
    await ctx.setSocialProfile({
      email: socialEmail,
      sub: ctx.uniqueToken("google-owner"),
      name: "Social Owner",
      emailVerified: true,
      idTokenValid: true,
    });
    const initiated = await social.client.signIn.social({
      provider: "google",
      callbackURL: "/dashboard",
    });
    expect(initiated.error).toBeNull();
    const socialState = new URL(initiated.data!.url!).searchParams.get("state")!;
    const callback = await social.fetch(
      `${authProfilePath(profile)}/callback/google?code=compat-code&state=${encodeURIComponent(socialState)}`,
      { redirect: "manual" },
    );
    expect(callback.status).toBe(302);
    social.cookies.push(callback.headers.getSetCookie());
    expect(decodeURIComponent(tracking(social.cookies.at(-1)!)!.value)).toBe("google");
    const socialSession = await social.client.getSession();
    expect(socialSession.error).toBeNull();
    expect(socialSession.data?.user.email).toBe(socialEmail);
    const afterSocial = await state(ctx);
    expect(afterSocial.users.find((row) => row.email === socialEmail)?.lastLoginMethod).toBe(
      "google",
    );
    expect(
      afterSocial.events.some(
        (event) =>
          event.path === "/callback/:id" &&
          (event.params as any).id === "google" &&
          event.requestPath === "/callback/google",
      ),
    ).toBe(true);
    const wallet = actor(ctx, "wallet", profile);
    const nonce = await wallet.client.siwe.nonce();
    expect(nonce.error).toBeNull();
    const signedMessage = walletMessage(z.object({ nonce: z.string() }).parse(nonce.data).nonce, {
      domain: "last-login.fixture",
    });
    const verified = await wallet.client.siwe.verify({
      message: signedMessage,
      signature: walletSignature(signedMessage),
    });
    expect(verified.error).toBeNull();
    expect(decodeURIComponent(tracking(wallet.cookies.at(-1)!)!.value)).toBe("siwe");
    const walletSession = await wallet.client.getSession();
    expect(walletSession.error).toBeNull();
    const afterWallet = await state(ctx);
    expect(
      afterWallet.users.find((row) => row.id === walletSession.data!.user.id)?.lastLoginMethod,
    ).toBe("siwe");
    const anonymous = await upgrade.client.signIn.anonymous();
    expect(anonymous.error).toBeNull();
    expect(tracking(upgrade.cookies.at(-1)!)).toBeUndefined();
    const beforeUpgrade = await ctx.readUserState({
      userId: anonymous.data!.user.id,
    });
    const upgraded = await upgrade.client.signUp.email(
      {
        email: ctx.uniqueEmail("upgraded-owner"),
        password,
        name: "Upgraded Owner",
      },
      { headers: { "x-last-login-probe": "upgrade-original" } },
    );
    expect(upgraded.error).toBeNull();
    expect(
      z
        .object({ lastLoginMethod: z.literal("email") })
        .passthrough()
        .parse(upgraded.data?.user),
    ).toBeDefined();
    expect(await ctx.readUserState({ userId: anonymous.data!.user.id })).toEqual({
      user: null,
      accounts: [],
      sessions: [],
      twoFactorExists: false,
    });
    expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(foreignBefore);
    return ctx.snapshot({
      signup,
      other,
      outputs,
      initiated,
      callback: {
        status: callback.status,
        location: callback.headers.get("location"),
      },
      socialSession,
      afterSocial: projectEvents(afterSocial),
      nonce,
      signedMessage,
      verified,
      walletSession,
      afterWallet: projectEvents(afterWallet),
      anonymous,
      beforeUpgrade,
      upgraded,
      final: projectEvents(await state(ctx)),
      ownerAfter: await ctx.readUserState({ userId: signup.data.user.id }),
      upgradedAfter: await ctx.readUserState({
        userId: upgraded.data!.user.id,
      }),
      foreignAfter: await ctx.readUserState({ userId: other.data!.user.id }),
    });
  },
  [
    "POST /sign-up/email",
    "POST /sign-in/username",
    "POST /email-otp/send-verification-otp",
    "POST /sign-in/email-otp",
    "GET /passkey/generate-register-options",
    "POST /passkey/verify-registration",
    "GET /passkey/generate-authenticate-options",
    "POST /passkey/verify-authentication",
    "POST /sign-in/magic-link",
    "GET /magic-link/verify",
    "POST /sign-in/anonymous",
    "POST /sign-in/social",
    "GET /callback/{}",
    "POST /siwe/nonce",
    "POST /siwe/verify",
  ],
);

compatScenario(
  "last login excessive cookie lifetime rejects serialization after real authentication commits",
  async (ctx) => {
    await control(ctx, { action: "reset" });
    const owner = actor(ctx, "owner", "last-login-excess");
    const email = ctx.uniqueEmail("excess-owner");
    const result = await owner.client.signUp.email({
      email,
      password: "password123",
      name: "Committed Owner",
    });
    expect(result.error?.status).toBe(500);
    expect(tracking(owner.cookies.at(-1)!)).toBeUndefined();
    const persisted = await state(ctx);
    const user = persisted.users.find((row) => row.email === email)!;
    expect(user.lastLoginMethod).toBe("email");
    const physical = await ctx.readUserState({ userId: user.id });
    expect(
      z
        .object({
          sessions: z.array(z.unknown()).length(1),
          accounts: z.array(z.unknown()).length(1),
        })
        .passthrough()
        .parse(physical),
    ).toBeDefined();
    return ctx.snapshot({
      result,
      persisted,
      physical,
      cookie: observed(owner.cookies.at(-1)!, "better-auth.last_used_login_method"),
    });
  },
  ["POST /sign-up/email"],
);

compatScenario(
  "last login custom resolver receives complete transformed endpoint numbers while raw HTTP bytes stay original",
  async (ctx) => {
    await control(ctx, { action: "reset" });
    const owner = actor(ctx, "owner", "last-login-custom");
    const email = ctx.uniqueEmail("numeric-context");
    const body = `{"email":${JSON.stringify(email)},"password":"password123","name":"Numeric Owner","username":"numericowner","extra":{"overflow":1e400,"zero":-0,"nested":[null,false,"literal"]}}`;
    const result = await owner.fetch(`${authProfilePath("last-login-custom")}/sign-up/email`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-last-login-body": "true",
      },
      body,
    });
    expect(result.status).toBe(200);
    const returned = await result.json();
    expect(
      decodeURIComponent(
        tracking(result.headers.getSetCookie(), "fixture.last_login_method")!.value,
      ),
    ).toBe("body:Infinity:-0");
    const persisted = await state(ctx);
    expect(persisted.users.find((row) => row.email === email)?.lastLoginMethod).toBe(
      "body:Infinity:-0",
    );
    expect(persisted.events.length).toBeGreaterThan(0);
    expect(
      persisted.events.filter((event) => event.kind === "cookie").map((event) => event.requestBody),
    ).toEqual([body]);
    for (const event of persisted.events) {
      expect(event.body).toEqual({
        email,
        password: "password123",
        name: "Numeric Owner",
        username: "numericowner",
        displayUsername: "numericowner",
        extra: {
          overflow: { $number: "Infinity" },
          zero: { $number: "-0" },
          nested: [null, false, "literal"],
        },
      });
    }
    return ctx.snapshot({
      returned,
      persisted,
      physical: await ctx.readUserState({ userId: returned.user.id }),
    });
  },
  ["POST /sign-up/email"],
);
