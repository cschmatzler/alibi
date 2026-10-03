import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../../support/scenario";

async function events(ctx: ScenarioContext) {
  const result = await ctx.rawRequest({ path: "/__test/captcha-events" });
  expect(result.status).toBe(200);
  return result.body as Record<string, unknown>[];
}

const ip = { "x-forwarded-for": "203.0.113.7" };

async function restoreAttempt(ctx: ScenarioContext, actor: string, body: unknown, userId: string) {
  const token = (body as { token?: unknown }).token;

  if (typeof token !== "string") {
    throw new Error("Admitted sign-in must return a genuine session token");
  }

  const read = await ctx.actor(actor).client.getSession();
  expect(read.error).toBeNull();
  expect(read.data!.user.id).toBe(userId);
  expect(read.data!.session.token).toBe(token);

  return ctx.snapshot(read);
}

async function principals(ctx: ScenarioContext) {
  const owner = ctx.actor("owner");
  const foreign = ctx.actor("foreign");
  const signup = await owner.client.signUp.email({
    email: ctx.uniqueEmail("owner"),
    password: "password123",
    name: "Owner",
  });
  const other = await foreign.client.signUp.email({
    email: ctx.uniqueEmail("foreign"),
    password: "password123",
    name: "Foreign",
  });
  expect(signup.error).toBeNull();
  expect(other.error).toBeNull();

  await events(ctx);
  return { signup, other, foreignBefore: await ctx.readUserState({ userId: other.data!.user.id }) };
}

for (const profile of [
  "captcha-turnstile",
  "captcha-turnstile-configured",
  "captcha-google",
  "captcha-google-configured",
  "captcha-google-zero",
  "captcha-hcaptcha",
  "captcha-hcaptcha-sitekey",
  "captcha-captchafox",
  "captcha-captchafox-sitekey",
  "captcha-turnstile-ip-disabled",
  "captcha-turnstile-ip-custom",
] as const) {
  compatScenario(
    `CAPTCHA ${profile} actual verification transport admits only provider-approved authentication`,
    async (ctx) => {
      const s = await principals(ctx);
      const path = authProfilePath(profile);
      const observations = [];

      for (const token of [
        "",
        "denied",
        "http-failure",
        "invalid-json",
        "null",
        "wrong-action",
        "wrong-host",
        "low-score",
        "v2",
        "valid",
        "special & = % + /",
        "blob-json",
        "empty-text",
        "truthy-success",
        "score-text",
        "score-null",
        "missing-action",
        "missing-host",
      ]) {
        const configured = profile.endsWith("-configured");
        const google = profile.includes("google");
        const status = !token
          ? 400
          : ["http-failure", "null", "empty-text"].includes(token)
            ? 500
            : ["denied", "invalid-json", "blob-json"].includes(token) ||
                (configured &&
                  ["wrong-action", "wrong-host", "missing-action", "missing-host"].includes(
                    token,
                  )) ||
                (google && profile !== "captcha-google-zero" && token === "low-score")
              ? 403
              : 200;
        const before = await ctx.readUserState({ userId: s.signup.data!.user.id });
        const headers = {
          ...ip,
          ...(profile.endsWith("-ip-custom") ? { "x-fixture-ip": "198.51.100.9" } : {}),
          ...(token ? { "x-captcha-response": token } : {}),
        };
        const result = await ctx.rawRequest({
          actor: `attempt-${token}`,
          path: path + "/sign-in/email",
          method: "POST",
          json: { email: s.signup.data!.user.email, password: "password123" },
          headers,
        });
        expect(result.status).toBe(status);

        const authenticated =
          status === 200
            ? await restoreAttempt(ctx, `attempt-${token}`, result.body, s.signup.data!.user.id)
            : null;
        const after = await ctx.readUserState({ userId: s.signup.data!.user.id });
        const receipts = await events(ctx);

        if (status !== 200) {
          expect(result.body).toMatchObject({
            code:
              status === 400
                ? "MISSING_RESPONSE"
                : status === 403
                  ? "VERIFICATION_FAILED"
                  : "UNKNOWN_ERROR",
          });
          expect(after).toEqual(before);
          expect(receipts.some((e) => e.kind === "before" || e.kind === "early-b")).toBe(false);
        } else {
          expect(result.body).toMatchObject({ user: { id: s.signup.data!.user.id } });
          expect(receipts.at(-1)).toMatchObject({ kind: "before", path: "/sign-in/email" });
        }

        const provider = receipts.find((e) => e.kind === "provider");
        const providerBody = provider?.body as Record<string, unknown> | undefined;

        if (token) {
          expect(provider!.body).toMatchObject({
            secret: "fixture-captcha-secret",
            response: token,
          });
          expect(providerBody?.remoteip ?? providerBody?.remoteIp).toBe(
            profile.endsWith("-ip-disabled")
              ? undefined
              : profile.endsWith("-ip-custom")
                ? "198.51.100.9"
                : "203.0.113.7",
          );
          if (profile.endsWith("-sitekey")) {
            expect(providerBody?.sitekey).toBe("fixture-site-key");
          }
        } else {
          expect(provider).toBeUndefined();
        }

        expect(await ctx.readUserState({ userId: s.other.data!.user.id })).toEqual(s.foreignBefore);

        observations.push({
          captchaResponse: token,
          before,
          result,
          authenticated,
          after,
          receipts,
        });
      }

      const newcomer = ctx.actor("new-owner", profile);
      const newSignup = await newcomer.client.signUp.email(
        { email: ctx.uniqueEmail("new-owner"), password: "password123", name: "Protected" },
        { headers: { ...ip, "x-fixture-ip": "198.51.100.9", "x-captcha-response": "valid" } },
      );
      expect(newSignup.error).toBeNull();

      const signupReceipts = await events(ctx);
      expect(signupReceipts.at(-1)).toMatchObject({ kind: "before", path: "/sign-up/email" });

      const authenticated = await newcomer.client.getSession();
      expect(authenticated.error).toBeNull();
      expect(authenticated.data!.user).toEqual(newSignup.data!.user);

      const signupToken = newSignup.data!.token;

      if (typeof signupToken !== "string") {
        throw new Error("Protected signup must issue a real session token");
      }

      expect(authenticated.data!.session.token).toBe(signupToken);

      const authenticatedReceipts = await events(ctx);
      return {
        authenticated: ctx.snapshot(authenticated),
        authenticatedReceipts,
        initial: ctx.snapshot(s.signup),
        other: ctx.snapshot(s.other),
        foreignBefore: s.foreignBefore,
        observations,
        newSignup: ctx.snapshot(newSignup),
        newState: await ctx.readUserState({ userId: newSignup.data!.user.id }),
        signupReceipts,
        foreignAfter: await ctx.readUserState({ userId: s.other.data!.user.id }),
      };
    },
    ["POST /sign-in/email", "POST /sign-up/email"],
  );
}

for (const profile of [
  "captcha-turnstile-custom",
  "captcha-turnstile-wildcard",
  "captcha-turnstile-globstar",
  "captcha-turnstile-empty",
  "captcha-turnstile-disabled",
  "captcha-turnstile-no-secret",
] as const) {
  compatScenario(
    `CAPTCHA ${profile} path and early rejection ordering preserve unchanged physical principals`,
    async (ctx) => {
      const s = await principals(ctx);
      const observations = [];
      const path = authProfilePath(profile);

      for (const route of [
        "/sign-in/email",
        "/sign-in/email/extra",
        "/sign-in//email",
        "/sign-in/email/",
        "/request-password-reset",
        "/ok",
      ]) {
        const before = await ctx.readUserState({ userId: s.signup.data!.user.id });
        const protectedPath = profile.endsWith("-custom")
          ? route === "/ok"
          : profile.endsWith("-wildcard")
            ? ["/sign-in/email", "/sign-in//email", "/sign-in/email/"].includes(route)
            : profile.endsWith("-globstar")
              ? route.startsWith("/sign-in/")
              : [
                  "/sign-in/email",
                  "/sign-in//email",
                  "/sign-in/email/",
                  "/request-password-reset",
                ].includes(route);
        const result = await ctx.rawRequest({
          actor: "invalid",
          path: path + route,
          method: route === "/ok" ? "GET" : "POST",
          body: route === "/ok" ? undefined : "{",
          headers: { ...ip, "content-type": "text/plain", origin: "https://foreign.fixture.test" },
        });
        const receipts = await events(ctx);
        const after = await ctx.readUserState({ userId: s.signup.data!.user.id });

        if (
          profile.endsWith("-disabled") &&
          ["/sign-in/email", "/sign-in/email/"].includes(route)
        ) {
          expect(result.status).toBe(404);
          expect(receipts).toEqual([]);
        } else if (protectedPath) {
          expect(result.status).toBe(profile.endsWith("-no-secret") ? 500 : 400);
          expect(result.body).toMatchObject({
            code: profile.endsWith("-no-secret") ? "UNKNOWN_ERROR" : "MISSING_RESPONSE",
          });
          expect(receipts.map((e) => e.kind)).toEqual(["early-a"]);
        } else {
          expect(receipts.map((e) => e.kind)).toEqual(
            route === "/ok" ? ["early-a", "early-b", "before"] : ["early-a", "early-b"],
          );
        }

        expect(after).toEqual(before);
        expect(await ctx.readUserState({ userId: s.other.data!.user.id })).toEqual(s.foreignBefore);

        observations.push({ route, before, result, receipts, after });
      }

      return {
        signup: ctx.snapshot(s.signup),
        other: ctx.snapshot(s.other),
        foreignBefore: s.foreignBefore,
        observations,
        foreignAfter: await ctx.readUserState({ userId: s.other.data!.user.id }),
      };
    },
    ["POST /sign-in/email", "POST /request-password-reset"],
    30_000,
    profile === "captcha-turnstile-globstar"
      ? {}
      : {
          oracle: {
            unroutedRequests: "asserts malformed and extended sign-in paths are not routed",
          },
        },
  );
}

for (const profile of [
  "captcha-botid",
  "captcha-botid-denied",
  "captcha-botid-custom",
  "captcha-botid-throw",
  "captcha-botid-validator-throw",
] as const) {
  compatScenario(
    `CAPTCHA ${profile} actual configured BotID callbacks preserve middleware and principal boundaries`,
    async (ctx) => {
      const s = await principals(ctx);
      const observations = [];

      for (const allow of [false, true]) {
        const before = await ctx.readUserState({ userId: s.signup.data!.user.id });
        const result = await ctx.rawRequest({
          actor: `bot-${allow}`,
          path: authProfilePath(profile) + "/sign-in/email",
          method: "POST",
          json: { email: s.signup.data!.user.email, password: "password123" },
          headers: { ...ip, ...(allow ? { "x-allow-verified": "yes" } : {}) },
        });
        const status = profile.endsWith("-throw")
          ? 500
          : profile === "captcha-botid" || (profile.endsWith("-custom") && allow)
            ? 200
            : 403;
        expect(result.status).toBe(status);

        const authenticated =
          status === 200
            ? await restoreAttempt(ctx, `bot-${allow}`, result.body, s.signup.data!.user.id)
            : null;
        const after = await ctx.readUserState({ userId: s.signup.data!.user.id });
        const receipts = await events(ctx);
        expect(receipts.some((e) => e.kind === "bot-check")).toBe(true);
        expect(receipts.some((e) => e.kind === "provider")).toBe(false);

        if (status !== 200) {
          expect(after).toEqual(before);
          expect(receipts.some((e) => e.kind === "early-b" || e.kind === "before")).toBe(false);
        } else {
          expect(result.body).toMatchObject({ user: { id: s.signup.data!.user.id } });
          expect(receipts.at(-1)).toMatchObject({ kind: "before" });
        }

        expect(await ctx.readUserState({ userId: s.other.data!.user.id })).toEqual(s.foreignBefore);

        observations.push({ allow, before, result, authenticated, after, receipts });
      }

      return {
        signup: ctx.snapshot(s.signup),
        other: ctx.snapshot(s.other),
        foreignBefore: s.foreignBefore,
        observations,
        foreignAfter: await ctx.readUserState({ userId: s.other.data!.user.id }),
      };
    },
    ["POST /sign-in/email"],
  );
}

compatScenario(
  "CAPTCHA verifier deadlines reject without auth writes while BotID application callbacks finish",
  async (ctx) => {
    const s = await principals(ctx);
    const observations = [];

    for (const profile of ["captcha-turnstile", "captcha-botid-timeout"] as const) {
      const before = await ctx.readUserState({ userId: s.signup.data!.user.id });
      const started = Date.now();
      const result = await ctx.rawRequest({
        path: authProfilePath(profile) + "/sign-in/email",
        method: "POST",
        json: { email: s.signup.data!.user.email, password: "password123" },
        headers: { ...ip, "x-captcha-response": "timeout" },
      });
      const elapsed = Date.now() - started;
      expect(result.status).toBe(500);
      expect(result.body).toEqual({ message: "Something went wrong", code: "UNKNOWN_ERROR" });
      expect(elapsed).toBeGreaterThanOrEqual(9_000);

      const rejected = await events(ctx);
      expect(rejected.map((event) => event.kind)).toEqual(
        profile === "captcha-turnstile" ? ["early-a", "provider"] : ["early-a", "bot-check"],
      );
      expect(await ctx.readUserState({ userId: s.signup.data!.user.id })).toEqual(before);

      await Bun.sleep(1_500);
      const completed = await events(ctx);
      expect(completed).toEqual(
        profile === "captcha-turnstile" ? [] : [{ profile, kind: "bot-finished" }],
      );

      const after = await ctx.readUserState({ userId: s.signup.data!.user.id });
      expect(after).toEqual(before);
      expect(await ctx.readUserState({ userId: s.other.data!.user.id })).toEqual(s.foreignBefore);

      observations.push({ profile, before, result, rejected, completed, after });
    }

    return {
      initial: ctx.snapshot(s.signup),
      foreign: ctx.snapshot(s.other),
      foreignBefore: s.foreignBefore,
      observations,
      foreignAfter: await ctx.readUserState({ userId: s.other.data!.user.id }),
    };
  },
  ["POST /sign-in/email"],
  65_000,
);

compatScenario(
  "CAPTCHA physical method rejection precedes CORS router resolution and disabled paths suppress every hook",
  async (ctx) => {
    const s = await principals(ctx);
    const observations = [];

    for (const profile of ["captcha-turnstile", "captcha-turnstile-disabled"] as const) {
      for (const method of ["GET", "OPTIONS", "PUT"] as const) {
        const before = await ctx.readUserState({ userId: s.signup.data!.user.id });
        const result = await ctx.rawRequest({
          path: authProfilePath(profile) + "/sign-in/email",
          method,
          headers: {
            ...ip,
            origin: "https://foreign.fixture.test",
            "access-control-request-method": "POST",
          },
        });
        expect(result.status).toBe(profile === "captcha-turnstile" ? 400 : 404);

        if (profile === "captcha-turnstile") {
          expect(result.body).toEqual({
            message: "Missing CAPTCHA response",
            code: "MISSING_RESPONSE",
          });
        }

        const receipts = await events(ctx);
        expect(receipts.map((event) => event.kind)).toEqual(
          profile === "captcha-turnstile" ? ["early-a"] : [],
        );

        const after = await ctx.readUserState({ userId: s.signup.data!.user.id });
        expect(after).toEqual(before);
        expect(await ctx.readUserState({ userId: s.other.data!.user.id })).toEqual(s.foreignBefore);

        observations.push({ profile, method, before, result, receipts, after });
      }
    }

    return {
      initial: ctx.snapshot(s.signup),
      foreign: ctx.snapshot(s.other),
      foreignBefore: s.foreignBefore,
      observations,
      foreignAfter: await ctx.readUserState({ userId: s.other.data!.user.id }),
    };
  },
  ["GET /sign-in/email", "OPTIONS /sign-in/email", "PUT /sign-in/email"],
);

compatScenario(
  "CAPTCHA verifier timeout ends at response headers and slow successful bodies still admit the real principal",
  async (ctx) => {
    const s = await principals(ctx);
    const before = await ctx.readUserState({ userId: s.signup.data!.user.id });
    const started = Date.now();
    const result = await ctx.rawRequest({
      actor: "slow-body",
      path: authProfilePath("captcha-turnstile") + "/sign-in/email",
      method: "POST",
      json: { email: s.signup.data!.user.email, password: "password123" },
      headers: { ...ip, "x-captcha-response": "slow-body" },
    });
    expect(result.status).toBe(200);
    expect(result.body).toMatchObject({ user: { id: s.signup.data!.user.id } });
    expect(Date.now() - started).toBeGreaterThanOrEqual(10_500);

    const receipts = await events(ctx);
    expect(receipts.map((event) => event.kind)).toEqual([
      "early-a",
      "provider",
      "early-b",
      "before",
    ]);

    const authenticated = await ctx.actor("slow-body").client.getSession();
    expect(authenticated.error).toBeNull();
    expect(authenticated.data!.user.id).toBe(s.signup.data!.user.id);

    const body = result.body;

    if (
      body === null ||
      typeof body !== "object" ||
      !("token" in body) ||
      typeof body.token !== "string"
    ) {
      throw new Error("Admitted sign-in must issue a real session token");
    }

    expect(authenticated.data!.session.token).toBe(body.token);

    const authenticatedReceipts = await events(ctx);
    const after = await ctx.readUserState({ userId: s.signup.data!.user.id });
    expect(after).not.toEqual(before);
    expect(await ctx.readUserState({ userId: s.other.data!.user.id })).toEqual(s.foreignBefore);

    return {
      authenticated: ctx.snapshot(authenticated),
      authenticatedReceipts,
      initial: ctx.snapshot(s.signup),
      foreign: ctx.snapshot(s.other),
      foreignBefore: s.foreignBefore,
      before,
      result,
      receipts,
      after,
      foreignAfter: await ctx.readUserState({ userId: s.other.data!.user.id }),
    };
  },
  ["POST /sign-in/email"],
  35_000,
);
