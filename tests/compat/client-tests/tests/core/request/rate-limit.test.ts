import { expect } from "bun:test";
import { createHmac } from "node:crypto";

import { Cookie } from "tough-cookie";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../../support/scenario";
import { readUserState, verificationCount } from "../../../support/verification";
import { readOtp } from "../../plugins/email-otp/helpers";

async function request(ctx: ScenarioContext, path: string, ip: string, json: unknown) {
  const response = await ctx.actor("limiter").fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json", "x-forwarded-for": ip },
    body: JSON.stringify(json),
  });
  const body = JSON.parse(await response.text());
  const rawCookies = response.headers.getSetCookie();
  let cookie = null;

  if (rawCookies.length) {
    expect(rawCookies).toHaveLength(1);

    const raw = rawCookies[0]!;
    const parsed = Cookie.parse(raw);

    if (!parsed) {
      throw new Error("Session issuance must emit a parseable cookie");
    }

    expect(parsed.key).toBe("better-auth.session_token");

    const value = decodeURIComponent(parsed.value);
    const signature = createHmac("sha256", "compat-test-only-key-not-real-minimum-32chars")
      .update(body.token)
      .digest("base64");
    expect(value).toBe(`${body.token}.${signature}`);

    cookie = { name: parsed.key, token: body.token, attributes: raw.slice(raw.indexOf(";")) };
  }

  return {
    status: response.status,
    body,
    headers: {
      "content-type": response.headers.get("content-type"),
      "x-retry-after": response.headers.get("x-retry-after"),
      "set-cookie": cookie,
    },
  };
}

compatScenario(
  "ordered rate overrides reject signup before any user or session is created",
  async (ctx) => {
    const path = authProfilePath("rate-limit-ordered") + "/sign-up/email";
    const signup = (email: string, ip = "198.51.100.171") =>
      request(ctx, path, ip, { email, name: "Limited Owner", password: "Password123!" });
    const first = await signup(ctx.uniqueEmail("rate-first"));
    const second = await signup(ctx.uniqueEmail("rate-second"));
    expect(first.status).toBe(200);
    expect(second.status).toBe(200);

    const owner = (first.body as { user: { id: string } }).user.id;
    const before = await readUserState(ctx, owner);
    const blockedEmail = ctx.uniqueEmail("rate-blocked");
    const denied = await signup(blockedEmail);
    expect(denied).toEqual({
      status: 429,
      body: { message: "Too many requests. Please try again later." },
      headers: {
        "content-type": "application/json",
        "x-retry-after": "60",
        "set-cookie": null,
      },
    });
    expect(await readUserState(ctx, owner)).toEqual(before);

    const foreign = await signup(blockedEmail, "198.51.100.172");
    expect(foreign.status).toBe(200);
    expect((foreign.body as { user: { email: string } }).user.email).toBe(blockedEmail);

    // The different trusted client can create the blocked identity: no phantom
    // user/account/session survived the rejected request.
    const foreignState = await readUserState(
      ctx,
      (foreign.body as { user: { id: string } }).user.id,
    );
    expect(foreignState.accounts).toHaveLength(1);
    expect(foreignState.sessions).toHaveLength(1);

    const read = async (endpoint: string, bypass = false, zero = false) => {
      const wire = await ctx
        .actor("limiter")
        .fetch(authProfilePath("rate-limit-ordered") + endpoint, {
          headers: {
            "x-forwarded-for": "198.51.100.177",
            ...(bypass ? { "x-rate-bypass": "yes" } : {}),
            ...(zero ? { "x-rate-zero": "yes" } : {}),
          },
        });
      return {
        status: wire.status,
        body: await wire.json(),
        retry: wire.headers.get("x-retry-after"),
      };
    };
    const admitted = await read("/get-session");
    expect(admitted.status).toBe(200);
    expect(admitted.body.user.id).toBe((foreign.body as { user: { id: string } }).user.id);

    const rejected = await read("/get-session");
    expect(rejected.status).toBe(429);
    expect(rejected.retry).toBe("60");

    const bypassed = await read("/get-session", true);
    expect(bypassed).toEqual(admitted);

    const stillRejected = await read("/get-session");
    expect(stillRejected).toEqual(rejected);

    const reset = await read("/get-session", false, true);
    expect(reset).toEqual(admitted);

    const resumed = await read("/get-session");
    expect(resumed).toEqual(admitted);

    const deniedAgain = await read("/get-session");
    expect(deniedAgain).toEqual(rejected);

    const disabled = [];

    for (let index = 0; index < 3; index++) {
      const result = await read("/list-sessions");
      expect(result.status).toBe(200);
      expect(result.body).toHaveLength(1);

      disabled.push(result);
    }

    expect(await readUserState(ctx, (foreign.body as { user: { id: string } }).user.id)).toEqual(
      foreignState,
    );

    return {
      first,
      second,
      before,
      denied,
      foreign,
      foreignState,
      admitted,
      rejected,
      bypassed,
      stillRejected,
      reset,
      resumed,
      deniedAgain,
      disabled,
      ownerAfter: await readUserState(ctx, owner),
    };
  },
  ["POST /sign-up/email"],
);

compatScenario(
  "installed OTP quota blocks before consuming a valid proof and another client can redeem it once",
  async (ctx) => {
    const path = authProfilePath("rate-limit-default");
    const email = ctx.uniqueEmail("rate-proof");
    const sent = await request(ctx, path + "/email-otp/send-verification-otp", "198.51.100.173", {
      email,
      type: "sign-in",
    });
    expect(sent.status).toBe(200);

    const otp = await readOtp(ctx, email, "sign-in");
    const attempts = [];

    for (let index = 0; index < 3; index++) {
      const failed = await request(ctx, path + "/sign-in/email-otp", "198.51.100.174", {
        email: ctx.uniqueEmail("rate-missing-" + index),
        otp: "000000",
      });
      expect(failed.status).toBe(400);
      attempts.push(failed);
    }

    expect(await verificationCount(ctx, `sign-in-otp-${email}`)).toBe(1);

    const denied = await request(ctx, path + "/sign-in/email-otp", "198.51.100.174", {
      email,
      otp,
    });
    expect(denied).toEqual({
      status: 429,
      body: { message: "Too many requests. Please try again later." },
      headers: {
        "content-type": "application/json",
        "x-retry-after": "60",
        "set-cookie": null,
      },
    });
    expect(await verificationCount(ctx, `sign-in-otp-${email}`)).toBe(1);

    const redeemed = await request(ctx, path + "/sign-in/email-otp", "198.51.100.175", {
      email,
      otp,
    });
    expect(redeemed.status).toBe(200);
    expect(await verificationCount(ctx, `sign-in-otp-${email}`)).toBe(0);

    const state = await readUserState(ctx, (redeemed.body as { user: { id: string } }).user.id);
    expect(state.sessions).toHaveLength(1);

    const replay = await request(ctx, path + "/sign-in/email-otp", "198.51.100.176", {
      email,
      otp,
    });
    expect(replay.status).toBe(400);
    expect(await readUserState(ctx, (redeemed.body as { user: { id: string } }).user.id)).toEqual(
      state,
    );

    return { sent, attempts, denied, redeemed, state, replay };
  },
  ["POST /email-otp/send-verification-otp", "POST /sign-in/email-otp"],
);
