import { expect } from "vitest";
import { z } from "zod";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import { readUserState, verificationCount } from "../../../support/verification";
import { passwordlessClient, readOtp } from "./helpers";

compatScenario(
  "new email OTP owner consumes a real proof before malformed username normalization fails and recovers with a fresh proof",
  async (ctx) => {
    const foreign = passwordlessClient(ctx, "foreign");
    const guest = passwordlessClient(ctx, "guest");
    const other = await foreign.signUp.email({
      email: ctx.uniqueEmail("malformed-foreign"),
      name: "Foreign",
      password: "password123",
    });
    expect(other.error).toBeNull();
    const foreignBefore = await readUserState(ctx, other.data!.user.id);
    const email = ctx.uniqueEmail("malformed-new-owner");
    const identifier = `sign-in-otp-${email}`;
    expect((await guest.emailOtp.sendVerificationOtp({ email, type: "sign-in" })).error).toBeNull();
    const otp = await readOtp(ctx, email, "sign-in");
    expect(await verificationCount(ctx, identifier)).toBe(1);
    const failure = await ctx.actor("guest").fetch(`${ctx.baseURL}/api/auth/sign-in/email-otp`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, otp, username: 5 }),
    });
    const rejected = {
      status: failure.status,
      body: await failure.text(),
      cookies: failure.headers.getSetCookie(),
    };
    expect(rejected.status).toBe(500);
    expect(rejected.body).toBe("");
    expect(rejected.cookies).toEqual([]);
    expect((await guest.getSession()).data).toBeNull();
    expect(await verificationCount(ctx, identifier)).toBe(0);
    expect(await readUserState(ctx, other.data!.user.id)).toEqual(foreignBefore);
    const replay = await guest.$fetch("/sign-in/email-otp", {
      method: "POST",
      body: { email, otp, username: "Recovered_Owner" },
    });
    expect(replay.error).toMatchObject({ status: 400, code: "INVALID_OTP" });
    expect((await guest.getSession()).data).toBeNull();
    expect(await verificationCount(ctx, identifier)).toBe(0);
    expect((await foreign.getSession()).data!.user.id).toBe(other.data!.user.id);
    expect((await guest.emailOtp.sendVerificationOtp({ email, type: "sign-in" })).error).toBeNull();
    const fresh = await readOtp(ctx, email, "sign-in");
    const accepted = await guest.$fetch("/sign-in/email-otp", {
      method: "POST",
      body: { email, otp: fresh, username: "Recovered_Owner", displayUsername: "Recovered Owner" },
    });
    expect(accepted.error).toBeNull();
    const payload = z
      .object({
        token: z.string(),
        user: z
          .object({
            id: z.string(),
            email: z.string(),
            emailVerified: z.boolean(),
            username: z.string(),
            displayUsername: z.string(),
          })
          .passthrough(),
      })
      .parse(accepted.data);
    expect(payload.user).toMatchObject({
      email,
      emailVerified: true,
      username: "recovered_owner",
      displayUsername: "Recovered Owner",
    });
    const current = await guest.getSession();
    expect(ctx.snapshot(current.data!.user)).toEqual(ctx.snapshot(payload.user));
    expect(current.data!.session.token).toBe(payload.token);
    const committed = await readUserState(ctx, payload.user.id);
    expect(committed.accounts).toHaveLength(0);
    expect(committed.sessions).toHaveLength(1);
    expect(await verificationCount(ctx, identifier)).toBe(0);
    const recoveryReplay = await guest.$fetch("/sign-in/email-otp", {
      method: "POST",
      body: { email, otp: fresh, username: "Recovered_Owner" },
    });
    expect(recoveryReplay.error).toMatchObject({ status: 400, code: "INVALID_OTP" });
    expect(await readUserState(ctx, payload.user.id)).toEqual(committed);
    expect(await readUserState(ctx, other.data!.user.id)).toEqual(foreignBefore);
    expect((await foreign.getSession()).data!.user.id).toBe(other.data!.user.id);
    return ctx.snapshot({ other, rejected, replay, accepted, current, recoveryReplay });
  },
  ["POST /sign-in/email-otp", "POST /email-otp/send-verification-otp", "GET /get-session"],
);

for (const input of [
  { label: "negative", value: -1, status: 400, username: null, display: null },
  { label: "zero", value: 0, status: 200, username: "0", display: null },
  { label: "false", value: false, status: 200, username: "0", display: null },
  { label: "preserve", value: 5, status: 200, username: "5", display: "5" },
] as const) {
  compatScenario(
    `raw email OTP ${input.label} username respects hook admission and actual scalar storage`,
    async (ctx) => {
      const profile = input.label === "preserve" ? "signup-username-preserve" : undefined;
      const guest = ctx.actor("raw-owner", profile);
      const foreign = ctx.actor("raw-foreign", profile);
      const foreignSignup = await foreign.client.signUp.email({
        email: ctx.uniqueEmail("raw-foreign"),
        password: "password123",
        name: "Foreign",
      });
      expect(foreignSignup.error).toBeNull();
      const foreignBefore = await readUserState(ctx, foreignSignup.data!.user.id);
      const email = ctx.uniqueEmail(`raw-${input.label}`);
      const sent = await guest.client.$fetch("/email-otp/send-verification-otp", {
        method: "POST",
        body: { email, type: "sign-in" },
      });
      expect(sent.error).toBeNull();
      let otp: string;
      if (profile) {
        const state = await ctx.rawRequest({
          path: `/__test/signup-policy/state?profile=${profile}`,
        });
        const events = z
          .object({
            events: z.array(
              z
                .object({
                  stage: z.string(),
                  email: z.string().optional(),
                  otp: z.string().optional(),
                })
                .passthrough(),
            ),
          })
          .parse(state.body).events;
        otp = z
          .string()
          .parse(events.findLast((row) => row.stage === "otp" && row.email === email)?.otp);
      } else {
        otp = await readOtp(ctx, email, "sign-in");
      }
      const path = profile ? authProfilePath(profile) : "/api/auth";
      const response = await guest.fetch(`${ctx.baseURL}${path}/sign-in/email-otp`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, otp, username: input.value }),
      });
      expect(response.status).toBe(input.status);
      const payload = (await response.json()) as unknown;
      expect(await verificationCount(ctx, `sign-in-otp-${email}`)).toBe(0);
      if (input.status === 400) {
        expect(payload).toMatchObject({ code: "INVALID_USERNAME" });
        expect(response.headers.getSetCookie()).toEqual([]);
        expect((await guest.client.getSession()).data).toBeNull();
      } else {
        const result = z
          .object({
            token: z.string(),
            user: z
              .object({
                id: z.string(),
                username: z.string(),
                displayUsername: z.string().nullable(),
                emailVerified: z.boolean(),
              })
              .passthrough(),
          })
          .parse(payload);
        expect(result.user).toMatchObject({
          username: input.username,
          displayUsername: input.display,
          emailVerified: true,
        });
        const current = await guest.client.getSession();
        expect(ctx.snapshot(current.data?.user)).toEqual(ctx.snapshot(result.user));
        expect(current.data?.session.token).toBe(result.token);
        const rows = await readUserState(ctx, result.user.id);
        expect(rows.accounts).toHaveLength(0);
        expect(rows.sessions).toHaveLength(1);
      }
      const replay = await guest.client.$fetch("/sign-in/email-otp", {
        method: "POST",
        body: { email, otp, username: "recovery" },
      });
      expect(replay.error).toMatchObject({ status: 400, code: "INVALID_OTP" });
      expect(await readUserState(ctx, foreignSignup.data!.user.id)).toEqual(foreignBefore);
      expect((await foreign.client.getSession()).data?.user.id).toBe(foreignSignup.data!.user.id);
      return ctx.snapshot({ foreignSignup, payload, replay });
    },
    ["POST /sign-in/email-otp", "POST /email-otp/send-verification-otp", "GET /get-session"],
  );
}
