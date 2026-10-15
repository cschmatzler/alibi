import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
import {
  readUserState,
  storedVerification,
  verificationCount,
} from "../../../support/verification";
import { readOtp, deliveredOtpCount } from "../../plugins/email-otp/helpers";

for (const current of [false, true]) {
  compatScenario(
    `server email change lifecycle preserves proof and caller authority with current verification ${current}`,
    async (ctx) => {
      const profile = current ? "passwordless-proof" : "passwordless-disabled";
      const actor = ctx.actor("owner", profile);
      const email = ctx.uniqueEmail("server-change-owner");
      const newEmail = ctx.uniqueEmail("server-change-new");
      const otherEmail = ctx.uniqueEmail("server-change-other");
      let cookie = "";
      const owner = await actor.client.signUp.email({
        email,
        password: "password123",
        name: "Change Owner",
        fetchOptions: {
          onSuccess({ response }) {
            cookie = response.headers
              .getSetCookie()
              .map((raw) => raw.split(";")[0])
              .join("; ");
          },
        },
      });
      expect(owner.error).toBeNull();
      let foreignCookie = "";
      const foreign = await ctx.actor("foreign", profile).client.signUp.email({
        email: otherEmail,
        password: "password123",
        name: "Foreign",
        fetchOptions: {
          onSuccess({ response }) {
            foreignCookie = response.headers
              .getSetCookie()
              .map((raw) => raw.split(";")[0])
              .join("; ");
          },
        },
      });
      expect(foreign.error).toBeNull();
      const before = await readUserState(ctx, owner.data!.user.id);
      const foreignBefore = await readUserState(ctx, foreign.data!.user.id);
      async function create() {
        const result = await ctx.rawRequest({
          path: "/__test/server-api",
          method: "POST",
          json: { operation: "create-email-otp", profile, email, type: "email-verification" },
        });
        expect(result.status).toBe(200);
        return result.body as string;
      }
      async function invoke(body: unknown, authenticated = true, selected: string = profile) {
        return ctx.rawRequest({
          path: "/__test/server-api/email-otp-request-change",
          method: "POST",
          json: { profile: selected, body, ...(authenticated ? { headers: { cookie } } : {}) },
        });
      }
      const oldOtp = await create();
      const oldIdentifier = `email-verification-otp-${email}`;
      const proof = await storedVerification(ctx, oldIdentifier);
      const unauthenticated = await invoke({ newEmail }, false);
      expect(unauthenticated.status).toBe(401);
      expect((unauthenticated.body as { code: string }).code).toBe("UNAUTHORIZED");
      const denied = [];
      for (const [body, message] of [
        [{ newEmail: "not-an-email" }, "Invalid email"],
        [{ newEmail: email.toUpperCase() }, "Email is the same"],
      ] as const) {
        const result = await invoke(body);
        expect(result.status).toBe(400);
        expect((result.body as { message: string }).message).toBe(message);
        expect(await storedVerification(ctx, oldIdentifier)).toEqual(proof);
        denied.push(result);
      }
      let required;
      let wrong;
      if (current) {
        required = await invoke({ newEmail });
        expect(required.status).toBe(400);
        expect((required.body as { message: string }).message).toBe(
          "OTP is required to verify current email",
        );
        expect(await storedVerification(ctx, oldIdentifier)).toEqual(proof);
        wrong = await invoke({ newEmail, otp: "wrong" });
        expect(wrong.status).toBe(400);
        expect((wrong.body as { code: string }).code).toBe("INVALID_OTP");
      }
      const issued = await invoke({
        newEmail: newEmail.toUpperCase(),
        ignored: true,
        ...(current ? { otp: oldOtp } : {}),
      });
      expect(issued.status).toBe(200);
      expect(issued.body).toEqual({ success: true });
      const otp = await readOtp(ctx, newEmail, "change-email");
      const identifier = `change-email-otp-${email}-${newEmail}`;
      expect((await storedVerification(ctx, identifier))[0]!.value).toBe(`${otp}:0`);
      expect(await verificationCount(ctx, oldIdentifier)).toBe(current ? 0 : 1);
      expect(await readUserState(ctx, owner.data!.user.id)).toEqual(before);
      const hidden = await invoke({
        newEmail: otherEmail,
        ...(current ? { otp: await create() } : {}),
      });
      expect(hidden.status).toBe(200);
      expect(hidden.body).toEqual({ success: true });
      expect(await deliveredOtpCount(ctx, otherEmail, "change-email")).toBe(0);
      expect(await verificationCount(ctx, `change-email-otp-${email}-${otherEmail}`)).toBe(0);
      expect(await readUserState(ctx, owner.data!.user.id)).toEqual(before);
      const targetProof = await storedVerification(ctx, identifier);
      const disabled = await invoke({ newEmail }, true, "otp-change-disabled-false");
      expect(disabled.status).toBe(400);
      expect(disabled.body).toEqual({ message: "Change email with OTP is disabled" });
      expect(await storedVerification(ctx, identifier)).toEqual(targetProof);
      async function complete(body: unknown, credentials?: string) {
        const response = await ctx
          .actor("completion-sdk", profile)
          .fetch(`${ctx.baseURL}/__test/server-api/email-otp-change`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              profile,
              body,
              ...(credentials ? { headers: { cookie: credentials } } : {}),
            }),
          });
        return {
          status: response.status,
          body: (await response.json()) as any,
          cookieCount: response.headers.getSetCookie().length,
        };
      }
      const completionInvalid = await complete({ newEmail, otp: 42 }, cookie);
      expect(completionInvalid.status).toBe(400);
      expect(completionInvalid.body.code).toBe("VALIDATION_ERROR");
      expect(await storedVerification(ctx, identifier)).toEqual(targetProof);
      const completionUnauthenticated = await complete({ newEmail, otp });
      expect(completionUnauthenticated.status).toBe(401);
      expect(await storedVerification(ctx, identifier)).toEqual(targetProof);
      const foreignAttempt = await complete({ newEmail, otp }, foreignCookie);
      expect(foreignAttempt.status).toBe(400);
      expect(foreignAttempt.body.code).toBe("INVALID_OTP");
      expect(await storedVerification(ctx, identifier)).toEqual(targetProof);
      const completionWrong = await complete({ newEmail, otp: "wrong" }, cookie);
      expect(completionWrong.status).toBe(400);
      expect(completionWrong.body.code).toBe("INVALID_OTP");
      const changed = await complete(
        { newEmail: newEmail.toUpperCase(), otp, userId: foreign.data!.user.id },
        cookie,
      );
      expect(changed.status).toBe(200);
      expect(changed.body).toEqual({ success: true });
      expect(changed.cookieCount).toBeGreaterThan(0);
      expect(
        (await ctx.actor("completion-sdk", profile).client.getSession()).data!.user.email,
      ).toBe(newEmail);
      const completed = await readUserState(ctx, owner.data!.user.id);
      const replay = await complete({ newEmail, otp }, cookie);
      expect(replay.status).toBe(400);
      expect(replay.body.message).toBe("Email is the same");
      expect(await readUserState(ctx, owner.data!.user.id)).toEqual(completed);
      expect(await verificationCount(ctx, identifier)).toBe(0);
      expect((await actor.client.getSession()).data!.user.email).toBe(newEmail);
      expect(await readUserState(ctx, foreign.data!.user.id)).toEqual(foreignBefore);
      return ctx.snapshot({
        before,
        unauthenticated,
        denied,
        ...(required ? { required, wrong } : {}),
        issued,
        hidden,
        disabled,
        completionInvalid,
        completionUnauthenticated,
        foreignAttempt,
        completionWrong,
        changed,
        replay,
      });
    },
  );
}
