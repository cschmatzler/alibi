import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import {
  readUserState,
  storedVerification,
  verificationCount,
} from "../../../support/verification";
import { readOtp, deliveredOtpCount } from "../../plugins/email-otp/helpers";

for (const current of [false, true]) {
  compatScenario(
    `server email change request preserves proof and delivery scope with current verification ${current}`,
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
      const foreign = await ctx
        .actor("foreign", profile)
        .client.signUp.email({ email: otherEmail, password: "password123", name: "Foreign" });
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
      const changed = await actor.client.emailOtp.changeEmail({ newEmail, otp });
      expect(changed.error).toBeNull();
      expect(changed.data).toEqual({ success: true });
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
        changed,
      });
    },
  );
}
