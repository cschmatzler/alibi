import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { storedVerification, verificationCount } from "../../../support/verification";
import {
  phoneClient,
  readPhoneOtp,
  readPhoneState,
  uniquePhone,
} from "../../plugins/phone-number/helpers";

compatScenario(
  "server phone verification preserves proof consumption and caller authority",
  async (ctx) => {
    const profile = "phone-default";
    const phoneNumber = uniquePhone(ctx, "server-phone-verification");
    let ownerCookie = "";
    const owner = await phoneClient(ctx, profile, "owner").signUp.email({
      email: ctx.uniqueEmail("verify-owner"),
      password: "password123",
      name: "Phone Owner",
      phoneNumber,
      fetchOptions: {
        onSuccess({ response }) {
          ownerCookie = response.headers
            .getSetCookie()
            .map((raw) => raw.split(";")[0])
            .join("; ");
        },
      },
    });
    expect(owner.error).toBeNull();
    const foreign = await phoneClient(ctx, profile, "foreign").signUp.email({
      email: ctx.uniqueEmail("verify-foreign"),
      password: "password123",
      name: "Foreign",
    });
    expect(foreign.error).toBeNull();
    const ownerId = owner.data!.user.id;
    const foreignId = foreign.data!.user.id;
    async function state() {
      return {
        owner: await readPhoneState(ctx, profile, ownerId),
        foreign: await readPhoneState(ctx, profile, foreignId),
      };
    }
    async function send(phone: string) {
      const result = await ctx.rawRequest({
        path: "/__test/server-api/phone-send-otp",
        method: "POST",
        json: { profile, body: { phoneNumber: phone } },
      });
      expect(result.status).toBe(200);
      return readPhoneOtp(ctx, phone);
    }
    async function invoke(body: unknown, headers?: Record<string, string>) {
      const response = await ctx
        .actor("verification-sdk", profile)
        .fetch(`${ctx.baseURL}/__test/server-api/phone-verification`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ profile, body, ...(headers ? { headers } : {}) }),
        });
      return {
        status: response.status,
        body: (await response.json()) as any,
        cookieCount: response.headers.getSetCookie().length,
      };
    }
    const code = await send(phoneNumber);
    const before = await state();
    const proof = await storedVerification(ctx, phoneNumber);
    const malformed = await invoke({ phoneNumber, code: 42 });
    expect(malformed.status).toBe(400);
    expect(malformed.body.code).toBe("VALIDATION_ERROR");
    expect(await storedVerification(ctx, phoneNumber)).toEqual(proof);
    expect(await state()).toEqual(before);
    const wrong = await invoke({ phoneNumber, code: "wrong" });
    expect(wrong.status).toBe(400);
    expect(wrong.body.code).toBe("INVALID_OTP");
    expect((await storedVerification(ctx, phoneNumber))[0]!.value).toBe(`${code}:1`);
    const verified = await invoke({
      phoneNumber,
      code,
      disableSession: true,
      username: "ignored",
      userId: foreignId,
    });
    expect(verified.status).toBe(200);
    expect(verified.body).toMatchObject({
      status: true,
      token: null,
      user: { id: ownerId, phoneNumberVerified: true },
    });
    expect(verified.cookieCount).toBe(0);
    expect(await verificationCount(ctx, phoneNumber)).toBe(0);
    expect((await readPhoneState(ctx, profile, ownerId)).sessions).toEqual(before.owner.sessions);
    const signedIn = await invoke({ phoneNumber, code: await send(phoneNumber) });
    expect(signedIn.status).toBe(200);
    expect(signedIn.body.user.id).toBe(ownerId);
    expect(signedIn.cookieCount).toBeGreaterThan(0);
    const session = await phoneClient(ctx, profile, "verification-sdk").getSession();
    expect(session.data!.user.id).toBe(ownerId);
    expect(session.data!.session.token).toBe(signedIn.body.token);
    const sessions = (await readPhoneState(ctx, profile, ownerId)).sessions;
    expect(sessions).toHaveLength(2);
    const newPhone = uniquePhone(ctx, "server-phone-update");
    const updated = await invoke(
      {
        phoneNumber: newPhone,
        code: await send(newPhone),
        updatePhoneNumber: true,
        userId: foreignId,
      },
      { cookie: ownerCookie },
    );
    expect(updated.status).toBe(200);
    expect(updated.body.user).toMatchObject({
      id: ownerId,
      phoneNumber: newPhone,
      phoneNumberVerified: true,
    });
    expect(updated.body.token).toBe(before.owner.sessions[0]!.token);
    expect(updated.cookieCount).toBe(0);
    const after = await readPhoneState(ctx, profile, ownerId);
    expect(after.sessions).toEqual(sessions);
    expect(after.accounts).toEqual(before.owner.accounts);
    expect(await readPhoneState(ctx, profile, foreignId)).toEqual(before.foreign);
    const deniedPhone = uniquePhone(ctx, "server-phone-unauthenticated-update");
    const deniedCode = await send(deniedPhone);
    const identities = await state();
    const denied = await invoke({
      phoneNumber: deniedPhone,
      code: deniedCode,
      updatePhoneNumber: true,
    });
    expect(denied.status).toBe(401);
    expect(denied.body.code).toBe("USER_NOT_FOUND");
    expect(denied.cookieCount).toBe(0);
    expect(await verificationCount(ctx, deniedPhone)).toBe(0);
    expect(await state()).toEqual(identities);
    const replay = await invoke({
      phoneNumber: deniedPhone,
      code: deniedCode,
      updatePhoneNumber: true,
    });
    expect(replay.status).toBe(400);
    expect(replay.body.code).toBe("OTP_NOT_FOUND");
    return ctx.snapshot({
      before,
      malformed,
      wrong,
      verified,
      signedIn,
      session,
      updated,
      denied,
      replay,
      after,
    });
  },
);
