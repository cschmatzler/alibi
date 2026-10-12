import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { phoneClient, readPhoneState, uniquePhone } from "../../plugins/phone-number/helpers";

compatScenario(
  "server phone sign-in publishes owned usable sessions without an original request",
  async (ctx) => {
    const profile = "phone-default";
    const email = ctx.uniqueEmail("server-phone-login");
    const phoneNumber = uniquePhone(ctx, "server-phone-login");
    const password = "password123";
    const owner = await phoneClient(ctx, profile, "owner").signUp.email({
      email,
      password,
      name: "Phone Owner",
      phoneNumber,
    });
    expect(owner.error).toBeNull();
    const foreign = await phoneClient(ctx, profile, "foreign").signUp.email({
      email: ctx.uniqueEmail("server-phone-foreign"),
      password,
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
    const before = await state();
    const denied = [];
    for (const [body, status, code] of [
      [{ phoneNumber: 42, password }, 400, "VALIDATION_ERROR"],
      [{ phoneNumber, password, rememberMe: "no" }, 400, "VALIDATION_ERROR"],
      [{ phoneNumber, password: "wrong-password" }, 401, "INVALID_PHONE_NUMBER_OR_PASSWORD"],
      [{ phoneNumber: "+15559999999", password }, 401, "INVALID_PHONE_NUMBER_OR_PASSWORD"],
    ] as const) {
      const result = await ctx.rawRequest({
        path: "/__test/server-api/phone-sign-in",
        method: "POST",
        json: { profile, body },
      });
      expect(result.status).toBe(status);
      expect((result.body as { code: string }).code).toBe(code);
      expect(await state()).toEqual(before);
      denied.push(result);
    }
    const minted = [];
    for (const rememberMe of [undefined, false, true]) {
      const actorName = `server-phone-${String(rememberMe)}`;
      const response = await ctx
        .actor(actorName, profile)
        .fetch(`${ctx.baseURL}/__test/server-api/phone-sign-in`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            profile,
            body: {
              phoneNumber,
              password,
              userId: foreignId,
              ...(rememberMe === undefined ? {} : { rememberMe }),
            },
            headers: { "user-agent": "server-phone-sdk", "x-forwarded-for": "198.51.100.27" },
          }),
        });
      expect(response.status).toBe(200);
      const value = (await response.json()) as { token: string; user: { id: string } };
      expect(value.user.id).toBe(ownerId);
      const cookies = response.headers.getSetCookie();
      const tokenCookie = cookies.find((cookie) => cookie.includes("session_token="))!;
      expect(tokenCookie).toBeDefined();
      expect(tokenCookie.toLowerCase().includes("max-age=")).toBe(rememberMe !== false);
      const session = await phoneClient(ctx, profile, actorName).getSession();
      expect(session.error).toBeNull();
      expect(session.data!.user.id).toBe(ownerId);
      expect(session.data!.session.token).toBe(value.token);
      expect(session.data!.session.userAgent).toBe("server-phone-sdk");
      expect(session.data!.session.ipAddress).toBe("198.51.100.27");
      const stored = await readPhoneState(ctx, profile, ownerId);
      const physical = stored.sessions.find((row) => row.token === value.token)!;
      expect(physical).toBeDefined();
      const expected = rememberMe === false ? 86400 : 604800;
      const ttl = (Date.parse(physical.expiresAt) - Date.now()) / 1000;
      expect(ttl).toBeGreaterThan(expected - 2);
      expect(ttl).toBeLessThanOrEqual(expected);
      expect(stored.user).toEqual(before.owner.user);
      expect(stored.accounts).toEqual(before.owner.accounts);
      expect(await readPhoneState(ctx, profile, foreignId)).toEqual(before.foreign);
      minted.push({ value, cookieCount: cookies.length, session, stored });
    }
    expect((await readPhoneState(ctx, profile, ownerId)).sessions).toHaveLength(4);
    return ctx.snapshot({ before, denied, minted });
  },
);
