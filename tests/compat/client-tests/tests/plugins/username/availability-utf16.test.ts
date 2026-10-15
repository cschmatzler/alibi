import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "default username availability checks UTF-16 bounds before character validation without writing principals",
  async (ctx) => {
    const profile = "signup-username";
    const reset = await ctx.rawRequest({
      path: "/__test/signup-policy",
      method: "POST",
      json: { operation: "mode", mode: "normal" },
    });
    expect(reset.status).toBe(200);
    const owner = ctx.actor("utf16-owner", profile);
    const guest = ctx.actor("utf16-guest", profile);
    const signup = await owner.client.signUp.email({
      email: ctx.uniqueEmail("availability-owner"),
      name: "Username owner",
      password: "password123",
      username: "taken_name",
    });
    expect(signup.error).toBeNull();
    const physical = async () => {
      const response = await ctx.rawRequest({
        path: `/__test/signup-policy/state?profile=${profile}`,
      });
      expect(response.status).toBe(200);
      const state = response.body as Record<string, unknown>;
      return {
        users: state.users,
        accounts: state.accounts,
        sessions: state.sessions,
        verifications: state.verifications,
      };
    };
    const beforeLogin = await physical();
    async function signIn(body: unknown) {
      const response = await owner.fetch(`${ctx.baseURL}/__test/server-api/username-sign-in`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          profile,
          body,
          headers: { "user-agent": "Username-SDK", "x-forwarded-for": "203.0.113.67" },
        }),
      });
      return {
        status: response.status,
        body: (await response.json()) as any,
        cookieCount: response.headers.getSetCookie().length,
        persistent: response.headers
          .getSetCookie()
          .find((raw) => raw.startsWith("better-auth.session_token="))
          ?.includes("Max-Age="),
      };
    }
    const loginErrors = [];
    for (const [input, status, code] of [
      [{ username: 42, password: "password123" }, 400, "VALIDATION_ERROR"],
      [{ username: "taken_name", password: "wrong-password" }, 401, "INVALID_USERNAME_OR_PASSWORD"],
      [{ username: "missing_name", password: "password123" }, 401, "INVALID_USERNAME_OR_PASSWORD"],
    ] as const) {
      const denied = await signIn(input);
      expect(denied.status).toBe(status);
      expect(denied.body.code).toBe(code);
      loginErrors.push(denied);
    }
    expect(await physical()).toEqual(beforeLogin);
    const login = await signIn({
      username: "TAKEN_NAME",
      password: "password123",
      rememberMe: false,
      userId: "foreign-selector",
    });
    expect(login.status).toBe(200);
    expect(login.body.user.id).toBe(signup.data!.user.id);
    expect(login.cookieCount).toBeGreaterThan(0);
    expect(login.persistent).toBe(false);
    const before = await physical();
    async function invoke(body: unknown) {
      const response = await guest.fetch(`${ctx.baseURL}/__test/server-api/username-available`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ profile, body }),
      });
      const result = {
        status: response.status,
        body: (await response.json()) as any,
        cookieCount: response.headers.getSetCookie().length,
      };
      expect(result.cookieCount).toBe(0);
      return result;
    }
    const malformed = await invoke({ username: 42 });
    expect(malformed.status).toBe(400);
    expect((malformed.body as any).code).toBe("VALIDATION_ERROR");
    expect(await physical()).toEqual(before);
    const denied = [];
    for (const [username, code] of [
      ["😀", "USERNAME_TOO_SHORT"],
      ["😀😀", "INVALID_USERNAME"],
      ["a".repeat(29) + "😀", "USERNAME_TOO_LONG"],
    ] as const) {
      const result = await invoke({ username });
      expect(result.status).toBe(422);
      expect((result.body as any).code).toBe(code);
      expect(await physical()).toEqual(before);
      denied.push({ username, result: ctx.snapshot(result) });
    }
    const available = await invoke({ username: "fresh_ascii", userId: "foreign-selector" });
    expect(available.status).toBe(200);
    expect(available.body).toEqual({ available: true });
    const taken = await invoke({ username: "TAKEN_NAME" });
    expect(taken.status).toBe(200);
    expect(taken.body).toEqual({ available: false });
    expect(await physical()).toEqual(before);
    const session = await owner.client.getSession();
    expect(session.data?.user.id).toBe(signup.data!.user.id);
    expect(session.data?.session.userAgent).toBe("Username-SDK");
    expect(session.data?.session.ipAddress).toBe("203.0.113.67");
    expect((await guest.client.getSession()).data).toBeNull();
    expect(await physical()).toEqual(before);
    return {
      signup: ctx.snapshot(signup),
      loginErrors,
      login: ctx.snapshot(login),
      denied,
      available: ctx.snapshot(available),
      taken: ctx.snapshot(taken),
      session: ctx.snapshot(session),
    };
  },
  ["POST /is-username-available"],
);
