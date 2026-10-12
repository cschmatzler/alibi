import { expect } from "bun:test";

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
    const login = await owner.client.signIn.username({
      username: "taken_name",
      password: "password123",
    });
    expect(login.error).toBeNull();
    expect(login.data?.user.id).toBe(signup.data!.user.id);
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
    expect((await guest.client.getSession()).data).toBeNull();
    expect(await physical()).toEqual(before);
    return {
      signup: ctx.snapshot(signup),
      login: ctx.snapshot(login),
      denied,
      available: ctx.snapshot(available),
      taken: ctx.snapshot(taken),
      session: ctx.snapshot(session),
    };
  },
  ["POST /is-username-available"],
);
