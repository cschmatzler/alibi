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
    const denied = [];
    for (const [username, code] of [
      ["😀", "USERNAME_TOO_SHORT"],
      ["😀😀", "INVALID_USERNAME"],
      ["a".repeat(29) + "😀", "USERNAME_TOO_LONG"],
    ] as const) {
      let cookies: string[] = [];
      const result = await guest.client.isUsernameAvailable(
        { username },
        {
          onResponse({ response }) {
            cookies = response.headers.getSetCookie();
          },
        },
      );
      expect(result.error).toMatchObject({ status: 422, code });
      expect(result.data).toBeNull();
      expect(cookies).toEqual([]);
      expect(await physical()).toEqual(before);
      denied.push({ username, result: ctx.snapshot(result), cookies });
    }
    const available = await guest.client.isUsernameAvailable({ username: "fresh_ascii" });
    expect(available.error).toBeNull();
    expect(available.data).toEqual({ available: true });
    const taken = await guest.client.isUsernameAvailable({ username: "TAKEN_NAME" });
    expect(taken.error).toBeNull();
    expect(taken.data).toEqual({ available: false });
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
