import { createAuthClient } from "better-auth/client";
import { multiSessionClient } from "better-auth/client/plugins";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

// Upstream reference: packages/better-auth/src/plugins/multi-session/multi-session.test.ts ::
// "multi-session database fallback" and sign-up.test.ts listing changes (1.7.12).
compatScenario(
  "secondary combined sessions list and switch from the database after cache eviction",
  async (ctx) => {
    const profile = "session-secondary-combined" as const;
    const browser = ctx.actor("browser", profile);
    const client = createAuthClient({
      baseURL: ctx.baseURL,
      plugins: [multiSessionClient()],
      fetchOptions: { customFetchImpl: browser.fetch },
    });
    const evict = async (token: string) => {
      const response = await ctx.rawRequest({
        path: "/__test/secondary-session/control",
        method: "POST",
        json: { profile, token, action: "remove" },
      });
      expect(response.status).toBe(200);
    };

    const first = await client.signUp.email({
      email: ctx.uniqueEmail("fallback-first"),
      name: "First holder",
      password: "password123",
    });
    const second = await client.signUp.email({
      email: ctx.uniqueEmail("fallback-second"),
      name: "Second holder",
      password: "password123",
    });
    const third = await client.signUp.email({
      email: ctx.uniqueEmail("fallback-third"),
      name: "Third holder",
      password: "password123",
    });
    expect(first.error).toBeNull();
    expect(second.error).toBeNull();
    expect(third.error).toBeNull();
    const firstToken = first.data!.token!;
    const thirdToken = third.data!.token!;

    // The cached copy of the first session disappears; the database row stays.
    await evict(firstToken);
    const devices = await client.multiSession.listDeviceSessions();
    expect(devices.error).toBeNull();
    expect(devices.data).toHaveLength(3);

    const owned = createAuthClient({
      baseURL: ctx.baseURL,
      fetchOptions: { customFetchImpl: ctx.actor("first-only", profile).fetch },
    });
    const signIn = await owned.signIn.email({
      email: first.data!.user.email,
      password: "password123",
    });
    expect(signIn.error).toBeNull();
    await evict(signIn.data!.token);
    const listed = await client.listSessions();
    expect(listed.error).toBeNull();

    // Revoking the active session switches to the first held session in
    // cookie order, including the one only the database still holds.
    const revoked = await client.multiSession.revoke({ sessionToken: thirdToken });
    expect(revoked.error).toBeNull();
    const active = await client.getSession();
    expect(active.data?.session.token).toBe(firstToken);
    const ownedSessions = await owned.listSessions();
    expect(ownedSessions.error).toBeNull();
    expect(ownedSessions.data!.map((session) => session.token).sort()).toEqual(
      [firstToken, signIn.data!.token].sort(),
    );

    return ctx.snapshot({
      first,
      second,
      third,
      devices,
      signIn,
      listed,
      revoked,
      active,
      ownedSessions,
    });
  },
  ["GET /multi-session/list-device-sessions", "POST /multi-session/revoke", "GET /list-sessions"],
);
