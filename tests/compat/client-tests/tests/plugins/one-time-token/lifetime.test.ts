import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { oneTimeTokenClient } from "better-auth/client/plugins";
import { z } from "zod";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

compatScenario(
  "one-time token custom lifetime persists three seconds and expires without transferring a session",
  async (ctx) => {
    const profile = "ott-short-lived" as const;
    const make = (name: string) =>
      createAuthClient({
        baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
        plugins: [oneTimeTokenClient()],
        fetchOptions: { customFetchImpl: ctx.actor(name, profile).fetch },
      });
    const owner = make("lifetime-owner");
    const receiver = make("lifetime-receiver");
    const signup = await owner.signUp.email({
      email: ctx.uniqueEmail("lifetime-owner"),
      name: "Lifetime owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    const before = await ctx.readUserState({ userId: signup.data!.user.id });
    const started = Date.now();
    const expiring = await owner.oneTimeToken.generate();
    expect(expiring.error).toBeNull();
    const finished = Date.now();
    const identifier = `one-time-token:${expiring.data!.token}`;
    const schema = z.array(
      z.object({
        id: z.string(),
        identifier: z.string(),
        value: z.string(),
        expiresAt: z.string(),
      }),
    );
    const stored = schema.parse(await ctx.readVerificationState({ identifier }));
    expect(stored).toHaveLength(1);
    expect(stored[0]!.value).toBe(signup.data!.token!);
    const expiry = Date.parse(stored[0]!.expiresAt);
    expect(expiry).toBeGreaterThanOrEqual(started + 3000);
    expect(expiry).toBeLessThanOrEqual(finished + 3000);
    const live = await owner.oneTimeToken.generate();
    expect(live.error).toBeNull();
    const transferred = await receiver.oneTimeToken.verify({ token: live.data!.token });
    expect(transferred.error).toBeNull();
    expect(transferred.data?.user.id).toBe(signup.data!.user.id);
    const replay = await receiver.oneTimeToken.verify({ token: live.data!.token });
    expect(replay.error).toMatchObject({ status: 400, message: "Invalid token" });
    await Bun.sleep(Math.max(0, expiry - Date.now()) + 100);
    const expired = await make("expired-receiver").oneTimeToken.verify({
      token: expiring.data!.token,
    });
    expect(expired.error).toMatchObject({ status: 400, message: "Invalid token" });
    const afterExpiry = await ctx.readVerificationState({ identifier });
    expect(afterExpiry).toEqual([]);
    const anonymousSession = await make("expired-receiver").getSession();
    expect(anonymousSession.data).toBeNull();
    expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(before);
    return ctx.snapshot({
      signup,
      expiring,
      stored: stored.map((row) => ({ ...row, value: { token: row.value } })),
      live,
      transferred,
      replay,
      expired,
      afterExpiry,
      anonymousSession,
      before,
    });
  },
  ["GET /one-time-token/generate", "POST /one-time-token/verify"],
);
