import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import { events, ip, principals } from "./middleware-shared";

compatScenario(
  "CAPTCHA verifier deadlines reject without auth writes while BotID application callbacks finish",
  async (ctx) => {
    const s = await principals(ctx);
    const observations = [];

    for (const profile of ["captcha-turnstile", "captcha-botid-timeout"] as const) {
      const before = await ctx.readUserState({ userId: s.signup.data!.user.id });
      const started = Date.now();
      const result = await ctx.rawRequest({
        path: authProfilePath(profile) + "/sign-in/email",
        method: "POST",
        json: { email: s.signup.data!.user.email, password: "password123" },
        headers: { ...ip, "x-captcha-response": "timeout" },
      });
      const elapsed = Date.now() - started;
      expect(result.status).toBe(500);
      expect(result.body).toEqual({ message: "Something went wrong", code: "UNKNOWN_ERROR" });
      expect(elapsed).toBeGreaterThanOrEqual(9_000);

      const rejected = await events(ctx);
      expect(rejected.map((event) => event.kind)).toEqual(
        profile === "captcha-turnstile" ? ["early-a", "provider"] : ["early-a", "bot-check"],
      );
      expect(await ctx.readUserState({ userId: s.signup.data!.user.id })).toEqual(before);

      await Bun.sleep(1_500);
      const completed = await events(ctx);
      expect(completed).toEqual(
        profile === "captcha-turnstile" ? [] : [{ profile, kind: "bot-finished" }],
      );

      const after = await ctx.readUserState({ userId: s.signup.data!.user.id });
      expect(after).toEqual(before);
      expect(await ctx.readUserState({ userId: s.other.data!.user.id })).toEqual(s.foreignBefore);

      observations.push({ profile, before, result, rejected, completed, after });
    }

    return {
      initial: ctx.snapshot(s.signup),
      foreign: ctx.snapshot(s.other),
      foreignBefore: s.foreignBefore,
      observations,
      foreignAfter: await ctx.readUserState({ userId: s.other.data!.user.id }),
    };
  },
  ["POST /sign-in/email"],
  65_000,
);
