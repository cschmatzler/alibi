import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import { events, ip, principals, restoreAttempt } from "./middleware-shared";

for (const profile of [
  "captcha-botid",
  "captcha-botid-denied",
  "captcha-botid-custom",
  "captcha-botid-throw",
  "captcha-botid-validator-throw",
] as const) {
  compatScenario(
    `CAPTCHA ${profile} actual configured BotID callbacks preserve middleware and principal boundaries`,
    async (ctx) => {
      const s = await principals(ctx);
      const observations = [];

      for (const allow of [false, true]) {
        const before = await ctx.readUserState({ userId: s.signup.data!.user.id });
        const result = await ctx.rawRequest({
          actor: `bot-${allow}`,
          path: authProfilePath(profile) + "/sign-in/email",
          method: "POST",
          json: { email: s.signup.data!.user.email, password: "password123" },
          headers: { ...ip, ...(allow ? { "x-allow-verified": "yes" } : {}) },
        });
        const status = profile.endsWith("-throw")
          ? 500
          : profile === "captcha-botid" || (profile.endsWith("-custom") && allow)
            ? 200
            : 403;
        expect(result.status).toBe(status);

        const authenticated =
          status === 200
            ? await restoreAttempt(ctx, `bot-${allow}`, result.body, s.signup.data!.user.id)
            : null;
        const after = await ctx.readUserState({ userId: s.signup.data!.user.id });
        const receipts = await events(ctx);
        expect(receipts.some((e) => e.kind === "bot-check")).toBe(true);
        expect(receipts.some((e) => e.kind === "provider")).toBe(false);

        if (status !== 200) {
          expect(after).toEqual(before);
          expect(receipts.some((e) => e.kind === "early-b" || e.kind === "before")).toBe(false);
        } else {
          expect(result.body).toMatchObject({ user: { id: s.signup.data!.user.id } });
          expect(receipts.at(-1)).toMatchObject({ kind: "before" });
        }

        expect(await ctx.readUserState({ userId: s.other.data!.user.id })).toEqual(s.foreignBefore);

        observations.push({ allow, before, result, authenticated, after, receipts });
      }

      return {
        signup: ctx.snapshot(s.signup),
        other: ctx.snapshot(s.other),
        foreignBefore: s.foreignBefore,
        observations,
        foreignAfter: await ctx.readUserState({ userId: s.other.data!.user.id }),
      };
    },
    ["POST /sign-in/email"],
  );
}
