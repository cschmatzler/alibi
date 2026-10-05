import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import { events, ip, principals } from "./middleware-shared";

compatScenario(
  "CAPTCHA physical method rejection precedes CORS router resolution and disabled paths suppress every hook",
  async (ctx) => {
    const s = await principals(ctx);
    const observations = [];

    for (const profile of ["captcha-turnstile", "captcha-turnstile-disabled"] as const) {
      for (const method of ["GET", "OPTIONS", "PUT"] as const) {
        const before = await ctx.readUserState({ userId: s.signup.data!.user.id });
        const result = await ctx.rawRequest({
          path: authProfilePath(profile) + "/sign-in/email",
          method,
          headers: {
            ...ip,
            origin: "https://foreign.fixture.test",
            "access-control-request-method": "POST",
          },
        });
        expect(result.status).toBe(profile === "captcha-turnstile" ? 400 : 404);

        if (profile === "captcha-turnstile") {
          expect(result.body).toEqual({
            message: "Missing CAPTCHA response",
            code: "MISSING_RESPONSE",
          });
        }

        const receipts = await events(ctx);
        expect(receipts.map((event) => event.kind)).toEqual(
          profile === "captcha-turnstile" ? ["early-a"] : [],
        );

        const after = await ctx.readUserState({ userId: s.signup.data!.user.id });
        expect(after).toEqual(before);
        expect(await ctx.readUserState({ userId: s.other.data!.user.id })).toEqual(s.foreignBefore);

        observations.push({ profile, method, before, result, receipts, after });
      }
    }

    return {
      initial: ctx.snapshot(s.signup),
      foreign: ctx.snapshot(s.other),
      foreignBefore: s.foreignBefore,
      observations,
      foreignAfter: await ctx.readUserState({ userId: s.other.data!.user.id }),
    };
  },
  ["GET /sign-in/email", "OPTIONS /sign-in/email", "PUT /sign-in/email"],
);
