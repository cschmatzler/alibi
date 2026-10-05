import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import { events, ip, principals } from "./middleware-shared";

for (const profile of [
  "captcha-turnstile-custom",
  "captcha-turnstile-wildcard",
  "captcha-turnstile-globstar",
  "captcha-turnstile-empty",
  "captcha-turnstile-disabled",
  "captcha-turnstile-no-secret",
] as const) {
  compatScenario(
    `CAPTCHA ${profile} path and early rejection ordering preserve unchanged physical principals`,
    async (ctx) => {
      const s = await principals(ctx);
      const observations = [];
      const path = authProfilePath(profile);

      for (const route of [
        "/sign-in/email",
        "/sign-in/email/extra",
        "/sign-in//email",
        "/sign-in/email/",
        "/request-password-reset",
        "/ok",
      ]) {
        const before = await ctx.readUserState({ userId: s.signup.data!.user.id });
        const protectedPath = profile.endsWith("-custom")
          ? route === "/ok"
          : profile.endsWith("-wildcard")
            ? ["/sign-in/email", "/sign-in//email", "/sign-in/email/"].includes(route)
            : profile.endsWith("-globstar")
              ? route.startsWith("/sign-in/")
              : [
                  "/sign-in/email",
                  "/sign-in//email",
                  "/sign-in/email/",
                  "/request-password-reset",
                ].includes(route);
        const result = await ctx.rawRequest({
          actor: "invalid",
          path: path + route,
          method: route === "/ok" ? "GET" : "POST",
          body: route === "/ok" ? undefined : "{",
          headers: { ...ip, "content-type": "text/plain", origin: "https://foreign.fixture.test" },
        });
        const receipts = await events(ctx);
        const after = await ctx.readUserState({ userId: s.signup.data!.user.id });

        if (
          profile.endsWith("-disabled") &&
          ["/sign-in/email", "/sign-in/email/"].includes(route)
        ) {
          expect(result.status).toBe(404);
          expect(receipts).toEqual([]);
        } else if (protectedPath) {
          expect(result.status).toBe(profile.endsWith("-no-secret") ? 500 : 400);
          expect(result.body).toMatchObject({
            code: profile.endsWith("-no-secret") ? "UNKNOWN_ERROR" : "MISSING_RESPONSE",
          });
          expect(receipts.map((e) => e.kind)).toEqual(["early-a"]);
        } else {
          expect(receipts.map((e) => e.kind)).toEqual(
            route === "/ok" ? ["early-a", "early-b", "before"] : ["early-a", "early-b"],
          );
        }

        expect(after).toEqual(before);
        expect(await ctx.readUserState({ userId: s.other.data!.user.id })).toEqual(s.foreignBefore);

        observations.push({ route, before, result, receipts, after });
      }

      return {
        signup: ctx.snapshot(s.signup),
        other: ctx.snapshot(s.other),
        foreignBefore: s.foreignBefore,
        observations,
        foreignAfter: await ctx.readUserState({ userId: s.other.data!.user.id }),
      };
    },
    ["POST /sign-in/email", "POST /request-password-reset"],
    30_000,
    profile === "captcha-turnstile-globstar"
      ? {}
      : {
          oracle: {
            unroutedRequests: "asserts malformed and extended sign-in paths are not routed",
          },
        },
  );
}
