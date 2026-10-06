import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import { events, ip, principals, restoreAttempt } from "./middleware-shared";

for (const profile of [
  "captcha-turnstile",
  "captcha-turnstile-configured",
  "captcha-google",
  "captcha-google-configured",
  "captcha-google-zero",
  "captcha-hcaptcha",
  "captcha-hcaptcha-sitekey",
  "captcha-captchafox",
  "captcha-captchafox-sitekey",
  "captcha-turnstile-ip-disabled",
  "captcha-turnstile-ip-custom",
] as const) {
  compatScenario(
    `CAPTCHA ${profile} actual verification transport admits only provider-approved authentication`,
    async (ctx) => {
      const s = await principals(ctx);
      const path = authProfilePath(profile);
      const observations = [];

      for (const token of [
        "",
        "denied",
        "http-failure",
        "invalid-json",
        "null",
        "wrong-action",
        "wrong-host",
        "low-score",
        "v2",
        "valid",
        "special & = % + /",
        "blob-json",
        "empty-text",
        "truthy-success",
        "score-text",
        "score-null",
        "missing-action",
        "missing-host",
      ]) {
        const configured = profile.endsWith("-configured");
        const google = profile.includes("google");
        const status = !token
          ? 400
          : ["http-failure", "null", "empty-text"].includes(token)
            ? 500
            : ["denied", "invalid-json", "blob-json"].includes(token) ||
                (configured &&
                  ["wrong-action", "wrong-host", "missing-action", "missing-host"].includes(
                    token,
                  )) ||
                (google && profile !== "captcha-google-zero" && token === "low-score")
              ? 403
              : 200;
        const before = await ctx.readUserState({ userId: s.signup.data!.user.id });
        const headers = {
          ...ip,
          ...(profile.endsWith("-ip-custom") ? { "x-fixture-ip": "198.51.100.9" } : {}),
          ...(token ? { "x-captcha-response": token } : {}),
        };
        const result = await ctx.rawRequest({
          actor: `attempt-${token}`,
          path: path + "/sign-in/email",
          method: "POST",
          json: { email: s.signup.data!.user.email, password: "password123" },
          headers,
        });
        expect(result.status).toBe(status);

        const authenticated =
          status === 200
            ? await restoreAttempt(ctx, `attempt-${token}`, result.body, s.signup.data!.user.id)
            : null;
        const after = await ctx.readUserState({ userId: s.signup.data!.user.id });
        const receipts = await events(ctx);

        if (status !== 200) {
          expect(result.body).toMatchObject({
            code:
              status === 400
                ? "MISSING_RESPONSE"
                : status === 403
                  ? "VERIFICATION_FAILED"
                  : "UNKNOWN_ERROR",
          });
          expect(after).toEqual(before);
          expect(receipts.some((e) => e.kind === "before" || e.kind === "early-b")).toBe(false);
        } else {
          expect(result.body).toMatchObject({ user: { id: s.signup.data!.user.id } });
          expect(receipts.at(-1)).toMatchObject({ kind: "before", path: "/sign-in/email" });
        }

        const provider = receipts.find((e) => e.kind === "provider");
        const providerBody = provider?.body as Record<string, unknown> | undefined;

        if (token) {
          expect(provider!.body).toMatchObject({
            secret: "fixture-captcha-secret",
            response: token,
          });
          expect(providerBody?.remoteip ?? providerBody?.remoteIp).toBe(
            profile.endsWith("-ip-disabled")
              ? undefined
              : profile.endsWith("-ip-custom")
                ? "198.51.100.9"
                : "203.0.113.7",
          );
          if (profile.endsWith("-sitekey")) {
            expect(providerBody?.sitekey).toBe("fixture-site-key");
          }
        } else {
          expect(provider).toBeUndefined();
        }

        expect(await ctx.readUserState({ userId: s.other.data!.user.id })).toEqual(s.foreignBefore);

        observations.push({
          captchaResponse: token,
          before,
          result,
          authenticated,
          after,
          receipts,
        });
      }

      const newcomer = ctx.actor("new-owner", profile);
      const newSignup = await newcomer.client.signUp.email(
        { email: ctx.uniqueEmail("new-owner"), password: "password123", name: "Protected" },
        { headers: { ...ip, "x-fixture-ip": "198.51.100.9", "x-captcha-response": "valid" } },
      );
      expect(newSignup.error).toBeNull();

      const signupReceipts = await events(ctx);
      expect(signupReceipts.at(-1)).toMatchObject({ kind: "before", path: "/sign-up/email" });

      const authenticated = await newcomer.client.getSession();
      expect(authenticated.error).toBeNull();
      expect(authenticated.data!.user).toEqual(newSignup.data!.user);

      const signupToken = newSignup.data!.token;

      if (typeof signupToken !== "string") {
        throw new Error("Protected signup must issue a real session token");
      }

      expect(authenticated.data!.session.token).toBe(signupToken);

      const authenticatedReceipts = await events(ctx);
      return {
        authenticated: ctx.snapshot(authenticated),
        authenticatedReceipts,
        initial: ctx.snapshot(s.signup),
        other: ctx.snapshot(s.other),
        foreignBefore: s.foreignBefore,
        observations,
        newSignup: ctx.snapshot(newSignup),
        newState: await ctx.readUserState({ userId: newSignup.data!.user.id }),
        signupReceipts,
        foreignAfter: await ctx.readUserState({ userId: s.other.data!.user.id }),
      };
    },
    ["POST /sign-in/email", "POST /sign-up/email"],
  );
}
