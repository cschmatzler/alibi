import { setTimeout } from "node:timers/promises";

import { expect } from "vitest";

import { cacheReceipt } from "../../../support/compact-cache-receipt";
import { authProfilePath } from "../../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../../support/scenario";
import { applicationHeaders } from "../../../support/trace";

function object(value: unknown): Record<string, any> {
  expect(value).not.toBeNull();
  expect(typeof value).toBe("object");
  return value as Record<string, any>;
}
async function invoke(
  ctx: ScenarioContext,
  profile: "server-dispatch" | "server-dispatch-cache",
  input: Record<string, unknown>,
) {
  const response = await ctx.rawRequest({
    path: `/__test/${profile}/call`,
    method: "POST",
    json: { operation: "getSession", ...input },
  });
  expect(response.status).toBe(200);
  return object(response.body);
}
for (const compact of [false, true]) {
  compatScenario(
    `server getSession returns identity absence renewal and every cookie with compact cache ${compact}`,
    async (ctx) => {
      const profile = compact ? "server-dispatch-cache" : "server-dispatch";
      const admission = [];
      for (const input of [{}, { headers: {}, query: [] }, { headers: {}, query: "raw" }]) {
        const rejected = await invoke(ctx, profile, input);
        expect(rejected.result.ok).toBe(false);
        expect(rejected.result.status).toBe(400);
        expect(rejected.result.body.code).toBe("VALIDATION_ERROR");
        admission.push(rejected);
      }
      const absent = await invoke(ctx, profile, { headers: {} });
      expect(absent.result.ok).toBe(true);
      expect(absent.result.value.response).toBeNull();
      expect(Object.hasOwn(absent.result.value, "status")).toBe(false);
      expect(absent.result.value.headers["cache-control"]).toBe("no-store");
      expect(absent.result.value.headers.pragma).toBe("no-cache");
      expect(absent.result.value.cookies).toEqual([]);
      const email = ctx.uniqueEmail("typed-session");
      const owner = ctx.actor("typed-session-owner", profile);
      const foreign = ctx.actor("typed-session-foreign", profile);
      const accepted = await owner.fetch(
        `${ctx.baseURL}${authProfilePath(profile)}/sign-up/email`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            email,
            name: "Session Owner",
            password: "Correct-Horse-Password-205",
          }),
        },
      );
      expect(accepted.status).toBe(200);
      const signup = object(await accepted.json());
      const publication = {
        status: accepted.status,
        headers: applicationHeaders(accepted.headers),
        body: signup,
        ...(compact ? await cacheReceipt(accepted.headers) : {}),
      };
      const header = accepted.headers
        .getSetCookie()
        .map((cookie) => cookie.split(";")[0])
        .join("; ");
      expect(header).toContain("better-auth.session_token=");
      const other = await foreign.client.signUp.email({
        email: ctx.uniqueEmail("typed-session-foreign"),
        name: "Foreign",
        password: "Correct-Horse-Password-205",
      });
      expect(other.error).toBeNull();
      const before = await ctx.readUserState({ userId: signup.user.id });
      const valid = await invoke(ctx, profile, { headers: { cookie: header } });
      expect(valid.result.ok).toBe(true);
      expect(valid.result.value.response.user.id).toBe(signup.user.id);
      expect(valid.result.value.response.session.token).toBe(signup.token);
      expect(await ctx.readUserState({ userId: signup.user.id })).toEqual(before);
      const { createLocalJWKSet, jwtVerify } = await import("jose");
      const jwks = await invoke(ctx, profile, { operation: "getJwks" });
      expect(jwks.result.ok).toBe(true);
      const verifier = createLocalJWKSet(jwks.result.value.response);
      let previousSecond = (await jwtVerify(valid.result.value.headers["set-auth-jwt"], verifier))
        .payload.iat!;
      expect(Number.isInteger(previousSecond)).toBe(true);
      async function laterSession(input: Record<string, unknown>) {
        // Consecutive default JWTs can be byte-identical within one second.
        // Observe distinct actual issuance seconds, as the existing dispatch owner does.
        while (Math.floor(Date.now() / 1000) <= previousSecond) {
          await setTimeout(Math.max(1, (previousSecond + 1) * 1000 - Date.now()));
        }
        const observed = await invoke(ctx, profile, input);
        if (observed.result.ok) {
          const verified = await jwtVerify(observed.result.value.headers["set-auth-jwt"], verifier);
          expect(verified.payload.iat!).toBeGreaterThan(previousSecond);
          previousSecond = verified.payload.iat!;
        }
        return observed;
      }
      const due = new Date(Date.now() + 3_600_000).toISOString();
      const clock = await ctx.rawRequest({
        path: "/__test/expire-session",
        method: "POST",
        json: { token: signup.token, expiresAt: due },
      });
      expect(clock.status).toBe(200);
      const unchanged = await ctx.readUserState({ userId: signup.user.id });
      const noRefresh = await laterSession({
        headers: { cookie: header },
        query: { disableCookieCache: true, disableRefresh: true },
      });
      expect(noRefresh.result.ok).toBe(true);
      expect(new Date(noRefresh.result.value.response.session.expiresAt).getTime()).toBe(
        new Date(due).getTime(),
      );
      expect(await ctx.readUserState({ userId: signup.user.id })).toEqual(unchanged);
      const renewed = await laterSession({
        headers: { cookie: header },
        query: { disableCookieCache: true },
      });
      expect(renewed.result.ok).toBe(true);
      expect(renewed.result.value.response.session.token).toBe(signup.token);
      expect(new Date(renewed.result.value.response.session.expiresAt).getTime()).toBeGreaterThan(
        new Date(due).getTime(),
      );
      const cookies: string[] = renewed.result.value.cookies;
      expect(cookies.some((cookie) => cookie.startsWith("better-auth.session_token="))).toBe(true);
      if (compact) {
        expect(cookies.some((cookie) => cookie.startsWith("better-auth.session_data="))).toBe(true);
      }
      expect(cookies.length).toBeGreaterThanOrEqual(compact ? 2 : 1);
      const renewalHeaders = new Headers();
      for (const cookie of cookies) renewalHeaders.append("set-cookie", cookie);
      const renewalPublication = compact ? await cacheReceipt(renewalHeaders) : null;
      const failed = await laterSession({
        headers: { cookie: header },
        mode: "after-error",
      });
      expect(failed.result.ok).toBe(false);
      expect(failed.result.name).toBe("Error");
      const expiredClock = await ctx.rawRequest({
        path: "/__test/expire-session",
        method: "POST",
        json: { token: signup.token, expiresAt: "2000-01-01T00:00:00.000Z" },
      });
      expect(expiredClock.status).toBe(200);
      const expired = await laterSession({
        headers: { cookie: header },
        query: { disableCookieCache: true },
      });
      expect(expired.result.ok).toBe(true);
      expect(expired.result.value.response).toBeNull();
      expect(
        expired.result.value.cookies.some(
          (cookie: string) =>
            cookie.startsWith("better-auth.session_token=") && cookie.includes("Max-Age=0"),
        ),
      ).toBe(true);
      expect(object(await ctx.readUserState({ userId: signup.user.id })).sessions).toEqual([]);
      expect((await foreign.client.getSession()).data?.user.id).toBe(other.data!.user.id);
      for (const observed of [absent, valid, noRefresh, renewed, expired]) {
        const stages = observed.events.map((event: Record<string, any>) => event.stage);
        expect(stages).toContain("user-before");
        expect(stages).toContain("user-after");
        expect(observed.events[0].path).toBe("/get-session");
        expect(observed.events[0].request).toBeNull();
      }
      const jwtReceipts = [];
      for (const observed of [valid, noRefresh, renewed, expired]) {
        const token = observed.result.value.headers["set-auth-jwt"];
        expect(token).toBeTypeOf("string");
        expect(
          observed.result.value.headers["access-control-expose-headers"]
            .split(",")
            .map((header: string) => header.trim()),
        ).toContain("set-auth-jwt");
        const verified = await jwtVerify(token, verifier);
        expect(verified.payload.sub).toBe(signup.user.id);
        expect(verified.payload.sub).not.toBe(other.data!.user.id);
        jwtReceipts.push({ token, header: verified.protectedHeader, payload: verified.payload });
      }
      return {
        admission,
        jwks,
        jwtReceipts,
        publication: ctx.snapshot(publication),
        renewalPublication,
        absent,
        valid,
        noRefresh,
        renewed,
        failed,
        expired,
      };
    },
    ["GET /get-session"],
  );
}
