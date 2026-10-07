import { expect } from "bun:test";
import { createHmac } from "node:crypto";

import { Cookie } from "tough-cookie";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

function cookieEvidence(rows: string[], sessionToken: string) {
  return rows.map((raw) => {
    const cookie = Cookie.parse(raw);
    expect(cookie).not.toBeNull();
    const value = decodeURIComponent(cookie!.value);
    if (cookie!.key === "better-auth.session_token") {
      const signature = createHmac("sha256", "compat-test-only-key-not-real-minimum-32chars")
        .update(sessionToken)
        .digest("base64");
      expect(value).toBe(`${sessionToken}.${signature}`);
    }
    return {
      name: cookie!.key,
      token: value,
      domain: cookie!.domain ?? null,
      path: cookie!.path,
      maxAge: cookie!.maxAge ?? null,
      expires: cookie!.expires instanceof Date ? cookie!.expires.toISOString() : null,
      secure: cookie!.secure,
      httpOnly: cookie!.httpOnly,
      sameSite: cookie!.sameSite,
    };
  });
}
for (const profile of [
  "session-update-age",
  "session-update-age-cache",
  "session-update-age-long",
  "session-deferred-update-age",
] as const) {
  compatScenario(
    `session ${profile} refresh cadence follows stored expiry with configured update age`,
    async (ctx) => {
      const actor = ctx.actor("owner", profile);
      const signup = await actor.client.signUp.email({
        email: ctx.uniqueEmail("cadence"),
        name: "Cadence Owner",
        password: "password123",
      });
      expect(signup.error).toBeNull();
      const userId = signup.data!.user.id;
      const token = signup.data!.token!;
      const read = async () => (await ctx.readUserState({ userId })) as any;
      const clock = async (remainingSeconds: number) => {
        const expiresAt = new Date(Date.now() + remainingSeconds * 1000).toISOString();
        expect(
          (
            await ctx.rawRequest({
              path: "/__test/expire-session",
              method: "POST",
              json: { token, expiresAt },
            })
          ).body,
        ).toEqual({ updated: 1 });
        return expiresAt;
      };
      const earlyExpiry = await clock(3500);
      const earlyBefore = await read();
      const early = await actor.client.getSession({ query: { disableCookieCache: true } });
      expect(early.error).toBeNull();
      expect(early.data!.session.expiresAt.toISOString()).toBe(earlyExpiry);
      expect(await read()).toEqual(earlyBefore);
      const dueExpiry = await clock(3400);
      const dueBefore = await read();
      if (profile === "session-update-age-cache") {
        const cached = await actor.client.getSession();
        expect(cached.data!.user.id).toBe(userId);
        expect(await read()).toEqual(dueBefore);
      }
      let cookies: string[] = [];
      const beforeRequest = Date.now();
      const due = await actor.client.getSession({
        query: { disableCookieCache: true },
        fetchOptions: {
          onResponse({ response }) {
            cookies = response.headers.getSetCookie();
          },
        },
      });
      expect(due.error).toBeNull();
      const afterGet = await read();
      const skipsGet =
        profile === "session-update-age-long" || profile === "session-deferred-update-age";
      if (skipsGet) {
        expect(afterGet).toEqual(dueBefore);
        expect(due.data!.session.expiresAt.toISOString()).toBe(dueExpiry);
      } else {
        const expiry = Date.parse(afterGet.sessions[0].expiresAt);
        expect(expiry).toBeGreaterThanOrEqual(beforeRequest + 3600000);
        expect(expiry).toBeLessThanOrEqual(Date.now() + 3600000);
        expect(cookies.some((cookie) => cookie.startsWith("better-auth.session_token="))).toBe(
          true,
        );
        expect(afterGet.sessions[0].id).toBe(dueBefore.sessions[0].id);
      }
      let post = null;
      if (profile === "session-deferred-update-age") {
        const response = await actor.fetch(
          ctx.baseURL + authProfilePath(profile) + "/get-session?disableCookieCache=true",
          { method: "POST" },
        );
        expect(response.status).toBe(200);
        post = {
          status: response.status,
          body: await response.json(),
          cookies: response.headers.getSetCookie(),
        };
        expect(Date.parse((await read()).sessions[0].expiresAt)).toBeGreaterThan(
          Date.parse(dueExpiry),
        );
        expect(post.cookies.some((cookie) => cookie.startsWith("better-auth.session_token="))).toBe(
          true,
        );
      }
      const final = await read();
      expect(final.user).toEqual(dueBefore.user);
      expect(final.accounts).toEqual(dueBefore.accounts);
      return ctx.snapshot({
        signup,
        early,
        due,
        cookies: cookieEvidence(cookies, token),
        post: post && { ...post, cookies: cookieEvidence(post.cookies, token) },
        earlyBefore,
        dueBefore,
        afterGet,
        final,
      });
    },
    ["GET /get-session", "POST /get-session"],
  );
}
