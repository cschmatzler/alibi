import { expect } from "bun:test";
import { apiKeyClient } from "@better-auth/api-key/client";
import { createAuthClient } from "better-auth/client";
import { jwtClient } from "better-auth/client/plugins";
import { z } from "zod";
import type { FixtureProfile } from "../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { jwtActor, verifyWithOfficialJose } from "./helpers";

const identity = z.object({ token: z.string(), user: z.object({ id: z.string() }) });
const sessionSnapshot = z
  .object({
    user: z.object({ id: z.string() }).passthrough(),
    session: z
      .object({
        id: z.string(),
        token: z.string(),
        userId: z.string(),
        expiresAt: z.string(),
        createdAt: z.string(),
        updatedAt: z.string(),
      })
      .passthrough(),
  })
  .passthrough();

async function persisted(ctx: ScenarioContext, profile: FixtureProfile, token: string) {
  const result = await ctx.rawRequest({
    path: "/__test/jwt",
    method: "POST",
    json: { operation: "session-state", profile, token },
  });
  expect(result.status).toBe(200);
  return result.body === null ? null : sessionSnapshot.parse(result.body);
}

async function age(ctx: ScenarioContext, token: string, milliseconds = 3_600_000) {
  const expiresAt = new Date(Date.now() + milliseconds).toISOString();
  const result = await ctx.rawRequest({
    path: "/__test/expire-session",
    method: "POST",
    json: { token, expiresAt },
  });
  expect(result).toEqual({ status: 200, location: null, body: { updated: 1 } });
  return expiresAt;
}

compatScenario(
  "JWT token middleware signs persisted refresh and browser preference branches",
  async (ctx) => {
    const observations = [];
    for (const [name, profile, query, remember, renew] of [
      ["normal", "jwt-session-normal", undefined, true, true],
      ["empty-query", "jwt-session-normal", "", true, true],
      ["false-query", "jwt-session-normal", "false", true, false],
      ["browser-preference", "jwt-session-normal", undefined, false, false],
      ["disabled", "jwt-session-disabled", undefined, true, false],
      ["deferred", "jwt-session-deferred", undefined, true, false],
      ["deferred-empty-query", "jwt-session-deferred", "", true, false],
      ["deferred-false-query", "jwt-session-deferred", "false", true, false],
      ["deferred-browser-preference", "jwt-session-deferred", undefined, false, false],
    ] as const) {
      const client = jwtActor(ctx, name, profile);
      const signup = await client.signUp.email(
        {
          email: ctx.uniqueEmail(`jwt-session-${name}`),
          password: "password123",
          name: "JWT Session Owner",
        },
        { body: { rememberMe: remember } },
      );
      expect(signup.error).toBeNull();
      const issued = identity.parse(signup.data);
      let fresh: unknown = null;
      if (name === "deferred") {
        const token = await client.token();
        const jwks = await client.jwks();
        if (!token.data || !jwks.data)
          throw new Error("A freshly issued deferred session must authorize its JWT");
        const checked = await verifyWithOfficialJose(
          token.data.token,
          jwks.data.keys,
          ctx.baseURL,
          ctx.baseURL,
        );
        const snapshot = sessionSnapshot.parse(checked.payload.snapshot);
        expect(snapshot.needsRefresh).toBe(false);
        const state = await persisted(ctx, profile, issued.token);
        if (!state) throw new Error("Deferred JWT middleware must retain the fresh session");
        expect({ user: snapshot.user, session: snapshot.session }).toEqual(state);
        fresh = { token, jwks, checked, state };
      }
      const oldExpiry = await age(ctx, issued.token);
      const before = await persisted(ctx, profile, issued.token);
      if (!before) throw new Error("The issued session must exist before JWT middleware reads it");
      expect(before.session.expiresAt).toBe(oldExpiry);
      const receipt: { cookies: string[]; url: string } = { cookies: [], url: "" };
      const startedAt = Date.now();
      const token = await client.token({
        fetchOptions: {
          ...(query === undefined ? {} : { query: { disableRefresh: query } }),
          onSuccess({ response }) {
            receipt.cookies = response.headers.getSetCookie();
            receipt.url = response.url;
          },
        },
      });
      const completedAt = Date.now();
      expect(token.error).toBeNull();
      if (!token.data) throw new Error("Normally authenticated middleware must issue a JWT");
      if (query !== undefined)
        expect(new URL(receipt.url).searchParams.get("disableRefresh")).toBe(query);
      const jwks = await client.jwks();
      if (!jwks.data) throw new Error("The issued JWT must have persisted public key material");
      const checked = await verifyWithOfficialJose(
        token.data.token,
        jwks.data.keys,
        ctx.baseURL,
        ctx.baseURL,
      );
      const after = await persisted(ctx, profile, issued.token);
      if (!after) throw new Error("JWT issuance must retain the original session row");
      const snapshot = sessionSnapshot.parse(checked.payload.snapshot);
      expect({ user: snapshot.user, session: snapshot.session }).toEqual(after);
      if (profile === "jwt-session-deferred" && remember && query !== "false") {
        expect(snapshot.needsRefresh).toBe(true);
      } else {
        expect(Object.hasOwn(snapshot, "needsRefresh")).toBe(false);
      }
      expect(checked.payload.sub).toBe(issued.user.id);
      expect(after.session.id).toBe(before.session.id);
      expect(after.session.token).toBe(issued.token);
      expect(after.session.userId).toBe(issued.user.id);
      if (renew) {
        expect(Date.parse(after.session.expiresAt)).toBeGreaterThanOrEqual(startedAt + 604_800_000);
        expect(Date.parse(after.session.expiresAt)).toBeLessThanOrEqual(completedAt + 604_800_000);
        expect(receipt.cookies).toHaveLength(1);
        expect(receipt.cookies[0]).toContain("better-auth.session_token=");
        expect(receipt.cookies[0]).toContain("Max-Age=604800");
      } else {
        expect(after).toEqual(before);
        expect(receipt.cookies).toEqual([]);
      }
      observations.push({
        name,
        profile,
        signup: ctx.snapshot(signup),
        fresh,
        before,
        token,
        jwks,
        checked,
        after,
      });
    }
    return { observations };
  },
  ["GET /token"],
);

compatScenario(
  "JWT session headers preserve original refresh expiry cleanup and exposed header order",
  async (ctx) => {
    const observations = [];
    for (const profile of [
      "jwt-session-normal",
      "jwt-session-disabled",
      "jwt-session-deferred",
    ] as const) {
      const client = jwtActor(ctx, profile, profile);
      const receipt: {
        cookie: string | null;
        token: string | null;
        exposed: string | null;
        cookies: string[];
      } = { cookie: null, token: null, exposed: null, cookies: [] };
      const signup = await client.signUp.email(
        { email: ctx.uniqueEmail(profile), password: "password123", name: "JWT Header Owner" },
        {
          onSuccess({ response }) {
            receipt.cookie =
              response.headers
                .getSetCookie()
                .find((value) => value.startsWith("better-auth.session_token="))
                ?.split(";")[0] ?? null;
          },
        },
      );
      const issued = identity.parse(signup.data);
      const jwks = await client.jwks();
      if (!jwks.data || !receipt.cookie)
        throw new Error("The real login must issue its signed session and public signing key");
      await age(ctx, issued.token);
      const before = await persisted(ctx, profile, issued.token);
      if (!before) throw new Error("Session must exist before direct get-session");
      const session = await client.getSession({
        fetchOptions: {
          onSuccess({ response }) {
            receipt.token = response.headers.get("set-auth-jwt");
            receipt.exposed = response.headers.get("access-control-expose-headers");
            receipt.cookies = response.headers.getSetCookie();
          },
        },
      });
      expect(session.error).toBeNull();
      if (!session.data || !receipt.token)
        throw new Error("Direct get-session must return a session and its JWT response header");
      expect(receipt.exposed).toBe("existing, set-auth-jwt, Existing");
      const header = await verifyWithOfficialJose(
        receipt.token,
        jwks.data.keys,
        ctx.baseURL,
        ctx.baseURL,
      );
      expect(sessionSnapshot.parse(header.payload.snapshot)).toEqual(before);
      expect(header.payload.sub).toBe(issued.user.id);
      const after = await persisted(ctx, profile, issued.token);
      if (!after)
        throw new Error("A valid direct get-session response must retain its original session row");
      const returned = sessionSnapshot.parse(ctx.snapshot(session.data));
      expect(sessionSnapshot.parse({ user: returned.user, session: returned.session })).toEqual(
        after,
      );
      if (profile === "jwt-session-normal") {
        expect(Date.parse(z.string().parse(after?.session.expiresAt))).toBeGreaterThan(
          Date.parse(before.session.expiresAt) + 6 * 86_400_000,
        );
        expect(receipt.cookies).toHaveLength(1);
        expect(receipt.cookies[0]).toContain("Max-Age=604800");
      } else {
        expect(after).toEqual(before);
        expect(receipt.cookies).toEqual([]);
      }
      await age(ctx, issued.token, -60_000);
      const expiredBefore = await persisted(ctx, profile, issued.token);
      if (!expiredBefore) throw new Error("The original row must exist before expiry cleanup");
      const expired = await client.getSession({
        fetchOptions: {
          onSuccess({ response }) {
            receipt.token = response.headers.get("set-auth-jwt");
            receipt.exposed = response.headers.get("access-control-expose-headers");
            receipt.cookies = response.headers.getSetCookie();
          },
        },
      });
      expect(expired.error).toBeNull();
      expect(expired.data).toBeNull();
      expect(receipt.exposed).toBe("existing, set-auth-jwt, Existing");
      expect(receipt.cookies.map((cookie) => cookie.split("=")[0])).toEqual([
        "better-auth.session_token",
        "better-auth.session_data",
        "better-auth.dont_remember",
      ]);
      if (!receipt.token)
        throw new Error(
          "The pinned completed-session hook retains the snapshot through expiry cleanup",
        );
      const expiredHeader = await verifyWithOfficialJose(
        receipt.token,
        jwks.data.keys,
        ctx.baseURL,
        ctx.baseURL,
      );
      expect(sessionSnapshot.parse(expiredHeader.payload.snapshot)).toEqual(expiredBefore);
      expect(expiredHeader.payload.sub).toBe(issued.user.id);
      const expiredAfter = await persisted(ctx, profile, issued.token);
      expect(expiredAfter).toEqual(profile === "jwt-session-deferred" ? expiredBefore : null);
      const rejected = await jwtActor(ctx, `${profile}-expired-token`, profile).token({
        fetchOptions: { headers: { cookie: receipt.cookie } },
      });
      expect(rejected.error).toMatchObject({ status: 401, code: "UNAUTHORIZED" });
      const rejectedAfter = await persisted(ctx, profile, issued.token);
      expect(rejectedAfter).toEqual(expiredAfter);
      observations.push({
        profile,
        signup: ctx.snapshot(signup),
        jwks,
        before,
        session: ctx.snapshot(session),
        header,
        after,
        expiredBefore,
        expired: ctx.snapshot(expired),
        expiredHeader,
        expiredAfter,
        rejected: ctx.snapshot(rejected),
        rejectedAfter,
      });
    }
    return { observations };
  },
  ["GET /get-session", "GET /token"],
);

compatScenario(
  "JWT API key principal owns signing while foreign cookies and persisted sessions remain unchanged",
  async (ctx) => {
    const profile = "jwt-session-normal";
    const keyActor = ctx.actor("key-owner", profile);
    const client = createAuthClient({
      baseURL: ctx.baseURL,
      plugins: [jwtClient(), apiKeyClient()],
      fetchOptions: { customFetchImpl: keyActor.fetch },
    });
    const signup = await client.signUp.email({
      email: ctx.uniqueEmail("jwt-key-owner"),
      password: "password123",
      name: "Key Owner",
    });
    const owner = identity.parse(signup.data);
    const created = await client.apiKey.create({ name: "JWT virtual principal" });
    expect(created.error).toBeNull();
    const key = z.object({ id: z.string(), key: z.string() }).parse(created.data);
    const other = jwtActor(ctx, "foreign-cookie", profile);
    const receipt: {
      cookie: string | null;
      cookies: string[];
      jwt: string | null;
      exposed: string | null;
    } = { cookie: null, cookies: [], jwt: null, exposed: null };
    const foreignSignup = await other.signUp.email(
      { email: ctx.uniqueEmail("jwt-cookie-owner"), password: "password123", name: "Cookie Owner" },
      {
        onSuccess({ response }) {
          receipt.cookie =
            response.headers
              .getSetCookie()
              .find((value) => value.startsWith("better-auth.session_token="))
              ?.split(";")[0] ?? null;
        },
      },
    );
    const foreign = identity.parse(foreignSignup.data);
    if (!receipt.cookie)
      throw new Error("The competing principal needs a real signed session cookie");
    await age(ctx, foreign.token);
    const ownerBefore = await persisted(ctx, profile, owner.token);
    const foreignBefore = await persisted(ctx, profile, foreign.token);
    const token = await jwtActor(ctx, "key-principal", profile).token({
      fetchOptions: {
        headers: { "x-api-key": key.key, cookie: receipt.cookie },
        onSuccess({ response }) {
          receipt.cookies = response.headers.getSetCookie();
        },
      },
    });
    expect(token.error).toBeNull();
    if (!token.data) throw new Error("The validated API key must authorize its own JWT principal");
    expect(receipt.cookies).toEqual([]);
    const jwks = await client.jwks();
    if (!jwks.data)
      throw new Error("The key principal JWT must have real persisted public material");
    const checked = await verifyWithOfficialJose(
      token.data.token,
      jwks.data.keys,
      ctx.baseURL,
      ctx.baseURL,
    );
    const snapshot = sessionSnapshot.parse(checked.payload.snapshot);
    expect(checked.payload.sub).toBe(owner.user.id);
    expect(checked.payload.sub).not.toBe(foreign.user.id);
    expect(snapshot.user.id).toBe(owner.user.id);
    expect(snapshot.session).toMatchObject({ id: key.id, token: key.key, userId: owner.user.id });
    const virtualState = await persisted(ctx, profile, key.key);
    expect(virtualState).toBeNull();
    const virtualGet = await jwtActor(ctx, "key-principal-get", profile).getSession({
      fetchOptions: {
        headers: { "x-api-key": key.key },
        onSuccess({ response }) {
          receipt.jwt = response.headers.get("set-auth-jwt");
          receipt.exposed = response.headers.get("access-control-expose-headers");
          receipt.cookies = response.headers.getSetCookie();
        },
      },
    });
    expect(virtualGet.data?.user.id).toBe(owner.user.id);
    expect(virtualGet.data?.session.id).toBe(key.id);
    expect(receipt.jwt).toBeNull();
    expect(receipt.exposed).toBeNull();
    expect(receipt.cookies).toEqual([]);
    const invalid = await jwtActor(ctx, "bad-key-principal", profile).token({
      fetchOptions: { headers: { "x-api-key": "invalid-short-key", cookie: receipt.cookie } },
    });
    expect(invalid.error).toMatchObject({ status: 403, code: "INVALID_API_KEY" });
    const ownerAfter = await persisted(ctx, profile, owner.token);
    const foreignAfter = await persisted(ctx, profile, foreign.token);
    expect(ownerAfter).toEqual(ownerBefore);
    expect(foreignAfter).toEqual(foreignBefore);
    return {
      signup: ctx.snapshot(signup),
      created: ctx.snapshot(created),
      foreignSignup: ctx.snapshot(foreignSignup),
      ownerBefore,
      foreignBefore,
      token,
      jwks,
      checked,
      virtualState,
      virtualGet: ctx.snapshot(virtualGet),
      invalid: ctx.snapshot(invalid),
      ownerAfter,
      foreignAfter,
    };
  },
  ["GET /token", "GET /get-session"],
);
