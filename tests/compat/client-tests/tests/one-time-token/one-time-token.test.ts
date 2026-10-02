import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { oneTimeTokenClient } from "better-auth/client/plugins";
import { z } from "zod";

import type { FixtureProfile } from "../../support/profiles";
import { compatScenario } from "../../support/scenario";

type Context = Parameters<Parameters<typeof compatScenario>[1]>[0];

const rows = z.array(
  z.object({
    id: z.string(),
    identifier: z.string(),
    value: z.string(),
    expiresAt: z.string(),
    createdAt: z.string(),
    updatedAt: z.string(),
  }),
);

function ottActor(ctx: Context, name = "owner", profile: FixtureProfile = "ott-default") {
  return createAuthClient({
    baseURL: ctx.baseURL,
    plugins: [oneTimeTokenClient()],
    fetchOptions: { customFetchImpl: ctx.actor(name, profile).fetch },
  });
}

async function signUp(ctx: Context, name = "owner", profile?: FixtureProfile) {
  const client = ottActor(ctx, name, profile);
  const signup = await client.signUp.email({
    email: ctx.uniqueEmail(`ott-${name}`),
    password: "password123",
    name: `OTT ${name}`,
  });
  expect(signup.error).toBeNull();

  if (!signup.data) {
    throw new Error("one-time-token owner must have a session");
  }

  return { client, signup, userId: signup.data.user.id };
}

compatScenario(
  "one-time tokens transfer the original session once without creating another session",
  async (ctx) => {
    const { client, signup, userId } = await signUp(ctx);
    const other = await signUp(ctx, "other");
    const before = await client.getSession();
    const guestGenerate = await ottActor(ctx, "guest").oneTimeToken.generate();
    expect(guestGenerate.error).toMatchObject({ status: 401, code: "UNAUTHORIZED" });

    const issuedAt = Date.now();
    const generated = await client.oneTimeToken.generate();
    const issuanceCompletedAt = Date.now();
    expect(generated.error).toBeNull();

    if (!generated.data) {
      throw new Error("authenticated generation must return a token");
    }

    expect(generated.data.token).toMatch(/^[a-zA-Z0-9_-]{32}$/);

    const identifier = `one-time-token:${generated.data.token}`;
    const persisted = rows.parse(await ctx.readVerificationState({ identifier }));
    expect(persisted).toHaveLength(1);
    expect(persisted[0]?.value).toBe(before.data?.session.token);

    if (!persisted[0]) {
      throw new Error("issued OTT must be persisted");
    }

    expect(new Date(persisted[0].expiresAt).getTime()).toBeGreaterThanOrEqual(issuedAt + 180000);
    expect(new Date(persisted[0].expiresAt).getTime()).toBeLessThanOrEqual(
      issuanceCompletedAt + 180000,
    );

    const invalid = await other.client.oneTimeToken.verify({ token: "incorrect-transfer-token" });
    expect(invalid.error).toMatchObject({ status: 400, message: "Invalid token" });

    const otherBefore = await other.client.getSession();
    expect(otherBefore.data?.user.id).toBe(other.userId);

    const transferred = await other.client.oneTimeToken.verify({ token: generated.data.token });
    expect(transferred.error).toBeNull();
    expect(transferred.data?.session.id).toBe(before.data?.session.id);
    expect(transferred.data?.session.token).toBe(before.data?.session.token);
    expect(transferred.data?.user.id).toBe(userId);

    const transferredSession = await other.client.getSession();
    expect(transferredSession.data?.user.id).toBe(userId);
    expect(transferredSession.data?.session.token).toBe(before.data?.session.token);

    const ownerState = z
      .object({ sessions: z.array(z.object({ token: z.string() })) })
      .parse(await ctx.readUserState({ userId }));
    expect(ownerState.sessions).toHaveLength(1);
    expect(ownerState.sessions[0]?.token).toBe(before.data?.session.token);

    const consumed = await ctx.readVerificationState({ identifier });
    expect(consumed).toEqual([]);

    const replay = await ottActor(ctx, "guest").oneTimeToken.verify({
      token: generated.data.token,
    });
    expect(replay.error).toMatchObject({ status: 400, message: "Invalid token" });

    return {
      signup: ctx.snapshot(signup),
      otherSignup: ctx.snapshot(other.signup),
      before: ctx.snapshot(before),
      guestGenerate,
      generated,
      persisted,
      invalid,
      otherBefore: ctx.snapshot(otherBefore),
      transferred: ctx.snapshot(transferred),
      transferredSession: ctx.snapshot(transferredSession),
      ownerState,
      consumed,
      replay,
    };
  },
  ["GET /one-time-token/generate", "POST /one-time-token/verify"],
);

compatScenario(
  "one-time token expiry and a revoked underlying session invalidate consumption and replay",
  async (ctx) => {
    const { client } = await signUp(ctx);
    const expired = await client.oneTimeToken.generate();

    if (!expired.data) {
      throw new Error("expiry test requires an issued token");
    }

    const identifier = `one-time-token:${expired.data.token}`;
    const expiry = await ctx.rawRequest({
      path: "/__test/verification-state",
      method: "POST",
      json: { action: "expire", identifier, expiresAt: "2000-01-01T00:00:00.000Z" },
    });
    expect(expiry.status).toBe(200);

    const expiredReject = await ottActor(ctx, "expired").oneTimeToken.verify({
      token: expired.data.token,
    });
    expect(expiredReject.error).toMatchObject({ status: 400, message: "Invalid token" });
    expect(await ctx.readVerificationState({ identifier })).toEqual([]);

    const pending = await client.oneTimeToken.generate();

    if (!pending.data) {
      throw new Error("revocation test requires an issued token");
    }

    await client.signOut();
    const revoked = await ottActor(ctx, "revoked").oneTimeToken.verify({
      token: pending.data.token,
    });
    expect(revoked.error).toMatchObject({ status: 400, message: "Session not found" });
    expect(
      await ctx.readVerificationState({ identifier: `one-time-token:${pending.data.token}` }),
    ).toEqual([]);

    const replay = await ottActor(ctx, "revoked").oneTimeToken.verify({
      token: pending.data.token,
    });
    expect(replay.error).toMatchObject({ status: 400, message: "Invalid token" });

    return { expired, expiredReject, pending, revoked, replay };
  },
);

compatScenario(
  "one-time token consumption rejects an expired underlying session after consuming the credential",
  async (ctx) => {
    const { client, userId } = await signUp(ctx);
    const session = await client.getSession();
    const generated = await client.oneTimeToken.generate();

    if (!session.data || !generated.data) {
      throw new Error("session-expiry test requires an issued transfer credential");
    }

    const expired = await ctx.rawRequest({
      path: "/__test/expire-session",
      method: "POST",
      json: { token: session.data.session.token, expiresAt: "2000-01-01T00:00:00.000Z" },
    });
    expect(expired.status).toBe(200);

    const consumer = ottActor(ctx, "expired-session");
    const rejected = await consumer.oneTimeToken.verify({ token: generated.data.token });
    expect(rejected.error).toMatchObject({ status: 400, message: "Session expired" });

    const consumed = await ctx.readVerificationState({
      identifier: `one-time-token:${generated.data.token}`,
    });
    expect(consumed).toEqual([]);

    const sessionState = z
      .object({ sessions: z.array(z.object({ token: z.string(), expiresAt: z.string() })) })
      .parse(await ctx.readUserState({ userId }));
    expect(sessionState.sessions).toHaveLength(1);
    expect(sessionState.sessions[0]?.token).toBe(session.data.session.token);
    expect(Date.parse(sessionState.sessions[0]?.expiresAt ?? "")).toBe(
      Date.parse("2000-01-01T00:00:00.000Z"),
    );

    const replay = await consumer.oneTimeToken.verify({ token: generated.data.token });
    expect(replay.error).toMatchObject({ status: 400, message: "Invalid token" });

    return { generated, expired, rejected, consumed, sessionState, replay };
  },
);

compatScenario(
  "one-time token transfer inherits the receiving browser's nonpersistent session preference",
  async (ctx) => {
    const owner = await signUp(ctx);
    const consumer = await signUp(ctx, "consumer");

    if (!consumer.signup.data?.user.email) {
      throw new Error("receiving actor requires credentials");
    }

    const nonpersistent = await consumer.client.signIn.email({
      email: consumer.signup.data.user.email,
      password: "password123",
      rememberMe: false,
    });
    expect(nonpersistent.error).toBeNull();

    const generated = await owner.client.oneTimeToken.generate();

    if (!generated.data) {
      throw new Error("owner must issue a transfer credential");
    }

    const cookieHeaders: { session: string | null; preference: string | null } = {
      session: null,
      preference: null,
    };
    const transferred = await consumer.client.oneTimeToken.verify({
      token: generated.data.token,
      fetchOptions: {
        onSuccess({ response }) {
          const cookies = response.headers.getSetCookie();
          cookieHeaders.session =
            cookies.find((cookie) => cookie.startsWith("better-auth.session_token=")) ?? null;
          cookieHeaders.preference =
            cookies.find((cookie) => cookie.startsWith("better-auth.dont_remember=")) ?? null;
        },
      },
    });
    expect(transferred.error).toBeNull();
    expect(transferred.data?.user.id).toBe(owner.userId);
    expect(cookieHeaders.session).not.toBeNull();
    expect(cookieHeaders.preference).not.toBeNull();

    for (const cookie of [cookieHeaders.session, cookieHeaders.preference]) {
      expect(cookie).not.toMatch(/max-age|expires=/i);
    }

    const current = await consumer.client.getSession();
    expect(current.data?.user.id).toBe(owner.userId);

    // Raw traces retain cookie attributes and ownership without putting signed
    // fixture cookie entropy into the application observation.
    return {
      owner: ctx.snapshot(owner.signup),
      consumer: ctx.snapshot(consumer.signup),
      nonpersistent: ctx.snapshot(nonpersistent),
      generated,
      transferred: ctx.snapshot(transferred),
      current: ctx.snapshot(current),
    };
  },
);

compatScenario(
  "one-time tokens consume only the newest generation and remove older siblings",
  async (ctx) => {
    const { client } = await signUp(ctx);
    const session = await client.getSession();
    const generated = await client.oneTimeToken.generate();

    if (!generated.data || !session.data) {
      throw new Error("duplicate generation test requires a session and token");
    }

    const identifier = `one-time-token:${generated.data.token}`;

    // Upstream selects by createdAt; simultaneous millisecond generations have
    // no specified tie order. Make the newer generation observably newer.
    await Bun.sleep(5);
    const seeded = await ctx.rawRequest({
      path: "/__test/verification-state",
      method: "POST",
      json: {
        action: "seed",
        identifier,
        value: session.data.session.token,
        expiresAt: "2000-01-01T00:00:00.000Z",
      },
    });
    expect(seeded.status).toBe(200);

    const before = rows.parse(await ctx.readVerificationState({ identifier }));
    expect(before).toHaveLength(2);
    expect(new Date(before[0]?.createdAt ?? "").getTime()).toBeGreaterThan(
      new Date(before[1]?.createdAt ?? "").getTime(),
    );

    const rejected = await ottActor(ctx, "consumer").oneTimeToken.verify({
      token: generated.data.token,
    });
    expect(rejected.error).toMatchObject({ status: 400, message: "Invalid token" });

    const after = await ctx.readVerificationState({ identifier });
    expect(after).toEqual([]);

    const owner = await client.getSession();
    expect(owner.data?.session.token).toBe(session.data.session.token);

    return { generated, before, rejected, after, owner: ctx.snapshot(owner) };
  },
);

compatScenario(
  "hashed one-time-token storage never stores the credential in its identifier",
  async (ctx) => {
    const { client, userId } = await signUp(ctx, "hashed", "ott-hashed");
    const before = await client.getSession();
    const generated = await client.oneTimeToken.generate();

    if (!generated.data) {
      throw new Error("hashed storage requires a token");
    }

    const hash = Buffer.from(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(generated.data.token)),
    ).toString("base64url");
    const plainRows = await ctx.readVerificationState({
      identifier: `one-time-token:${generated.data.token}`,
    });
    expect(plainRows).toEqual([]);

    const persisted = rows.parse(
      await ctx.readVerificationState({ identifier: `one-time-token:${hash}` }),
    );
    expect(persisted).toHaveLength(1);
    expect(persisted[0]?.identifier).toBe(`one-time-token:${hash}`);
    expect(persisted[0]?.value).toBe(before.data?.session.token);

    const consumed = await ottActor(ctx, "consumer", "ott-hashed").oneTimeToken.verify({
      token: generated.data.token,
    });
    expect(consumed.error).toBeNull();
    expect(consumed.data?.user.id).toBe(userId);
    expect(await ctx.readVerificationState({ identifier: `one-time-token:${hash}` })).toEqual([]);

    const replay = await ottActor(ctx, "consumer", "ott-hashed").oneTimeToken.verify({
      token: generated.data.token,
    });
    expect(replay.error).toMatchObject({ status: 400, message: "Invalid token" });

    return { generated, plainRows, persisted, consumed: ctx.snapshot(consumed), replay };
  },
);

compatScenario(
  "one-time token no-cookie mode returns the existing session without signing the consumer in",
  async (ctx) => {
    const { client, userId } = await signUp(ctx, "no-cookie", "ott-no-cookie");
    const generated = await client.oneTimeToken.generate();

    if (!generated.data) {
      throw new Error("no-cookie mode requires a token");
    }

    const consumer = ottActor(ctx, "consumer", "ott-no-cookie");
    const setCookies: string[] = [];
    const consumed = await consumer.oneTimeToken.verify({
      token: generated.data.token,
      fetchOptions: {
        onSuccess({ response }) {
          setCookies.push(...response.headers.getSetCookie());
        },
      },
    });
    expect(consumed.data?.user.id).toBe(userId);
    expect(setCookies).toEqual([]);

    const session = await consumer.getSession();
    expect(session.data).toBeNull();

    return {
      generated,
      consumed: ctx.snapshot(consumed),
      session: ctx.snapshot(session),
      setCookies,
    };
  },
);

compatScenario(
  "disabled client OTT generation still supports server generation and new-session response headers",
  async (ctx) => {
    const client = ottActor(ctx, "header-owner", "ott-server-header");
    const responseHeaders: { token: string | null; exposed: string | null } = {
      token: null,
      exposed: null,
    };
    const signup = await client.signUp.email({
      email: ctx.uniqueEmail("ott-header"),
      password: "password123",
      name: "OTT Header Owner",
      fetchOptions: {
        onSuccess({ response }) {
          responseHeaders.token = response.headers.get("set-ott");
          responseHeaders.exposed = response.headers.get("access-control-expose-headers");
        },
      },
    });
    expect(signup.error).toBeNull();

    const { token: headerToken, exposed: exposedHeaders } = responseHeaders;

    if (!headerToken || !signup.data?.token) {
      throw new Error("new-session hook must set a one-time token");
    }

    const signupToken = signup.data.token;
    expect(exposedHeaders).toBe("existing, set-ott, Existing");

    const persistedHeader = rows.parse(
      await ctx.readVerificationState({ identifier: `one-time-token:${headerToken}` }),
    );
    expect(persistedHeader[0]?.value).toBe(signupToken);

    const disabled = await client.oneTimeToken.generate();
    expect(disabled.error).toMatchObject({ status: 400, message: "Client requests are disabled" });

    const serverResponse = await ctx
      .actor("header-owner", "ott-server-header")
      .fetch(`${ctx.baseURL}/__test/one-time-token`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ operation: "generate", profile: "ott-server-header" }),
      });
    expect(serverResponse.status).toBe(200);

    const serverGenerated = z.object({ token: z.string() }).parse(await serverResponse.json());
    expect(serverGenerated.token).not.toBe(headerToken);

    const fromHeader = await ottActor(ctx, "consumer", "ott-server-header").oneTimeToken.verify({
      token: headerToken,
    });
    expect(fromHeader.data?.session.token).toBe(signupToken);

    const fromServer = await ottActor(
      ctx,
      "server-consumer",
      "ott-server-header",
    ).oneTimeToken.verify({ token: serverGenerated.token });
    expect(fromServer.data?.session.token).toBe(signupToken);

    return {
      signup: ctx.snapshot(signup),
      header: { token: headerToken },
      exposedHeaders,
      persistedHeader,
      disabled,
      serverGenerated,
      fromHeader: ctx.snapshot(fromHeader),
      fromServer: ctx.snapshot(fromServer),
    };
  },
);

compatScenario(
  "one-time token schema errors preserve an issued credential until a valid single consumption",
  async (ctx) => {
    const { client, userId } = await signUp(ctx);
    const session = await client.getSession();
    const issued = await client.oneTimeToken.generate();

    if (!issued.data || !session.data) {
      throw new Error("schema rejection requires a real issued transfer credential");
    }

    const identifier = `one-time-token:${issued.data.token}`;
    const rejected = [];

    for (const [body, received] of [
      [null, "null"],
      [{}, "undefined"],
      [{ token: null }, "null"],
      [{ token: 7 }, "number"],
      [{ token: [] }, "array"],
      [{ token: false }, "boolean"],
    ] as const) {
      const response = await ctx.rawRequest({
        path: "/__test/profiles/ott-default/api/auth/one-time-token/verify",
        method: "POST",
        json: body,
      });
      expect(response.status).toBe(400);
      expect(response.body).toEqual({
        code: "VALIDATION_ERROR",
        message:
          body === null
            ? "[body] Invalid input: expected object, received null"
            : `[body.token] Invalid input: expected string, received ${received}`,
      });

      const pending = rows.parse(await ctx.readVerificationState({ identifier }));
      expect(pending).toHaveLength(1);
      expect(pending[0]?.value).toBe(session.data.session.token);

      rejected.push(response);
    }

    const empty = await ctx.rawRequest({
      path: "/__test/profiles/ott-default/api/auth/one-time-token/verify",
      method: "POST",
      json: { token: "" },
    });
    expect(empty.status).toBe(400);
    expect(empty.body).toEqual({ message: "Invalid token" });
    expect(rows.parse(await ctx.readVerificationState({ identifier }))).toHaveLength(1);

    const consumed = await ottActor(ctx, "schema-consumer").oneTimeToken.verify({
      token: issued.data.token,
    });
    expect(consumed.error).toBeNull();
    expect(consumed.data?.session.token).toBe(session.data.session.token);
    expect(consumed.data?.user.id).toBe(userId);
    expect(await ctx.readVerificationState({ identifier })).toEqual([]);

    const replay = await ottActor(ctx, "schema-consumer").oneTimeToken.verify({
      token: issued.data.token,
    });
    expect(replay.error).toMatchObject({ status: 400, message: "Invalid token" });

    return { issued, rejected, empty, consumed: ctx.snapshot(consumed), replay };
  },
  ["POST /one-time-token/verify"],
);

compatScenario(
  "one-time token generation refreshes aged sessions and honors query browser and configuration preferences",
  async (ctx) => {
    const observations = [];
    for (const [name, profile, query, dontRemember, refresh] of [
      ["default", "ott-default", "", false, true],
      ["query-false", "ott-default", "?disableRefresh=false", false, false],
      ["query-empty", "ott-default", "?disableRefresh=", false, true],
      ["browser", "ott-default", "", true, false],
      ["disabled", "ott-refresh-disabled", "", false, false],
      ["deferred", "ott-refresh-deferred", "", false, false],
    ] as const) {
      const owner = await signUp(ctx, `refresh-${name}`, profile);
      const login = dontRemember
        ? await owner.client.signIn.email({
            email: owner.signup.data!.user.email,
            password: "password123",
            rememberMe: false,
          })
        : owner.signup;
      expect(login.error).toBeNull();

      if (!login.data?.token) {
        throw new Error("refresh control requires a real authenticated session");
      }

      const token = login.data.token;
      const agedExpiry = new Date(Date.now() + 3600000).toISOString();
      const aged = await ctx.rawRequest({
        path: "/__test/expire-session",
        method: "POST",
        json: { token, expiresAt: agedExpiry },
      });
      expect(aged.status).toBe(200);

      const state = z.object({
        sessions: z.array(z.object({ token: z.string(), expiresAt: z.string() })),
      });
      const before = state
        .parse(await ctx.readUserState({ userId: owner.userId }))
        .sessions.find((session) => session.token === token);
      expect(before?.expiresAt).toBe(agedExpiry);

      const startedAt = Date.now();
      const cookies: string[] = [];
      let generated: { token: string };

      if (query) {
        const response = await ctx
          .actor(`refresh-${name}`, profile)
          .fetch(
            `${ctx.baseURL}/__test/profiles/${profile}/api/auth/one-time-token/generate${query}`,
          );
        expect(response.status).toBe(200);

        cookies.push(...response.headers.getSetCookie());
        generated = z.object({ token: z.string() }).parse(await response.json());
      } else {
        const result = await owner.client.oneTimeToken.generate({
          fetchOptions: {
            onSuccess({ response }) {
              cookies.push(...response.headers.getSetCookie());
            },
          },
        });
        expect(result.error).toBeNull();

        if (!result.data) {
          throw new Error("aged session must still issue a one-time token");
        }

        generated = result.data;
      }

      const completedAt = Date.now();
      const after = state
        .parse(await ctx.readUserState({ userId: owner.userId }))
        .sessions.find((session) => session.token === token);
      expect(after).toBeDefined();

      if (!after) {
        throw new Error("generation must retain the underlying session row");
      }

      if (refresh) {
        expect(Date.parse(after!.expiresAt)).toBeGreaterThanOrEqual(startedAt + 604800000);
        expect(Date.parse(after!.expiresAt)).toBeLessThanOrEqual(completedAt + 604800000);

        const refreshedCookie = cookies.find((cookie) =>
          cookie.startsWith("better-auth.session_token="),
        );
        expect(refreshedCookie).toBeDefined();
        expect(refreshedCookie).toMatch(/Max-Age=604800/i);
        expect(refreshedCookie).toMatch(/HttpOnly/i);
      } else {
        expect(after?.expiresAt).toBe(agedExpiry);
        expect(cookies).toEqual([]);
      }

      const pending = rows.parse(
        await ctx.readVerificationState({ identifier: `one-time-token:${generated.token}` }),
      );
      expect(pending).toHaveLength(1);
      expect(pending[0]?.value).toBe(token);

      const consumed = await ottActor(ctx, `refresh-consumer-${name}`, profile).oneTimeToken.verify(
        { token: generated.token },
      );
      expect(consumed.error).toBeNull();
      expect(consumed.data?.session.token).toBe(token);

      if (!consumed.data?.session.expiresAt) {
        throw new Error("consumption must retain the stored session expiry");
      }

      expect(new Date(consumed.data.session.expiresAt).toISOString()).toBe(after.expiresAt);
      expect(
        await ctx.readVerificationState({ identifier: `one-time-token:${generated.token}` }),
      ).toEqual([]);

      observations.push({
        name,
        signup: ctx.snapshot(owner.signup),
        login: ctx.snapshot(login),
        before,
        after,
        generated,
        pending,
        consumed: ctx.snapshot(consumed),
      });
    }
    return observations;
  },
  ["GET /one-time-token/generate", "POST /one-time-token/verify"],
);
