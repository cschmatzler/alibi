import { expect } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { passkeyClient } from "@better-auth/passkey/client";
import { z } from "zod";
import { Authenticator } from "../../support/authenticator";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { authProfilePath, type FixtureProfile } from "../../support/profiles";

const identity = z.object({ user: z.object({ id: z.string() }) });
const code = (result: { error: unknown }) =>
  z.object({ code: z.string() }).parse(result.error).code;
const cookieHeader = (cookies: string[]) =>
  cookies.map((cookie) => cookie.split(";")[0]).join("; ");
function client(
  ctx: ScenarioContext,
  name = "owner",
  profile: FixtureProfile = "passkey-first",
) {
  return createAuthClient({
    baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
    plugins: [passkeyClient()],
    fetchOptions: { customFetchImpl: ctx.actor(name, profile).fetch },
  });
}
async function signup(
  ctx: ScenarioContext,
  name = "owner",
  profile: FixtureProfile = "passkey-first",
) {
  const actor = ctx.actor(name, profile);
  let cookies: string[] = [];
  const result = await actor.client.signUp.email(
    {
      email: ctx.uniqueEmail(name),
      password: "password123",
      name: `${name} applicant`,
    },
    {
      onSuccess({ response }) {
        cookies = response.headers.getSetCookie();
      },
    },
  );
  expect(result.error).toBeNull();
  return {
    actor,
    result,
    cookies,
    id: identity.parse(result.data).user.id,
    email: ctx.uniqueEmail(name),
  };
}
async function enroll(
  ctx: ScenarioContext,
  context: string,
  mode = "normal",
  name = "owner",
  extra: Record<string, unknown> = {},
) {
  const response = await ctx
    .actor(name, "passkey-first")
    .fetch(`${ctx.baseURL}/__test/passkey-enrollment`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ context, mode, ...extra }),
    });
  expect(response.status).toBe(200);
  const result = z
    .object({ token: z.string(), userId: z.string() })
    .parse(await response.json());
  expect(response.headers.getSetCookie()).toHaveLength(1);
  return { result, cookies: response.headers.getSetCookie() };
}
async function options(
  ctx: ScenarioContext,
  context: string,
  headers?: HeadersInit,
) {
  let cookies: string[] = [];
  const result = await client(ctx).$fetch(
    "/passkey/generate-register-options",
    {
      method: "GET",
      query: { context },
      ...(headers ? { headers } : {}),
      onSuccess({ response }) {
        cookies = response.headers.getSetCookie();
      },
    },
  );
  expect(result.error).toBeNull();
  expect(cookies).toHaveLength(1);
  return { result, cookies };
}
async function state(ctx: ScenarioContext, userId: string) {
  return z
    .object({
      passkeys: z.array(
        z.object({
          userId: z.string(),
          counter: z.number(),
          name: z.string().nullable(),
        }),
      ),
      sessions: z.object({ count: z.number() }),
      challenges: z.object({ count: z.number() }),
    })
    .parse(
      await (
        await ctx
          .actor("owner", "passkey-first")
          .fetch(
            `${ctx.baseURL}/__test/passkey-state?userId=${encodeURIComponent(userId)}`,
          )
      ).json(),
    );
}
async function events(ctx: ScenarioContext) {
  const observed = z
    .object({ events: z.array(z.record(z.string(), z.unknown())) })
    .parse(
      await (
        await ctx
          .actor("owner", "passkey-first")
          .fetch(`${ctx.baseURL}/__test/passkey-registration-events`)
      ).json(),
    ).events;
  for (const event of observed) {
    if (event.stage !== "verified") continue;
    const original = z
      .object({ response: z.object({ clientDataJSON: z.string() }) })
      .parse(event.clientData);
    expect(
      z
        .object({ origin: z.string() })
        .parse(
          JSON.parse(
            Buffer.from(
              original.response.clientDataJSON,
              "base64url",
            ).toString(),
          ),
        ).origin,
    ).toBe(ctx.baseURL);
  }
  return observed;
}

// JSON decoding is reversible: retain every original callback value while comparing
// the challenge and origin through the existing semantic comparator.
function observation(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(observation);
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value).map(([key, child]) => {
        if (key !== "clientDataJSON" || typeof child !== "string")
          return [key, observation(child)];
        const decoded = JSON.parse(
          Buffer.from(child, "base64url").toString(),
        ) as Record<string, unknown>;
        expect(Buffer.from(JSON.stringify(decoded)).toString("base64url")).toBe(
          child,
        );
        return [key, { ...decoded, origin: { url: decoded.origin } }];
      }),
    );
  return value;
}

compatScenario(
  "passkey registration policy resolves a proven existing owner and creates its real session with callback facts",
  async (ctx) => {
    const owner = await signup(ctx);
    const other = await signup(ctx, "other");
    const context = ctx.uniqueToken("enrollment");
    const enrollment = await enroll(ctx, context, "normal", "owner", {
      userId: other.id,
    });
    expect(enrollment.result.userId).toBe(owner.id);
    await owner.actor.client.signOut();
    expect((await owner.actor.client.getSession()).data).toBeNull();
    const challenge = await options(ctx, context);
    const authenticator = new Authenticator();
    const response = {
      ...authenticator.register(challenge.result.data, ctx.baseURL),
      applicationMarker: "original-client-response",
      userId: other.id,
    };
    const registered = await client(ctx).$fetch(
      "/passkey/verify-registration",
      {
        method: "POST",
        body: {
          response,
          createSession: true,
          name: " \uFEFF \uFEFF",
          context: "forged-context",
          userId: other.id,
        },
      },
    );
    expect(registered.error).toBeNull();
    const credential = z
      .object({
        id: z.string(),
        userId: z.string(),
        name: z.string(),
        credentialID: z.string(),
        publicKey: z.string(),
        counter: z.number(),
        aaguid: z.string(),
        session: z.object({
          id: z.string(),
          token: z.string(),
          userId: z.string(),
        }),
        user: z.object({ id: z.string() }),
      })
      .parse(registered.data);
    expect(credential.userId).toBe(owner.id);
    expect(credential.user.id).toBe(owner.id);
    expect(credential.session.userId).toBe(owner.id);
    expect(credential.name).toBe("Callback Label");
    expect(credential.credentialID).toBe(response.id);
    const current = await owner.actor.client.getSession();
    expect(current.data?.user.id).toBe(owner.id);
    expect(current.data?.session.id).toBe(credential.session.id);
    expect(current.data?.session.token).toBe(credential.session.token);
    const observed = await events(ctx);
    expect(observed).toHaveLength(2);
    expect(observed[0]).toMatchObject({
      stage: "resolved",
      context,
      userId: owner.id,
    });
    expect(observed[1]).toMatchObject({
      stage: "verified",
      context,
      userId: owner.id,
      user: {
        id: `pending:${owner.id}`,
        name: "Passkey Applicant",
        displayName: "Passkey Applicant",
      },
      credentialID: response.id,
      publicKey: credential.publicKey,
      counter: 0,
      aaguid: credential.aaguid,
      deviceType: "singleDevice",
      backedUp: false,
      clientData: response,
    });
    expect(observed[1]?.clientData).toEqual(response);
    const persisted = await state(ctx, owner.id);
    expect(persisted).toEqual({
      passkeys: [{ userId: owner.id, counter: 0, name: "Callback Label" }],
      sessions: { count: 1 },
      challenges: { count: 0 },
    });
    expect((await state(ctx, other.id)).sessions.count).toBe(1);
    const replay = await client(ctx).$fetch("/passkey/verify-registration", {
      method: "POST",
      body: { response, createSession: true },
    });
    expect(code(replay)).toBe("CHALLENGE_NOT_FOUND");
    expect(await state(ctx, owner.id)).toEqual(persisted);
    return {
      enrollment: enrollment.result,
      options: challenge.result,
      registered: ctx.snapshot(registered),
      current: ctx.snapshot(current),
      observed: observation(observed),
      persisted,
      replay: ctx.snapshot(replay),
    };
  },
  ["POST /passkey/verify-registration"],
);

compatScenario(
  "passkey registration trusted stored owner resists swapped forged expired proofs and authenticated reassignment",
  async (ctx) => {
    const owner = await signup(ctx);
    const foreign = await signup(ctx, "foreign");
    const context = ctx.uniqueToken("bound-context");
    const ownProof = await enroll(ctx, context);
    const foreignProof = await enroll(ctx, context, "normal", "foreign");
    await owner.actor.client.signOut();
    const challenge = await options(ctx, context);
    const response = new Authenticator().register(
      challenge.result.data,
      ctx.baseURL,
    );
    const swapped = await client(ctx).$fetch("/passkey/verify-registration", {
      method: "POST",
      headers: {
        cookie: cookieHeader([...challenge.cookies, ...foreignProof.cookies]),
      },
      body: { response, createSession: true },
    });
    expect(swapped.error?.status).toBe(403);
    expect(code(swapped)).toBe("ENROLLMENT_DENIED");
    const replay = await client(ctx).$fetch("/passkey/verify-registration", {
      method: "POST",
      headers: {
        cookie: cookieHeader([...challenge.cookies, ...ownProof.cookies]),
      },
      body: { response, createSession: true },
    });
    expect(code(replay)).toBe("CHALLENGE_NOT_FOUND");
    const cryptoChallenge = await options(ctx, context);
    const cryptoResponse = new Authenticator().register(
      cryptoChallenge.result.data,
      ctx.baseURL,
    );
    const cryptoClientData = JSON.parse(
      Buffer.from(
        cryptoResponse.response.clientDataJSON,
        "base64url",
      ).toString(),
    ) as Record<string, unknown>;
    const invalidCryptoResponse = {
      ...cryptoResponse,
      response: {
        ...cryptoResponse.response,
        clientDataJSON: Buffer.from(
          JSON.stringify({
            ...cryptoClientData,
            challenge: "wrong-authenticator-challenge",
          }),
        ).toString("base64url"),
      },
    };
    const invalidCrypto = await client(ctx).$fetch(
      "/passkey/verify-registration",
      {
        method: "POST",
        body: { response: invalidCryptoResponse, createSession: true },
      },
    );
    expect(invalidCrypto.error?.status).toBe(500);
    expect(code(invalidCrypto)).toBe("FAILED_TO_VERIFY_REGISTRATION");
    const cryptoReplay = await client(ctx).$fetch(
      "/passkey/verify-registration",
      {
        method: "POST",
        body: { response: cryptoResponse, createSession: true },
      },
    );
    expect(code(cryptoReplay)).toBe("CHALLENGE_NOT_FOUND");
    const segments = ownProof.result.token.split(".");
    const payload = JSON.parse(
      Buffer.from(segments[1]!, "base64url").toString(),
    ) as Record<string, unknown>;
    segments[1] = Buffer.from(
      JSON.stringify({ ...payload, userId: foreign.id }),
    ).toString("base64url");
    const forged = await client(ctx).$fetch(
      "/passkey/generate-register-options",
      {
        method: "GET",
        query: { context, userId: foreign.id },
        headers: { cookie: `passkey_enrollment=${segments.join(".")}` },
      },
    );
    expect(forged.error?.status).toBe(403);
    expect(code(forged)).toBe("ENROLLMENT_DENIED");
    let authenticatedCookies: string[] = [];
    await owner.actor.client.signIn.email(
      {
        email: owner.email,
        password: "password123",
      },
      {
        onSuccess({ response }) {
          authenticatedCookies = response.headers.getSetCookie();
        },
      },
    );
    const authenticated = await options(ctx, context);
    const authenticatedResponse = new Authenticator().register(
      authenticated.result.data,
      ctx.baseURL,
    );
    const reassigned = await client(ctx).$fetch(
      "/passkey/verify-registration",
      {
        method: "POST",
        headers: {
          cookie: cookieHeader([
            ...authenticatedCookies,
            ...authenticated.cookies,
            ...foreignProof.cookies,
          ]),
        },
        body: { response: authenticatedResponse, createSession: true },
      },
    );
    expect(reassigned.error?.status).toBe(401);
    expect(code(reassigned)).toBe(
      "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY",
    );
    const expiredProof = await enroll(ctx, context, "expired");
    await owner.actor.client.signOut();
    const expired = await client(ctx).$fetch(
      "/passkey/generate-register-options",
      { method: "GET", query: { context } },
    );
    expect(expired.error?.status).toBe(403);
    expect(code(expired)).toBe("ENROLLMENT_DENIED");
    const guestMint = await ctx
      .actor("guest", "passkey-first")
      .fetch(`${ctx.baseURL}/__test/passkey-enrollment`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ context, userId: foreign.id }),
      });
    expect(guestMint.status).toBe(401);
    const persisted = await state(ctx, owner.id);
    expect(persisted.passkeys).toEqual([]);
    expect(persisted.sessions.count).toBe(0);
    expect(persisted.challenges.count).toBe(0);
    expect((await state(ctx, foreign.id)).sessions.count).toBe(1);
    const observed = await events(ctx);
    expect(observed.filter((event) => event.stage === "resolved")).toHaveLength(
      2,
    );
    expect(observed.filter((event) => event.stage === "verified")).toHaveLength(
      1,
    );
    expect(
      observed.find((event) => event.stage === "verified")?.clientData,
    ).toEqual(authenticatedResponse);
    return {
      ownProof: ownProof.result,
      foreignProof: foreignProof.result,
      swapped: ctx.snapshot(swapped),
      replay: ctx.snapshot(replay),
      forged: ctx.snapshot(forged),
      invalidCrypto: ctx.snapshot(invalidCrypto),
      cryptoReplay: ctx.snapshot(cryptoReplay),
      reassigned: ctx.snapshot(reassigned),
      expiredProof: expiredProof.result,
      expired: ctx.snapshot(expired),
      guestMint: await guestMint.json(),
      observed: observation(observed),
      persisted,
    };
  },
  ["POST /passkey/verify-registration"],
);

compatScenario(
  "passkey registration callback failures burn proofs and cancelled session creation rolls back credentials before retry",
  async (ctx) => {
    const owner = await signup(ctx);
    const context = ctx.uniqueToken("failure-policy");
    const failures: unknown[] = [];
    for (const [mode, expectedStatus, expectedCode] of [
      ["after-dynamic-api", 500, "APPLICATION_POLICY_DENIED"],
      ["after-forbidden", 403, null],
      ["after-validation", 400, null],
      ["session-error", 403, null],
      ["after-throw", 500, "FAILED_TO_VERIFY_REGISTRATION"],
      ["after-api", 403, "CALLBACK_DENIED"],
      ["missing-user", 500, "USER_NOT_FOUND"],
      ["normal", 500, "UNABLE_TO_CREATE_SESSION"],
    ] as const) {
      const attemptContext = `${context}-${mode}`;
      const enrollment = await enroll(ctx, attemptContext, mode);
      await owner.actor.client.signOut();
      const challenge = await options(ctx, attemptContext);
      const response = new Authenticator().register(
        challenge.result.data,
        ctx.baseURL,
      );
      const failed = await client(ctx).$fetch("/passkey/verify-registration", {
        method: "POST",
        body: { response, createSession: true },
        ...(mode === "normal" || mode === "session-error"
          ? {
              headers: {
                "x-passkey-policy":
                  mode === "normal" ? "session-deny" : "session-error",
              },
            }
          : {}),
      });
      expect(failed.error?.status).toBe(expectedStatus);
      if (mode === "after-dynamic-api")
        expect(
          z.object({ message: z.string() }).parse(failed.error).message,
        ).toBe(`Application enrollment denied: ${attemptContext}`);
      if (expectedCode) expect(code(failed)).toBe(expectedCode);
      if (!expectedCode) {
        expect(failed.error).not.toHaveProperty("code");
        expect(
          z.object({ message: z.string() }).parse(failed.error).message,
        ).toBe(
          mode === "after-validation"
            ? "Validation error: Callback validation rejected"
            : "session creation cancelled by database hook",
        );
      }
      const replay = await client(ctx).$fetch("/passkey/verify-registration", {
        method: "POST",
        body: { response, createSession: true },
      });
      expect(code(replay)).toBe("CHALLENGE_NOT_FOUND");
      const persisted = await state(ctx, owner.id);
      expect(persisted).toEqual({
        passkeys: [],
        sessions: { count: 0 },
        challenges: { count: 0 },
      });
      const observed = await events(ctx);
      expect(observed).toHaveLength(2);
      expect(observed[1]?.stage).toBe("verified");
      expect(observed[1]?.clientData).toEqual(response);
      failures.push({
        mode,
        enrollment: enrollment.result,
        failed: ctx.snapshot(failed),
        replay: ctx.snapshot(replay),
        persisted,
        observed: observation(observed),
      });
      expect(
        (
          await owner.actor.client.signIn.email({
            email: owner.email,
            password: "password123",
          })
        ).error,
      ).toBeNull();
    }
    const successContext = `${context}-complete`;
    const enrollment = await enroll(ctx, successContext);
    await owner.actor.client.signOut();
    const challenge = await options(ctx, successContext);
    const response = new Authenticator().register(
      challenge.result.data,
      ctx.baseURL,
    );
    const success = await client(ctx).$fetch("/passkey/verify-registration", {
      method: "POST",
      body: { response, createSession: true, name: "  Client Label  " },
    });
    expect(success.error).toBeNull();
    expect(z.object({ name: z.string() }).parse(success.data).name).toBe(
      "Client Label",
    );
    const persisted = await state(ctx, owner.id);
    expect(persisted).toEqual({
      passkeys: [{ userId: owner.id, counter: 0, name: "Client Label" }],
      sessions: { count: 1 },
      challenges: { count: 0 },
    });
    const observed = await events(ctx);
    expect(observed).toHaveLength(2);
    expect(observed[1]?.clientData).toEqual(response);
    return {
      failures,
      enrollment: enrollment.result,
      success: ctx.snapshot(success),
      persisted,
      observed: observation(observed),
    };
  },
  ["POST /passkey/verify-registration"],
);

compatScenario(
  "passkey optional registration needs a resolver only for guests and preserves resolver exception behavior",
  async (ctx) => {
    const missing = client(ctx, "missing", "passkey-first-missing");
    const missingResult = await missing.$fetch(
      "/passkey/generate-register-options",
      { method: "GET" },
    );
    expect(missingResult.error?.status).toBe(400);
    expect(code(missingResult)).toBe("RESOLVE_USER_REQUIRED");
    const authenticated = await signup(ctx, "missing", "passkey-first-missing");
    const authenticatedResult = await missing.$fetch(
      "/passkey/generate-register-options",
      { method: "GET" },
    );
    expect(authenticatedResult.error).toBeNull();
    const owner = await signup(ctx);
    const context = ctx.uniqueToken("resolver-policy");
    const failures: unknown[] = [];
    for (const [mode, status, expectedCode] of [
      ["resolver-invalid-id", 400, "RESOLVED_USER_INVALID"],
      ["resolver-invalid-name", 400, "RESOLVED_USER_INVALID"],
      ["resolver-api", 403, "RESOLVER_DENIED"],
      ["resolver-throw", 500, null],
    ] as const) {
      const enrollment = await enroll(ctx, context, mode);
      await owner.actor.client.signOut();
      const result = await client(ctx).$fetch(
        "/passkey/generate-register-options",
        { method: "GET", query: { context } },
      );
      expect(result.error?.status).toBe(status);
      if (expectedCode) expect(code(result)).toBe(expectedCode);
      expect((await state(ctx, owner.id)).passkeys).toEqual([]);
      const observed = await events(ctx);
      expect(observed).toHaveLength(1);
      expect(observed[0]?.stage).toBe("resolved");
      failures.push({
        enrollment: enrollment.result,
        result: ctx.snapshot(result),
        observed: observation(observed),
      });
      expect(
        (
          await owner.actor.client.signIn.email({
            email: owner.email,
            password: "password123",
          })
        ).error,
      ).toBeNull();
    }
    const successContext = `${context}-complete`;
    const enrollment = await enroll(ctx, successContext);
    await owner.actor.client.signOut();
    const challenge = await options(ctx, successContext);
    const response = new Authenticator().register(
      challenge.result.data,
      ctx.baseURL,
    );
    const invalidInputs: unknown[] = [];
    for (const [createSession, received] of [
      [null, "null"],
      [0, "number"],
      ["true", "string"],
      [[], "array"],
      [{}, "object"],
    ] as const) {
      const invalid = await client(ctx).$fetch("/passkey/verify-registration", {
        method: "POST",
        body: { response, createSession },
      });
      expect(invalid.error?.status).toBe(400);
      expect(code(invalid)).toBe("VALIDATION_ERROR");
      expect(
        z.object({ message: z.string() }).parse(invalid.error).message,
      ).toBe(
        `[body.createSession] Invalid input: expected boolean, received ${received}`,
      );
      const unchanged = await state(ctx, owner.id);
      expect(unchanged.passkeys).toEqual([]);
      expect(unchanged.sessions.count).toBe(0);
      // Both this guest challenge and the independent authenticated missing-resolver challenge remain.
      expect(unchanged.challenges.count).toBe(2);
      invalidInputs.push(ctx.snapshot(invalid));
    }
    let cookies: string[] = [];
    const noSession = await client(ctx).$fetch("/passkey/verify-registration", {
      method: "POST",
      body: { response, createSession: false },
      onSuccess({ response }) {
        cookies = response.headers.getSetCookie();
      },
    });
    expect(noSession.error).toBeNull();
    const registered = z
      .object({ userId: z.string(), name: z.string() })
      .parse(noSession.data);
    expect(registered.userId).toBe(owner.id);
    expect(registered.name).toBe("Callback Label");
    expect(noSession.data).not.toHaveProperty("session");
    expect(noSession.data).not.toHaveProperty("user");
    expect(cookies).toEqual([]);
    expect((await owner.actor.client.getSession()).data).toBeNull();
    const persisted = await state(ctx, owner.id);
    expect(persisted.passkeys).toEqual([
      { userId: owner.id, counter: 0, name: "Callback Label" },
    ]);
    expect(persisted.sessions.count).toBe(0);
    const verified = await events(ctx);
    expect(verified).toHaveLength(2);
    expect(verified[1]?.clientData).toEqual(response);
    return {
      missing: ctx.snapshot(missingResult),
      authenticated: ctx.snapshot(authenticatedResult),
      authenticatedOwner: { userId: authenticated.id },
      failures,
      enrollment: enrollment.result,
      noSession: ctx.snapshot(noSession),
      invalidInputs,
      persisted,
      verified: observation(verified),
    };
  },
  ["POST /passkey/verify-registration", "GET /passkey/generate-register-options"],
);
