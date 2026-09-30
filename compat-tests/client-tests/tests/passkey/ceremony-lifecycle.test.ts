import { expect } from "bun:test";
import { z } from "zod";
import { createAuthClient } from "better-auth/client";
import { passkeyClient } from "@better-auth/passkey/client";
import { Authenticator } from "../../support/authenticator";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { createTracingFetch, type TraceEntry } from "../../support/trace";
import type { FixtureProfile } from "../../support/profiles";

compatScenario(
  "passkey overlapping real signed ceremonies commit exactly one credential and one owner session",
  async (ctx) => {
    const owner = ctx.actor("owner");
    const passkey = client(ctx, "owner");
    let ownerCookies: string[] = [];
    const signup = await owner.client.signUp.email(
      {
        email: ctx.uniqueEmail("overlap-owner"),
        password: "password123",
        name: "Overlap Owner",
      },
      {
        onSuccess({ response }) {
          ownerCookies = response.headers.getSetCookie();
        },
      },
    );
    expect(signup.error).toBeNull();
    const user = identity.parse(signup.data).user;
    const authenticator = new Authenticator();
    let challengeCookies: string[] = [];
    const options = await passkey.$fetch("/passkey/generate-register-options", {
      method: "GET",
      onSuccess({ response }) {
        challengeCookies = response.headers.getSetCookie();
      },
    });
    expect(options.error).toBeNull();
    expect(ownerCookies.length).toBeGreaterThan(0);
    expect(challengeCookies.length).toBe(1);
    const cookieHeader = (cookies: string[]) =>
      cookies.map((cookie) => cookie.split(";")[0]).join("; ");
    async function submit(path: string, body: unknown, cookie: string) {
      // Concurrent outcomes own separate existing traces; completion order is not a protocol guarantee.
      const traces: TraceEntry[] = [];
      const local = createAuthClient({
        baseURL: `${ctx.baseURL}/api/auth`,
        plugins: [passkeyClient()],
        fetchOptions: {
          customFetchImpl: createTracingFetch(ctx.baseURL, "overlap", traces),
        },
      });
      let cookies: string[] = [];
      const result = await local.$fetch(path, {
        method: "POST",
        body,
        headers: { cookie },
        onSuccess({ response }) {
          cookies = response.headers.getSetCookie();
        },
      });
      expect(traces).toHaveLength(1);
      expect(traces[0]?.path).toBe(`/api/auth${path}`);
      expect(traces[0]?.method).toBe("POST");
      expect(traces[0]?.responseStatus).toBe(result.error?.status ?? 200);
      return { result, traces, cookies };
    }
    const response = authenticator.register(options.data, ctx.baseURL);
    const registrations = await Promise.all(
      [0, 1].map(() =>
        submit(
          "/passkey/verify-registration",
          { response, name: "One Winner" },
          cookieHeader([...ownerCookies, ...challengeCookies]),
        ),
      ),
    );
    expect(registrations).toHaveLength(2);
    const registered = registrations.filter(
      ({ result }) => result.error === null,
    );
    const rejectedRegistration = registrations.filter(
      ({ result }) => result.error !== null,
    );
    expect(registered).toHaveLength(1);
    expect(rejectedRegistration).toHaveLength(1);
    const credential = z
      .object({
        userId: z.string(),
        credentialID: z.string(),
        counter: z.number(),
      })
      .parse(registered[0]?.result.data);
    expect(credential).toMatchObject({
      userId: user.id,
      credentialID: response.id,
      counter: 0,
    });
    expect(rejectedRegistration[0]?.result.error?.status).toBe(400);
    expect(
      z
        .object({ code: z.string() })
        .parse(rejectedRegistration[0]?.result.error).code,
    ).toBe("CHALLENGE_NOT_FOUND");
    ctx.recordTransport(registered[0]?.traces ?? []);
    ctx.recordTransport(rejectedRegistration[0]?.traces ?? []);
    const afterRegistration = await state(ctx, user.id);
    expect(afterRegistration).toEqual({
      passkeys: [{ userId: user.id, counter: 0, name: "One Winner" }],
      sessions: { count: 1 },
      challenges: { count: 0 },
    });
    await owner.client.signOut();
    expect((await owner.client.getSession()).data).toBeNull();
    const authOptions = await passkey.$fetch(
      "/passkey/generate-authenticate-options",
      {
        method: "GET",
        onSuccess({ response }) {
          challengeCookies = response.headers.getSetCookie();
        },
      },
    );
    expect(authOptions.error).toBeNull();
    expect(challengeCookies.length).toBe(1);
    const assertion = authenticator.authenticate(authOptions.data, ctx.baseURL);
    const authentications = await Promise.all(
      [0, 1].map(() =>
        submit(
          "/passkey/verify-authentication",
          { response: assertion },
          cookieHeader(challengeCookies),
        ),
      ),
    );
    expect(authentications).toHaveLength(2);
    const authenticated = authentications.filter(
      ({ result }) => result.error === null,
    );
    const rejectedAuthentication = authentications.filter(
      ({ result }) => result.error !== null,
    );
    expect(authenticated).toHaveLength(1);
    expect(rejectedAuthentication).toHaveLength(1);
    const session = z
      .object({
        user: z.object({ id: z.string() }),
        session: z.object({
          id: z.string(),
          userId: z.string(),
          token: z.string(),
        }),
      })
      .parse(authenticated[0]?.result.data);
    expect(session.user.id).toBe(user.id);
    expect(session.session.userId).toBe(user.id);
    expect(rejectedAuthentication[0]?.result.error?.status).toBe(400);
    expect(
      z
        .object({ code: z.string() })
        .parse(rejectedAuthentication[0]?.result.error).code,
    ).toBe("CHALLENGE_NOT_FOUND");
    ctx.recordTransport(authenticated[0]?.traces ?? []);
    ctx.recordTransport(rejectedAuthentication[0]?.traces ?? []);
    expect(authenticated[0]?.cookies).toHaveLength(1);
    const current = await owner.client.getSession({
      fetchOptions: {
        headers: { cookie: cookieHeader(authenticated[0]?.cookies ?? []) },
      },
    });
    expect(current.data?.user.id).toBe(user.id);
    expect(current.data?.session.id).toBe(session.session.id);
    expect(current.data?.session.token).toBe(session.session.token);
    const committed = await state(ctx, user.id);
    expect(committed).toEqual({
      passkeys: [{ userId: user.id, counter: 1, name: "One Winner" }],
      sessions: { count: 1 },
      challenges: { count: 0 },
    });
    const replay = await passkey.$fetch("/passkey/verify-authentication", {
      method: "POST",
      body: { response: assertion },
    });
    expect(z.object({ code: z.string() }).parse(replay.error).code).toBe(
      "CHALLENGE_NOT_FOUND",
    );
    expect(await state(ctx, user.id)).toEqual(committed);
    return {
      registration: {
        success: {
          result: ctx.snapshot(registered[0]?.result),
        },
        denied: {
          result: ctx.snapshot(rejectedRegistration[0]?.result),
        },
      },
      afterRegistration,
      authentication: {
        success: {
          result: ctx.snapshot(authenticated[0]?.result),
        },
        denied: {
          result: ctx.snapshot(rejectedAuthentication[0]?.result),
        },
      },
      current: ctx.snapshot(current),
      committed,
      replay: ctx.snapshot(replay),
    };
  },
);

function client(ctx: ScenarioContext, actor: string, profile?: FixtureProfile) {
  const transport = ctx.actor(actor, profile);
  return createAuthClient({
    baseURL: `${ctx.baseURL}/api/auth`,
    plugins: [passkeyClient()],
    fetchOptions: { customFetchImpl: transport.fetch },
  });
}

const identity = z.object({
  user: z.object({ id: z.string() }),
  token: z.string(),
});
const stateSchema = z.object({
  passkeys: z.array(
    z.object({
      userId: z.string(),
      counter: z.number(),
      name: z.string().nullable(),
    }),
  ),
  sessions: z.object({ count: z.number() }),
  challenges: z.object({ count: z.number() }),
});
async function state(ctx: ScenarioContext, userId: string) {
  const response = await fetch(
    `${ctx.baseURL}/__test/passkey-state?userId=${encodeURIComponent(userId)}`,
  );
  expect(response.status).toBe(200);
  return stateSchema.parse(await response.json());
}
async function control(ctx: ScenarioContext, path: string, body: unknown) {
  const response = await fetch(`${ctx.baseURL}/__test/${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  expect(response.status).toBe(200);
}
function wrongChallenge<T extends { response: { clientDataJSON: string } }>(
  response: T,
): T {
  const parsed = JSON.parse(
    Buffer.from(response.response.clientDataJSON, "base64url").toString(),
  );
  parsed.challenge = Buffer.from(
    "a-different-authenticator-challenge",
  ).toString("base64url");
  return {
    ...response,
    response: {
      ...response.response,
      clientDataJSON: Buffer.from(JSON.stringify(parsed)).toString("base64url"),
    },
  };
}

compatScenario(
  "passkey rejected cryptographic attempts consume challenges without credential or session writes",
  async (ctx) => {
    const owner = ctx.actor("owner");
    const passkey = client(ctx, "owner");
    const signup = await owner.client.signUp.email({
      email: ctx.uniqueEmail("ceremony-owner"),
      password: "password123",
      name: "Ceremony Owner",
    });
    expect(signup.error).toBeNull();
    const user = identity.parse(signup.data).user;
    const authenticator = new Authenticator();
    const options = await passkey.$fetch("/passkey/generate-register-options", {
      method: "GET",
    });
    const response = authenticator.register(options.data, ctx.baseURL);
    const rejected = await passkey.$fetch("/passkey/verify-registration", {
      method: "POST",
      body: { response: wrongChallenge(response), name: "Rejected" },
    });
    expect(rejected.error?.status).toBe(500);
    const afterRejection = await state(ctx, user.id);
    expect(afterRejection).toEqual({
      passkeys: [],
      sessions: { count: 1 },
      challenges: { count: 0 },
    });
    const retry = await passkey.$fetch("/passkey/verify-registration", {
      method: "POST",
      body: { response, name: "Replayed" },
    });
    expect(z.object({ code: z.string() }).parse(retry.error).code).toBe(
      "CHALLENGE_NOT_FOUND",
    );
    const fresh = await passkey.$fetch("/passkey/generate-register-options", {
      method: "GET",
    });
    const registered = await passkey.$fetch("/passkey/verify-registration", {
      method: "POST",
      body: {
        response: authenticator.register(fresh.data, ctx.baseURL),
        name: "Owned",
      },
    });
    expect(registered.error).toBeNull();
    await owner.client.signOut();
    // Invalid endpoint-schema input must leave the signed generation reusable.
    const schemaOptions = await passkey.$fetch(
      "/passkey/generate-authenticate-options",
      { method: "GET" },
    );
    const schemaAssertion = authenticator.authenticate(
      schemaOptions.data,
      ctx.baseURL,
    );
    const invalidBodies = [];
    for (const response of [[], null, 0, "credential", false]) {
      const invalid = await passkey.$fetch("/passkey/verify-authentication", {
        method: "POST",
        body: { response },
      });
      expect(await state(ctx, user.id)).toEqual({
        passkeys: [{ userId: user.id, counter: 0, name: "Owned" }],
        sessions: { count: 0 },
        challenges: { count: 1 },
      });
      expect(invalid.error?.status).toBe(400);
      expect(z.object({ code: z.string() }).parse(invalid.error).code).toBe(
        "VALIDATION_ERROR",
      );
      invalidBodies.push(ctx.snapshot(invalid));
    }
    const schemaAccepted = await passkey.$fetch(
      "/passkey/verify-authentication",
      { method: "POST", body: { response: schemaAssertion } },
    );
    expect(schemaAccepted.error).toBeNull();
    expect((await owner.client.getSession()).data?.user.id).toBe(user.id);
    await owner.client.signOut();
    const failures = [];
    for (const kind of [
      "signature",
      "challenge",
      "unknown-credential",
    ] as const) {
      const authOptions = await passkey.$fetch(
        "/passkey/generate-authenticate-options",
        { method: "GET" },
      );
      const assertion = authenticator.authenticate(
        authOptions.data,
        ctx.baseURL,
      );
      const signature = Buffer.from(assertion.response.signature, "base64url");
      signature[signature.length - 1] =
        (signature[signature.length - 1] ?? 0) ^ 1;
      const rejectedAssertion =
        kind === "signature"
          ? {
              ...assertion,
              response: {
                ...assertion.response,
                signature: signature.toString("base64url"),
              },
            }
          : kind === "challenge"
            ? wrongChallenge(assertion)
            : {
                ...assertion,
                id: Buffer.from("a-different-credential-id").toString(
                  "base64url",
                ),
              };
      const failedAuth = await passkey.$fetch(
        "/passkey/verify-authentication",
        { method: "POST", body: { response: rejectedAssertion } },
      );
      expect(failedAuth.error?.status).toBe(kind === "challenge" ? 400 : 401);
      expect(z.object({ code: z.string() }).parse(failedAuth.error).code).toBe(
        kind === "unknown-credential"
          ? "PASSKEY_NOT_FOUND"
          : "AUTHENTICATION_FAILED",
      );
      expect((await owner.client.getSession()).data).toBeNull();
      const afterFailedAuth = await state(ctx, user.id);
      expect(afterFailedAuth).toEqual({
        passkeys: [{ userId: user.id, counter: 1, name: "Owned" }],
        sessions: { count: 0 },
        challenges: { count: 0 },
      });
      const authRetry = await passkey.$fetch("/passkey/verify-authentication", {
        method: "POST",
        body: { response: assertion },
      });
      expect(z.object({ code: z.string() }).parse(authRetry.error).code).toBe(
        "CHALLENGE_NOT_FOUND",
      );
      failures.push({
        kind,
        failedAuth: ctx.snapshot(failedAuth),
        afterFailedAuth,
        authRetry: ctx.snapshot(authRetry),
      });
    }
    const finalOptions = await passkey.$fetch(
      "/passkey/generate-authenticate-options",
      { method: "GET" },
    );
    const authenticated = await passkey.$fetch(
      "/passkey/verify-authentication",
      {
        method: "POST",
        body: {
          response: authenticator.authenticate(finalOptions.data, ctx.baseURL),
        },
      },
    );
    expect(authenticated.error).toBeNull();
    expect((await owner.client.getSession()).data?.user.id).toBe(user.id);
    const finalState = await state(ctx, user.id);
    expect(finalState).toEqual({
      passkeys: [{ userId: user.id, counter: 5, name: "Owned" }],
      sessions: { count: 1 },
      challenges: { count: 0 },
    });
    return {
      rejected: ctx.snapshot(rejected),
      retry: ctx.snapshot(retry),
      afterRejection,
      invalidBodies,
      schemaAccepted: ctx.snapshot(schemaAccepted),
      failures,
      authenticated: ctx.snapshot(authenticated),
      finalState,
    };
  },
);

compatScenario(
  "passkey foreign owner, expired challenge and wrong ceremony retire the actual persisted generation",
  async (ctx) => {
    const owner = ctx.actor("owner");
    const ownerClient = client(ctx, "owner");
    const signup = await owner.client.signUp.email({
      email: ctx.uniqueEmail("ceremony-owner"),
      password: "password123",
      name: "Owner",
    });
    expect(signup.error).toBeNull();
    const user = identity.parse(signup.data).user;
    const attacker = ctx.actor("attacker");
    const attackerSignup = await attacker.fetch("/api/auth/sign-up/email", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        email: ctx.uniqueEmail("ceremony-attacker"),
        password: "password123",
        name: "Attacker",
      }),
    });
    expect(attackerSignup.status).toBe(200);
    const attackerUser = identity.parse(await attackerSignup.json()).user;
    const attackerCookies = attackerSignup.headers
      .getSetCookie()
      .map((cookie) => cookie.split(";")[0])
      .join("; ");
    const options = await owner.fetch(
      "/api/auth/passkey/generate-register-options",
    );
    expect(options.status).toBe(200);
    const challengeCookie = options.headers
      .getSetCookie()
      .map((cookie) => cookie.split(";")[0])
      .join("; ");
    const authenticator = new Authenticator();
    const response = authenticator.register(await options.json(), ctx.baseURL);
    const foreignResponse = await attacker.fetch(
      "/api/auth/passkey/verify-registration",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie: `${attackerCookies}; ${challengeCookie}`,
        },
        body: JSON.stringify({ response, name: "Stolen" }),
      },
    );
    const foreign = {
      status: foreignResponse.status,
      body: await foreignResponse.json(),
    };
    expect(foreign.status).toBe(401);
    const ownerRetry = await ownerClient.$fetch(
      "/passkey/verify-registration",
      { method: "POST", body: { response } },
    );
    expect(z.object({ code: z.string() }).parse(ownerRetry.error).code).toBe(
      "CHALLENGE_NOT_FOUND",
    );
    expect((await state(ctx, user.id)).passkeys).toEqual([]);
    expect((await state(ctx, attackerUser.id)).sessions.count).toBe(1);
    const expiryOptions = await ownerClient.$fetch(
      "/passkey/generate-register-options",
      { method: "GET" },
    );
    const expiryResponse = authenticator.register(
      expiryOptions.data,
      ctx.baseURL,
    );
    await control(ctx, "passkey-challenge-clock", {
      expiresAt: "2000-01-01T00:00:00.000Z",
    });
    const expired = await ownerClient.$fetch("/passkey/verify-registration", {
      method: "POST",
      body: { response: expiryResponse },
    });
    expect(z.object({ code: z.string() }).parse(expired.error).code).toBe(
      "CHALLENGE_NOT_FOUND",
    );
    expect((await state(ctx, user.id)).challenges.count).toBe(0);
    const ceremonyOptions = await ownerClient.$fetch(
      "/passkey/generate-register-options",
      { method: "GET" },
    );
    const ceremonyResponse = authenticator.register(
      ceremonyOptions.data,
      ctx.baseURL,
    );
    const wrongCeremony = await ownerClient.$fetch(
      "/passkey/verify-authentication",
      { method: "POST", body: { response: ceremonyResponse } },
    );
    expect(z.object({ code: z.string() }).parse(wrongCeremony.error).code).toBe(
      "CHALLENGE_NOT_FOUND",
    );
    const ceremonyRetry = await ownerClient.$fetch(
      "/passkey/verify-registration",
      { method: "POST", body: { response: ceremonyResponse } },
    );
    expect(z.object({ code: z.string() }).parse(ceremonyRetry.error).code).toBe(
      "CHALLENGE_NOT_FOUND",
    );
    const finalState = await state(ctx, user.id);
    expect(finalState).toEqual({
      passkeys: [],
      sessions: { count: 1 },
      challenges: { count: 0 },
    });
    return {
      foreign,
      ownerRetry: ctx.snapshot(ownerRetry),
      expired: ctx.snapshot(expired),
      wrongCeremony: ctx.snapshot(wrongCeremony),
      ceremonyRetry: ctx.snapshot(ceremonyRetry),
      finalState,
    };
  },
);

compatScenario(
  "passkey registration freshness rejects before consumption and freshAge zero permits old sessions",
  async (ctx) => {
    const results = [];
    for (const profile of ["passkey-fresh", "passkey-no-freshness"] as const) {
      const actor = ctx.actor(profile, profile);
      const passkey = client(ctx, profile, profile);
      const email = ctx.uniqueEmail(profile);
      const signup = await actor.client.signUp.email({
        email,
        password: "password123",
        name: profile,
      });
      expect(signup.error).toBeNull();
      const { user, token } = identity.parse(signup.data);
      const options = await passkey.$fetch(
        "/passkey/generate-register-options",
        { method: "GET" },
      );
      expect(options.error).toBeNull();
      const authenticator = new Authenticator();
      const response = authenticator.register(options.data, ctx.baseURL);
      await control(ctx, "expire-session", {
        token,
        createdAt: "2000-01-01T00:00:00.000Z",
        expiresAt: "2100-01-01T00:00:00.000Z",
      });
      let staleGeneration, staleVerification;
      if (profile === "passkey-fresh") {
        staleGeneration = await passkey.$fetch(
          "/passkey/generate-register-options",
          { method: "GET" },
        );
        expect(staleGeneration.error?.status).toBe(403);
        expect(
          z.object({ code: z.string() }).parse(staleGeneration.error).code,
        ).toBe("SESSION_NOT_FRESH");
        staleVerification = await passkey.$fetch(
          "/passkey/verify-registration",
          { method: "POST", body: { response } },
        );
        expect(
          z.object({ code: z.string() }).parse(staleVerification.error).code,
        ).toBe("SESSION_NOT_FRESH");
        const untouched = await state(ctx, user.id);
        expect(untouched).toEqual({
          passkeys: [],
          sessions: { count: 1 },
          challenges: { count: 1 },
        });
        expect(
          (await actor.client.signIn.email({ email, password: "password123" }))
            .error,
        ).toBeNull();
      }
      const verified = await passkey.$fetch("/passkey/verify-registration", {
        method: "POST",
        body: { response, name: profile },
      });
      expect(verified.error).toBeNull();
      const persisted = await state(ctx, user.id);
      expect(persisted.passkeys).toContainEqual({
        userId: user.id,
        counter: 0,
        name: profile,
      });
      expect(persisted.challenges.count).toBe(0);
      results.push({
        profile,
        staleGeneration: ctx.snapshot(staleGeneration ?? null),
        staleVerification: ctx.snapshot(staleVerification ?? null),
        verified: ctx.snapshot(verified),
      });
      await ctx.resetServerState();
    }
    return results;
  },
);
