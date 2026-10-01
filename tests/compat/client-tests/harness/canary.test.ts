import { expect, test } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { SignJWT } from "jose";
import { compareValues } from "../support/compare";
import { createTracingFetch, type TraceEntry } from "../support/trace";

// Negative controls go through HTTP, the real SDK, tracing and the production comparator.
// They must fail comparison even though both HTTP responses report success.
test("live response mutations cannot hide broken ownership or cookie security", async () => {
  let mode = "valid";
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch() {
      return Response.json(
        {
          session: {
            id: "session-1",
            userId: mode === "ownership" ? "some-other-user" : "user-1",
            token: "opaque-session-token",
            expiresAt: "2030-01-01T00:00:00.000Z",
          },
          user: {
            id: "user-1",
            email: "canary@test.com",
            emailVerified: false,
            name: "Canary",
            createdAt: "2026-01-01T00:00:00.000Z",
            updatedAt: "2026-01-01T00:00:00.000Z",
          },
        },
        {
          headers:
            mode === "missing-cookie"
              ? {}
              : {
                  "set-cookie": `better-auth.session_token=opaque-session-token; Path=/; SameSite=Lax${mode === "insecure-cookie" ? "" : "; HttpOnly; Secure"}`,
                },
        },
      );
    },
  });
  try {
    const baseURL = server.url.origin;
    async function observe(mutation: string) {
      mode = mutation;
      const traces: TraceEntry[] = [];
      const tracing = createTracingFetch(baseURL, "canary", traces);
      const client = createAuthClient({
        baseURL,
        fetchOptions: { customFetchImpl: tracing },
      });
      return { result: await client.getSession(), traces };
    }
    const baseline = await observe("valid");
    expect(baseline.result.error).toBeNull();
    const context = {
      leftBaseURL: baseURL,
      rightBaseURL: baseURL,
      leftStartedAt: 0,
      rightStartedAt: 0,
    };
    expect(compareValues(baseline, await observe("valid"), context)).toEqual(
      [],
    );
    for (const mode of ["ownership", "insecure-cookie", "missing-cookie"]) {
      const mutated = await observe(mode);
      expect(mutated.result.error).toBeNull();
      const differences = compareValues(baseline, mutated, context);
      expect(differences.length).toBeGreaterThan(0);
      expect(
        differences.every((entry) =>
          mode === "ownership"
            ? entry.path.startsWith("result.data.") ||
              entry.path.startsWith("traces.0.responseBody.")
            : entry.path.startsWith("traces.0.responseCookies."),
        ),
      ).toBe(true);
    }
  } finally {
    await server.stop(true);
  }
});

test("independently signed JWTs keep application id, token and state claims literal", async () => {
  const claims = {
    exp: 4102444800,
    iss: "https://issuer.example",
    aud: "client",
    custom: { id: "literal-owner", token: "literal-value", state: "approved" },
  };
  const sign = (payload: typeof claims, key: string) =>
    new SignJWT(payload)
      .setProtectedHeader({ alg: "HS256" })
      .sign(new TextEncoder().encode(key.repeat(32)));
  const left = { token: await sign(claims, "a") },
    context = {
      leftBaseURL: "http://localhost:1",
      rightBaseURL: "http://localhost:2",
      leftStartedAt: 0,
      rightStartedAt: 0,
    };
  expect(
    compareValues(left, { token: await sign(claims, "b") }, context),
  ).toEqual([]);
  for (const field of ["id", "token", "state"] as const) {
    const changed = {
      ...claims,
      custom: { ...claims.custom, [field]: "changed-literal" },
    };
    expect(
      compareValues(left, { token: await sign(changed, "b") }, context).some(
        (diff) => diff.path === `token.payload.custom.${field}`,
      ),
    ).toBe(true);
  }
});

test("complete enrollment responses retain credential formats, relationships and literal extra fields", () => {
  const observe = (secret: string, code: string) => ({
    traces: [
      {
        path: "/api/auth/two-factor/enable",
        responseBody: {
          totpURI: `otpauth://totp/Fixture:user?secret=${secret}&digits=6`,
          backupCodes: [code],
          metadata: {
            backupCodes: ["literal-code"],
            totpURI: "otpauth://totp/app?secret=AAAAAAAA",
          },
        },
      },
      {
        path: "/api/auth/two-factor/get-totp-uri",
        responseBody: {
          totpURI: `otpauth://totp/Fixture:user?secret=${secret}&digits=6`,
        },
      },
    ],
  });
  const context = {
    leftBaseURL: "http://localhost:1",
    rightBaseURL: "http://localhost:2",
    leftStartedAt: 0,
    rightStartedAt: 0,
  };
  const left = observe("AAAAAAAA", "aaaaa-11111"),
    right = observe("BBBBBBBB", "bbbbb-22222");
  expect(compareValues(left, right, context)).toEqual([]);
  const changed = structuredClone(right);
  changed.traces[1]!.responseBody.totpURI =
    changed.traces[1]!.responseBody.totpURI.replace("BBBBBBBB", "CCCCCCCC");
  expect(compareValues(left, changed, context).length).toBeGreaterThan(0);
  const malformed = structuredClone(right);
  malformed.traces[0]!.responseBody.backupCodes = ["wrong-format"];
  expect(compareValues(left, malformed, context).length).toBeGreaterThan(0);
  const literal = structuredClone(right);
  literal.traces[0]!.responseBody.metadata!.backupCodes = ["changed-code"];
  expect(compareValues(left, literal, context).length).toBeGreaterThan(0);
  const duplicate = structuredClone(right);
  duplicate.traces[0]!.responseBody.totpURI += "&secret=WRONG";
  expect(compareValues(left, duplicate, context).length).toBeGreaterThan(0);
});

test("request clocks tolerate slower execution while preserving session lifetime and issuance bounds", () => {
  const row = (created: number, token: string) => ({
    id: token,
    token,
    userId: "owner",
    createdAt: new Date(created).toISOString(),
    updatedAt: new Date(created).toISOString(),
    expiresAt: new Date(created + 60_000).toISOString(),
  });
  const leftRow = row(100_100, "left"),
    rightRow = row(200_100, "right");
  const observed = (session: typeof leftRow) => ({
    observation: { session },
    traces: [
      {
        method: "GET",
        path: "/api/auth/get-session",
        responseBody: { session },
      },
    ],
  });
  const context = {
    leftBaseURL: "http://localhost:1",
    rightBaseURL: "http://localhost:2",
    leftStartedAt: 100_000,
    rightStartedAt: 190_000,
    leftRequestWindows: [
      { startedAt: 100_000, finishedAt: 100_200, inputDates: {} },
    ],
    rightRequestWindows: [
      { startedAt: 200_000, finishedAt: 200_200, inputDates: {} },
    ],
  };
  expect(compareValues(observed(leftRow), observed(rightRow), context)).toEqual(
    [],
  );
  expect(
    compareValues(
      observed(leftRow),
      observed({ ...rightRow, expiresAt: new Date(300_100).toISOString() }),
      context,
    ).length,
  ).toBeGreaterThan(0);
  expect(
    compareValues(observed(leftRow), observed(row(210_100, "right")), context)
      .length,
  ).toBeGreaterThan(0);
  expect(
    compareValues(
      observed(leftRow),
      observed({ ...rightRow, expiresAt: new Date(250_100).toISOString() }),
      context,
    ).some((diff) => diff.path.endsWith("expiresAt")),
  ).toBe(true);
});

test("later session and user clocks require their actual issuance and update receipts", () => {
  const iso = (n: number) => new Date(n).toISOString();
  const observe = (side: string, issued: number, updated: number) => ({
    traces: [
      {
        method: "POST",
        path: "/api/auth/sign-in/email",
        responseStatus: 200,
        responseBody: { token: side, user: { id: `${side}-user` } },
      },
      {
        method: "POST",
        path: "/api/auth/update-user",
        responseStatus: 200,
        responseBody: { status: true },
      },
      {
        method: "GET",
        path: "/api/auth/get-session",
        responseStatus: 200,
        responseBody: {
          session: {
            id: `${side}-session`,
            token: side,
            userId: `${side}-user`,
            createdAt: iso(issued),
            updatedAt: iso(issued),
            expiresAt: iso(issued + 60_000),
          },
          user: { id: `${side}-user`, updatedAt: iso(updated) },
        },
      },
    ],
  });
  const left = observe("left", 100_100, 105_100),
    right = observe("right", 200_100, 210_100);
  const windows = (side: string, issued: number, updated: number) => [
    {
      startedAt: issued,
      finishedAt: issued + 200,
      inputDates: {},
      issuedSessionCookie: `better-auth.session_token=${side}.signed`,
    },
    {
      startedAt: updated,
      finishedAt: updated + 200,
      inputDates: {},
      sessionCookie: `better-auth.session_token=${side}.signed`,
    },
    { startedAt: updated + 500, finishedAt: updated + 600, inputDates: {} },
  ];
  const context = {
    leftBaseURL: "http://localhost:1",
    rightBaseURL: "http://localhost:2",
    leftStartedAt: 100_000,
    rightStartedAt: 190_000,
    leftRequestWindows: windows("left", 100_000, 105_000),
    rightRequestWindows: windows("right", 200_000, 210_000),
  };
  expect(compareValues(left, right, context)).toEqual([]);
  for (const change of [
    "unknown-cookie",
    "read-endpoint",
    "foreign-owner",
    "wrong-lifetime",
  ]) {
    const altered = structuredClone(right),
      clocks = structuredClone(context);
    if (change === "unknown-cookie")
      clocks.rightRequestWindows[1]!.sessionCookie =
        "better-auth.session_token=unissued.signed";
    if (change === "read-endpoint")
      altered.traces[0]!.path = "/api/auth/get-session";
    if (change === "foreign-owner")
      altered.traces[2]!.responseBody.session!.userId = "another-user";
    if (change === "wrong-lifetime")
      altered.traces[2]!.responseBody.session!.expiresAt = iso(250_100);
    expect(compareValues(left, altered, clocks).length).toBeGreaterThan(0);
  }
});

test("clock evidence cannot approve another field, entity or a changed lifetime", () => {
  const iso = (milliseconds: number) => new Date(milliseconds).toISOString();
  const session = (expiry: number) => ({
    id: "session",
    token: "token",
    userId: "owner",
    createdAt: iso(10),
    updatedAt: iso(10),
    expiresAt: iso(expiry),
  });
  const trace = (responseBody: unknown) => ({
    method: "GET",
    path: "/api/auth/get-session",
    responseBody,
  });
  const context = {
    leftBaseURL: "http://localhost:1",
    rightBaseURL: "http://localhost:2",
    leftStartedAt: 0,
    rightStartedAt: 0,
    leftRequestWindows: [
      { startedAt: 0, finishedAt: 100, inputDates: {} },
      { startedAt: 50, finishedAt: 100, inputDates: {} },
    ],
    rightRequestWindows: [
      { startedAt: 0, finishedAt: 6000, inputDates: {} },
      { startedAt: 5500, finishedAt: 5600, inputDates: {} },
    ],
  };
  const left = { traces: [trace({ session: session(50) })] };
  const right = { traces: [trace({ session: session(5500) })] };
  for (const extra of [false, true]) {
    const a = structuredClone(left),
      b = structuredClone(right);
    if (extra) {
      a.traces.push(trace({ user: { id: "user", createdAt: iso(50) } }));
      b.traces.push(trace({ user: { id: "user", createdAt: iso(5500) } }));
    }
    expect(
      compareValues(a, b, context).some(
        (diff) => diff.path === "traces.0.responseBody.session.expiresAt",
      ),
    ).toBe(true);
  }
});

test("discarded successful bodies and response policy headers remain observable", async () => {
  let mode = "baseline";
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch: () =>
      Response.json(
        { result: { enabled: mode !== "body" } },
        {
          headers:
            mode === "headers"
              ? {}
              : {
                  "access-control-allow-origin": "https://client.example",
                  "cache-control": "no-store",
                },
        },
      ),
  });
  try {
    async function observe(next: string) {
      mode = next;
      const traces: TraceEntry[] = [];
      await createTracingFetch(
        server.url.origin,
        "actor",
        traces,
      )("/api/auth/ok");
      return { traces };
    }
    const baseline = await observe("baseline"),
      context = {
        leftBaseURL: server.url.origin,
        rightBaseURL: server.url.origin,
        leftStartedAt: 0,
        rightStartedAt: 0,
      };
    expect(compareValues(baseline, await observe("baseline"), context)).toEqual(
      [],
    );
    expect(
      compareValues(baseline, await observe("body"), context).some(
        (diff) => diff.path === "traces.0.responseBody.result.enabled",
      ),
    ).toBe(true);
    const missing = compareValues(baseline, await observe("headers"), context);
    expect(
      missing.some((diff) => diff.path.endsWith("access-control-allow-origin")),
    ).toBe(true);
    expect(missing.some((diff) => diff.path.endsWith("cache-control"))).toBe(
      true,
    );
  } finally {
    server.stop(true);
  }
});
