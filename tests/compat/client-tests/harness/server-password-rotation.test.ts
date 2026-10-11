import { Database } from "bun:sqlite";
import { expect, test } from "bun:test";
import { createHash, createHmac } from "node:crypto";

import { betterAuth, type BetterAuthOptions } from "better-auth";
import { getMigrations } from "better-auth/db/migration";

import { cacheReceipt } from "../support/compact-cache-receipt";
import { compareValues, type ComparisonContext } from "../support/compare";
import { normalizeClientValue } from "../support/normalize";
import { createTracingFetch, requestWindow, type TraceEntry } from "../support/trace";

const secret = "compat-test-only-key-not-real-minimum-32chars";
const authPath = "/__test/profiles/server-dispatch-cache/api/auth";
const control = "/__test/server-dispatch-cache/call";
async function capture() {
  const database = new Database(":memory:");
  let auth: ReturnType<typeof betterAuth>;
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      if (new URL(request.url).pathname === control) {
        const input = await request.json();
        const value = await auth.api.changePassword({
          body: input.body,
          query: input.query,
          headers: new Headers(input.headers),
          returnHeaders: true,
        });
        return Response.json({
          result: {
            ok: true,
            value: {
              response: value.response,
              headers: {
                ...Object.fromEntries(value.headers),
                "set-cookie": value.headers.getSetCookie().join(", "),
              },
              cookies: value.headers.getSetCookie(),
            },
          },
        });
      }
      return auth.handler(request);
    },
  });
  const baseURL = `http://127.0.0.1:${server.port}`;
  try {
    const options: BetterAuthOptions = {
      baseURL,
      basePath: authPath,
      secret,
      database,
      rateLimit: { enabled: false },
      emailAndPassword: { enabled: true },
      session: { cookieCache: { enabled: true, strategy: "compact" as const, maxAge: 300 } },
    };
    await (await getMigrations(options)).runMigrations();
    auth = betterAuth(options);
    const traces: TraceEntry[] = [];
    const startedAt = Date.now();
    const fetch = createTracingFetch(baseURL, "owner", traces, authPath);
    const signup = await fetch(`${baseURL}${authPath}/sign-up/email`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        name: "Owner",
        email: "rotation@fixture.test",
        password: "initial-password-123",
      }),
    });
    expect(signup.status).toBe(200);
    const signupBody = await signup.json();
    const cookie = signup.headers
      .getSetCookie()
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const rotation = await fetch(`${baseURL}${control}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        operation: "changePassword",
        query: { disableRefresh: true },
        headers: { cookie },
        body: {
          currentPassword: "initial-password-123",
          newPassword: "rotated-password-123",
          revokeOtherSessions: true,
        },
      }),
    });
    expect(rotation.status).toBe(200);
    const output = await rotation.json();
    const publishedHeaders = new Headers();
    for (const raw of output.result.value.cookies) publishedHeaders.append("set-cookie", raw);
    const published = await cacheReceipt(publishedHeaders);
    const restored = await fetch(`${baseURL}${authPath}/get-session`, {
      headers: {
        cookie: output.result.value.cookies.map((raw: string) => raw.split(";")[0]).join("; "),
      },
    });
    expect(restored.status).toBe(200);
    const restoredBody = await restored.json();
    expect(restoredBody.session.token).toBe(output.result.value.response.token);
    return {
      value: normalizeClientValue({
        observation: { signup: signupBody, output, published, restored: restoredBody },
        traces,
      }),
      windows: traces.map((trace) => structuredClone(trace[requestWindow])),
      baseURL,
      startedAt,
      finishedAt: Date.now(),
    };
  } finally {
    server.stop(true);
    database.close();
  }
}

test("logical rotation needs actual issuer, owner, signature, clock and browser read", async () => {
  const left = await capture();
  const right = await capture();
  const context: ComparisonContext = {
    leftBaseURL: left.baseURL,
    rightBaseURL: right.baseURL,
    leftStartedAt: left.startedAt,
    rightStartedAt: right.startedAt,
    leftFinishedAt: left.finishedAt,
    rightFinishedAt: right.finishedAt,
    leftRequestWindows: left.windows,
    rightRequestWindows: right.windows,
    sessionCookieSecret: secret,
    compactSessionCacheSecret: secret,
    sessionCookieSecretsByAuthPath: { [authPath]: secret },
  };
  expect(compareValues(left.value, right.value, context)).toEqual([]);
  for (const mutate of [
    (windows: typeof right.windows) => {
      delete windows[0]!.issuedSessionCookie;
    },
    (windows: typeof right.windows) => {
      const receipt = windows[1]!.logicalEndpoint!;
      const response = receipt.response as any;
      response.result.value.response.user.id = "foreign-owner";
      receipt.digest = createHash("sha256").update(JSON.stringify(response)).digest("hex");
    },
    (windows: typeof right.windows) => {
      const receipt = windows[1]!.logicalEndpoint!;
      const response = receipt.response as any;
      const token = "unissued-token";
      const signature = createHmac("sha256", secret).update(token).digest("base64");
      response.result.value.response.token = token;
      response.result.value.headers["set-cookie"] =
        `better-auth.session_token=${encodeURIComponent(`${token}.${signature}`)}; Path=/; HttpOnly`;
      receipt.digest = createHash("sha256").update(JSON.stringify(response)).digest("hex");
    },
    (windows: typeof right.windows) => {
      delete windows[1]!.logicalEndpoint;
    },
    (windows: typeof right.windows) => {
      windows[1]!.logicalEndpoint!.digest = "altered";
    },
    (windows: typeof right.windows) => {
      (windows[1]!.logicalEndpoint!.input as any).headers.cookie =
        "better-auth.session_token=unissued";
    },
    (windows: typeof right.windows) => {
      (windows[1]!.logicalEndpoint!.input as any).body.revokeOtherSessions = false;
    },
    (windows: typeof right.windows) => {
      windows[1]!.finishedAt = windows[1]!.startedAt - 1000;
    },
    (windows: typeof right.windows) => {
      delete windows[2]!.sessionCookie;
    },
  ]) {
    const windows = structuredClone(right.windows);
    mutate(windows);
    expect(
      compareValues(left.value, right.value, { ...context, rightRequestWindows: windows }).some(
        (difference) => difference.reason.includes("corresponding observed issuance"),
      ),
    ).toBe(true);
  }
  const damaged = structuredClone(right.value) as any;
  damaged.observation.output.result.value.headers["set-cookie"] =
    "better-auth.session_token=forged; Path=/; HttpOnly";
  expect(compareValues(left.value, damaged, context)).not.toEqual([]);
});
