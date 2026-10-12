import { Database } from "bun:sqlite";
import { expect } from "bun:test";
import { createHash } from "node:crypto";

import { betterAuth, type BetterAuthOptions } from "better-auth";
import { getMigrations } from "better-auth/db/migration";

import { cacheReceipt } from "../../support/compact-cache-receipt";
import { normalizeClientValue } from "../../support/normalize";
import { createTracingFetch, requestWindow, type TraceEntry } from "../../support/trace";

export const secret = "compat-test-only-key-not-real-minimum-32chars";
export const authPath = "/__test/profiles/server-dispatch-cache/api/auth";
const control = "/__test/server-dispatch-cache/call";
export async function captureSessionIssuer(
  operation: "signInEmail" | "changePassword" | "signUpEmail",
) {
  const database = new Database(":memory:");
  let auth: ReturnType<typeof betterAuth>;
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      if (new URL(request.url).pathname === control) {
        const input = await request.json();
        const args = {
          body: input.body,
          query: input.query,
          headers: new Headers(input.headers),
          returnHeaders: true as const,
        };
        const value =
          operation === "signInEmail"
            ? await auth.api.signInEmail(args)
            : operation === "signUpEmail"
              ? await auth.api.signUpEmail(args)
              : await auth.api.changePassword(args);
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
        operation,
        query: { disableRefresh: true },
        headers: { cookie },
        body:
          operation === "signInEmail"
            ? { email: "ROTATION@FIXTURE.TEST", password: "initial-password-123" }
            : operation === "signUpEmail"
              ? {
                  name: "Created Owner",
                  email: "CREATION@FIXTURE.TEST",
                  password: "initial-password-123",
                }
              : {
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
    const userId = output.result.value.response.user.id;
    const user = database
      .query<{ id: string; email: string; createdAt: number }, [string]>(
        "SELECT * FROM user WHERE id=?",
      )
      .get(userId)!;
    const accounts = database.query("SELECT * FROM account WHERE userId=?").all(userId);
    const sessions = database
      .query<{ id: string; token: string; userId: string; expiresAt: number }, [string]>(
        "SELECT * FROM session WHERE userId=?",
      )
      .all(userId);
    const physicalBody = {
      user: { ...user, createdAt: new Date(user.createdAt).toISOString() },
      accounts,
      sessions: sessions.map((row) => ({
        ...row,
        expiresAt: new Date(row.expiresAt).toISOString(),
      })),
    };
    const physicalObservations = [
      {
        kind: "session" as const,
        owner: userId,
        body: physicalBody,
        digest: createHash("sha256").update(JSON.stringify(physicalBody)).digest("hex"),
      },
    ];
    return {
      physicalObservations,
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
