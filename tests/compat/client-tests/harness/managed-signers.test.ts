import { Database } from "bun:sqlite";
import { expect, test } from "bun:test";
import { createHmac } from "node:crypto";

import { betterAuth, type BetterAuthOptions } from "better-auth";
import { createAuthClient } from "better-auth/client";
import { getMigrations } from "better-auth/db/migration";

import { compareValues } from "../support/compare";
import { createTracingFetch, requestWindow, type TraceEntry } from "../support/trace";

// Actual pinned Source HTTP issuances independently guard the comparator's
// per-runtime expected signer. No retained-key search or receipt manufacture.
test("managed profile signatures require the issuing runtime key and actual matching issuance", async () => {
  const old = "managed-harness-old-key-at-least-32-characters";
  const current = "managed-harness-current-key-at-least-32-characters";
  const path = "/__test/profiles/managed-old/api/auth";
  async function observe() {
    const database = new Database(":memory:");
    let auth: ReturnType<typeof betterAuth>;
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch: (request) => auth.handler(request),
    });
    const baseURL = `http://127.0.0.1:${server.port}`;
    const options: BetterAuthOptions = {
      baseURL,
      basePath: path,
      database,
      secrets: [{ version: 0, value: old }],
      emailAndPassword: { enabled: true },
      rateLimit: { enabled: false },
    };
    try {
      await (await getMigrations(options)).runMigrations();
      auth = betterAuth(options);
      const traces: TraceEntry[] = [];
      const startedAt = Date.now();
      const client = createAuthClient({
        baseURL: baseURL + path,
        fetchOptions: { customFetchImpl: createTracingFetch(baseURL, "owner", traces, path) },
      });
      const issued = await client.signUp.email({
        email: "managed-signer@harness.test",
        password: "password123",
        name: "Managed signer",
      });
      expect(issued.error).toBeNull();
      const read = await client.getSession();
      expect(read.data?.session.token).toBe(issued.data!.token!);
      return {
        value: {
          observation: {
            issued,
            read,
            headers: { "set-cookie": traces[0]![requestWindow]!.issuedSessionCookie! },
          },
          traces,
        },
        baseURL,
        startedAt,
        finishedAt: Date.now(),
        windows: traces.map((trace) => trace[requestWindow]),
      };
    } finally {
      server.stop(true);
      database.close();
    }
  }
  const left = await observe();
  const right = await observe();
  const context = {
    leftBaseURL: left.baseURL,
    rightBaseURL: right.baseURL,
    leftStartedAt: left.startedAt,
    rightStartedAt: right.startedAt,
    leftFinishedAt: left.finishedAt,
    rightFinishedAt: right.finishedAt,
    leftRequestWindows: left.windows,
    rightRequestWindows: right.windows,
    sessionCookieSecret: current,
    sessionCookieSecretsByAuthPath: { [path]: old },
  };
  expect(compareValues(left.value, right.value, context)).toEqual([]);
  expect(
    compareValues(left.value, right.value, { ...context, sessionCookieSecretsByAuthPath: {} })
      .length,
  ).toBeGreaterThan(0);
  expect(
    compareValues(left.value, right.value, {
      ...context,
      sessionCookieSecretsByAuthPath: { [path]: current, "/__test/profiles/foreign/api/auth": old },
    }).length,
  ).toBeGreaterThan(0);
  const token = right.value.observation.issued.data!.token!;
  const wrong = `better-auth.session_token=${encodeURIComponent(`${token}.${createHmac("sha256", current).update(token).digest("base64")}`)}`;
  const forged = structuredClone(right.value);
  forged.observation.headers["set-cookie"] = wrong;
  const windows = right.windows.map((window) => window && { ...window });
  windows[0]!.issuedSessionCookie = wrong;
  expect(
    compareValues(left.value, forged, { ...context, rightRequestWindows: windows }).length,
  ).toBeGreaterThan(0);
  expect(
    compareValues(left.value, right.value, {
      ...context,
      rightRequestWindows: right.windows.map(
        (window) => window && { ...window, issuedSessionCookie: undefined },
      ),
    }).length,
  ).toBeGreaterThan(0);
});
