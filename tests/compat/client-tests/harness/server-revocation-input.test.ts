import { Database } from "bun:sqlite";
import { expect, test } from "bun:test";

import { betterAuth, type BetterAuthOptions } from "better-auth";
import { createAuthMiddleware } from "better-auth/api";
import { getMigrations } from "better-auth/db/migration";
import { z } from "zod";

import { compareValues, type ComparisonContext } from "../support/compare";
import { normalizeClientValue } from "../support/normalize";
import { createTracingFetch, requestWindow, type TraceEntry } from "../support/trace";

const control = "/__test/server-dispatch-cache/call";
async function capture(operation: "revokeSession" | "resetPassword") {
  let resetToken = "";
  const database = new Database(":memory:");
  let auth: ReturnType<typeof betterAuth>;
  const events: unknown[] = [];
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      if (new URL(request.url).pathname === control) {
        const input = await request.json();
        events.length = 0;
        const output =
          operation === "revokeSession"
            ? await auth.api.revokeSession({
                body: input.body,
                query: input.query,
                headers: new Headers(input.headers),
                returnHeaders: true,
              })
            : await auth.api.resetPassword({
                body: input.body,
                query: input.query,
                returnHeaders: true,
              });
        return Response.json({
          result: {
            ok: true,
            value: { response: output.response, headers: Object.fromEntries(output.headers) },
          },
          events,
        });
      }
      return auth.handler(request);
    },
  });
  const baseURL = `http://127.0.0.1:${server.port}`;
  try {
    const options: BetterAuthOptions = {
      baseURL,
      secret: "actual-revocation-input-control-secret-32chars",
      database,
      rateLimit: { enabled: false },
      emailAndPassword: {
        enabled: true,
        sendResetPassword: async ({ token }) => {
          resetToken = token;
        },
        password: {
          hash: async (password) => `fast:${password}`,
          verify: async ({ hash, password }) => hash === `fast:${password}`,
        },
      },
      hooks: {
        after: createAuthMiddleware(async (ctx) => {
          if (
            ctx.path === (operation === "resetPassword" ? "/reset-password" : "/revoke-session")
          ) {
            const frame = {
              path: ctx.path,
              headers: ctx.headers ? Object.fromEntries(ctx.headers) : null,
              body: ctx.body,
            };
            events.push({ stage: "user-after", ...frame, current: frame });
          }
        }),
      },
    };
    await (await getMigrations(options)).runMigrations();
    auth = betterAuth(options);
    const traces: TraceEntry[] = [];
    const startedAt = Date.now();
    const fetch = createTracingFetch(baseURL, "owner", traces);
    const signup = await fetch(`${baseURL}/api/auth/sign-up/email`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        name: "Owner",
        email: "empty-revocation@fixture.test",
        password: "actual-password-123",
      }),
    });
    expect(signup.status).toBe(200);
    await signup.json();
    const cookie = signup.headers
      .getSetCookie()
      .map((raw) => raw.split(";")[0])
      .join("; ");
    if (operation === "resetPassword") {
      await auth.api.requestPasswordReset({ body: { email: "empty-revocation@fixture.test" } });
      expect(resetToken.length).toBeGreaterThan(0);
    }
    const response = await fetch(`${baseURL}${control}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        operation,
        body:
          operation === "resetPassword"
            ? { token: "", newPassword: "replacement-password-205" }
            : { token: "" },
        ...(operation === "revokeSession" ? { headers: { cookie } } : {}),
        query: operation === "resetPassword" ? { token: resetToken } : { disableRefresh: true },
      }),
    });
    expect(response.status).toBe(200);
    const output = await response.json();
    expect(output.result.value.response).toEqual({ status: true });
    expect(output.events[0].body.token).toBe("");
    return {
      value: z
        .object({
          observation: z
            .object({
              output: z
                .object({
                  events: z.array(
                    z
                      .object({
                        body: z.object({ token: z.string() }).passthrough(),
                        path: z.string(),
                      })
                      .passthrough(),
                  ),
                  result: z
                    .object({
                      value: z
                        .object({
                          response: z
                            .object({ status: z.boolean(), token: z.string().optional() })
                            .passthrough(),
                        })
                        .passthrough(),
                    })
                    .passthrough(),
                })
                .passthrough(),
            })
            .passthrough(),
          traces: z.array(z.unknown()),
        })
        .passthrough()
        .parse(normalizeClientValue({ observation: { output }, traces })),
      windows: traces.map((trace) => structuredClone(trace[requestWindow])),
      startedAt,
      finishedAt: Date.now(),
      baseURL,
    };
  } finally {
    server.stop(true);
    database.close();
  }
}
for (const operation of ["revokeSession", "resetPassword"] as const) {
  test(`actual accepted empty ${operation} input requires its original hook receipt`, async () => {
    const captured = await capture(operation);
    const context: ComparisonContext = {
      leftBaseURL: captured.baseURL,
      rightBaseURL: captured.baseURL,
      leftStartedAt: captured.startedAt,
      rightStartedAt: captured.startedAt,
      leftFinishedAt: captured.finishedAt,
      rightFinishedAt: captured.finishedAt,
      leftRequestWindows: captured.windows,
      rightRequestWindows: captured.windows,
    };
    const compare = (right = captured.value, options = context) =>
      compareValues(captured.value, right, options);
    expect(compare()).toEqual([]);
    expect(
      compare(captured.value, { ...context, rightRequestWindows: undefined }).length,
    ).toBeGreaterThan(0);
    const badDigest = structuredClone(captured.windows);
    badDigest[1]!.logicalEndpoint!.digest = "forged";
    expect(
      compare(captured.value, { ...context, rightRequestWindows: badDigest }).length,
    ).toBeGreaterThan(0);
    const wrongOperation = structuredClone(captured.windows);
    (wrongOperation[1]!.logicalEndpoint!.input as { operation: string }).operation =
      "verifyPassword";
    expect(
      compare(captured.value, { ...context, rightRequestWindows: wrongOperation }).length,
    ).toBeGreaterThan(0);
    if (operation === "resetPassword") {
      const missingProof = structuredClone(captured.windows);
      (missingProof[1]!.logicalEndpoint!.input as { query?: unknown }).query = {};
      expect(
        compare(captured.value, { ...context, rightRequestWindows: missingProof }).length,
      ).toBeGreaterThan(0);
      const emptyProof = structuredClone(captured.windows);
      (emptyProof[1]!.logicalEndpoint!.input as { query?: unknown }).query = { token: "" };
      expect(
        compare(captured.value, { ...context, rightRequestWindows: emptyProof }).length,
      ).toBeGreaterThan(0);
    }
    const different = structuredClone(captured.value);
    different.observation.output.events[0]!.body.token = "nonempty-token";
    expect(compare(different).length).toBeGreaterThan(0);
    const unrelatedFrame = structuredClone(captured.value);
    unrelatedFrame.observation.output.events[0]!.path = "/verify-password";
    expect(compare(unrelatedFrame).some((diff) => diff.reason === "empty identity or token")).toBe(
      true,
    );
    const issued = structuredClone(captured.value);
    issued.observation.output.result.value.response.token = "";
    expect(
      compareValues(issued, issued, context).some(
        (diff) => diff.reason === "empty identity or token",
      ),
    ).toBe(true);
  });
}
