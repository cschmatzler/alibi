import { expect, test } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { compareValues } from "../support/compare";
import { createTracingFetch, type TraceEntry } from "../support/trace";

// Negative controls go through HTTP, the real SDK, tracing and the production comparator.
// They must fail comparison even though both HTTP responses report success.
test("live response mutations cannot hide broken ownership or cookie security", async () => {
  let mode = "valid";
  const server = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch() {
    return Response.json({
      session: { id: "session-1", userId: mode === "ownership" ? "some-other-user" : "user-1", token: "opaque-session-token", expiresAt: "2030-01-01T00:00:00.000Z" },
      user: { id: "user-1", email: "canary@test.com", emailVerified: false, name: "Canary", createdAt: "2026-01-01T00:00:00.000Z", updatedAt: "2026-01-01T00:00:00.000Z" },
    }, { headers: mode === "missing-cookie" ? {} : { "set-cookie": `better-auth.session_token=opaque-session-token; Path=/; SameSite=Lax${mode === "insecure-cookie" ? "" : "; HttpOnly; Secure"}` } });
  } });
  try {
    const baseURL = server.url.origin;
    async function observe(mutation: string) {
      mode = mutation;
      const traces: TraceEntry[] = [];
      const tracing = createTracingFetch(baseURL, "canary", traces);
      const client = createAuthClient({ baseURL, fetchOptions: { customFetchImpl: tracing } });
      return { result: await client.getSession(), traces };
    }
    const baseline = await observe("valid");
    expect(baseline.result.error).toBeNull();
    const context = { leftBaseURL: baseURL, rightBaseURL: baseURL, leftStartedAt: 0, rightStartedAt: 0 };
    expect(compareValues(baseline, await observe("valid"), context)).toEqual([]);
    for (const mode of ["ownership", "insecure-cookie", "missing-cookie"]) {
      const mutated = await observe(mode);
      expect(mutated.result.error).toBeNull();
      const differences = compareValues(baseline, mutated, context);
      expect(differences.length).toBeGreaterThan(0);
      expect(differences.every(entry => mode === "ownership" ? entry.path.startsWith("result.data.") : entry.path.startsWith("traces.0.responseCookies."))).toBe(true);
    }
  } finally { await server.stop(true); }
});
