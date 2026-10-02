import { expect, test } from "bun:test";
import { compareValues, type Difference } from "../support/compare";
import { classifyDifferences } from "../support/scenario";

const context = { leftBaseURL: "http://localhost:3100", rightBaseURL: "http://localhost:3200", leftStartedAt: 0, rightStartedAt: 0 };

// The runner only fails on differences whose paths sit under `observation` or
// `traces`. Every comparator failure must therefore use those exact roots; a
// stray leading separator would silently discard the finding.
test("comparator paths from nested helper walkers reach the scenario gate", () => {
  const row = { id: "key-1", configId: "default", enabled: true, remaining: null, key: "pk_first", start: "pk_", prefix: "pk_" };
  const left = { observation: { issued: row, persisted: row }, traces: [] };
  const right = { observation: { issued: row, persisted: { ...row, key: "pk_second" } }, traces: [] };
  const differences = compareValues(left, right, context);
  expect(differences.length).toBeGreaterThan(0);
  const { clientDiffs, rawDiffs, unclassified } = classifyDifferences(differences);
  expect(unclassified).toEqual([]);
  expect(rawDiffs).toEqual([]);
  expect(clientDiffs.map(entry => entry.path)).toContain("observation.persisted");
});

test("every comparator difference lands in exactly one gate bucket", () => {
  const left = {
    observation: { user: { id: "u1", createdAt: "2026-01-01T00:00:00.000Z" }, list: [{ id: "a" }] },
    traces: [{ actor: "owner", method: "POST", path: "/api/auth/sign-in/email", responseStatus: 200, responseHeaders: { "content-type": "application/json" }, responseCookies: { "better-auth.session_token;;/": { httpOnly: true } }, requestBodyShape: null, responseBodyShape: { token: "string" } }],
  };
  const right = {
    observation: { user: { id: "u2", createdAt: "2026-01-01T00:00:09.000Z" }, list: [{ id: "b" }, { id: "c" }] },
    traces: [{ ...left.traces[0]!, responseStatus: 401, responseCookies: { "better-auth.session_token;;/": { httpOnly: false } }, responseBodyShape: { message: "string" } }],
  };
  const differences = compareValues(left, right, context);
  const buckets = classifyDifferences(differences);
  expect(buckets.unclassified).toEqual([]);
  expect(buckets.clientDiffs.length + buckets.rawDiffs.length).toBe(differences.length);
  for (const entry of buckets.clientDiffs) expect(entry.path.startsWith("observation")).toBe(true);
  for (const entry of buckets.rawDiffs) expect(entry.path.startsWith("traces.")).toBe(true);
  expect(buckets.rawDiffs.map(entry => entry.path)).toContain("traces.0.responseStatus");
  expect(buckets.rawDiffs.map(entry => entry.path)).toContain("traces.0.responseCookies.better-auth.session_token;;/.httpOnly");
});

test("differences outside both roots are reported instead of ignored", () => {
  const stray: Difference[] = [{ path: ".observation.persisted", reason: "API key changed for a persisted row" }];
  const { clientDiffs, rawDiffs, unclassified } = classifyDifferences(stray);
  expect(clientDiffs).toEqual([]);
  expect(rawDiffs).toEqual([]);
  expect(unclassified).toEqual(stray);
});
