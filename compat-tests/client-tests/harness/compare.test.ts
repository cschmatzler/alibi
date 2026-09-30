import { createHash } from "node:crypto";
import { expect, test } from "bun:test";
import { compareValues } from "../support/compare";
import { jsonShape, normalizeClientValue } from "../support/normalize";
import { RAW_DIFF_ALLOWLIST } from "../support/allowlist";

const context = { leftBaseURL: "http://localhost:3100", rightBaseURL: "http://localhost:3200", leftStartedAt: 0, rightStartedAt: 0 };

test("identity bijection preserves cross-object relationships and token rotation", () => {
  const a = { user: { id: "alice" }, session: { userId: "alice", token: "a" }, renewed: { token: "b" } };
  const b = { user: { id: "bob" }, session: { userId: "bob", token: "c" }, renewed: { token: "d" } };
  expect(compareValues(a, b, context)).toEqual([]);
  expect(compareValues(a, { ...b, session: { ...b.session, userId: "wrong" } }, context).length).toBeGreaterThan(0);
  expect(compareValues(a, { ...b, renewed: { token: "c" } }, context).length).toBeGreaterThan(0);
});

for (const [name, left, right] of [
  ["provider", { providerId: "github" }, { providerId: "google" }],
  ["config", { configId: "one" }, { configId: "two" }],
  ["empty token", { token: "abc" }, { token: "" }],
  ["invalid timestamp", { expiresAt: "2026-10-01T00:00:00Z" }, { expiresAt: "invalid" }],
  ["wrong lifetime", { expiresAt: "2026-10-01T00:00:00Z" }, { expiresAt: "2026-10-02T00:00:00Z" }],
  ["missing expiry", { refreshTokenExpiresAt: null }, {}],
  ["error cause", { cause: "one" }, { cause: "two" }],
  ["wrong callback host", { callbackURL: "https://a.example/ok" }, { callbackURL: "https://b.example/ok" }],
  ["wrong callback protocol", { callbackURL: "http://localhost:3100/ok" }, { callbackURL: "https://localhost:3200/ok" }],
  ["wrong callback path", { callbackURL: "/ok" }, { callbackURL: "/wrong" }],
  ["array length", [1], [1, 2]],
  ["later array item", [1, { ok: true }], [1, { ok: false }]],
  ["null vs object", { user: null }, { user: {} }],
] as const) {
  test(`comparison rejects ${name}`, () => expect(compareValues(left, right, context).length).toBeGreaterThan(0));
}

test("only configured server origins and opaque URL parameters are normalized", () => {
  expect(compareValues({ url: "http://localhost:3100/callback?state=abc&provider=github" }, { url: "http://localhost:3200/callback?state=xyz&provider=github" }, context)).toEqual([]);
  expect(compareValues({ url: "http://localhost:3100/callback?state=abc" }, { url: "http://elsewhere:3200/callback?state=xyz" }, context).length).toBeGreaterThan(0);
});

test("snapshots retain fields and array shapes include every item", () => {
  expect(normalizeClientValue({ token: "secret", cause: 1, refreshTokenExpiresAt: null })).toEqual({ token: "secret", cause: 1, refreshTokenExpiresAt: null });
  expect(jsonShape([{ ok: true }, { wrong: 1 }])).toEqual([{ ok: "boolean" }, { wrong: "number" }]);
});

test("no exception can swallow an entire cookie or its security attributes", () => {
  for (const allowance of RAW_DIFF_ALLOWLIST) {
    for (const field of ["", ".httpOnly", ".secure", ".path", ".domain", ".sameSite"]) {
      expect(allowance.path.test(`0.responseCookies.better-auth.session_token${field}`)).toBe(false);
    }
    expect(allowance.path.source.endsWith("$")).toBe(true);
  }
});

test("reset-password URL entropy retains token relationships", () => {
  const left = { first: { url: "/reset-password/one" }, second: { url: "/reset-password/one" } };
  expect(compareValues(left, { first: { url: "/reset-password/two" }, second: { url: "/reset-password/two" } }, context)).toEqual([]);
  expect(compareValues(left, { first: { url: "/reset-password/two" }, second: { url: "/reset-password/three" } }, context).length).toBeGreaterThan(0);
});

test("one-time-token storage preserves exact derivation session ownership and response header relationships", () => {
  const timestamp = "2026-09-30T00:00:00.000Z";
  const stored = (token: string, hashed: boolean) => `one-time-token:${hashed ? createHash("sha256").update(token).digest("base64url") : token}`;
  for (const hashed of [false, true]) {
    const run = (side: string) => ({
      issued: { token: `${side}-ott` },
      owner: { id: `${side}-owner`, token: `${side}-session`, expiresAt: timestamp },
      other: { id: `${side}-other`, token: `${side}-other-session`, expiresAt: timestamp },
      persisted: { id: `${side}-proof`, identifier: stored(`${side}-ott`, hashed), value: `${side}-session`, expiresAt: timestamp, createdAt: timestamp, updatedAt: timestamp },
      traces: [{ responseHeaders: { "set-ott": `${side}-ott` } }],
      url: `/__test/verification-state?identifier=${encodeURIComponent(stored(`${side}-ott`, hashed))}`,
    });
    const left = run("left"), right = run("right");
    expect(compareValues(left, right, context)).toEqual([]);
    for (const incorrect of [
      { ...right, persisted: { ...right.persisted, identifier: stored("unrelated", hashed) } },
      { ...right, persisted: { ...right.persisted, identifier: stored("right-ott", !hashed) } },
      { ...right, persisted: { ...right.persisted, identifier: "wrong-prefix:right-ott" } },
      { ...right, persisted: { ...right.persisted, value: "right-other-session" } },
      { ...right, persisted: { ...right.persisted, value: "unobserved-session" } },
      { ...right, persisted: { ...right.persisted, value: null } },
      { ...right, traces: [{ responseHeaders: { "set-ott": "rotated-ott" } }] },
      { ...right, url: `/__test/verification-state?identifier=${encodeURIComponent(stored("unrelated", hashed))}` },
      { ...right, persisted: { ...right.persisted, expiresAt: "2026-09-30T00:03:00.000Z" } },
    ]) expect(compareValues(left, incorrect, context).length).toBeGreaterThan(0);
  }
  expect(compareValues({ identifier: "literal", value: "literal" }, { identifier: "literal", value: "changed" }, context).length).toBeGreaterThan(0);
});
