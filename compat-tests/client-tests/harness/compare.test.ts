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

test("multi-team invitations preserve every ordered team identity", () => {
  const left = { teams: [{ id: "left-first" }, { id: "left-second" }], invitation: { teamId: "left-first,left-second" } };
  const right = { teams: [{ id: "right-first" }, { id: "right-second" }], invitation: { teamId: "right-first,right-second" } };
  expect(compareValues(left, right, context)).toEqual([]);
  for (const teamId of ["right-second,right-first", "right-first,unrelated", "right-first", "right-first,right-second,extra"]) {
    expect(compareValues(left, { ...right, invitation: { teamId } }, context).length).toBeGreaterThan(0);
  }
});

test("dynamic role selectors retain their persisted role identity and literal role names", () => {
  const left = { persisted: { id: "left-role", role: "auditor" }, url: "/organization/get-role?roleId=left-role" };
  const right = { persisted: { id: "right-role", role: "auditor" }, url: "/organization/get-role?roleId=right-role" };
  expect(compareValues(left, right, context)).toEqual([]);
  expect(compareValues(left, { ...right, url: "/organization/get-role?roleId=unrelated" }, context).length).toBeGreaterThan(0);
  expect(compareValues(left, { ...right, persisted: { ...right.persisted, role: "owner" } }, context).length).toBeGreaterThan(0);
});

test("issued API-key entropy retains stored start, configured prefix, row scope and rotation", () => {
  const issued = (id: string, key: string, referenceId: string) => ({ id, key, prefix: "test-", start: key.slice(0, 8), configId: "organization", referenceId, enabled: true, remaining: null });
  const left = issued("left-id", "test-LeftFirstRandom", "left-org"), right = issued("right-id", "test-RightFirstRandm", "right-org");
  const read = ({ key: _key, ...row }: ReturnType<typeof issued>) => row;
  const a = { issued: left, read: read(left), next: issued("left-next", "test-LeftOtherRandom", "left-org") };
  const b = { issued: right, read: read(right), next: issued("right-next", "test-RightOtherRandm", "right-org") };
  expect(compareValues(a, b, context)).toEqual([]);
  for (const changed of [
    { ...b, read: { ...b.read, start: "test-Bad" } },
    { ...b, read: { ...b.read, start: b.read.start.slice(0, -1) } },
    { ...b, issued: { ...right, prefix: "other-" } },
    { ...b, read: { ...b.read, configId: "default" } },
    { ...b, read: { ...b.read, referenceId: "unrelated-org" } },
    { ...b, read: { ...b.read, id: "unrelated-row" } },
    { ...b, issued: { ...right, key: `${right.key}extra` } },
    { ...b, next: { ...b.next, key: right.key, start: right.start } },
    { ...b, read: { ...b.read, enabled: false } },
    { ...b, read: { ...b.read, remaining: 1 } },
  ]) expect(compareValues(a, changed, context).length).toBeGreaterThan(0);
  const shape = { traces: [{ responseBodyShape: jsonShape(left) }] };
  expect(compareValues(shape, { traces: [{ responseBodyShape: jsonShape(right) }] }, context)).toEqual([]);
  expect(compareValues(shape, { traces: [{ responseBodyShape: jsonShape({ ...right, start: null }) }] }, context).length).toBeGreaterThan(0);
  expect(compareValues({ payload: { responseBodyShape: left } }, { payload: { responseBodyShape: right } }, context)).toEqual([]);
  expect(compareValues({ payload: { responseBodyShape: left } }, { payload: { responseBodyShape: { ...right, start: "test-Bad" } } }, context).length).toBeGreaterThan(0);
  expect(compareValues({ key: "literal" }, { key: "changed" }, context).length).toBeGreaterThan(0);
  expect(compareValues({ issued: left, metadata: left }, { issued: right, metadata: left }, context)).toEqual([]);
  expect(compareValues({ issued: left, metadata: left }, { issued: right, metadata: right }, context).length).toBeGreaterThan(0);
  expect(compareValues({ issued: left, metadata: { nested: [left] } }, { issued: right, metadata: { nested: [right] } }, context).length).toBeGreaterThan(0);
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
