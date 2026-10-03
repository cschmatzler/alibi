import { Database } from "bun:sqlite";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { admin } from "better-auth/plugins/admin";
import { APIError } from "@better-auth/core/error";
// Explicit fixture clock; published files are untouched. Both constructor and
// Date.now return the exact same instant; monotonic runtime clocks stay real.
const RealDate = Date;
const clockMs = 1893456000000;
class ProofDate extends RealDate {
  constructor(...args) {
    super(...(args.length ? args : [clockMs]));
  }
  static now() {
    return clockMs;
  }
}
globalThis.Date = ProofDate;
assert.equal(new Date().getTime(), Date.now());
const database = new Database(":memory:");
const secret = "numeric-admin-identity-secret-at-least-32";
let mode = 0;
const events = [];
const event = (name, failure) => {
  events.push(name);
  if (mode === failure) {
    throw new APIError("CONFLICT", {
      code: "HOOK_REFUSED",
      message: "configured hook refused",
    });
  }
  if (
    (mode === 2 && name === "session-before") ||
    (mode === 8 && name === "user-before") ||
    (mode === 9 && name === "user-after") ||
    (mode === 10 && name === "session-after")
  ) {
    throw new Error("ordinary hook failure");
  }
};
const options = {
  database,
  secret,
  baseURL: "http://localhost:31983",
  advanced: { database: { generateId: "serial" } },
  plugins: [admin({ adminUserIds: ["1"] })],
  databaseHooks: {
    session: {
      create: {
        before: async (input) => {
          event("session-before", 1);
          if (mode === 6) return false;
          if (mode === 5) return { data: { ...input, userId: "42" } };
        },
        after: async () => {
          event("session-after", 7);
        },
      },
    },
    user: {
      update: {
        before: async () => {
          event("user-before", 3);
        },
        after: async () => {
          event("user-after", 4);
        },
      },
    },
  },
};
await (await getMigrations(options)).runMigrations();
const auth = betterAuth(options);
const ctx = await auth.$context;
for (const id of [1, 2, 3, 42, 43]) {
  database
    .query(
      "INSERT INTO user(id,name,email,emailVerified,createdAt,updatedAt,role,banned) VALUES(?,?,?,0,?,?,'user',0)",
    )
    .run(
      id,
      `User ${id}`,
      `id-${id}@identity.fixture.test`,
      new Date().toISOString(),
      new Date().toISOString(),
    );
  database
    .query(
      "INSERT INTO account(id,accountId,providerId,userId,password,createdAt,updatedAt) VALUES(?,?,'credential',?,'fixture-password',?,?)",
    )
    .run(
      id,
      String(id),
      id,
      new Date().toISOString(),
      new Date().toISOString(),
    );
}
const original = await ctx.internalAdapter.createSession("1");
await ctx.internalAdapter.createSession("42");
const snapshot = () =>
  Object.fromEntries(
    ["user", "account", "session"].map((t) => [
      t,
      database.query(`SELECT * FROM ${t} ORDER BY id`).all(),
    ]),
  );
const signed = encodeURIComponent(
  original.token +
    "." +
    createHmac("sha256", secret).update(original.token).digest("base64"),
);
for (const [m, delta, target, status, expected, cleared, inserted] of [
  [0, 0, "00042", 403, [], false, false],
  [0, 1, "00042", 403, [], false, false],
  [
    0,
    -1,
    "00042",
    200,
    ["user-before", "user-after", "session-before", "session-after"],
    true,
    true,
  ],
  [
    1,
    -1,
    "00042",
    409,
    ["user-before", "user-after", "session-before"],
    true,
    false,
  ],
  [
    2,
    -1,
    "00042",
    500,
    ["user-before", "user-after", "session-before"],
    true,
    false,
  ],
  [3, -1, "00042", 409, ["user-before"], false, false],
  [4, -1, "00042", 409, ["user-before", "user-after"], true, false],
  [5, 0, "43", 200, ["session-before", "session-after"], false, true],
  [
    6,
    -1,
    "00042",
    500,
    ["user-before", "user-after", "session-before"],
    true,
    false,
  ],
  [
    7,
    -1,
    "00042",
    409,
    ["user-before", "user-after", "session-before", "session-after"],
    true,
    true,
  ],
  [8, -1, "00042", 500, ["user-before"], false, false],
  [9, -1, "00042", 500, ["user-before", "user-after"], true, false],
  [
    10,
    -1,
    "00042",
    500,
    ["user-before", "user-after", "session-before", "session-after"],
    true,
    true,
  ],
]) {
  mode = m;
  database
    .query(
      "UPDATE user SET banned=1,banReason='boundary',banExpires=?,updatedAt=? WHERE id=42",
    )
    .run(new Date(clockMs + delta).toISOString(), new Date().toISOString());
  events.length = 0;
  const before = snapshot();
  const response = await auth.handler(
    new Request("http://localhost:31983/api/auth/admin/impersonate-user", {
      method: "POST",
      headers: {
        origin: options.baseURL,
        "content-type": "application/json",
        cookie: `better-auth.session_token=${signed}`,
      },
      body: JSON.stringify({ userId: target }),
    }),
  );
  const body = await response.text();
  const after = snapshot();
  console.log(
    JSON.stringify({
      clockMs,
      mode: m,
      delta,
      target,
      status: response.status,
      body,
      events: [...events],
      before,
      after,
    }),
  );
  assert.equal(response.status, status);
  assert.deepEqual(events, expected);
  const principal = after.user.find((u) => u.id === 42);
  assert.equal(Boolean(principal.banned), !cleared);
  assert.equal(principal.banExpires === null, cleared);
  assert.equal(principal.banReason === null, cleared);
  if (!cleared) assert.deepEqual(after.user, before.user);
  else {
    for (const row of before.user.filter((u) => u.id !== 42)) {
      assert.deepEqual(
        after.user.find((u) => u.id === row.id),
        row,
      );
    }
  }
  assert.deepEqual(after.account, before.account);
  assert.equal(after.session.length, before.session.length + Number(inserted));
  for (const row of before.session) {
    assert.deepEqual(
      after.session.find((s) => s.id === row.id),
      row,
    );
  }
  if ([2, 8, 9, 10].includes(m)) assert.equal(body, "");
}
