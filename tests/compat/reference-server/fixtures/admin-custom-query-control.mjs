// Public admin sorting/paging control against published Better Auth 1.7.6.
import { Database } from "bun:sqlite";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";

import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { admin } from "better-auth/plugins/admin";

const database = new Database(":memory:");
const secret = "numeric-admin-identity-secret-at-least-32";
const options = {
  database,
  secret,
  baseURL: "http://localhost:31982",
  advanced: { database: { generateId: "serial" } },
  user: {
    additionalFields: {
      score: { type: "number", required: false },
      reviewedAt: { type: "date", required: false },
      profile: { type: "json", required: false },
    },
  },
  plugins: [admin({ adminUserIds: ["1"] })],
};
await (await getMigrations(options)).runMigrations();
const auth = betterAuth(options);
const ctx = await auth.$context;
for (const [id, day] of [
  [1, 1],
  [2, 5],
  [3, 4],
  [42, 3],
  [43, 2],
]) {
  const date = new Date(
    `2020-01-${String(day).padStart(2, "0")}T00:00:00Z`,
  ).toISOString();
  database
    .query(
      "INSERT INTO user(id,name,email,emailVerified,createdAt,updatedAt,role,banned) VALUES (?,?,?,0,?,?,'user',0)",
    )
    .run(id, `User ${id}`, `id-${id}@identity.fixture.test`, date, date);
}
for (const [id, score, day, tier] of [
  [1, 1, 1, "a"],
  [2, 20, 5, "b"],
  [3, 10, 4, "a"],
  [42, 3, 3, "b"],
  [43, 2, 2, "a"],
]) {
  database
    .query(
      "UPDATE user SET score=?, reviewedAt=?, profile=?, createdAt='2019-01-01T00:00:00Z', updatedAt='2019-01-01T00:00:00Z' WHERE id=?",
    )
    .run(
      score,
      `2020-01-${String(day).padStart(2, "0")}T00:00:00Z`,
      JSON.stringify({ tier }),
      id,
    );
}
const session = await ctx.internalAdapter.createSession("1");
const snapshot = () =>
  Object.fromEntries(
    ["user", "account", "session"].map((table) => [
      table,
      database.query(`SELECT * FROM ${table} ORDER BY id`).all(),
    ]),
  );
const before = snapshot();
const signed = encodeURIComponent(
  session.token +
    "." +
    createHmac("sha256", secret).update(session.token).digest("base64"),
);
for (const [field, operator, value, sort, direction, expected, total] of [
  ["score", "gte", "3", "score", "asc", ["3", "2"], 3],
  ["score", "gte", "3", "score", "desc", ["3", "42"], 3],
  [
    "reviewedAt",
    "gt",
    "2020-01-01T00:00:00Z",
    "reviewedAt",
    "asc",
    ["42", "3"],
    4,
  ],
  ["profile", "eq", '{"tier":"a"}', "score", "asc", ["43", "3"], 3],
  ["profile", "contains", "b", "id", "asc", ["42"], 2],
  ["score", "gte", "3", "profile", "asc", ["2", "42"], 3],
  ["score", "lt", "3", "id", "desc", ["1"], 2],
]) {
  const url = new URL("http://localhost:31982/api/auth/admin/list-users");
  for (const [key, v] of Object.entries({
    filterField: field,
    filterOperator: operator,
    filterValue: value,
    sortBy: sort,
    sortDirection: direction,
    offset: "1",
    limit: "2",
  })) {
    url.searchParams.set(key, v);
  }
  const response = await auth.handler(
    new Request(url, {
      headers: { cookie: `better-auth.session_token=${signed}` },
    }),
  );
  const body = await response.json();
  console.log(
    JSON.stringify({
      field,
      operator,
      value,
      sort,
      direction,
      status: response.status,
      body,
      before,
      after: snapshot(),
    }),
  );
  assert.equal(response.status, 200);
  assert.deepEqual(
    body.users.map((u) => u.id),
    expected,
  );
  assert.equal(body.total, total);
  assert.equal(body.offset, 1);
  assert.equal(body.limit, 2);
  assert.deepEqual(snapshot(), before);
}
