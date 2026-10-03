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
  const date = new Date(`2020-01-${String(day).padStart(2, "0")}T00:00:00Z`).toISOString();
  database
    .query(
      "INSERT INTO user(id,name,email,emailVerified,createdAt,updatedAt,role,banned) VALUES (?,?,?,0,?,?,'user',0)",
    )
    .run(id, `User ${id}`, `id-${id}@identity.fixture.test`, date, date);
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
  session.token + "." + createHmac("sha256", secret).update(session.token).digest("base64"),
);
for (const [direction, expected] of [
  [null, ["42", "3"]],
  ["asc", ["42", "3"]],
  ["desc", ["3", "42"]],
]) {
  const url = new URL("http://localhost:31982/api/auth/admin/list-users");
  for (const [key, value] of Object.entries({
    sortBy: "createdAt",
    filterField: "createdAt",
    filterOperator: "gt",
    filterValue: "2020-01-01T00:00:00Z",
    offset: "1",
    limit: "2",
  })) {
    url.searchParams.set(key, value);
  }
  if (direction !== null) url.searchParams.set("sortDirection", direction);
  const response = await auth.handler(
    new Request(url, { headers: { cookie: `better-auth.session_token=${signed}` } }),
  );
  const body = await response.json();
  console.log(
    JSON.stringify({ direction, status: response.status, body, before, after: snapshot() }),
  );
  assert.equal(response.status, 200);
  assert.deepEqual(
    body.users.map((user) => user.id),
    expected,
  );
  assert.equal(body.total, 4);
  assert.equal(body.offset, 1);
  assert.equal(body.limit, 2);
  assert.deepEqual(snapshot(), before);
}
