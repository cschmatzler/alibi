// Focused native control for Better Auth 1.7.6; run with Bun from the pinned reference project.
import { Database } from "bun:sqlite";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";

import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { createAccessControl } from "better-auth/plugins/access";
import { admin } from "better-auth/plugins/admin";
const database = new Database(":memory:");
const secret = "numeric-admin-identity-secret-at-least-32";
const ac = createAccessControl({ user: ["impersonate", "impersonate-admins"] });
const options = {
  database,
  secret,
  baseURL: "http://localhost:31981",
  advanced: { database: { generateId: "serial" } },
  plugins: [
    admin({
      ac,
      adminRoles: [],
      adminUserIds: ["42"],
      roles: {
        operator: ac.newRole({ user: ["impersonate"] }),
        elevated: ac.newRole({ user: ["impersonate-admins"] }),
        user: ac.newRole({ user: [] }),
      },
    }),
  ],
};
await (await getMigrations(options)).runMigrations();
const auth = betterAuth(options);
const ctx = await auth.$context;
for (const [id, role] of [
  [1, "operator"],
  [2, "operator,elevated"],
  [3, "elevated"],
  [42, "user"],
  [43, "user"],
]) {
  database
    .query(
      "INSERT INTO user (id,name,email,emailVerified,createdAt,updatedAt,role,banned) VALUES (?,?,?,0,?,?,?,0)",
    )
    .run(id, `User ${id}`, `id-${id}@identity.fixture.test`, Date.now(), Date.now(), role);
}
for (const id of [1, 2, 3, 42, 43]) {
  database
    .query(
      "INSERT INTO account(id,accountId,providerId,userId,password,createdAt,updatedAt) VALUES (?,?,?, ?,?,?,?)",
    )
    .run(id, String(id), "credential", id, "fixture-password", Date.now(), Date.now());
}
assert.equal(
  database.query("SELECT typeof(id) AS type FROM user WHERE id=42").get().type,
  "integer",
);
const alias = await ctx.internalAdapter.findUserById("00042");
assert.equal(alias.id, "42");
for (const [actor, target, status] of [
  ["1", "42", 403],
  ["1", "00042", 403],
  ["1", "00043", 200],
  ["2", "00042", 200],
  ["3", "00043", 403],
]) {
  const original = await ctx.internalAdapter.createSession(actor);
  const before = Object.fromEntries(
    ["user", "session", "account"].map((table) => [
      table,
      database.query(`SELECT * FROM ${table} ORDER BY id`).all(),
    ]),
  );
  const signed = encodeURIComponent(
    original.token + "." + createHmac("sha256", secret).update(original.token).digest("base64"),
  );
  const response = await auth.handler(
    new Request("http://localhost:31981/api/auth/admin/impersonate-user", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "http://localhost:31981",
        cookie: `better-auth.session_token=${signed}`,
      },
      body: JSON.stringify({ userId: target }),
    }),
  );
  const body = await response.json();
  const after = Object.fromEntries(
    ["user", "session", "account"].map((table) => [
      table,
      database.query(`SELECT * FROM ${table} ORDER BY id`).all(),
    ]),
  );
  console.log(JSON.stringify({ actor, target, status: response.status, body, before, after }));
  assert.equal(response.status, status);
  assert.deepEqual(after.user, before.user);
  assert.deepEqual(after.account, before.account);
  assert.equal(after.session.length, before.session.length + (status === 200 ? 1 : 0));
  for (const row of before.session) {
    assert.deepEqual(
      after.session.find((other) => other.id === row.id),
      row,
    );
  }
  if (status === 200) {
    assert.equal(body.user.id, String(Number(target)));
    assert.equal(body.session.userId, String(Number(target)));
    assert.equal(body.session.impersonatedBy, actor);
    assert.equal(
      String(
        database.query("SELECT userId FROM session WHERE token=?").get(body.session.token).userId,
      ),
      String(Number(target)),
    );
  } else if (actor === "1") assert.equal(body.message, "You cannot impersonate admins");
}
console.log("Authentic Better Auth 1.7.6 numeric identity controls passed");
