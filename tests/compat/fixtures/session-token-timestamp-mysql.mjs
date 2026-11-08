import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { betterAuth } from "../reference-server/node_modules/better-auth/dist/index.mjs";
import { getMigrations } from "../reference-server/node_modules/better-auth/dist/db/get-migration.mjs";
import { createMysqlDatabase } from "./support/mysql-database.mjs";

const mysql = await createMysqlDatabase();
try {
  let events = [];
  let applying = false;
  const callbackResult = "2035-02-03 04:05:06.123987";
  function event(phase, data) {
    events.push({ phase, token: data?.token ?? null, expiresAt: data?.expiresAt ?? null });
  }
  const options = {
    baseURL: "http://localhost", secret: "session-token-timestamp-secret-at-least-32", database: { type: "mysql", db: mysql.db },
    session: { additionalFields: { expiresAt: { type: "date", required: true, transform: { input(value) {
      events.push({ phase: "input", value });
      return applying ? callbackResult : value;
    } } } } },
    databaseHooks: { session: { update: {
      before(data) { event("update.before", data); },
      after(data) { event("update.after", data); },
    } } },
  };
  const migrations = await getMigrations(options);
  const schemaSql = await migrations.compileMigrations();
  await migrations.runMigrations();
  const { internalAdapter } = await betterAuth(options).$context;
  const user = await internalAdapter.createUser({ name: "Token Timestamp", email: "session-token-timestamp@example.com", emailVerified: false });
  const cases = [];
  for (const changeToken of [false, true]) {
    const token = `old-token-${changeToken}`;
    const nextToken = changeToken ? `new-token-${changeToken}` : token;
    applying = false;
    const original = await internalAdapter.createSession(user.id, false, { token, expiresAt: new Date("2031-01-01T00:00:00.123Z") }, true);
    applying = true;
    events = [];
    const input = { token: nextToken, expiresAt: new Date("2031-02-03T04:05:06.123Z") };
    const session = await internalAdapter.updateSession(token, input);
    assert.equal(session.token, nextToken);
    assert.equal(session.id, original.id);
    assert.equal(session.expiresAt.toISOString(), "2035-02-03T04:05:06.124Z");
    const old = await internalAdapter.findSession(token);
    const updated = await internalAdapter.findSession(nextToken);
    assert.equal(old !== null, !changeToken);
    assert.equal(updated.session.id, original.id);
    const [rows] = await mysql.pool.promise().query("SELECT token,DATE_FORMAT(expiresAt,'%Y-%m-%dT%H:%i:%s.%fZ') AS expiresAt FROM session WHERE userId = ? AND token = ?", [user.id, nextToken]);
    assert.equal(rows.length, 1);
    cases.push({ change_token: changeToken, token, input, callback_result: callbackResult, events: [...events], returned_token: session.token, expiresAt: session.expiresAt, old_exists: old !== null, new_exists: updated !== null, rows });
  }
  await writeFile(new URL("../../fixtures/session-token-timestamp-mysql.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", backend: "mysql", mysql: mysql.mysqlVersion, mysql2: mysql.mysql2Version, schema_sql: schemaSql, cases }) + "\n");
  console.log("Two actual MySQL session token/timestamp update cases");
} finally { await mysql.close(); }
