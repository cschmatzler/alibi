import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { betterAuth } from "../reference-server/node_modules/better-auth/dist/index.mjs";
import { getMigrations } from "../reference-server/node_modules/better-auth/dist/db/get-migration.mjs";
import { createMysqlDatabase } from "./support/mysql-database.mjs";

const mysql = await createMysqlDatabase();
try {
  let events = [];
  let applying = false;
  let resultText;
  const event = (phase, value) => events.push({ phase, kind: value instanceof Date ? "date" : typeof value, value });
  const options = {
    baseURL: "http://localhost", secret: "session-string-result-probe-secret-at-least-32", database: { type: "mysql", db: mysql.db },
    session: { additionalFields: { expiresAt: { type: "date", required: true, transform: { input(value) { event("input", value); return applying ? resultText : value; } } } } },
    databaseHooks: { session: {
      create: { before(data) { event("create.before", data.expiresAt); }, after(data) { event("create.after", data.expiresAt); } },
      update: { before(data) { event("update.before", data.expiresAt); }, after(data) { event("update.after", data?.expiresAt); } },
    } },
  };
  const migrations = await getMigrations(options);
  const schema_sql = await migrations.compileMigrations();
  await migrations.runMigrations();
  const { internalAdapter } = await betterAuth(options).$context;
  const user = await internalAdapter.createUser({ name: "String Result", email: "session-string-result@example.com", emailVerified: false });
  const cases = [];
  for (const operation of ["create", "update"]) for (const compatible of [false, true]) {
    const token = `string-${operation}-${cases.length}`;
    applying = false;
    if (operation === "update") await internalAdapter.createSession(user.id, false, { token, expiresAt: new Date("2031-01-01T00:00:00.123Z") }, true);
    applying = true;
    resultText = compatible ? "2035-02-03 04:05:06.123987" : "2035-02-03T04:05:06.123987Z";
    events = [];
    let outcome;
    try {
      const input = { expiresAt: new Date("2031-02-03T04:05:06.123Z") };
      const session = operation === "create" ? await internalAdapter.createSession(user.id, false, { token, ...input }, true) : await internalAdapter.updateSession(token, input);
      assert.ok(compatible);
      assert.equal(session.expiresAt.toISOString(),"2035-02-03T04:05:06.124Z");
      outcome = { output: session.expiresAt };
    } catch (error) {
      assert.ok(!compatible);
      assert.equal(error.code,"ER_TRUNCATED_WRONG_VALUE");
      assert.equal(error.sqlState,"22007");
      outcome = { error: { code: error.code, state: error.sqlState, message: error.sqlMessage } };
    }
    const [stored] = await mysql.pool.promise().query("SELECT DATE_FORMAT(expiresAt,'%Y-%m-%dT%H:%i:%s.%fZ') AS value FROM session WHERE token = ?", [token]);
    const readback = await internalAdapter.findSession(token);
    cases.push({ operation, compatible, token, callback_result: resultText, events: [...events], outcome, rows: stored.length, physical: stored[0]?.value ?? null, readback: readback?.session.expiresAt ?? null });
  }
  assert.equal(cases.length,4);
  await writeFile(new URL("../../fixtures/session-timestamp-hooks-string-mysql.json",import.meta.url),JSON.stringify({ better_auth: "1.7.18", backend: "mysql", mysql: mysql.mysqlVersion, mysql2: mysql.mysql2Version, schema_sql, cases })+"\n");
  console.log("Four actual MySQL session callback-string cases");
} finally { await mysql.close(); }
