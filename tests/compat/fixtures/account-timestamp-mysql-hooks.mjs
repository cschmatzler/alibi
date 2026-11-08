import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { betterAuth } from "../reference-server/node_modules/better-auth/dist/index.mjs";
import { getMigrations } from "../reference-server/node_modules/better-auth/dist/db/get-migration.mjs";
import { createMysqlDatabase } from "./support/mysql-database.mjs";

const compatible = process.argv[2] === "--compatible";
assert.ok(process.argv[2] === undefined || compatible, "unknown fixture output mode");
const pin = JSON.parse(await readFile(new URL("../upstream-source.json", import.meta.url)));
assert.equal(pin.commit, "38f43e390920faa400d51ff0bd18570a424d05ce");
assert.equal(pin.version, "1.7.18");
for (const name of ["better-auth", "@better-auth/core", "@better-auth/kysely-adapter"]) {
  assert.equal(JSON.parse(await readFile(new URL(`../reference-server/node_modules/${name}/package.json`, import.meta.url))).version, "1.7.18");
}
const mysql = await createMysqlDatabase();
let events = [];
let applyingInput = false;
function event(phase, value) {
  events.push({ phase, kind: value instanceof Date ? "date" : value === null ? "null" : typeof value, value: value === undefined ? null : value });
}
try {
  const options = {
    baseURL: "http://localhost", secret: "account-timestamp-parameters-secret-at-least-32", database: { type: "mysql", db: mysql.db },
    account: { additionalFields: { accessTokenExpiresAt: {
      type: "date", required: false, onUpdate: () => "2031-02-03T04:05:06.123987Z", transform: { input: async value => {
        event("input", value);
        if (value == null) return value;
        return applyingInput ? compatible ? "2035-02-03 04:05:06.123987" : "2035-02-03T04:05:06.123987Z" : new Date(new Date(value).getTime() + 1000);
      } },
    } } },
    databaseHooks: { account: {
      create: { before: async data => { event("create.before", data.accessTokenExpiresAt); }, after: async data => { event("create.after", data.accessTokenExpiresAt); } },
      update: { before: async data => { event("update.before", data.accessTokenExpiresAt); }, after: async data => { event("update.after", data.accessTokenExpiresAt); } },
    } },
  };
  const migrations = await getMigrations(options);
  const schemaSql = await migrations.compileMigrations();
  await migrations.runMigrations();
  const { internalAdapter } = await betterAuth(options).$context;
  const user = await internalAdapter.createUser({ name: "Timestamp", email: "account-timestamp@example.com", emailVerified: false });
  const cases = [];
  for (const operation of ["create", "update"]) {
    for (const [kind, input] of [["date", new Date("2031-02-03T04:05:06.123987Z")], ["string", "2031-02-03T04:05:06.123987Z"], ["null", null], ["omitted", undefined]]) {
      const key = `${operation}-${kind}`;
      applyingInput = false;
      const original = operation === "update" ? await internalAdapter.createAccount({ userId: user.id, providerId: "timestamp-provider", accountId: key, accessTokenExpiresAt: new Date("2030-01-01T00:00:00.123Z") }) : null;
      applyingInput = true;
      events = [];
      const fields = kind === "omitted" ? {} : { accessTokenExpiresAt: input };
      let outcome;
      try {
        const account = operation === "create"
          ? await internalAdapter.createAccount({ userId: user.id, providerId: "timestamp-provider", accountId: key, ...fields })
          : await internalAdapter.updateAccount(original.id, fields);
        outcome = { output: account.accessTokenExpiresAt };
      } catch (error) {
        assert.ok(error.code, "expected a real mysql2 driver error");
        outcome = { error: { code: error.code, sql_state: error.sqlState, message: error.sqlMessage } };
      }
      const readback = await internalAdapter.findAccountByKey({ providerId: "timestamp-provider", accountId: key });
      const stored = await mysql.db.selectFrom("account").select("accessTokenExpiresAt").where("accountId", "=", key).executeTakeFirst();
      cases.push({ operation, kind, input, events: [...events], outcome, exists: readback !== null, readback: readback?.accessTokenExpiresAt ?? null, stored: stored?.accessTokenExpiresAt ?? null });
    }
  }
  assert.equal(cases.length, 8);
  const filename = compatible ? "account-timestamp-mysql-compatible-hooks" : "account-timestamp-mysql-hooks";
  await writeFile(new URL(`../../fixtures/${filename}.json`, import.meta.url), JSON.stringify({ better_auth: "1.7.18", backend: "mysql", schema_sql: schemaSql, cases }) + "\n");
  console.log("Eight actual MySQL account date-transform string results and driver failures");
} finally {
  await mysql.close();
}
