import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { betterAuth } from "../reference-server/node_modules/better-auth/dist/index.mjs";
import { getMigrations } from "../reference-server/node_modules/better-auth/dist/db/get-migration.mjs";
import { config } from "../reference-server/probes/schema-parity.mjs";
import { createMysqlDatabase } from "./support/mysql-database.mjs";

const database = await createMysqlDatabase();
const events = [], cases = [];
const expiresAt = new Date("2030-01-02T03:04:05.678Z");
let mode;
try {
  await (await getMigrations({ ...config, database: { type: "mysql", db: database.db } })).runMigrations();
  const auth = betterAuth({ baseURL: "http://localhost", secret: "mysql-verification-update-secret-at-least-32", database: { type: "mysql", db: database.db },
    databaseHooks: { verification: { update: {
      before: async data => {
        events.push({ hook: "before", value: data.value });
        if (mode === "veto") return false;
        if (mode === "mutate") return { data: { value: "hook-value" } };
      },
      after: async row => { events.push({ hook: "after", value: row?.value ?? null }); },
    } } },
  });
  const { internalAdapter } = await auth.$context;
  for (const action of ["present", "missing", "veto", "mutate", "siblings", "sql-failure"]) {
    mode = action;
    events.length = 0;
    await database.pool.promise().query("DELETE FROM verification");
    const identifier = "mysql-update-proof";
    if (action !== "missing") {
      await internalAdapter.createVerificationValue({ identifier, value: "original", expiresAt });
      if (action === "siblings") await internalAdapter.createVerificationValue({ identifier, value: "sibling", expiresAt });
    }
    if (action === "sql-failure") await database.pool.promise().query("ALTER TABLE verification ADD CONSTRAINT reject_changed_value CHECK (value = 'original')");
    let result, failed = false;
    try { result = await internalAdapter.updateVerificationByIdentifier(identifier, { value: "changed", expiresAt }); }
    catch (error) { assert.equal(error.code, "ER_CHECK_CONSTRAINT_VIOLATED"); failed = true; }
    const [stored] = await database.pool.promise().query("SELECT value, expiresAt FROM verification ORDER BY value");
    assert.equal(failed, action === "sql-failure");
    if (action === "sql-failure") await database.pool.promise().query("ALTER TABLE verification DROP CHECK reject_changed_value");
    if (action === "siblings") assert.deepEqual(stored.map(row => row.value), ["changed", "changed"]);
    cases.push({ action, failed, result: result ? { identifier: result.identifier, value: result.value, expiresAt: result.expiresAt } : null,
      events: structuredClone(events), stored });
  }
  assert.equal(cases.length, 6);
  await writeFile(new URL("../../fixtures/mysql-verification-updates.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", cases }) + "\n");
  console.log(`${cases.length} actual MySQL verification update/readback and hook-order cases`);
} finally {
  await database.close();
}
