import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { betterAuth } from "../reference-server/node_modules/better-auth/dist/index.mjs";
import { getMigrations } from "../reference-server/node_modules/better-auth/dist/db/get-migration.mjs";
import { config } from "../reference-server/probes/schema-parity.mjs";
import { createMysqlDatabase } from "./support/mysql-database.mjs";

const database = await createMysqlDatabase({ connectionLimit: 4 });
const cases = [];
const expiresAt = new Date("2030-01-02T03:04:05.678Z");
try {
  await (await getMigrations({ ...config, database: { type: "mysql", db: database.db } })).runMigrations();
  const auth = betterAuth({ baseURL: "http://localhost", secret: "mysql-verification-claims-secret-at-least-32", database: { type: "mysql", db: database.db } });
  const { adapter } = await auth.$context;
  for (const action of ["success", "mismatch", "missing", "unchanged", "sql-failure", "concurrent"]) {
    await database.pool.promise().query("DELETE FROM verification");
    const id = "mysql-claimed-proof";
    if (action !== "missing") await adapter.create({ model: "verification", forceAllowId: true, data: { id, identifier: "mysql-claim", value: "original", expiresAt: new Date("2029-01-01T00:00:00.123Z") } });
    if (action === "sql-failure") await database.pool.promise().query("ALTER TABLE verification ADD CONSTRAINT reject_claim CHECK (value = 'original')");
    const expected = action === "mismatch" ? "stale" : "original";
    const value = action === "unchanged" ? "original" : "claimed";
    async function claim() {
      return await adapter.incrementOne({ model: "verification", where: [{ field: "id", value: id }, { field: "value", value: expected }], increment: {}, set: { value, expiresAt } });
    }
    let results = [], failed = false;
    try { results = action === "concurrent" ? await Promise.all(Array.from({ length: 8 }, claim)) : [await claim()]; }
    catch (error) { assert.equal(error.code, "ER_CHECK_CONSTRAINT_VIOLATED"); failed = true; }
    if (action === "sql-failure") await database.pool.promise().query("ALTER TABLE verification DROP CHECK reject_claim");
    const winners = results.filter(Boolean);
    assert.equal(failed, action === "sql-failure");
    assert.equal(winners.length, ["mismatch", "missing", "sql-failure"].includes(action) ? 0 : 1);
    const [stored] = await database.pool.promise().query("SELECT id, value, expiresAt FROM verification");
    cases.push({ action, expected, value, calls: action === "concurrent" ? 8 : 1, failed, winners: winners.length,
      snapshots: winners.map(row => ({ id: row.id, value: row.value, expiresAt: row.expiresAt })), stored });
  }
  assert.equal(cases.length, 6);
  await writeFile(new URL("../../fixtures/mysql-verification-claims.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", cases }) + "\n");
  console.log(`${cases.length} actual MySQL guarded verification claims including an eight-call race`);
} finally {
  await database.close();
}
