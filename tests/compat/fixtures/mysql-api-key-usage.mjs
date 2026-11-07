import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { betterAuth } from "../reference-server/node_modules/better-auth/dist/index.mjs";
import { getMigrations } from "../reference-server/node_modules/better-auth/dist/db/get-migration.mjs";
import { apiKey } from "../reference-server/node_modules/@better-auth/api-key/dist/index.mjs";
import { config } from "../reference-server/probes/schema-parity.mjs";
import { createMysqlDatabase } from "./support/mysql-database.mjs";

assert.equal(JSON.parse(await readFile(new URL("../reference-server/node_modules/@better-auth/api-key/package.json", import.meta.url))).version, "1.7.18");
const database = await createMysqlDatabase({ connectionLimit: 4 });
try {
  await (await getMigrations({ ...config, database: { type: "mysql", db: database.db } })).runMigrations();
  const auth = betterAuth({ baseURL: "http://localhost", secret: "mysql-api-key-secret-at-least-32-characters", database: { type: "mysql", db: database.db }, emailAndPassword: { enabled: true }, rateLimit: { enabled: false }, plugins: [apiKey({ deferUpdates: false })], logger: { level: "error", disabled: true } });
  const owner = await auth.api.signUpEmail({ body: { name: "Owner", email: "mysql-api-key@example.com", password: "Password123!" } });
  const created = await auth.api.createApiKey({ body: { name: "Quota key", userId: owner.user.id, remaining: 2, rateLimitEnabled: false } });
  assert.equal(created.remaining, 2);
  const cases = [];
  for (let call = 1; call <= 3; call++) {
    const result = await auth.api.verifyApiKey({ body: { key: created.key } });
    assert.equal(result.valid, call <= 2);
    const key = result.key && {
      name: result.key.name, configId: result.key.configId, enabled: result.key.enabled, remaining: result.key.remaining,
      requestCount: result.key.requestCount, rateLimitEnabled: result.key.rateLimitEnabled, metadata: result.key.metadata,
    };
    if (result.key) assert.equal(result.key.referenceId, owner.user.id);
    const [rows] = await database.pool.promise().query("SELECT remaining, requestCount, enabled, rateLimitEnabled FROM apikey WHERE id = ?", [created.id]);
    assert.equal(rows.length, call === 3 ? 0 : 1);
    cases.push({ call, output: { valid: result.valid, error: result.error, key }, stored: rows[0] ?? null });
  }
  assert.equal(cases[1].stored.remaining, 0);
  assert.equal(cases[2].stored, null);
  const limited = await auth.api.createApiKey({ body: { name: "Refill key", userId: owner.user.id, remaining: 3, refillAmount: 3, refillInterval: 3600000, rateLimitEnabled: false } });
  const results = await Promise.all(Array.from({ length: 8 }, () => auth.api.verifyApiKey({ body: { key: limited.key } })));
  const allowed = results.filter(result => result.valid).length;
  const exhausted = results.filter(result => !result.valid && result.error?.code === "USAGE_EXCEEDED").length;
  const [rows] = await database.pool.promise().query("SELECT remaining FROM apikey WHERE id = ?", [limited.id]);
  assert.equal(rows.length, 1);
  const concurrent = { calls: results.length, allowed, exhausted, remaining: rows[0].remaining };
  assert.deepEqual(concurrent, { calls: 8, allowed: 3, exhausted: 5, remaining: 0 });
  const refillKey = await auth.api.createApiKey({ body: { name: "Due refill key", userId: owner.user.id, remaining: 0, refillAmount: 3, refillInterval: 3600000, rateLimitEnabled: false } });
  await database.pool.promise().query("UPDATE apikey SET lastRefillAt = '2000-01-01 00:00:00.123' WHERE id = ?", [refillKey.id]);
  const refillResults = await Promise.all(Array.from({ length: 8 }, () => auth.api.verifyApiKey({ body: { key: refillKey.key } })));
  const [refillRows] = await database.pool.promise().query("SELECT remaining, lastRefillAt FROM apikey WHERE id = ?", [refillKey.id]);
  assert.equal(refillRows.length, 1);
  const refillConcurrent = { calls: refillResults.length, allowed: refillResults.filter(result => result.valid).length,
    exhausted: refillResults.filter(result => !result.valid && result.error?.code === "USAGE_EXCEEDED").length,
    remaining: refillRows[0].remaining, refilled: refillRows[0].lastRefillAt.getTime() > Date.UTC(2000, 0, 1, 0, 0, 0, 123) };
  assert.deepEqual(refillConcurrent, { calls: 8, allowed: 3, exhausted: 5, remaining: 0, refilled: true });
  const rateKey = await auth.api.createApiKey({ body: { name: "Rate key", userId: owner.user.id, rateLimitEnabled: true, rateLimitMax: 3, rateLimitTimeWindow: 3600000 } });
  const rateResults = await Promise.all(Array.from({ length: 8 }, () => auth.api.verifyApiKey({ body: { key: rateKey.key } })));
  const denied = rateResults.filter(result => !result.valid);
  assert.equal(denied.length, 5);
  const denialCode = denied[0].error.code;
  assert.ok(denied.every(result => result.error.code === denialCode));
  const [rateRows] = await database.pool.promise().query("SELECT requestCount FROM apikey WHERE id = ?", [rateKey.id]);
  assert.equal(rateRows.length, 1);
  const rateConcurrent = { calls: rateResults.length, allowed: rateResults.filter(result => result.valid).length, denied: denied.length, code: denialCode, requestCount: rateRows[0].requestCount };
  assert.equal(rateConcurrent.allowed, 3);
  assert.equal(rateConcurrent.requestCount, 3);
  const resetKey = await auth.api.createApiKey({ body: { name: "Reset key", userId: owner.user.id, rateLimitEnabled: true, rateLimitMax: 3, rateLimitTimeWindow: 3600000 } });
  await database.pool.promise().query("UPDATE apikey SET requestCount = 99, lastRequest = '2000-01-01 00:00:00.123' WHERE id = ?", [resetKey.id]);
  const resetResults = await Promise.all(Array.from({ length: 8 }, () => auth.api.verifyApiKey({ body: { key: resetKey.key } })));
  const [resetRows] = await database.pool.promise().query("SELECT requestCount, lastRequest FROM apikey WHERE id = ?", [resetKey.id]);
  assert.equal(resetRows.length, 1);
  const resetConcurrent = { calls: resetResults.length, allowed: resetResults.filter(result => result.valid).length,
    denied: resetResults.filter(result => !result.valid && result.error?.code === denialCode).length, code: denialCode,
    requestCount: resetRows[0].requestCount, reset: resetRows[0].lastRequest.getTime() > Date.UTC(2000, 0, 1, 0, 0, 0, 123) };
  assert.deepEqual(resetConcurrent, { ...rateConcurrent, reset: true });
  await writeFile(new URL("../../fixtures/mysql-api-key-usage.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", cases, concurrent, refill_concurrent: refillConcurrent, rate_concurrent: rateConcurrent, reset_concurrent: resetConcurrent }) + "\n");
  console.log(`${cases.length} actual MySQL sequential API-key cases and four eight-call quota/refill/rate/reset bursts`);
} finally {
  await database.close();
}
