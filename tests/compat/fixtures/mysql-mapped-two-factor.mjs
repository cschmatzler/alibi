import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { betterAuth } from "../reference-server/node_modules/better-auth/dist/index.mjs";
import { getMigrations } from "../reference-server/node_modules/better-auth/dist/db/get-migration.mjs";
import { twoFactor } from "../reference-server/node_modules/better-auth/dist/plugins/index.mjs";
import { config } from "../reference-server/probes/schema-parity.mjs";
import { createMysqlDatabase } from "./support/mysql-database.mjs";

const database = await createMysqlDatabase();
const origin = "http://localhost";
const fields = { secret: "factor_secret", backupCodes: "backup_codes", userId: "owner_id", verified: "is_verified", failedVerificationCount: "failure_count", lockedUntil: "locked_until" };
const plugin = twoFactor({ skipVerificationOnEnable: true, schema: { twoFactor: { modelName: "factor_records", fields } } });
const cases = [];
try {
  const migrations = await getMigrations({ ...config, plugins: config.plugins.map(installed => installed.id === "two-factor" ? plugin : installed), database: { type: "mysql", db: database.db } });
  const sql = await migrations.compileMigrations();
  await migrations.runMigrations();
  const auth = betterAuth({ baseURL: origin, secret: "mysql-mapped-factor-secret-at-least-32-characters", database: { type: "mysql", db: database.db }, emailAndPassword: { enabled: true }, rateLimit: { enabled: false }, plugins: [plugin] });
  const jar = new Map();
  async function call(action, path, input) {
    const response = await auth.handler(new Request(`${origin}/api/auth${path}`, { method: "POST", headers: { origin, "content-type": "application/json", cookie: [...jar].map(([name, value]) => `${name}=${value}`).join("; ") }, body: JSON.stringify(input) }));
    for (const cookie of response.headers.getSetCookie()) {
      const [pair] = cookie.split(";");
      const index = pair.indexOf("=");
      const name = pair.slice(0, index), value = pair.slice(index + 1);
      if (value) jar.set(name, value); else jar.delete(name);
    }
    const output = await response.json();
    assert.equal(response.status, action === "replay" ? 401 : 200, `${action}: ${JSON.stringify(output)}`);
    const projected = action === "signup" || action === "backup" ? { email: output.user.email, token: Boolean(output.token) }
      : action === "enable" ? { backupCodes: output.backupCodes.length, totp: output.totpURI.startsWith("otpauth://totp/") } : output;
    cases.push({ action, status: response.status, output: projected });
    return output;
  }
  const password = "Password123!";
  await call("signup", "/sign-up/email", { name: "Owner", email: "mysql-mapped@example.com", password });
  const enabled = await call("enable", "/two-factor/enable", { password });
  const code = enabled.backupCodes[0];
  await call("backup", "/two-factor/verify-backup-code", { code });
  await call("replay", "/two-factor/verify-backup-code", { code });
  await call("disable", "/two-factor/disable", { password });
  const [remaining] = await database.pool.promise().query("SELECT COUNT(*) AS total FROM factor_records");
  assert.equal(remaining[0].total, 0);
  assert.equal(cases.length, 5);
  await writeFile(new URL("../../fixtures/mysql-mapped-factor-schema.sql", import.meta.url), sql + "\n");
  await writeFile(new URL("../../fixtures/mysql-mapped-factor.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", fields, cases }) + "\n");
  console.log(`${cases.length} actual MySQL HTTP responses with mapped two-factor storage`);
} finally {
  await database.close();
}
