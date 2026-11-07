import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { betterAuth } from "../reference-server/node_modules/better-auth/dist/index.mjs";
import { getMigrations } from "../reference-server/node_modules/better-auth/dist/db/get-migration.mjs";
import { username, twoFactor } from "../reference-server/node_modules/better-auth/dist/plugins/index.mjs";
import { passkey } from "../reference-server/node_modules/@better-auth/passkey/dist/index.mjs";
import { config as schemaConfig } from "../reference-server/probes/schema-parity.mjs";
import { createMysqlDatabase } from "./support/mysql-database.mjs";
import { registrationProof } from "./support/passkey-proof.mjs";

const database = await createMysqlDatabase();
const origin = "http://localhost";
const password = "Password123!";
const cases = [];
const jar = new Map();
let userId, passkeyId, backupCode, token, publicKey, createdAt;
function passkeyOutput(row) {
  assert.equal(row.userId, userId);
  assert.equal(row.id, passkeyId);
  assert.equal(typeof row.publicKey, "string");
  assert.ok(Number.isFinite(Date.parse(row.createdAt)));
  publicKey ??= row.publicKey;
  createdAt ??= row.createdAt;
  assert.equal(row.publicKey, publicKey);
  assert.equal(row.createdAt, createdAt);
  return { ...row, id: "<passkey>", userId: "<owner>", publicKey: "<public-key>", createdAt: "<date>" };
}
try {
  const migrations = await getMigrations({ ...schemaConfig, database: { type: "mysql", db: database.db } });
  const sql = await migrations.compileMigrations();
  await migrations.runMigrations();
  const auth = betterAuth({
    baseURL: origin, secret: "mysql-parity-secret-at-least-32-characters",
    database: { type: "mysql", db: database.db }, emailAndPassword: { enabled: true }, rateLimit: { enabled: false },
    plugins: [username(), twoFactor({ skipVerificationOnEnable: true }), passkey({ rpID: "localhost", origin })],
  });
  async function call(action, path, body, project = value => value) {
    const response = await auth.handler(new Request(`${origin}/api/auth${path}`, {
      method: body === undefined ? "GET" : "POST",
      headers: { origin, "content-type": "application/json", cookie: [...jar].map(([name, value]) => `${name}=${value}`).join("; ") },
      body: body === undefined ? undefined : JSON.stringify(body),
    }));
    for (const header of response.headers.getSetCookie()) {
      const pair = header.split(";")[0];
      const index = pair.indexOf("=");
      const name = pair.slice(0, index), value = pair.slice(index + 1);
      if (value) jar.set(name, value); else jar.delete(name);
    }
    const value = await response.json();
    assert.equal(response.status, action === "backup-replay" ? 401 : 200, `${action}: ${JSON.stringify(value)}`);
    cases.push({ action, status: response.status, output: project(value) });
    return value;
  }
  await call("signup", "/sign-up/email", { name: "Owner", email: "mysql-parity@example.com", password }, value => {
    userId = value.user.id;
    assert.equal(typeof value.token, "string");
    token = value.token;
    return { email: value.user.email, name: value.user.name, emailVerified: value.user.emailVerified, token: Boolean(value.token) };
  });
  await call("session", "/get-session", undefined, value => {
    assert.equal(value.user.id, userId);
    assert.equal(value.session.userId, userId);
    assert.equal(value.session.token, token);
    return { email: value.user.email, name: value.user.name, token: Boolean(value.session.token) };
  });
  const options = await call("register-options", "/passkey/generate-register-options", undefined, value => ({
    name: value.user.name, rp: value.rp, excludeCredentials: value.excludeCredentials, extensions: value.extensions,
  }));
  const proof = registrationProof(options.challenge, "mysql-workflow-credential", ["usb", "nfc"]);
  await call("register", "/passkey/verify-registration", { response: proof, name: "Security key" }, value => {
    passkeyId = value.id;
    return passkeyOutput(value);
  });
  await call("list", "/passkey/list-user-passkeys", undefined, value => value.map(passkeyOutput));
  await call("rename", "/passkey/update-passkey", { id: passkeyId, name: "Renamed" }, value => ({ passkey: passkeyOutput(value.passkey) }));
  await call("authenticate-options", "/passkey/generate-authenticate-options", undefined, value => ({
    rpId: value.rpId, allowCredentials: value.allowCredentials, userVerification: value.userVerification,
  }));
  await call("enable-factor", "/two-factor/enable", { password }, value => {
    backupCode = value.backupCodes[0];
    assert.ok(value.totpURI.startsWith("otpauth://totp/"));
    return { backupCodes: value.backupCodes.length, totp: true };
  });
  await call("backup", "/two-factor/verify-backup-code", { code: backupCode }, value => ({
    token: Boolean(value.token), email: value.user.email,
  }));
  await call("backup-replay", "/two-factor/verify-backup-code", { code: backupCode });
  await call("disable-factor", "/two-factor/disable", { password });
  await call("delete", "/passkey/delete-passkey", { id: passkeyId });
  await call("empty-list", "/passkey/list-user-passkeys");
  const [users] = await database.pool.promise().query("SELECT twoFactorEnabled FROM user WHERE id = ?", [userId]);
  const [factors] = await database.pool.promise().query("SELECT * FROM twoFactor WHERE userId = ?", [userId]);
  const [passkeys] = await database.pool.promise().query("SELECT * FROM passkey WHERE userId = ?", [userId]);
  assert.equal(users[0].twoFactorEnabled, 0);
  assert.equal(factors.length, 0);
  assert.equal(passkeys.length, 0);
  assert.equal(cases.length, 13);
  await writeFile(new URL("../../fixtures/mysql-source-schema.sql", import.meta.url), sql + "\n");
  await writeFile(new URL("../../fixtures/mysql-auth-workflow.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", mysql: database.mysqlVersion, cases }) + "\n");
  console.log(`${cases.length} actual MySQL HTTP workflow responses and final physical state`);
} finally {
  await database.close();
}
