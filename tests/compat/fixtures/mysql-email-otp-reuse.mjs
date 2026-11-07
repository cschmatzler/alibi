import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { betterAuth } from "../reference-server/node_modules/better-auth/dist/index.mjs";
import { getMigrations } from "../reference-server/node_modules/better-auth/dist/db/get-migration.mjs";
import { emailOTP } from "../reference-server/node_modules/better-auth/dist/plugins/index.mjs";
import { config } from "../reference-server/probes/schema-parity.mjs";
import { createMysqlDatabase } from "./support/mysql-database.mjs";

const profiles = [];
for (const strategy of [null, "uuid"]) {
  const database = await createMysqlDatabase();
  const origin = "http://localhost";
  const email = "mysql-otp-reuse@example.com";
  const deliveries = [], cases = [];
  const jar = new Map();
  try {
    await (await getMigrations({ ...config, database: { type: "mysql", db: database.db } })).runMigrations();
    const auth = betterAuth({ baseURL: origin, secret: "mysql-email-otp-secret-at-least-32-characters", database: { type: "mysql", db: database.db },
      emailAndPassword: { enabled: true }, rateLimit: { enabled: false }, logger: { disabled: true },
      advanced: strategy ? { database: { generateId: strategy } } : {},
      plugins: [emailOTP({ resendStrategy: "reuse", sendVerificationOTP: async delivery => { deliveries.push(delivery); } })],
    });
    let code, expiry, identifier;
    for (const action of ["signup", "send", "reuse", "wrong", "correct", "replay"]) {
      const path = action === "signup" ? "/sign-up/email" : action === "send" || action === "reuse" ? "/email-otp/send-verification-otp" : "/sign-in/email-otp";
      const input = action === "signup" ? { name: "Owner", email, password: "Password123!" }
        : action === "send" || action === "reuse" ? { email, type: "sign-in" } : { email, otp: action === "wrong" ? code === "000000" ? "111111" : "000000" : code };
      const response = await auth.handler(new Request(`${origin}/api/auth${path}`, { method: "POST", headers: { origin, "content-type": "application/json", cookie: [...jar].map(([name, value]) => `${name}=${value}`).join("; ") }, body: JSON.stringify(input) }));
      for (const cookie of response.headers.getSetCookie()) {
        const [pair] = cookie.split(";");
        const index = pair.indexOf("=");
        const name = pair.slice(0, index), value = pair.slice(index + 1);
        if (value) jar.set(name, value); else jar.delete(name);
      }
      const text = await response.text();
      const output = text ? JSON.parse(text) : null;
      const expected = action === "wrong" || action === "replay" ? 400 : action === "correct" && !strategy ? 500 : 200;
      assert.equal(response.status, expected, `${strategy}/${action}: ${text}`);
      const projected = action === "signup" || action === "correct" && strategy ? { email: output.user.email, name: output.user.name, emailVerified: output.user.emailVerified, token: Boolean(output.token) } : output;
      const row = { action, status: response.status, output: projected, deliveries: deliveries.length };
      if (action === "send") {
        assert.equal(deliveries.length, 1);
        code = deliveries[0].otp;
        assert.match(code, /^\d{6}$/);
      }
      if (["send", "reuse", "wrong"].includes(action)) {
        const [stored] = await database.pool.promise().query("SELECT identifier, value, expiresAt FROM verification");
        assert.equal(stored.length, 1);
        if (action === "send") identifier = stored[0].identifier;
        assert.equal(stored[0].identifier, identifier);
        row.identifier = identifier;
        row.value = stored[0].value.replaceAll(code, "<otp>");
        const currentExpiry = stored[0].expiresAt.getTime();
        if (action === "reuse") {
          assert.equal(deliveries.length, 2);
          assert.equal(deliveries[1].otp, code);
          assert.ok(currentExpiry >= expiry);
          row.expiry_extended = true;
        }
        if (action === "wrong") {
          assert.equal(currentExpiry, expiry);
          row.expiry_preserved = true;
        }
        expiry = currentExpiry;
      }
      if (action === "correct" || action === "replay") {
        const [stored] = await database.pool.promise().query("SELECT COUNT(*) AS total FROM verification WHERE identifier = ?", [identifier]);
        assert.equal(stored[0].total, 0);
        row.otp_records = stored[0].total;
      }
      cases.push(row);
    }
    assert.equal(cases.length, 6);
    profiles.push({ strategy, cases });
  } finally {
    await database.close();
  }
}
await writeFile(new URL("../../fixtures/mysql-email-otp-reuse.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", profiles }) + "\n");
console.log("12 actual MySQL email OTP cases across default and UUID ID strategies");
