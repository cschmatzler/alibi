import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { betterAuth } from "../reference-server/node_modules/better-auth/dist/index.mjs";
import { getMigrations } from "../reference-server/node_modules/better-auth/dist/db/get-migration.mjs";
import { admin } from "../reference-server/node_modules/better-auth/dist/plugins/index.mjs";
import { config } from "../reference-server/probes/schema-parity.mjs";
import { createMysqlDatabase } from "./support/mysql-database.mjs";

const database = await createMysqlDatabase();
const cases = [];
try {
  await (await getMigrations({ ...config, database: { type: "mysql", db: database.db } })).runMigrations();
  const auth = betterAuth({ baseURL: "http://localhost", secret: "mysql-admin-pages-secret-at-least-32-characters", database: { type: "mysql", db: database.db }, emailAndPassword: { enabled: true }, rateLimit: { enabled: false }, plugins: [admin()] });
  const signup = await auth.handler(new Request("http://localhost/api/auth/sign-up/email", { method: "POST", headers: { origin: "http://localhost", "content-type": "application/json" }, body: JSON.stringify({ name: "Owner", email: "owner@example.com", password: "Password123!" }) }));
  assert.equal(signup.status, 200);
  const cookie = signup.headers.getSetCookie().map(value => value.split(";")[0]).join("; ");
  for (const email of ["a@example.com", "b@example.com"]) await auth.api.signUpEmail({ body: { name: email[0], email, password: "Password123!" } });
  await database.pool.promise().query("UPDATE user SET role = 'admin' WHERE email = 'owner@example.com'");
  for (const [action, query] of [
    ["default", {}], ["first", { limit: "1" }], ["second", { limit: "1", offset: "1" }],
    ["fraction-limit", { limit: "1.5" }], ["subunit-limit", { limit: "0.5" }], ["fraction-offset", { limit: "1", offset: "0.5" }],
    ["zero-limit", { limit: "0" }], ["negative-limit", { limit: "-1" }], ["negative-offset", { limit: "1", offset: "-1" }],
    ["nan-limit", { limit: "NaN" }], ["exponent-limit", { limit: "1e0" }], ["space-limit", { limit: " 1 " }],
    ["decimal-integer", { limit: "2.0", offset: "1.0" }],
  ]) {
    const url = new URL("http://localhost/api/auth/admin/list-users");
    url.search = new URLSearchParams({ ...query, sortBy: "email", sortDirection: "asc" }).toString();
    const response = await auth.handler(new Request(url, { headers: { origin: "http://localhost", cookie } }));
    const output = await response.json();
    assert.equal(response.status, 200, `${action}: ${JSON.stringify(output)}`);
    assert.ok(Array.isArray(output.users));
    cases.push({ action, query, status: response.status, output: { ...output, users: output.users.map(user => user.email) } });
  }
  assert.equal(cases.length, 13);
  const [remaining] = await database.pool.promise().query("SELECT COUNT(*) AS total FROM user");
  assert.equal(remaining[0].total, 3);
  await writeFile(new URL("../../fixtures/mysql-admin-pages.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", cases }) + "\n");
  console.log(`${cases.length} actual MySQL admin HTTP page coercion and error-fallback cases`);
} finally {
  await database.close();
}
