import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { readFile, writeFile } from "node:fs/promises";
import pg from "../reference-server/node_modules/pg/lib/index.js";
import { Kysely, PostgresDialect, SqliteDialect } from "../reference-server/node_modules/kysely/dist/index.js";
import { betterAuth } from "../reference-server/node_modules/better-auth/dist/index.mjs";
import { getMigrations } from "../reference-server/node_modules/better-auth/dist/db/get-migration.mjs";
import { passkey } from "../reference-server/node_modules/@better-auth/passkey/dist/index.mjs";
import { config } from "../reference-server/probes/schema-parity.mjs";
import { registrationProof } from "./support/passkey-proof.mjs";

const pin = JSON.parse(await readFile(new URL("../upstream-source.json", import.meta.url)));
assert.equal(pin.commit, "38f43e390920faa400d51ff0bd18570a424d05ce");
assert.equal(pin.version, "1.7.18");
for (const name of ["better-auth", "@better-auth/core", "@better-auth/kysely-adapter", "@better-auth/passkey"]) {
  assert.equal(JSON.parse(await readFile(new URL(`../reference-server/node_modules/${name}/package.json`, import.meta.url))).version, "1.7.18");
}
assert.ok(process.env.BETTER_AUTH_TEST_POSTGRES_URL, "requires a disposable PostgreSQL database URL");
const schema = `passkey_clock_${randomBytes(8).toString("hex")}`;
const admin = new pg.Client({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL });
await admin.connect();
await admin.query(`CREATE SCHEMA ${schema}`);
const pool = new pg.Pool({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL, options: `-csearch_path=${schema}`, max: 1 });
const db = new Kysely({ dialect: new PostgresDialect({ pool }) });
const sqlite = new DatabaseSync(":memory:");
const sqliteDb = new Kysely({ dialect: new SqliteDialect({ database: {
  close() { sqlite.close(); },
  prepare(sql) {
    const statement = sqlite.prepare(sql);
    return { reader: statement.columns().length > 0, all(parameters) { return statement.all({}, ...parameters); }, run(parameters) { return statement.run({}, ...parameters); } };
  },
} }) });
const cases = [];
async function capture(backend, database) {
  await (await getMigrations({ ...config, database: { type: backend, db: database } })).runMigrations();
  for (const mode of ["session", "resolved", "resolved-session"]) {
    let owner;
    const plugin = passkey({ rpID: "localhost", rpName: "Clock", origin: "http://localhost", registration: {
      requireSession: mode === "session", ...(mode !== "session" ? { resolveUser: async () => owner } : {}),
    } });
    const auth = betterAuth({ baseURL: "http://localhost", secret: "passkey-clock-source-secret-at-least-32", database: { type: backend, db: database }, emailAndPassword: { enabled: true }, rateLimit: { enabled: false }, plugins: [plugin] });
    const jar = new Map();
    async function exchange(path, input) {
      const response = await auth.handler(new Request(`http://localhost/api/auth${path}`, {
        method: input === undefined ? "GET" : "POST",
        headers: { origin: "http://localhost", "content-type": "application/json", cookie: [...jar].map(([key, value]) => `${key}=${value}`).join("; ") },
        ...(input === undefined ? {} : { body: JSON.stringify(input) }),
      }));
      for (const value of response.headers.getSetCookie()) {
        const [pair] = value.split(";");
        const index = pair.indexOf("=");
        if (pair.slice(index + 1)) jar.set(pair.slice(0, index), pair.slice(index + 1));
        else jar.delete(pair.slice(0, index));
      }
      const output = await response.json();
      assert.equal(response.status, 200, `${mode}/${path}: ${JSON.stringify(output)}`);
      return output;
    }
    owner = (await exchange("/sign-up/email", { name: "Clock", email: `${mode}@passkey-clock.example.com`, password: "Password123!" })).user;
    if (mode !== "session") jar.clear();
    const generated = await exchange("/passkey/generate-register-options");
    const response = registrationProof(generated.challenge, `clock-${mode}`);
    const output = await exchange("/passkey/verify-registration", { response, ...(mode === "resolved-session" ? { createSession: true } : {}) });
    const rows = backend === "postgres"
      ? (await pool.query('SELECT "createdAt", (extract(microseconds FROM "createdAt")::bigint % 1000 = 0) AS millisecond_aligned FROM passkey WHERE "credentialID" = $1', [response.id])).rows
      : await database.selectFrom("passkey").select(["createdAt"]).where("credentialID", "=", response.id).execute();
    assert.equal(rows.length, 1);
    const clock = { millisecond_aligned: backend === "postgres" ? rows[0].millisecond_aligned : /\.\d{3}Z$/.test(rows[0].createdAt), persisted_matches_output: new Date(rows[0].createdAt).toISOString() === output.createdAt };
    assert.deepEqual(clock, { millisecond_aligned: true, persisted_matches_output: true });
    cases.push({ backend, mode, clock });
  }
}
try {
  for (const [backend, database] of [["sqlite", sqliteDb], ["postgres", db]]) {
    await capture(backend, database);
  }
  await writeFile(new URL("../../fixtures/passkey-registration-clock.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", cases }) + "\n");
  console.log(`${cases.length} actual SQLite/PostgreSQL passkey registration clock and physical-precision cases`);
} finally {
  await sqliteDb.destroy();
  await db.destroy();
  await admin.query(`DROP SCHEMA ${schema} CASCADE`);
  await admin.end();
}
