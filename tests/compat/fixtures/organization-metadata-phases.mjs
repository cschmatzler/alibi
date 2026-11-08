import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { writeFile } from "node:fs/promises";
import pg from "../reference-server/node_modules/pg/lib/index.js";
import { Kysely, PostgresDialect, SqliteDialect } from "../reference-server/node_modules/kysely/dist/index.js";
import { betterAuth } from "../reference-server/node_modules/better-auth/dist/index.mjs";
import { getMigrations } from "../reference-server/node_modules/better-auth/dist/db/get-migration.mjs";
import { organization } from "../reference-server/node_modules/better-auth/dist/plugins/index.mjs";
import { createMysqlDatabase } from "./support/mysql-database.mjs";

const outputModes = new Map([["--user-update-clock", "user-update-clock"], ["--session-clock", "session-creation-clock"], ["--account-clock", "account-clock"]]);
assert.ok(process.argv[2] === undefined || outputModes.has(process.argv[2]), "unknown fixture output mode");
const onlyOutput = outputModes.get(process.argv[2]);
const mysql = await createMysqlDatabase();
const sqlite = new DatabaseSync(":memory:");
const sqliteDb = new Kysely({ dialect: new SqliteDialect({ database: {
  close() { sqlite.close(); },
  prepare(sql) {
    const statement = sqlite.prepare(sql);
    return { reader: statement.columns().length > 0, all(parameters) { return statement.all({}, ...parameters); }, run(parameters) { return statement.run({}, ...parameters); } };
  },
} }) });
assert.ok(process.env.BETTER_AUTH_TEST_POSTGRES_URL, "requires a disposable PostgreSQL database URL");
const schema = `org_metadata_oracle_${randomBytes(8).toString("hex")}`;
const admin = new pg.Client({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL });
await admin.connect();
await admin.query(`CREATE SCHEMA ${schema}`);
const pool = new pg.Pool({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL, options: `-csearch_path=${schema}`, max: 1 });
const postgresDb = new Kysely({ dialect: new PostgresDialect({ pool }) });
const profiles = [];
const userClocks = [];
const updateClocks = [];
const sessionClocks = [];
const accountClocks = [];
try {
  for (const [backend, db] of [["sqlite", sqliteDb], ["postgres", postgresDb], ["mysql", mysql.db]]) {
    const options = { baseURL: "http://localhost", secret: "organization-metadata-source-secret-at-least-32", database: { type: backend, db }, emailAndPassword: { enabled: true }, rateLimit: { enabled: false }, plugins: [organization()] };
    await (await getMigrations(options)).runMigrations();
    const auth = betterAuth(options);
    const jar = new Map();
    async function call(path, input) {
      const response = await auth.handler(new Request(`http://localhost/api/auth${path}`, { method: "POST", headers: { origin: "http://localhost", "content-type": "application/json", cookie: [...jar].map(([name, value]) => `${name}=${value}`).join("; ") }, body: JSON.stringify(input) }));
      for (const cookie of response.headers.getSetCookie()) {
        const [pair] = cookie.split(";");
        const index = pair.indexOf("=");
        const name = pair.slice(0, index), value = pair.slice(index + 1);
        if (value) jar.set(name, value); else jar.delete(name);
      }
      const output = await response.json();
      assert.equal(response.status, 200, `${backend}/${path}: ${JSON.stringify(output)}`);
      return output;
    }
    await call("/sign-up/email", { name: "Owner", email: "org-metadata@example.com", password: "Password123!" });
    const { internalAdapter } = await auth.$context;
    const generated = await internalAdapter.createUser({ name: "Clock", email: "user-clock@example.com", emailVerified: false });
    const readback = await internalAdapter.findUserById(generated.id);
    for (const value of [generated.createdAt, generated.updatedAt, readback.createdAt, readback.updatedAt]) assert.ok(value instanceof Date);
    const clock = {
      created_at_millisecond_aligned: /\.\d{3}Z$/.test(generated.createdAt.toISOString()),
      updated_at_millisecond_aligned: /\.\d{3}Z$/.test(generated.updatedAt.toISOString()),
      readback_matches: generated.createdAt.getTime() === readback.createdAt.getTime() && generated.updatedAt.getTime() === readback.updatedAt.getTime(),
    };
    assert.deepEqual(clock, { created_at_millisecond_aligned: true, updated_at_millisecond_aligned: true, readback_matches: true });
    userClocks.push(clock);
    const updated = await internalAdapter.updateUser(generated.id, { name: "Updated clock" });
    const updatedReadback = await internalAdapter.findUserById(generated.id);
    for (const value of [updated.createdAt, updated.updatedAt, updatedReadback.createdAt, updatedReadback.updatedAt]) assert.ok(value instanceof Date);
    const updateClock = {
      created_at_preserved: generated.createdAt.getTime() === updated.createdAt.getTime(),
      updated_at_millisecond_aligned: /\.\d{3}Z$/.test(updated.updatedAt.toISOString()),
      readback_matches: updated.createdAt.getTime() === updatedReadback.createdAt.getTime() && updated.updatedAt.getTime() === updatedReadback.updatedAt.getTime(),
    };
    assert.deepEqual(updateClock, { created_at_preserved: true, updated_at_millisecond_aligned: true, readback_matches: true });
    updateClocks.push(updateClock);
    const expiresAt = new Date("2031-01-01T00:00:00.123Z");
    const session = await internalAdapter.createSession(generated.id, false, { token: "generated-session-clock", expiresAt }, true);
    const sessionReadback = await internalAdapter.findSession(session.token);
    assert.equal(sessionReadback.user.id, generated.id);
    const sessionClock = {
      created_at_millisecond_aligned: /\.\d{3}Z$/.test(session.createdAt.toISOString()),
      updated_at_millisecond_aligned: /\.\d{3}Z$/.test(session.updatedAt.toISOString()),
      expires_at_preserved: session.expiresAt.getTime() === expiresAt.getTime(),
      readback_matches: session.createdAt.getTime() === sessionReadback.session.createdAt.getTime() && session.updatedAt.getTime() === sessionReadback.session.updatedAt.getTime() && session.expiresAt.getTime() === sessionReadback.session.expiresAt.getTime(),
    };
    assert.deepEqual(sessionClock, { created_at_millisecond_aligned: true, updated_at_millisecond_aligned: true, expires_at_preserved: true, readback_matches: true });
    sessionClocks.push(sessionClock);
    const account = await internalAdapter.createAccount({ userId: generated.id, providerId: "clock-provider", accountId: "generated-account-clock", password: "opaque-hash" });
    const accountReadback = await internalAdapter.findAccountByKey({ providerId: "clock-provider", accountId: "generated-account-clock" });
    assert.equal(accountReadback.id, account.id);
    const accountClock = {
      created_at_millisecond_aligned: /\.\d{3}Z$/.test(account.createdAt.toISOString()),
      updated_at_millisecond_aligned: /\.\d{3}Z$/.test(account.updatedAt.toISOString()),
      readback_matches: account.createdAt.getTime() === accountReadback.createdAt.getTime() && account.updatedAt.getTime() === accountReadback.updatedAt.getTime(),
    };
    assert.deepEqual(accountClock, { created_at_millisecond_aligned: true, updated_at_millisecond_aligned: true, readback_matches: true });
    const updatedAccount = await internalAdapter.updateAccount(account.id, { scope: "email" });
    const updatedAccountReadback = await internalAdapter.findAccountByKey({ providerId: "clock-provider", accountId: "generated-account-clock" });
    assert.equal(updatedAccount.id, account.id);
    assert.equal(updatedAccountReadback.scope, "email");
    const accountUpdateClock = {
      created_at_preserved: account.createdAt.getTime() === updatedAccount.createdAt.getTime(),
      updated_at_millisecond_aligned: /\.\d{3}Z$/.test(updatedAccount.updatedAt.toISOString()),
      readback_matches: updatedAccount.createdAt.getTime() === updatedAccountReadback.createdAt.getTime() && updatedAccount.updatedAt.getTime() === updatedAccountReadback.updatedAt.getTime(),
    };
    assert.deepEqual(accountUpdateClock, { created_at_preserved: true, updated_at_millisecond_aligned: true, readback_matches: true });
    accountClocks.push([{ action: "create", clock: accountClock }, { action: "update", clock: accountUpdateClock }]);
    const cases = [];
    let organizationId;
    for (const action of ["omitted", "create", "update"]) {
      const input = action === "omitted" ? undefined : { clock: "2025-02-03T04:05:06Z", numbers: [1e20, 1e21, 1e-6, 1e-7, -0], project: action, revisions: [1, 2] };
      const output = action === "update" ? await call("/organization/update", { organizationId, data: { metadata: input } })
        : await call("/organization/create", { name: "Metadata", slug: `metadata-${action}`, ...(input === undefined ? {} : { metadata: input }) });
      organizationId = output.id;
      const stored = await db.selectFrom("organization").select("metadata").where("id", "=", organizationId).executeTakeFirstOrThrow();
      const row = { action, ...(input === undefined ? {} : { input }), own: Object.hasOwn(output, "metadata"), output: output.metadata ?? null, stored: stored.metadata };
      if (action === "omitted") assert.equal(stored.metadata, null);
      else assert.equal(row.output.clock, action === "create" ? input.clock : "2025-02-03T04:05:06.000Z");
      cases.push(row);
    }
    profiles.push({ backend, cases });
  }
  for (const profile of profiles) assert.deepEqual(profile.cases, profiles[0].cases);
  for (const clock of userClocks) assert.deepEqual(clock, userClocks[0]);
  for (const clock of updateClocks) assert.deepEqual(clock, updateClocks[0]);
  for (const clock of sessionClocks) assert.deepEqual(clock, sessionClocks[0]);
  for (const cases of accountClocks) assert.deepEqual(cases, accountClocks[0]);
  const common = { better_auth: "1.7.18", backends: profiles.map(profile => profile.backend) };
  const outputs = [
    ["organization-metadata-phases", { ...common, cases: profiles[0].cases }],
    ["user-creation-clock", { ...common, clock: userClocks[0] }],
    ["user-update-clock", { ...common, clock: updateClocks[0] }],
    ["session-creation-clock", { ...common, clock: sessionClocks[0] }],
    ["account-clock", { ...common, cases: accountClocks[0] }],
  ];
  for (const [name, output] of outputs) {
    if (onlyOutput && name !== onlyOutput) continue;
    await writeFile(new URL(`../../fixtures/${name}.json`, import.meta.url), JSON.stringify(output) + "\n");
  }
  console.log("Nine actual SQLite/PostgreSQL/MySQL organization metadata creation/update cases");
  console.log("Three actual user creation/readback millisecond clock cases");
  console.log("Three actual user update/readback millisecond clock cases");
  console.log("Three actual session creation/readback millisecond clock cases");
  console.log("Six actual account creation/update millisecond clock cases");
} finally {
  await sqliteDb.destroy();
  await postgresDb.destroy();
  await admin.query(`DROP SCHEMA ${schema} CASCADE`);
  await admin.end();
  await mysql.close();
}
