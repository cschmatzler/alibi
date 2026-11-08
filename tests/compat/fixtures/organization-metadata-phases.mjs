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
  await writeFile(new URL("../../fixtures/organization-metadata-phases.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", backends: profiles.map(profile => profile.backend), cases: profiles[0].cases }) + "\n");
  console.log("Nine actual SQLite/PostgreSQL/MySQL organization metadata creation/update cases");
} finally {
  await sqliteDb.destroy();
  await postgresDb.destroy();
  await admin.query(`DROP SCHEMA ${schema} CASCADE`);
  await admin.end();
  await mysql.close();
}
