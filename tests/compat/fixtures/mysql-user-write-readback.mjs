import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { kyselyAdapter } from "../reference-server/node_modules/@better-auth/kysely-adapter/dist/index.mjs";
import { createMysqlDatabase } from "./support/mysql-database.mjs";

const database = await createMysqlDatabase();
const cases = [];
try {
  await database.pool.promise().query("CREATE TABLE user (id VARCHAR(36) PRIMARY KEY, name VARCHAR(255) NOT NULL, email VARCHAR(255) NOT NULL UNIQUE, emailVerified BOOLEAN NOT NULL, image TEXT, createdAt TIMESTAMP(3) NOT NULL, updatedAt TIMESTAMP(3) NOT NULL)");
  const adapter = kyselyAdapter(database.db, { type: "mysql" })({
    user: { additionalFields: { name: { type: "string" }, id: { type: "string" } } },
  });
  const date = new Date("2026-01-01T00:00:00.123Z");
  for (const [index, replacement] of ["renamed", ""].entries()) {
    const id = `owner-${index}`;
    const row = await adapter.create({ model: "user", forceAllowId: true, data: {
      id, name: "Owner", email: `mysql-readback-${index}@example.com`, emailVerified: false, image: null, createdAt: date, updatedAt: date,
    } });
    assert.equal(row.id, id);
    const updated = await adapter.update({ model: "user", where: [{ field: "id", value: id }], update: { id: replacement, name: "Renamed", updatedAt: date } });
    assert.equal(updated.id, replacement || id);
    const old = await adapter.findOne({ model: "user", where: [{ field: "id", value: id }] });
    assert.equal(old === null, Boolean(replacement));
    cases.push({ id, replacement, created: row, updated });
  }
  await writeFile(new URL("../../fixtures/mysql-user-write-readback.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", cases }) + "\n");
  console.log(`${cases.length} actual MySQL user insert and changed-ID update readbacks`);
} finally {
  await database.close();
}
