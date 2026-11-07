import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { memoryAdapter } from "../reference-server/node_modules/@better-auth/memory-adapter/dist/index.mjs";
import { passkey } from "../reference-server/node_modules/@better-auth/passkey/dist/index.mjs";

const pkg = JSON.parse(await readFile(new URL("../reference-server/node_modules/@better-auth/memory-adapter/package.json", import.meta.url)));
assert.equal(pkg.version, "1.7.18");
assert.equal(JSON.parse(await readFile(new URL("../reference-server/node_modules/@better-auth/passkey/package.json", import.meta.url))).version, "1.7.18");
const cases = [];
for (const [kind, rollback, concurrent] of [
  ["commit-disjoint", false, "other"], ["rollback-disjoint", true, "other"],
  ["commit-conflict", false, "existing"], ["rollback-conflict", true, "existing"],
  ["commit-concurrent-delete", false, "delete"],
]) {
  const database = { user: [{ id: "existing", name: "base" }, { id: "other", name: "base-other" }] };
  const adapter = memoryAdapter(database)({ advanced: { database: { generateId: false } } });
  const where = value => [{ field: "id", value }];
  const read = async (db, id) => (await db.findOne({ model: "user", where: where(id) }))?.name ?? null;
  let entered, release;
  const ready = new Promise(resolve => { entered = resolve; });
  const barrier = new Promise(resolve => { release = resolve; });
  let inside;
  const transaction = adapter.transaction(async tx => {
    await tx.update({ model: "user", where: where("existing"), update: { name: "transaction" } });
    await tx.create({ model: "user", data: { id: "tx-created", name: "tx-created" }, forceAllowId: true });
    inside = [await read(tx, "existing"), await read(tx, "tx-created")];
    entered();
    await barrier;
    if (rollback) throw new Error("intentional rollback");
  }).then(() => "committed", error => error.message);
  await ready;
  const during = [await read(adapter, "existing"), await read(adapter, "tx-created")];
  assert.deepEqual(during, ["base", null]);
  if (concurrent === "delete") {
    await adapter.delete({ model: "user", where: where("existing") });
  } else {
    await adapter.update({ model: "user", where: where(concurrent), update: { name: "concurrent" } });
  }
  await adapter.create({ model: "user", data: { id: "live-created", name: "live-created" }, forceAllowId: true });
  release();
  const outcome = await transaction;
  const rows = (await adapter.findMany({ model: "user" })).map(({ id, name }) => ({ id, name }));
  cases.push({ kind, rollback, concurrent, inside, during, outcome, rows });
}
const records = [];
for (const rollback of [false, true]) {
  const database = { user: [], account: [], verification: [], passkey: [] };
  const adapter = memoryAdapter(database)({ advanced: { database: { generateId: false } }, plugins: [passkey({ rpID: "example.test", rpName: "Example" })] });
  let entered, release;
  const ready = new Promise(resolve => { entered = resolve; });
  const barrier = new Promise(resolve => { release = resolve; });
  const transaction = adapter.transaction(async tx => {
    await tx.create({ model: "user", data: { id: "owner", name: "Owner", email: "owner@test" }, forceAllowId: true });
    assert.equal((await tx.findOne({ model: "user", where: [{ field: "email", value: "owner@test" }] })).id, "owner");
    await tx.create({ model: "account", data: { id: "account", userId: "owner", providerId: "provider", accountId: "remote" }, forceAllowId: true });
    assert.equal((await tx.findOne({ model: "account", where: [{ field: "accountId", value: "remote" }] })).userId, "owner");
    await tx.create({ model: "verification", data: { id: "verification", identifier: "tx-code", value: "secret", expiresAt: new Date("2090-01-01T00:00:00.000Z") }, forceAllowId: true });
    await tx.create({ model: "passkey", data: { id: "passkey", userId: "owner", publicKey: "public", credentialID: "credential", counter: 0, deviceType: "singleDevice", backedUp: false }, forceAllowId: true });
    entered(); await barrier;
    if (rollback) throw new Error("intentional rollback");
  }).then(() => "committed", error => error.message);
  await ready;
  const during = Object.values(database).map(rows => rows.length);
  release();
  const outcome = await transaction;
  const after = Object.values(database).map(rows => rows.length);
  records.push({ rollback, during, outcome, after });
}
await writeFile(new URL("../../../crates/core/src/store/memory_transaction_isolation_cases.json", import.meta.url), JSON.stringify({ better_auth: pkg.version, cases, records }) + "\n");
console.log(`${cases.length} isolation and ${records.length} multi-model transaction cases from Better Auth ${pkg.version}`);
