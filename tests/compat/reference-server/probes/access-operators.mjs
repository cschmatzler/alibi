import { Database } from "bun:sqlite";
import { readFileSync } from "node:fs";

// Run with Bun from the repository root. The published package owns decisions;
// SQLite records the effects of an application consuming its public role API.
import { createAccessControl, role } from "better-auth/plugins/access";

const fixture = JSON.parse(readFileSync("tests/fixtures/access/operators-1.7.6.json", "utf8"));
const db = new Database(":memory:");
db.exec("CREATE TABLE effects(name TEXT); CREATE TABLE grants(permission TEXT)");
db.query("INSERT INTO grants VALUES (?)").run(fixture.literal);
const permissionBefore = db.query("SELECT permission FROM grants").get().permission;
const statements = JSON.parse(permissionBefore);
const teamCountBefore = db.query("SELECT COUNT(*) AS count FROM effects").get().count;
const ac = createAccessControl({ team: ["create", "delete"] });
const custom = ac.newRole(statements);
const direct = role(statements);
for (const entry of fixture.cases) {
  const request = entry.insertionOrder
    ? Object.fromEntries(entry.insertionOrder.map((name) => [name, entry.request[name]]))
    : entry.request;
  const result = custom.authorize(request, entry.connector);
  const same = direct.authorize(request, entry.connector);
  if (JSON.stringify(result) !== JSON.stringify(same)) throw new Error("constructor mismatch");
  if (result.success) db.query("INSERT INTO effects VALUES (?)").run(entry.name);
  entry.expected = result;
}
fixture.effects = db
  .query("SELECT name FROM effects ORDER BY rowid")
  .all()
  .map((row) => row.name);
if (db.query("SELECT permission FROM grants").get().permission !== fixture.literal) {
  throw new Error("authorization changed literal grants");
}
fixture.physical = {
  permissionBefore,
  permissionAfter: db.query("SELECT permission FROM grants").get().permission,
  teamCountBefore,
  teamCountAfter: db.query("SELECT COUNT(*) AS count FROM effects").get().count,
};
console.log(JSON.stringify(fixture, null, 2));
db.close();
