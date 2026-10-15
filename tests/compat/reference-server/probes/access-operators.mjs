import { readFileSync } from "node:fs";

// Run with Nub from the repository root. The published package owns decisions;
// SQLite records the effects of an application consuming its public role API.
import { createAccessControl, role } from "better-auth/plugins/access";

import { createDatabase } from "../sqlite.ts";

const fixture = JSON.parse(readFileSync("tests/fixtures/access/operators-1.7.6.json", "utf8"));
const db = createDatabase(":memory:");
db.exec("CREATE TABLE effects(name TEXT); CREATE TABLE grants(permission TEXT)");
db.prepare("INSERT INTO grants VALUES (?)").run(fixture.literal);
const permissionBefore = db.prepare("SELECT permission FROM grants").get().permission;
const statements = JSON.parse(permissionBefore);
const teamCountBefore = db.prepare("SELECT COUNT(*) AS count FROM effects").get().count;
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
  if (result.success) db.prepare("INSERT INTO effects VALUES (?)").run(entry.name);
  entry.expected = result;
}
fixture.effects = db
  .prepare("SELECT name FROM effects ORDER BY rowid")
  .all()
  .map((row) => row.name);
if (db.prepare("SELECT permission FROM grants").get().permission !== fixture.literal) {
  throw new Error("authorization changed literal grants");
}
fixture.physical = {
  permissionBefore,
  permissionAfter: db.prepare("SELECT permission FROM grants").get().permission,
  teamCountBefore,
  teamCountAfter: db.prepare("SELECT COUNT(*) AS count FROM effects").get().count,
};
console.log(JSON.stringify(fixture, null, 2));
db.close();
