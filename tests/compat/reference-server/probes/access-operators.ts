// Run with Bun from the repository root. The published package owns decisions;
// SQLite records the effects of an application consuming its public role API.
import { createAccessControl, role } from "better-auth/plugins/access";
import { Database } from "bun:sqlite";
import { readFileSync } from "node:fs";

const fixture = JSON.parse(readFileSync("tests/fixtures/access/operators-1.7.6.json", "utf8"));
const db = new Database(":memory:");
db.exec("CREATE TABLE effects(name TEXT); CREATE TABLE grants(permission TEXT)");
db.query("INSERT INTO grants VALUES (?)").run(fixture.literal);
const statements = JSON.parse(db.query("SELECT permission FROM grants").get().permission);
const ac = createAccessControl({ team: ["create", "delete"] });
const custom = ac.newRole(statements);
const direct = role(statements);
for (const entry of fixture.cases) {
  const result = custom.authorize(entry.request, entry.connector);
  const same = direct.authorize(entry.request, entry.connector);
  if (JSON.stringify(result) !== JSON.stringify(same)) throw new Error("constructor mismatch");
  if (result.success) db.query("INSERT INTO effects VALUES (?)").run(entry.name);
  entry.expected = result;
}
fixture.effects = db.query("SELECT name FROM effects ORDER BY rowid").all().map(row => row.name);
if (db.query("SELECT permission FROM grants").get().permission !== fixture.literal) {
  throw new Error("authorization changed literal grants");
}
console.log(JSON.stringify(fixture, null, 2));
db.close();
