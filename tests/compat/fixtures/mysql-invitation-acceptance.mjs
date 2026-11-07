import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { betterAuth } from "../reference-server/node_modules/better-auth/dist/index.mjs";
import { getMigrations } from "../reference-server/node_modules/better-auth/dist/db/get-migration.mjs";
import { organization } from "../reference-server/node_modules/better-auth/dist/plugins/index.mjs";
import { config } from "../reference-server/probes/schema-parity.mjs";
import { createMysqlDatabase } from "./support/mysql-database.mjs";

const database = await createMysqlDatabase({ connectionLimit: 4 });
const origin = "http://localhost";
const cases = [];
try {
  await (await getMigrations({ ...config, database: { type: "mysql", db: database.db } })).runMigrations();
  const auth = betterAuth({ baseURL: origin, secret: "mysql-invitation-secret-at-least-32-characters", database: { type: "mysql", db: database.db },
    emailAndPassword: { enabled: true }, rateLimit: { enabled: false }, logger: { disabled: true }, plugins: [organization()],
  });
  async function call(jar, path, input) {
    const response = await auth.handler(new Request(`${origin}/api/auth${path}`, { method: "POST", headers: { origin, "content-type": "application/json", cookie: [...jar].map(([name, value]) => `${name}=${value}`).join("; ") }, body: JSON.stringify(input) }));
    for (const cookie of response.headers.getSetCookie()) {
      const [pair] = cookie.split(";");
      const index = pair.indexOf("=");
      const name = pair.slice(0, index), value = pair.slice(index + 1);
      if (value) jar.set(name, value); else jar.delete(name);
    }
    const text = await response.text();
    return { status: response.status, output: text ? JSON.parse(text) : null };
  }
  const ownerJar = new Map(), guestJar = new Map();
  for (const [jar, email] of [[ownerJar, "mysql-owner@example.com"], [guestJar, "mysql-guest@example.com"]]) {
    const response = await call(jar, "/sign-up/email", { name: "Owner", email, password: "Password123!" });
    assert.equal(response.status, 200);
  }
  const empty = await call(ownerJar, "/organization/create", { name: "Empty metadata", slug: "mysql-empty" });
  assert.equal(empty.status, 200);
  const [emptyRows] = await database.pool.promise().query("SELECT metadata FROM organization WHERE id = ?", [empty.output.id]);
  assert.equal(emptyRows[0].metadata, null);
  const org = await call(ownerJar, "/organization/create", { name: "MySQL organization", slug: "mysql-invitations", metadata: { clock: "2025-02-03T04:05:06Z", project: "invitations", revisions: [1, 2] } });
  assert.equal(org.status, 200);
  const organizationId = org.output.id;
  assert.deepEqual(org.output.metadata, { clock: "2025-02-03T04:05:06Z", project: "invitations", revisions: [1, 2] });
  const updated = await call(ownerJar, "/organization/update", { organizationId, data: { metadata: { clock: "2025-02-03T04:05:06Z", project: "updated", revisions: [3] } } });
  assert.equal(updated.status, 200);
  assert.deepEqual(updated.output.metadata, { clock: "2025-02-03T04:05:06.000Z", project: "updated", revisions: [3] });
  const [metadataRows] = await database.pool.promise().query("SELECT metadata FROM organization WHERE id = ?", [organizationId]);
  const metadata = { omitted: emptyRows[0].metadata, created: org.output.metadata, updated: updated.output.metadata, stored: metadataRows[0].metadata };
  const invited = await call(ownerJar, "/organization/invite-member", { email: "mysql-guest@example.com", role: "member", organizationId });
  assert.equal(invited.status, 200);
  const invitationId = invited.output.id;
  for (const action of ["fail-membership", "retry", "replay"]) {
    if (action === "fail-membership") await database.pool.promise().query("ALTER TABLE member ADD CONSTRAINT reject_guest_member CHECK (role <> 'member')");
    const response = await call(guestJar, "/organization/accept-invitation", { invitationId });
    assert.equal(response.status, action === "fail-membership" ? 500 : action === "replay" ? 400 : 200, `${action}: ${JSON.stringify(response.output)}`);
    if (action === "fail-membership") {
      await assert.rejects(auth.api.acceptInvitation({ body: { invitationId }, headers: new Headers({ cookie: [...guestJar].map(([name, value]) => `${name}=${value}`).join("; ") }) }),
        error => error.code === "ER_CHECK_CONSTRAINT_VIOLATED");
      await database.pool.promise().query("ALTER TABLE member DROP CHECK reject_guest_member");
    }
    const [invitations] = await database.pool.promise().query("SELECT status FROM invitation WHERE id = ?", [invitationId]);
    const [members] = await database.pool.promise().query("SELECT role FROM member WHERE organizationId = ? ORDER BY role", [organizationId]);
    const [sessions] = await database.pool.promise().query("SELECT activeOrganizationId FROM session WHERE userId = (SELECT id FROM user WHERE email = ?)", ["mysql-guest@example.com"]);
    assert.equal(invitations.length, 1);
    assert.equal(sessions.length, 1);
    const output = action === "retry" ? { invitation: { status: response.output.invitation.status, email: response.output.invitation.email, role: response.output.invitation.role }, member: { role: response.output.member.role } } : response.output;
    cases.push({ action, status: response.status, output, sql_failure: action === "fail-membership", invitation_status: invitations[0].status, roles: members.map(row => row.role), active_organization: sessions[0].activeOrganizationId === organizationId });
  }
  assert.equal(cases[0].invitation_status, "pending");
  assert.deepEqual(cases[0].roles, ["owner"]);
  assert.equal(cases[1].invitation_status, "accepted");
  assert.deepEqual(cases[1].roles, ["member", "owner"]);
  const { adapter } = await auth.$context;
  const claims = await Promise.all(Array.from({ length: 8 }, () => adapter.incrementOne({ model: "invitation",
    where: [{ field: "id", value: invitationId }, { field: "status", value: "accepted" }], increment: {}, set: { status: "canceled" },
  })));
  const winners = claims.filter(Boolean);
  assert.equal(winners.length, 1);
  assert.equal(winners[0].status, "canceled");
  const [stored] = await database.pool.promise().query("SELECT status FROM invitation WHERE id = ?", [invitationId]);
  const concurrent = { calls: claims.length, winners: winners.length, status: stored[0].status };
  await writeFile(new URL("../../fixtures/mysql-invitation-acceptance.json", import.meta.url), JSON.stringify({ better_auth: "1.7.18", metadata, cases, concurrent }) + "\n");
  console.log(`${cases.length} actual MySQL invitation HTTP cases and eight guarded status claims`);
} finally {
  await database.close();
}
