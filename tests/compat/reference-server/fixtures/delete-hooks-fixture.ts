import { Database } from "bun:sqlite";

import { betterAuth, type BetterAuthOptions } from "better-auth";
export function deleteHooksFixture(base: BetterAuthOptions) {
  const db = base.database as Database;
  db.exec("CREATE TABLE IF NOT EXISTS application_delete_receipts (model TEXT, row_id TEXT)");
  let model = "",
    mode = "";
  const events: unknown[] = [];
  const hooks = Object.fromEntries(
    ["user", "account", "session"].map((owner) => [
      owner,
      {
        delete: {
          async before(row: any) {
            if (model !== owner) return;
            events.push({ model: owner, phase: "before", rowId: row.id });
            if (mode === "cancel") return false;
            if (mode === "before-error") throw new Error("Application delete before rejected");
            if (mode === "data") return { data: { ...row, id: "application-replacement-id" } };
          },
          async after(row: any) {
            if (model !== owner) return;
            events.push({ model: owner, phase: "after", rowId: row.id });
            db.query("INSERT INTO application_delete_receipts (model,row_id) VALUES (?,?)").run(
              owner,
              row.id,
            );
            if (mode === "after-error") throw new Error("Application delete after rejected");
          },
        },
      },
    ]),
  );
  const auth = betterAuth({
    ...base,
    basePath: "/__test/profiles/delete-hooks/api/auth",
    databaseHooks: hooks,
    plugins: (base.plugins ?? []).filter((plugin) => ["admin", "username"].includes(plugin.id)),
  });
  return {
    async handle(request: Request) {
      const path = new URL(request.url).pathname;
      if (path.startsWith("/__test/profiles/delete-hooks/api/auth/")) return auth.handler(request);
      if (path === "/__test/delete-hooks/control") {
        if (request.method === "POST") {
          const input = await request.json();
          model = input.model;
          mode = input.mode;
          events.length = 0;
          db.exec("DELETE FROM application_delete_receipts");
        }
        return Response.json({
          events,
          receipts: db
            .query("SELECT model, row_id AS rowId FROM application_delete_receipts")
            .all(),
        });
      }
      return null;
    },
  };
}
