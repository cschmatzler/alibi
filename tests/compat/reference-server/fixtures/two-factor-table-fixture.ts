import { Database } from "bun:sqlite";

import { betterAuth, type BetterAuthOptions } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { twoFactor } from "better-auth/plugins";
export async function twoFactorTableFixture(base: BetterAuthOptions) {
  const db = new Database(":memory:");
  const deliveries = new Map<string, string>();
  // The pinned plugin mutates its shared schema when applying mappings.
  // Snapshot this application's schema and restore the module defaults before
  // any other profile lazily initializes its adapter.
  const sharedSchema = twoFactor().schema!;
  const defaultSchema = structuredClone(sharedSchema);
  const customPlugin = twoFactor({
    twoFactorTable: "application_second_factor",
    schema: {
      twoFactor: {
        fields: {
          secret: "application_secret",
          backupCodes: "application_backups",
          userId: "application_owner",
        },
      },
    },
    otpOptions: {
      async sendOTP({ user, otp }) {
        deliveries.set(user.email, otp);
      },
    },
  });
  customPlugin.schema = structuredClone(customPlugin.schema);
  for (const [name, table] of Object.entries(sharedSchema)) {
    const saved = (defaultSchema as any)[name];
    if (saved.modelName === undefined) delete (table as any).modelName;
    else (table as any).modelName = saved.modelName;
    for (const [field, definition] of Object.entries(table.fields)) {
      const original = saved.fields[field];
      if (original.fieldName === undefined) delete definition.fieldName;
      else definition.fieldName = original.fieldName;
    }
  }
  const options: BetterAuthOptions = {
    ...base,
    database: db,
    basePath: "/__test/profiles/two-factor-custom-table/api/auth",
    plugins: [customPlugin],
  };
  await (await getMigrations(options)).runMigrations();
  const auth = betterAuth(options);
  return {
    async handle(request: Request) {
      const url = new URL(request.url);
      if (url.pathname.startsWith("/__test/profiles/two-factor-custom-table/api/auth/")) {
        return auth.handler(request);
      }
      if (url.pathname === "/__test/two-factor-custom-table/otp") {
        return Response.json({ otp: deliveries.get(url.searchParams.get("email")!) });
      }
      if (url.pathname === "/__test/two-factor-custom-table/state") {
        const tables = db.query("SELECT name FROM sqlite_master WHERE type='table'").all() as {
          name: string;
        }[];
        const rows = db
          .query(
            "SELECT id, application_owner AS userId, application_secret AS secret, application_backups AS backups FROM application_second_factor WHERE application_owner = ?",
          )
          .all(url.searchParams.get("userId")) as any[];
        return Response.json({
          customTableExists: tables.some((t) => t.name === "application_second_factor"),
          defaultTableExists: tables.some((t) => t.name === "twoFactor"),
          rows: rows.map((row) => ({
            id: row.id,
            userId: row.userId,
            secretPresent: typeof row.secret === "string" && row.secret.length > 0,
            backupPresent: typeof row.backups === "string" && row.backups.length > 0,
          })),
        });
      }
      return null;
    },
  };
}
