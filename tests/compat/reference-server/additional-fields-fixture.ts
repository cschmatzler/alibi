import { betterAuth, type BetterAuthOptions } from "better-auth";
import { openAPI } from "better-auth/plugins";
import { getMigrations } from "better-auth/db/migration";
import { Database } from "bun:sqlite";

/** Real application entities isolated from other profiles' physical schemas. */
export async function additionalFieldsFixture(base: BetterAuthOptions) {
  const database = new Database(":memory:");
  const path = "/__test/profiles/additional-fields/api/auth";
  const auth = betterAuth({ ...base, database, basePath: path, plugins: [openAPI()],
    user: { modelName: "app_user", fields: { name: "display_name" }, additionalFields: {
      label: { type: "string", required: false, defaultValue: "user-initial", fieldName: "user_label" },
      hidden: { type: "string", required: false, returned: false, defaultValue: "user-secret" },
    } },
    session: { modelName: "app_session", additionalFields: {
      label: { type: "string", required: false, defaultValue: "session-initial" },
      hidden: { type: "string", required: false, returned: false, defaultValue: "session-secret" },
    } },
    account: { ...base.account, modelName: "app_account", additionalFields: {
      label: { type: "string", required: false, defaultValue: "account-initial" },
      hidden: { type: "string", required: false, returned: false, defaultValue: "account-secret" },
    } }, verification: { modelName: "app_verification" },
  });
  await (await getMigrations(auth.options)).runMigrations();
  database.run("ALTER TABLE app_user ADD COLUMN private_column TEXT NOT NULL DEFAULT 'physical-private'");
  return { profiles: new Map([[path, auth]]), reset() {
    for (const table of ["app_session", "app_account", "app_verification", "app_user"]) database.run(`DELETE FROM ${table}`);
  }, handle(request: Request) {
    if (new URL(request.url).pathname !== "/__test/additional-fields/state") return null;
    const rows = (table: string) => database.query(`SELECT * FROM ${table} ORDER BY id`).all().map(value => {
      const row = value as Record<string, unknown>;
      for (const field of ["createdAt", "updatedAt", "expiresAt", "accessTokenExpiresAt", "refreshTokenExpiresAt"]) if (row[field] !== null && row[field] !== undefined) row[field] = new Date(row[field] as string | number).toISOString();
      if (table === "app_user") { row.name = row.display_name; delete row.display_name; row.label = row.user_label; delete row.user_label; row.emailVerified = row.emailVerified === 1; }
      return row;
    });
    return Response.json({ users: rows("app_user"), sessions: rows("app_session"), accounts: rows("app_account"), verifications: rows("app_verification") });
  } };
}
