import { betterAuth, type BetterAuthOptions } from "better-auth";
import { createAuthMiddleware } from "better-auth/api";
import { openAPI } from "better-auth/plugins";
import { getMigrations } from "better-auth/db/migration";
import { Database } from "bun:sqlite";

/** Real application entities isolated from other profiles' physical schemas. */
export async function additionalFieldsFixture(base: BetterAuthOptions) {
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  const applications = new Map<string, { database: Database; events: Record<string, unknown>[] }>();
  for (const mode of ["normal", "output", "policy", "async-validation", "cached", "plugin"] as const) {
    const transformed = mode === "output" || mode === "cached";
    const database = new Database(":memory:");
    const events: Record<string, unknown>[] = [];
    const path = `/__test/profiles/${mode === "normal" ? "additional-fields" : `additional-${mode}-fields`}/api/auth`;
    const output = (entity: string, field: string) => async (value: unknown) => {
      events.push({ phase: "output", entity, field, value });
      await Promise.resolve();
      if (entity === "user" && field === "label" && value === "throw") throw new Error("application output failed");
      return field === "hidden" ? String(value).toUpperCase() : field === "omitted" ? undefined : { stored: value };
    };
    const after = (entity: "user" | "account" | "session", action: string) => async (record: Record<string, unknown>) => {
      const owner = entity === "user" ? record.id : record.userId;
      events.push({ phase: "after", entity, action, record,
        omittedPresent: Object.hasOwn(record, "omitted"), omittedUndefined: record.omitted === undefined,
        persisted: { users: database.query('SELECT COUNT(*) AS count FROM app_user WHERE id = ?').get(owner)!.count,
          accounts: database.query('SELECT COUNT(*) AS count FROM app_account WHERE userId = ?').get(owner)!.count,
          sessions: database.query('SELECT COUNT(*) AS count FROM app_session WHERE userId = ?').get(owner)!.count } });
    };
    const validateLabel = (value: unknown) => {
      events.push({ phase: "validation", entity: "user", field: "label", value });
      if (mode === "async-validation") return Promise.resolve({ value });
      return typeof value !== "string" || value === "reject" ? { issues: [{ message: "Label rejected" }] } : { value: value.trim() };
    };
    const bindLabel = async (value: unknown) => {
      events.push({ phase: "input", entity: "user", field: "label", value });
      await Promise.resolve();
      if (value === "explode") throw new Error("application input failed");
      return `bound:${value}`;
    };
    const fields = (entity: string) => ({
      label: { type: "string" as const, required: false, defaultValue: mode === "normal" ? () => { events.push({phase:"default",entity,field:"label"}); return `${entity}-initial`; } : `${entity}-initial`, ...(mode === "normal" ? {required:true} : {}), ...(mode === "cached" && entity === "session" ? {onUpdate:()=>{events.push({phase:"on-update",entity,field:"label"});return "session-updated";}} : {}), ...(entity === "user" ? { fieldName: "user_label" } : {}), ...(transformed ? { validator:{output:{"~standard":{version:1 as const,vendor:"application",validate:(value:unknown)=>{events.push({phase:"output-validation",entity,field:"label",value});throw new Error("Output validation must remain metadata");}}}}, transform: { output: output(entity, "label") } } : mode === "plugin" ? { transform: { output: async (value: unknown) => { events.push({phase:"configured-output",entity,field:"label",value}); return {configured:value}; } } } : {}) },
      hidden: { type: "string" as const, required: false, returned: false, defaultValue: `${entity}-secret`, ...(transformed ? { transform: { output: output(entity, "hidden") } } : {}) },
      omitted: { type: "string" as const, required: false, ...(transformed ? { defaultValue: "drop", transform: { output: output(entity, "omitted") } } : {}) },
      ...(entity === "user" ? { readonly: { type: "string" as const, required: false, ...(mode === "policy" ? { input: false } : {}), ...(transformed ? { input: false, defaultValue: "initial", onUpdate: () => "updated", transform: { input: (value: unknown) => { events.push({ phase: "input", entity, field: "readonly", value }); return `${value}:bound`; } } } : {}) } } : {}),
      ...((mode === "policy" || mode === "async-validation") && entity === "user" ? {
        label: { type: "string" as const, required: mode === "policy", fieldName: "user_label",
          validator: { input: { "~standard": { version: 1 as const, vendor: "application", validate: validateLabel } } },
          ...(mode === "policy" ? { transform: { input: bindLabel } } : {}) },
        hidden: { type: "string" as const, required: false, returned: false, input: false, defaultValue: "user-secret" },
      } : {}),
    });
    const auth = betterAuth({ ...base, database, basePath: path, plugins: [openAPI(), ...(mode === "plugin" ? [{ id:"application-fields", schema: {
        user: {fields:{label:{type:"string" as const,required:false,defaultValue:"plugin-user",returned:false},role:{type:"string" as const,required:false,input:false,defaultValue:"plugin-role",transform:{output:async (value:unknown)=>{events.push({phase:"plugin-output",entity:"user",field:"role",value});return `observed:${value}`;}}}}},
        session: {fields:{label:{type:"string" as const,required:false,defaultValue:"plugin-session",returned:false}}},
        account: {fields:{label:{type:"string" as const,required:false,defaultValue:"plugin-account",returned:false}}},
      } }] : [])],
      user: { ...base.user, modelName: "app_user", fields: { name: "display_name" }, additionalFields: fields("user") },
      session: { modelName: "app_session", additionalFields: fields("session"), ...(mode === "cached" ? { cookieCache: { enabled: true, version: async (session: Record<string, unknown>, user: Record<string, unknown>) => {
        events.push({ phase: "version", user, session, userOmittedPresent: Object.hasOwn(user,"omitted"), userOmittedUndefined: user.omitted === undefined, sessionOmittedPresent: Object.hasOwn(session,"omitted"), sessionOmittedUndefined: session.omitted === undefined });
        await Promise.resolve(); return `fields:${(user.label as {stored:string}).stored}:${(session.label as {stored:string}).stored}`;
      } } } : {}) },
      account: { ...base.account, modelName: "app_account", additionalFields: {...fields("account"),password:{type:"string",required:false,returned:true},accessToken:{type:"string",required:false,returned:true}} },
      verification: { modelName: "app_verification" },
      ...(mode === "cached" ? { hooks: { after: createAuthMiddleware(async ctx => {
        const record = ctx.context.newSession;
        events.push({ phase: "completed", path: ctx.path, record: record ?? null,
          userOmittedPresent: record ? Object.hasOwn(record.user,"omitted") : null, userOmittedUndefined: record ? record.user.omitted === undefined : null,
          sessionOmittedPresent: record ? Object.hasOwn(record.session,"omitted") : null, sessionOmittedUndefined: record ? record.session.omitted === undefined : null });
      }) } } : {}),
      ...(mode !== "normal" ? { databaseHooks: {
        user: { create: { after: after("user", "create") }, update: { after: after("user", "update") } },
        account: { create: { after: after("account", "create") }, update: { after: after("account", "update") } },
        session: { create: { after: after("session", "create") }, update: { after: after("session", "update") } },
      } } : {}),
    });
    await (await getMigrations(auth.options)).runMigrations();
    if (mode !== "plugin") database.run("ALTER TABLE app_user ADD COLUMN role TEXT");
    database.run("ALTER TABLE app_user ADD COLUMN private_column TEXT NOT NULL DEFAULT 'physical-private'");
    profiles.set(path, auth);
    applications.set(mode, { database, events });
  }
  return { profiles, reset() {
    for (const { database, events } of applications.values()) {
      events.length = 0;
      for (const table of ["app_session", "app_account", "app_verification", "app_user"]) database.run(`DELETE FROM ${table}`);
    }
  }, async handle(request: Request) {
    const url = new URL(request.url);
    if (url.pathname !== "/__test/additional-fields/state" && url.pathname !== "/__test/additional-fields/rewind-session") return null;
    const application = applications.get(url.searchParams.get("profile") ?? "normal");
    if (!application) return Response.json({ message: "Unknown application" }, { status: 404 });
    const { database, events } = application;
    if(url.pathname === "/__test/additional-fields/rewind-session") {
      const {token,expiresAt}=await request.json() as {token:string;expiresAt:string};
      if(request.method!=="POST" || typeof token!=="string" || !Number.isFinite(new Date(expiresAt).getTime())) return Response.json({message:"Invalid operator input"},{status:400});
      database.run("UPDATE app_session SET expiresAt=? WHERE token=?",[new Date(expiresAt).getTime(),token]);
    }
    const rows = (table: string) => database.query(`SELECT * FROM ${table}`).all().map(value => {
      const row = value as Record<string, unknown>;
      for (const field of ["createdAt", "updatedAt", "expiresAt", "accessTokenExpiresAt", "refreshTokenExpiresAt"]) if (row[field] !== null && row[field] !== undefined) row[field] = new Date(row[field] as string | number).toISOString();
      if (table === "app_user") { row.name = row.display_name; delete row.display_name; row.label = row.user_label; delete row.user_label; row.emailVerified = row.emailVerified === 1; }
      return row;
    });
    return Response.json({ users: rows("app_user"), sessions: rows("app_session"), accounts: rows("app_account"), verifications: rows("app_verification"), events });
  } };
}
