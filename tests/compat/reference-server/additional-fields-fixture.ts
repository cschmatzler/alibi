import { betterAuth, type BetterAuthOptions } from "better-auth";
import { APIError } from "better-auth/api";
import { tryGetCurrentAuthEndpointContext } from "@better-auth/core/context";
import { createAuthMiddleware } from "better-auth/api";
import { magicLink, openAPI } from "better-auth/plugins";
import { getMigrations } from "better-auth/db/migration";
import { Database } from "bun:sqlite";

/** Real application entities isolated from other profiles' physical schemas. */
export async function additionalFieldsFixture(base: BetterAuthOptions) {
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  const mapperReceipts: unknown[] = [];
  const applications = new Map<string, { database: Database; events: Record<string, unknown>[] }>();
  for (const mode of ["normal", "output", "policy", "async-validation", "cached", "plugin", "provider", "issuer"] as const) {
    const transformed = mode === "output" || mode === "cached" || mode === "provider" || mode === "issuer";
    const database = new Database(":memory:");
    const events: Record<string, unknown>[] = [];
    const path = `/__test/profiles/${mode === "normal" ? "additional-fields" : `additional-${mode}-fields`}/api/auth`;
    const output = (entity: string, field: string) => async (value: unknown) => {
      events.push({ phase: "output", entity, field, value });
      await Promise.resolve();
      if(entity === "session" && field === "label" && value === "collection-slow"){await new Promise(resolve=>setTimeout(resolve,200));events.push({phase:"settled",entity,field,value,requestScoped:tryGetCurrentAuthEndpointContext()?.path==="/change-password"});}
      if (field === "label" && (value === "throw" || value === "collection-reject")) throw new Error("application output failed");
      return field === "hidden" ? String(value).toUpperCase() : field === "omitted" ? undefined : { stored: value };
    };
    const after = (entity: "user" | "account" | "session", action: string) => async (record: Record<string, unknown>) => {
      if(!record){events.push({phase:"after",entity,action,record:null});return;}
      const owner = entity === "user" ? record.id : record.userId;
      if(mode === "cached" && entity === "session" && action === "update" && (record.label as {stored?:string})?.stored === "after-error") throw new Error("application after failed");
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
      ...(mode === "provider" && entity === "user" ? {hidden:{type:"string" as const,required:false,returned:false,input:false,defaultValue:"user-secret",transform:{output:output(entity,"hidden")}}} : {}),
      ...(mode === "async-validation" && entity === "session" ? {label:{type:"string" as const,required:false,defaultValue:"session-initial",validator:{input:{"~standard":{version:1 as const,vendor:"application",validate:(value:unknown)=>{events.push({phase:"validation",entity:"session",field:"label",value:typeof value === "number" && value===0 ? 0 : value,negativeZero:Object.is(value,-0),infinite:typeof value === "number" && !Number.isFinite(value)});return Promise.resolve({value});}}}}}} : {}),
      ...(entity === "user" ? { readonly: { type: "string" as const, required: false, ...(mode === "policy" ? { input: false } : {}), ...(transformed ? { input: false, defaultValue: "initial", onUpdate: () => "updated", transform: { input: (value: unknown) => { events.push({ phase: "input", entity, field: "readonly", value }); return `${value}:bound`; } } } : {}) } } : {}),
      ...((mode === "policy" || mode === "async-validation") && entity === "user" ? {
        label: { type: "string" as const, required: mode === "policy", fieldName: "user_label",
          validator: { input: { "~standard": { version: 1 as const, vendor: "application", validate: validateLabel } } },
          ...(mode === "policy" ? { transform: { input: bindLabel } } : {}) },
        hidden: { type: "string" as const, required: false, returned: false, input: false, defaultValue: "user-secret" },
      } : {}),
    });
    const auth = betterAuth({ ...base, database, basePath: path, plugins: [openAPI(), ...(mode === "issuer" ? [magicLink({sendMagicLink:async delivery=>{events.push({phase:"delivery",delivery:{...delivery,metadata:delivery.metadata??null},metadataPresent:delivery.metadata!==undefined});}})] : []), ...(mode === "plugin" ? [{ id:"application-fields", schema: {
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
      ...(mode === "provider" ? {socialProviders:{atlassian:{clientId:"fixture-social-client",clientSecret:"fixture-social-secret",overrideUserInfoOnSignIn:true,mapProfileToUser:(profile:Record<string,unknown>)=>{mapperReceipts.push(profile);return {id:"mapped-public-id-184",email:profile.email as string,name:`Mapped ${profile.name}`,image:profile.picture as string,emailVerified:true,label:profile.nickname,hidden:"provider-cannot-set-hidden",unknown:"provider-unknown"};}}}} : {}),
      ...(mode === "cached" ? { hooks: { after: createAuthMiddleware(async ctx => {
        const record = ctx.context.newSession;
        events.push({ phase: "completed", path: ctx.path, record: record ?? null,
          userOmittedPresent: record ? Object.hasOwn(record.user,"omitted") : null, userOmittedUndefined: record ? record.user.omitted === undefined : null,
          sessionOmittedPresent: record ? Object.hasOwn(record.session,"omitted") : null, sessionOmittedUndefined: record ? record.session.omitted === undefined : null });
      }) } } : {}),
      ...(mode !== "normal" ? { databaseHooks: {
        user: { create: { after: after("user", "create") }, update: { after: after("user", "update") } },
        account: { create: { after: after("account", "create") }, update: { after: after("account", "update") } },
        session: { create: { after: after("session", "create") }, update: { ...(mode === "cached" ? {before:async (data:Record<string,unknown>,ctx:{context:{session?:{session:{token:string}}}}|null)=>{
          events.push({phase:"before",entity:"session",fields:Object.fromEntries(Object.entries(data).filter(([key])=>!["updatedAt","expiresAt"].includes(key)))});
          const token=ctx?.context.session?.session.token;
          const stored=database.query("SELECT hidden FROM app_session WHERE token=?").get(token??"") as {hidden:string}|null;
          const command=data.hidden??(!Object.hasOwn(data,"label")?stored?.hidden:undefined);
          if(command==="cancel")return false;
          if(command==="ordinary-error")throw new Error("application before failed");
          if(command==="api-error")throw new APIError("FORBIDDEN",{code:"APP_DENIED",message:"Application denied"});
          if(command==="delete")database.query("DELETE FROM app_session WHERE token=?").run(token??"");
          if(command==="after-error"||command==="throw")return {data:{...data,label:command}};
          if(command==="mutate")return {data:{...data,label:"hook-updated"}};
          return {data};
        }} : {}), after: after("session", "update") } },
      } } : {}),
    });
    await (await getMigrations(auth.options)).runMigrations();
    if (mode !== "plugin") database.run("ALTER TABLE app_user ADD COLUMN role TEXT");
    database.run("ALTER TABLE app_user ADD COLUMN private_column TEXT NOT NULL DEFAULT 'physical-private'");
    profiles.set(path, auth);
    applications.set(mode, { database, events });
  }
  return { profiles, reset() {
    mapperReceipts.length=0;
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
      const {token,expiresAt,hidden,label}=await request.json() as {token:string;expiresAt:string;hidden?:string;label?:string};
      if(request.method!=="POST" || typeof token!=="string" || !Number.isFinite(new Date(expiresAt).getTime())) return Response.json({message:"Invalid operator input"},{status:400});
      database.run("UPDATE app_session SET expiresAt=? WHERE token=?",[new Date(expiresAt).toISOString(),token]);
      if(label!==undefined)database.run("UPDATE app_session SET label=? WHERE token=?",[label,token]);
      if(hidden!==undefined)database.run("UPDATE app_session SET hidden=? WHERE token=?",[hidden,token]);
    }
    const rows = (table: string) => database.query(`SELECT * FROM ${table}`).all().map(value => {
      const row = value as Record<string, unknown>;
      for (const field of ["createdAt", "updatedAt", "expiresAt", "accessTokenExpiresAt", "refreshTokenExpiresAt"]) if (row[field] !== null && row[field] !== undefined) row[field] = new Date(row[field] as string | number).toISOString();
      if (table === "app_user") { row.name = row.display_name; delete row.display_name; row.label = row.user_label; delete row.user_label; row.emailVerified = row.emailVerified === 1; }
      return row;
    });
    return Response.json({ users: rows("app_user"), sessions: rows("app_session"), accounts: rows("app_account"), verifications: rows("app_verification"), events, ...(url.searchParams.get("profile")==="provider" ? {mapperReceipts} : {}) });
  } };
}
