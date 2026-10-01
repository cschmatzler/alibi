/** Application-owned SQLite keys reached by the actual published JWT plugin. */
import { Database } from "bun:sqlite";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { APIError } from "better-auth/api";
import { jwt, signJWT, createJwk, resolveSigningKey } from "better-auth/plugins/jwt";

type StoredKey = {
  rowId: number; profile: string; id: string; publicKey: string; privateKey: string;
  createdAt: number; expiresAt: number | null; alg: string | null; crv: string | null;
};
type Race = {
  first: Promise<void>; firstDone: () => void;
  both: Promise<void>; bothDone: () => void; entered: number;
  second: Promise<void>; secondDone: () => void;
};
function deferred() {
  let done!: () => void;
  const promise = new Promise<void>(resolve => { done = resolve; });
  return {promise, done};
}
// The application encodes its numeric cache clock losslessly for its JWT
// snapshot. The tag retains the callback input type as well as its full value.
function snapshot(session: any) {
  if (!Object.hasOwn(session,"updatedAt")) return session;
  const value=session.updatedAt;
  const date=new Date(value);
  if (typeof value!=="number" || !Number.isSafeInteger(value) || date.getTime()!==value) throw new Error("invalid cache clock");
  return {...session,updatedAt:date.toISOString(),updatedAtType:"number"};
}
async function bounded(promise: Promise<void>) {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { await Promise.race([promise, new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error("application keyring scheduling timeout")), 10000); })]); }
  finally { clearTimeout(timer); }
}
export function createJwtKeyringFixture(base: BetterAuthOptions, database: Database) {
  database.exec(`CREATE TABLE IF NOT EXISTS fixtureJwtKeyring (
    rowId INTEGER PRIMARY KEY AUTOINCREMENT, profile TEXT NOT NULL, id TEXT,
    publicKey TEXT NOT NULL, privateKey TEXT NOT NULL, createdAt INTEGER NOT NULL,
    expiresAt INTEGER, alg TEXT, crv TEXT)`);
  const events: unknown[] = [];
  let failure: {operation: string; kind: string} | null = null;
  let race: Race | null = null;
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  const configurations = new Map<string, any>();
  function rows(profile: string) {
    return database.query<StoredKey, [string]>("SELECT * FROM fixtureJwtKeyring WHERE profile=? ORDER BY rowId").all(profile);
  }
  function key(row: StoredKey) {
    return {
      id: row.id, publicKey: row.publicKey, privateKey: row.privateKey,
      createdAt: new Date(row.createdAt),
      ...(row.expiresAt === null ? {} : {expiresAt:new Date(row.expiresAt)}),
      ...(row.alg === null ? {} : {alg:row.alg}), ...(row.crv === null ? {} : {crv:row.crv}),
    };
  }
  function observed(row: StoredKey) {
    let publicKey: unknown, encrypted = false;
    try { publicKey = JSON.parse(row.publicKey); } catch { publicKey = row.publicKey; }
    try { encrypted = typeof JSON.parse(row.privateKey) === "string"; } catch {}
    return {id:row.id,publicKey,privateKeyEncrypted:encrypted,createdAt:new Date(row.createdAt),expiresAt:row.expiresAt===null?null:new Date(row.expiresAt),alg:row.alg,crv:row.crv};
  }
  function context(ctx: any) {
    return {path:ctx.path??null,method:ctx.request?.method??null,marker:ctx.headers?.get("x-keyring-proof")??null,hasCookie:!!ctx.headers?.get("cookie")};
  }
  function reject(operation: string) {
    if (failure?.operation !== operation) return;
    if (failure.kind === "api") throw new APIError("FORBIDDEN", {code:"APPLICATION_KEYRING_DENIED",message:"application denied keys"});
    if (failure.kind === "api500") throw new APIError("INTERNAL_SERVER_ERROR", {code:"APPLICATION_KEYRING_DENIED",message:"application denied keys"});
    throw new Error("application keyring failed");
  }
  for (const mode of ["standard","plain","cache","custom-cache","empty-subject","null-subject"] as const) {
    const name = `jwt-keyring-${mode}`;
    const adapter = {
      getJwks: async (ctx: any) => {
        const marker = ctx.headers?.get("x-keyring-proof");
        const scheduled = race;
        if (scheduled && marker === "race-second") await bounded(scheduled.first);
        const result = rows(name).map(key);
        events.push({operation:"read",profile:name,context:context(ctx),ids:result.map(key=>key.id)});
        reject("read");
        if (scheduled && result.length === 0 && (marker === "race-first" || marker === "race-second")) {
          if (marker === "race-first") scheduled.firstDone();
          if (++scheduled.entered === 2) scheduled.bothDone();
          await bounded(scheduled.both);
        }
        return result;
      },
      createJwk: async (data: any, ctx: any) => {
        const scheduled = race;
        if (scheduled && ctx.headers?.get("x-keyring-proof") === "race-second") await bounded(scheduled.second);
        events.push({operation:"create",profile:name,context:context(ctx),key:{publicKey:JSON.parse(data.publicKey),privateKeyEncrypted:typeof JSON.parse(data.privateKey)==="string",createdAt:data.createdAt,expiresAt:data.expiresAt??null,alg:data.alg??null,crv:data.crv??null}});
        reject("create");
        const inserted = database.query("INSERT INTO fixtureJwtKeyring(profile,publicKey,privateKey,createdAt,expiresAt,alg,crv) VALUES(?,?,?,?,?,?,?)")
          .run(name,data.publicKey,data.privateKey,data.createdAt.getTime(),data.expiresAt?.getTime()??null,data.alg??null,data.crv??null);
        const id = `application-key-${inserted.lastInsertRowid}`;
        database.query("UPDATE fixtureJwtKeyring SET id=? WHERE rowId=?").run(id,inserted.lastInsertRowid);
        return key(rows(name).find(row=>row.id===id)!);
      },
    };
    const options = {
      adapter,
      jwks: {
        keyPairConfig: mode === "plain" ? {alg:"RS256",modulusLength:3072} : {alg:"EdDSA",crv:"Ed25519"},
        keyPairConfigs:[{alg:"ES256"}],
        ...(mode === "plain" ? {disablePrivateKeyEncryption:true,rotationInterval:3600,gracePeriod:3600} : {}),
      },
      jwt: mode === "cache" ? {} : {
        definePayload: async (session: any) => {
          const input=snapshot(session);
          events.push({operation:"payload",profile:name,session:input});
          reject("payload");
          return {iat:100,exp:4102444800,application:"external-keyring",snapshot:input};
        },
        getSubject: async (session: any) => {
          events.push({operation:"subject",profile:name,session:snapshot(session)});
          reject("subject");
          return mode === "empty-subject" ? "" : mode === "null-subject" ? null : mode === "custom-cache" ? `${session.user.email}|version:${session.version??"absent"}|clock:${typeof session.updatedAt}` : session.user.email;
        },
      },
    };
    configurations.set(name,options);
    profiles.set(name,betterAuth({...base,basePath:`/__test/profiles/${name}/api/auth`,
      ...(mode === "cache" || mode === "custom-cache" ? {session:{cookieCache:{enabled:true,strategy:"compact",maxAge:300}}} : {}),
      plugins:[...base.plugins!.filter(plugin=>plugin.id==="username"),jwt(options as any)],
    }));
  }
  return {profiles,async handle(request: Request) {
    if (new URL(request.url).pathname !== "/__test/jwt-keyring") return null;
    const body = await request.json() as any;
    const profile = body.profile ?? "jwt-keyring-standard";
    const auth = profiles.get(profile);
    const options = configurations.get(profile);
    if (!auth) return Response.json({message:"unknown keyring profile"},{status:400});
    if (body.operation === "reset") {
      database.query("DELETE FROM fixtureJwtKeyring").run();
      database.query("DELETE FROM sqlite_sequence WHERE name='fixtureJwtKeyring'").run();
      events.length=0;failure=null;race=null;
    } else if (body.operation === "clear-events") events.length=0;
    else if (body.operation === "failure") failure=body.failure??null;
    else if (body.operation === "race-arm") {
      const first=deferred(),both=deferred(),second=deferred();
      race={first:first.promise,firstDone:first.done,both:both.promise,bothDone:both.done,entered:0,second:second.promise,secondDone:second.done};
      return Response.json({armed:true});
    } else if (body.operation === "race-release") { race?.secondDone();return Response.json({released:true}); }
    else if (body.operation === "expire") database.query("UPDATE fixtureJwtKeyring SET expiresAt=? WHERE profile=? AND id=?").run(Date.parse(body.expiresAt),profile,body.id);
    else if (body.operation === "corrupt") {
      const column = body.field === "public" ? "publicKey" : "privateKey";
      database.query(`UPDATE fixtureJwtKeyring SET ${column}=? WHERE profile=? AND id=?`).run(body.field==="public"?"corrupt":"\"corrupt\"",profile,body.id);
    } else if (body.operation === "legacy") database.query("UPDATE fixtureJwtKeyring SET alg=NULL,crv=NULL WHERE profile=? AND id=?").run(profile,body.id);
    else if (body.operation === "delete") database.query("DELETE FROM fixtureJwtKeyring WHERE profile=? AND id=?").run(profile,body.id);
    else if (["sign","resolve-sign","create","verify","api-sign"].includes(body.operation)) {
      try {
        const transport=body.absentRequest?{}:{request,headers:request.headers};
        if (body.operation === "api-sign") {
          const signed=await auth.api.signJWT({...transport,body:{payload:body.payload}});
          return Response.json(signed instanceof Response ? await signed.json() : signed);
        }
        if (body.operation === "verify") {
          const verified=await auth.api.verifyJWT({...transport,body:{token:body.token,...(body.issuer!==undefined?{issuer:body.issuer}:{})}});
          return Response.json(verified instanceof Response ? await verified.json() : verified);
        }
        let configured = options;
        if (body.expiration) {
          const expiration = body.expiration.nan ? NaN : body.expiration.nonfinite === "positive" ? Infinity : body.expiration.nonfinite === "negative" ? -Infinity : body.expiration.date ? new Date(body.expiration.date) : body.expiration.source ?? body.expiration.number;
          configured={...options,jwt:{...options.jwt,expirationTime:expiration}};
        }
        const ctx = {context:await auth.$context,path:"/__test/jwt-keyring",request,headers:request.headers} as any;
        if (body.operation === "create") { await createJwk(ctx,configured);return Response.json({created:true}); }
        const overrides={signingKeyId:body.signingKeyId,signingAlgorithm:body.signingAlgorithm};
        const resolvedKey = body.operation === "resolve-sign" ? await resolveSigningKey(ctx,configured,overrides) : undefined;
        const token = await signJWT(ctx,{options:configured,payload:body.payload,header:body.header,...overrides,...(resolvedKey?{resolvedKey}:{})});
        return Response.json({token});
      } catch { return Response.json({message:"Internal server error"},{status:500}); }
    } else if (body.operation !== "state") return Response.json({message:"unknown keyring operation"},{status:400});
    return Response.json({keys:rows(profile).map(observed),events:[...events]});
  }};
}
