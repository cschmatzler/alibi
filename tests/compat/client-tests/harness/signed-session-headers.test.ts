import { Database } from "bun:sqlite";
import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { createAuthClient } from "better-auth/client";
import { getMigrations } from "better-auth/db/migration";
import { createAuthMiddleware } from "better-auth/api";
import { getCookieCache } from "better-auth/cookies";
import { verifyPassword } from "better-auth/crypto";
import { jwt, oneTimeToken } from "better-auth/plugins";
import { createHmac } from "node:crypto";
import { createLocalJWKSet, jwtVerify } from "jose";
import { compareValues, type ComparisonContext } from "../support/compare";
import { normalizeClientValue } from "../support/normalize";
import { createTracingFetch, requestWindow, type TraceEntry } from "../support/trace";

const secret = "signed-header-harness-application-secret32";
type Data = Record<string, any>;

async function capture(compact = false) {
  const database = new Database(":memory:"), traces: TraceEntry[] = [], events: Data[] = [];
  let baseURL = "", active = false;
  const observe = (stage: string, ctx: Data) => {
    if (!active) return;
    events.push({ stage, path: ctx.path, method: ctx.method,
      headers: ctx.headers ? Object.fromEntries(ctx.headers) : null,
      request: ctx.request ? { url: ctx.request.url, method: ctx.request.method,
        headers: Object.fromEntries(ctx.request.headers) } : null,
      session: ctx.context.session });
  };
  const server = Bun.serve({ port: 0, async fetch(request) {
    if (new URL(request.url).pathname !== "/__test/signed-header-call") return auth.handler(request);
    const physical = request.clone();
    events.length = 0; active = true;
    try {
      const headers = new Headers({ cookie: request.headers.get("cookie")! });
      const token = await auth.api.getToken({ headers, request: physical, asResponse: false });
      const generated = await auth.api.generateOneTimeToken({ headers });
      const verified = await auth.api.verifyOneTimeToken({ body: generated, returnHeaders: true });
      const restoredHeaders=compact?new Headers({cookie:verified.headers.getSetCookie().map(raw=>raw.split(";")[0]).join("; ")}):undefined;
      return Response.json({ token, generated, verified: { response: verified.response,
        headers: {...Object.fromEntries(verified.headers),...compact?{"set-cookie":verified.headers.get("set-cookie")} : {}},...compact?{issued:await compactReceipt(verified.headers)}:{} },...compact?{restoreInput:{headers:Object.fromEntries(restoredHeaders!)}}:{}, events: [...events] });
    } finally { active = false; }
  } });
  baseURL = `http://localhost:${server.port}`;
  const auth = betterAuth({ baseURL, secret, database, rateLimit: { enabled: false },
    emailAndPassword: { enabled: true }, plugins: [jwt(), oneTimeToken()],
    ...compact ? {session:{cookieCache:{enabled:true,strategy:"compact" as const,maxAge:300}}} : {},
    hooks: {
      before: createAuthMiddleware(async ctx => { observe("before", ctx); }),
      after: createAuthMiddleware(async ctx => { observe("after", ctx); }),
    },
  });
  const startedAt = Date.now();
  async function compactReceipt(headers: Headers) {
    const rawCookies=headers.getSetCookie().filter(raw=>raw.startsWith("better-auth.session_data="));
    expect(rawCookies).toHaveLength(1);
    const token=decodeURIComponent(rawCookies[0]!.split(";")[0]!.slice("better-auth.session_data=".length));
    const envelope=JSON.parse(Buffer.from(token,"base64url").toString()),observedAt=Date.now();
    expect(envelope.signature).toBe(createHmac("sha256",secret).update(JSON.stringify({...envelope.session,expiresAt:envelope.expiresAt})).digest("base64url"));
    const decoded=await getCookieCache(new Headers({cookie:rawCookies[0]!.split(";")[0]!}),{secret,strategy:"compact"});
    expect(decoded).not.toBeNull();
    return {compactSessionCache:{token,envelope,decoded,observedAt,effectiveMaxAgeSeconds:300,rawCookies}};
  }
  try {
    await (await getMigrations(auth.options)).runMigrations();
    const signup = async (name: string) => {
      let cookie = "";
      let rawHeaders: Headers | undefined;
      const fetch = createTracingFetch(baseURL, name, traces);
      const client = createAuthClient({ baseURL, fetchOptions: { customFetchImpl: fetch } });
      const result = await client.signUp.email({ name, email: `${name}@signed-header.local`, password: "password123",
        fetchOptions: { onSuccess({ response }) { rawHeaders=new Headers(response.headers);cookie = response.headers.getSetCookie().map(raw => raw.split(";")[0]).join("; "); } } });
      expect(result.error).toBeNull(); expect(cookie).toContain("better-auth.session_token=");
      const pair=cookie.split("; ").find(pair=>pair.startsWith("better-auth.session_token="))!;
      const raw = decodeURIComponent(pair.slice(pair.indexOf("=") + 1)), dot = raw.lastIndexOf(".");
      expect(raw.slice(0, dot)).toBe(result.data!.token!);
      expect(raw.slice(dot + 1)).toBe(createHmac("sha256", secret).update(result.data!.token!).digest("base64"));
      return { result: result.data, headers: { cookie }, fetch, client,...compact?{issued:await compactReceipt(rawHeaders!)}:{} };
    };
    const owner = await signup("owner"), foreign = await signup("foreign");
    const response = await owner.fetch(`${baseURL}/__test/signed-header-call`, { method: "POST",
      headers: { "content-type": "application/json", host: "signed-header-owner.example.test",
        origin: "http://signed-header-owner.example.test" }, body: "{}" });
    expect(response.status).toBe(200); const observed = await response.json() as Data;
    const jwks = await auth.api.getJwks({});
    const verifiedToken = await jwtVerify(observed.token.token, createLocalJWKSet(jwks));
    expect(verifiedToken.payload.sub).toBe(owner.result!.user.id);
    expect(observed.verified.response.session.token).toBe(owner.result!.token);
    expect(observed.events.length).toBeGreaterThan(0);
    for (const event of observed.events.filter((event: Data) => event.headers?.cookie)) {
      if(compact){
        const decoded=await getCookieCache(new Headers({cookie:event.headers.cookie}),{secret,strategy:"compact"});
        expect(decoded).not.toBeNull();expect(decoded!.user.id).toBe(owner.result!.user.id);expect(decoded!.session.token).toBe(owner.result!.token!);
      }else expect(event.headers.cookie).toBe(owner.headers.cookie);
    }
    const restoredCookie = observed.verified.headers["set-cookie"].split(";")[0];
    const restored = await auth.api.getSession({ headers: new Headers({ cookie: compact?observed.restoreInput.headers.cookie:restoredCookie }) });
    expect(restored!.user.id).toBe(owner.result!.user.id);
    const replay = await auth.api.verifyOneTimeToken({ body: observed.generated }).then(() => null, error => error);
    expect(replay.statusCode).toBe(400); expect(replay.body).toEqual({ message: "Invalid token" });
    expect(database.query("SELECT * FROM verification").all()).toEqual([]);
    let rotatedCookie = "";
    let rotatedHeaders:Headers|undefined;
    const rotated = await owner.client.signIn.email({ email: "owner@signed-header.local", password: "password123",
      fetchOptions: { onSuccess({ response }) { rotatedHeaders=new Headers(response.headers);rotatedCookie = response.headers.getSetCookie().map(raw => raw.split(";")[0]).join("; "); } } });
    expect(rotated.error).toBeNull(); expect(rotated.data!.user.id).toBe(owner.result!.user.id);
    expect(rotated.data!.token).not.toBe(owner.result!.token);
    expect(database.query("SELECT * FROM session").all()).toHaveLength(3);
    const rows:Data={};
    if(compact){
      for(const table of ["user","account","session","verification"]){
        const stored=database.query(table==="account"?"SELECT account.* FROM account JOIN user ON user.id=account.userId ORDER BY user.name,account.id":`SELECT * FROM ${table} ORDER BY ${table==="verification"?"identifier":table==="user"?"name":"createdAt"},id`).all() as Data[];
        rows[table]=await Promise.all(stored.map(async row=>{
          if(table!=="account"||row.password===null)return row;
          expect(await verifyPassword({hash:row.password,password:"password123"})).toBe(true);
          expect(await verifyPassword({hash:row.password,password:"foreign-password-control"})).toBe(false);
          const [salt,key]=row.password.split(":");
          return {...row,password:{token:row.password,salt:{token:salt,length:salt.length},derivedKey:{token:key,length:key.length},encoding:"hex-lower"}};
        }));
      }
      for(const issued of [owner,foreign]){
        const decoded=issued.issued!.compactSessionCache.decoded!;
        const stored=rows.session.find((row:Data)=>row.token===issued.result!.token)!;
        expect(decoded.user.id).toBe(issued.result!.user.id);expect(decoded.session.userId).toBe(decoded.user.id);
        expect(decoded.session.id).toBe(stored.id);expect(decoded.session.token).toBe(stored.token);
        expect(decoded.session.expiresAt.toISOString()).toBe(stored.expiresAt);
      }
    }
    const value = normalizeClientValue({ observation: {
      owner: { result: owner.result, headers: owner.headers,...compact?{issued:owner.issued}:{} }, foreign: { result: foreign.result, headers: foreign.headers,...compact?{issued:foreign.issued}:{} },
      rotated: { result: rotated.data, headers: { cookie: rotatedCookie },...compact?{issued:await compactReceipt(rotatedHeaders!)}:{} }, observed, verifiedToken, jwks, restored,...compact?{rows}:{},
    }, traces }) as Data;
    return { value, baseURL, startedAt, finishedAt: Date.now(), windows: traces.map(trace => trace[requestWindow]) };
  } finally { server.stop(true); database.close(); }
}

test("actual Source signed session headers retain HMAC issuance physical and logical cookie relationships", async () => {
  const left = await capture(), right = await capture();
  const context: ComparisonContext = { leftBaseURL: left.baseURL, rightBaseURL: right.baseURL,
    sessionCookieSecret: secret,
    leftStartedAt: left.startedAt, leftFinishedAt: left.finishedAt,
    rightStartedAt: right.startedAt, rightFinishedAt: right.finishedAt,
    leftRequestWindows: left.windows, rightRequestWindows: right.windows,
  };
  if (Bun.env.COMPAT_SIGNED_HEADER_CAPTURE)
    await Bun.write(Bun.env.COMPAT_SIGNED_HEADER_CAPTURE, JSON.stringify({ left: left.value, right: right.value, context }, null, 2));
  // These are complete real Source captures. The comparator must reconcile the
  // independently random credentials without editing any header observation.
  expect(compareValues(left.value, right.value, context)).toEqual([]);
  const cookiePath = "observation.owner.headers.cookie";
  const cookie = (value: Data) => value.observation.owner.headers.cookie as string;
  const setCookiePath = "observation.observed.verified.headers.set-cookie";
  const invalidSignature = (raw: string) => {
    const separator = raw.indexOf("="), decoded = decodeURIComponent(raw.slice(separator + 1));
    const dot = decoded.lastIndexOf("."), signature = decoded.slice(dot + 1);
    return `${raw.slice(0, separator + 1)}${encodeURIComponent(`${decoded.slice(0, dot + 1)}${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`)}`;
  };
  const mutations: { mutate: (value: Data) => void; path: string; reason: string }[] = [
    { mutate: value => { value.observation.owner.headers.cookie = value.observation.foreign.headers.cookie; }, path: cookiePath,
      reason: "signed session cookie does not match corresponding observed issuance" },
    { mutate: value => { value.observation.owner.headers.cookie = value.observation.rotated.headers.cookie; }, path: cookiePath,
      reason: "signed session cookie does not match corresponding observed issuance" },
    { mutate: value => { value.observation.owner.headers.cookie = left.value.observation.foreign.headers.cookie; }, path: cookiePath,
      reason: "signed session cookie does not match corresponding observed issuance" },
    { mutate: value => { value.observation.owner.headers.cookie = invalidSignature(cookie(value)); }, path: cookiePath,
      reason: "signed session cookie signature is invalid" },
    { mutate: value => { value.observation.owner.headers.cookie = cookie(value).replace("%3D", "%3d"); }, path: cookiePath,
      reason: "signed session cookie encoding is not canonical" },
    { mutate: value => { value.observation.owner.headers.cookie = cookie(value).replace("better-auth.session_token", "__Secure-better-auth.session_token"); }, path: cookiePath,
      reason: "signed session cookie presence or name differs" },
    { mutate: value => { value.observation.owner.headers.cookie = `${cookie(value)}; ${cookie(value)}`; }, path: cookiePath,
      reason: "signed session cookie presence or name differs" },
    { mutate: value => { value.observation.owner.headers.cookie = `${cookie(value)}; application=changed-literal`; }, path: cookiePath,
      reason: "signed session cookie header bytes or attributes differ" },
    ...["Path=/", "HttpOnly", "SameSite=Lax", "Max-Age=604800"].map(attribute => ({
      mutate: (value: Data) => { value.observation.observed.verified.headers["set-cookie"] =
        (value.observation.observed.verified.headers["set-cookie"] as string).replace(attribute, `${attribute}-changed`); },
      path: setCookiePath, reason: "signed session cookie header bytes or attributes differ",
    })),
  ];
  for (const mutation of mutations) {
    const changed = structuredClone(right.value); mutation.mutate(changed);
    expect(compareValues(left.value, changed, context)).toContainEqual({ path: mutation.path, reason: mutation.reason });
  }
  const unrecorded = { ...context, rightRequestWindows: right.windows.map(window => window && { ...window, issuedSessionCookie: undefined }) };
  expect(compareValues(left.value, right.value, unrecorded)).toContainEqual({ path: cookiePath,
    reason: "signed session cookie does not match corresponding observed issuance" });
  const wrongSecret = { ...context, sessionCookieSecret: "another-real-application-secret-for-negative" };
  expect(compareValues(left.value, right.value, wrongSecret)).toContainEqual({ path: cookiePath,
    reason: "signed session cookie signature is invalid" });
  const invalidLeft = structuredClone(left.value), invalidRight = structuredClone(right.value);
  invalidLeft.observation.owner.headers.cookie = invalidRight.observation.owner.headers.cookie = invalidSignature(cookie(right.value));
  expect(compareValues(invalidLeft, invalidRight, context)).toContainEqual({ path: cookiePath,
    reason: "signed session cookie signature is invalid" });
  const orderedLeft = structuredClone(left.value), orderedRight = structuredClone(right.value);
  orderedLeft.observation.owner.headers.cookie += "; application=literal";
  orderedRight.observation.owner.headers.cookie += "; application=literal";
  expect(compareValues(orderedLeft, orderedRight, context)).toEqual([]);
  orderedRight.observation.owner.headers.cookie = `application=literal; ${cookie(right.value)}`;
  expect(compareValues(orderedLeft, orderedRight, context)).toContainEqual({ path: cookiePath,
    reason: "signed session cookie header bytes or attributes differ" });
  for (const field of ["metadata", "additionalFields", "custom", "applicationData"]) {
    const appLeft = { ...left.value, [field]: { headers: left.value.observation.owner.headers } };
    const appRight = { ...right.value, [field]: { headers: right.value.observation.owner.headers } };
    expect(compareValues(appLeft, appRight, context)).toContainEqual({ path: `${field}.headers.cookie`, reason: "value or type differs" });
  }
  expect(compareValues(left.value, right.value, { ...context, sessionCookieSecret: undefined })).toContainEqual({ path: cookiePath, reason: "value or type differs" });
});

test("actual Source co-present compact cookie headers bind authenticated cache to signed issuance and complete persisted owners",async()=>{
  const left=await capture(true),right=await capture(true);
  const context:ComparisonContext={leftBaseURL:left.baseURL,rightBaseURL:right.baseURL,sessionCookieSecret:secret,compactSessionCacheSecret:secret,leftStartedAt:left.startedAt,leftFinishedAt:left.finishedAt,rightStartedAt:right.startedAt,rightFinishedAt:right.finishedAt,leftRequestWindows:left.windows,rightRequestWindows:right.windows};
  if(Bun.env.COMPAT_COMPACT_HEADER_CAPTURE)await Bun.write(Bun.env.COMPAT_COMPACT_HEADER_CAPTURE,JSON.stringify({left:left.value,right:right.value,context},null,2));
  expect(compareValues(left.value,right.value,context)).toEqual([]);
  const cookiePath="observation.owner.headers.cookie",setCookiePath="observation.observed.verified.headers.set-cookie";
  const cacheMismatch="compact cookie does not match authenticated corresponding session issuance";
  const scaffoldMismatch="signed session cookie header bytes or attributes differ";
  const receipt=(value:Data)=>value.observation.owner.issued.compactSessionCache as Data;
  const cachePair=(cookie:string)=>cookie.split("; ").find(pair=>pair.startsWith("better-auth.session_data="))!;
  const replaceCache=(value:Data,pair:string)=>{
    value.observation.owner.headers.cookie=value.observation.owner.headers.cookie.replace(/better-auth\.session_data=[^;\s]*/,pair);
  };
  // Each negative changes a genuine Source capture. Assert its owning path and
  // reason so an unrelated row or JWT guard cannot satisfy the negative.
  const mutations:{mutate:(value:Data)=>void;path:string;reason:string}[]=[
    {mutate:value=>replaceCache(value,cachePair(value.observation.foreign.headers.cookie)),path:cookiePath,reason:cacheMismatch},
    {mutate:value=>replaceCache(value,cachePair(value.observation.rotated.headers.cookie)),path:cookiePath,reason:cacheMismatch},
    {mutate:value=>replaceCache(value,cachePair(left.value.observation.foreign.headers.cookie)),path:cookiePath,reason:cacheMismatch},
    {mutate:value=>{delete value.observation.owner.issued;},path:cookiePath,reason:cacheMismatch},
    {mutate:value=>{value.observation.owner.issued=value.observation.foreign.issued;},path:cookiePath,reason:cacheMismatch},
    {mutate:value=>{value.observation.owner.issued=value.observation.rotated.issued;},path:cookiePath,reason:cacheMismatch},
    {mutate:value=>{delete receipt(value).rawCookies;},path:cookiePath,reason:cacheMismatch},
    {mutate:value=>{receipt(value).rawCookies[0]=receipt(value).rawCookies[0].replace("Path=/","Path=/changed");},path:"observation.owner.issued.compactSessionCache.rawCookies.0.attributes",reason:"value or type differs"},
    {mutate:value=>{receipt(value).rawCookies[0]=receipt(value).rawCookies[0].replace("better-auth.session_data=","better-auth.session_data.0=");},path:cookiePath,reason:cacheMismatch},
    {mutate:value=>{receipt(value).token+="=";},path:cookiePath,reason:cacheMismatch},
    {mutate:value=>{receipt(value).decoded.user.id=value.observation.foreign.result.user.id;},path:cookiePath,reason:cacheMismatch},
    {mutate:value=>{receipt(value).envelope.signature="A".repeat(43);},path:cookiePath,reason:cacheMismatch},
    {mutate:value=>{receipt(value).observedAt=context.rightFinishedAt!+1;},path:cookiePath,reason:cacheMismatch},
    {mutate:value=>{receipt(value).effectiveMaxAgeSeconds=301;},path:cookiePath,reason:cacheMismatch},
    {mutate:value=>replaceCache(value,`${cachePair(value.observation.owner.headers.cookie)}=`),path:cookiePath,reason:cacheMismatch},
    {mutate:value=>{value.observation.owner.headers.cookie+=`; ${cachePair(value.observation.owner.headers.cookie)}`;},path:cookiePath,reason:cacheMismatch},
    {mutate:value=>replaceCache(value,cachePair(value.observation.owner.headers.cookie).replace("session_data=","session_data.0=")),path:cookiePath,reason:cacheMismatch},
    {mutate:value=>{value.observation.owner.headers.cookie+="; application=changed-literal";},path:cookiePath,reason:scaffoldMismatch},
    ...["Path=/","HttpOnly","SameSite=Lax","Max-Age=300"].map(attribute=>({
      mutate:(value:Data)=>{value.observation.observed.verified.headers["set-cookie"]=value.observation.observed.verified.headers["set-cookie"].replace(attribute,`${attribute}-changed`);},path:setCookiePath,reason:scaffoldMismatch,
    })),
  ];
  for(const mutation of mutations){
    const changed=structuredClone(right.value);mutation.mutate(changed);
    expect(compareValues(left.value,changed,context)).toContainEqual({path:mutation.path,reason:mutation.reason});
  }
  const resign=(value:Data,change:(cache:Data)=>void)=>{
    const cache=receipt(value),old=cache.token;change(cache);
    cache.envelope.signature=createHmac("sha256",secret).update(JSON.stringify({...cache.envelope.session,expiresAt:cache.envelope.expiresAt})).digest("base64url");
    cache.token=Buffer.from(JSON.stringify(cache.envelope)).toString("base64url");
    cache.rawCookies=cache.rawCookies.map((raw:string)=>raw.replace(old,cache.token));
    replaceCache(value,`better-auth.session_data=${cache.token}`);
  };
  // A valid MAC admits no exemption for the full decoded principal, payload,
  // version or expiry. Deliberately sign mutations of these real Source rows.
  const payloadMutations:{change:(cache:Data)=>void;field:string;reason:string}[]=[
    {change:cache=>{cache.envelope.session.user.name=cache.decoded.user.name="Changed actual owner";},field:"user.name",reason:"value or type differs"},
    {change:cache=>{cache.envelope.session.session.userId=cache.decoded.session.userId=right.value.observation.foreign.result.user.id;},field:"session.userId",reason:"identity relationship or token rotation differs"},
    {change:cache=>{cache.envelope.session.session.id=cache.decoded.session.id=right.value.observation.foreign.issued.compactSessionCache.decoded.session.id;},field:"session.id",reason:"identity relationship or token rotation differs"},
    {change:cache=>{cache.envelope.session.session.token=cache.decoded.session.token=right.value.observation.foreign.result.token;},field:"session.token",reason:"identity relationship or token rotation differs"},
    {change:cache=>{cache.envelope.session.version=cache.decoded.version="Changed-version";},field:"version",reason:"value or type differs"},
  ];
  for(const mutation of payloadMutations){
    const changed=structuredClone(right.value);resign(changed,mutation.change);
    const differences=compareValues(left.value,changed,context);
    for(const prefix of ["envelope.session","decoded"])
      expect(differences).toContainEqual({path:`observation.owner.issued.compactSessionCache.${prefix}.${mutation.field}`,reason:mutation.reason});
    if(["session.userId","session.token"].includes(mutation.field))
      expect(differences).toContainEqual({path:cookiePath,reason:cacheMismatch});
  }
  const expiryChanged=structuredClone(right.value);
  const changedExpiry=new Date(Date.parse(receipt(expiryChanged).decoded.session.expiresAt)+3_600_000).toISOString();
  resign(expiryChanged,cache=>{cache.envelope.session.session.expiresAt=cache.decoded.session.expiresAt=changedExpiry;});
  for(const prefix of ["envelope.session","decoded"])
    expect(compareValues(left.value,expiryChanged,context)).toContainEqual({path:`observation.owner.issued.compactSessionCache.${prefix}.session.expiresAt`,reason:`timestamp or lifetime differs: ${receipt(left.value).decoded.session.expiresAt} vs ${changedExpiry}`});
  for(const changedContext of [
    {...context,compactSessionCacheSecret:undefined},
    {...context,compactSessionCacheSecret:"another-real-compact-application-secret32"},
  ])expect(compareValues(left.value,right.value,changedContext)).toContainEqual({path:cookiePath,reason:cacheMismatch});
  const missingIssuance={...context,rightRequestWindows:right.windows.map(window=>window&&{...window,issuedSessionCookie:undefined})};
  expect(compareValues(left.value,right.value,missingIssuance)).toContainEqual({path:cookiePath,reason:"signed session cookie does not match corresponding observed issuance"});
  const corruptLeft=structuredClone(left.value),corruptRight=structuredClone(right.value);
  // Identical corrupt cache bytes must still fail authentication at the header.
  replaceCache(corruptLeft,"better-auth.session_data=not-a-real-envelope");
  replaceCache(corruptRight,"better-auth.session_data=not-a-real-envelope");
  expect(compareValues(corruptLeft,corruptRight,context)).toContainEqual({path:cookiePath,reason:cacheMismatch});
  const corruptEnvelope=structuredClone(receipt(right.value).envelope);
  corruptEnvelope.signature="A".repeat(43);
  const corruptToken=Buffer.from(JSON.stringify(corruptEnvelope)).toString("base64url");
  for(const value of [corruptLeft,corruptRight]){
    const cache=receipt(value),old=cache.token;
    cache.token=corruptToken;cache.envelope=structuredClone(corruptEnvelope);
    cache.rawCookies=cache.rawCookies.map((raw:string)=>raw.replace(old,corruptToken));
    replaceCache(value,`better-auth.session_data=${corruptToken}`);
  }
  expect(compareValues(corruptLeft,corruptRight,context)).toContainEqual({path:cookiePath,reason:cacheMismatch});
  const orderedLeft=structuredClone(left.value),orderedRight=structuredClone(right.value);
  orderedLeft.observation.owner.headers.cookie+="; application=literal; better-auth.session_data.0=literal-chunk";
  orderedRight.observation.owner.headers.cookie+="; application=literal; better-auth.session_data.0=literal-chunk";
  expect(compareValues(orderedLeft,orderedRight,context)).toEqual([]);
  orderedRight.observation.owner.headers.cookie=orderedRight.observation.owner.headers.cookie.replace("literal-chunk","changed-chunk");
  expect(compareValues(orderedLeft,orderedRight,context)).toContainEqual({path:cookiePath,reason:scaffoldMismatch});
  orderedRight.observation.owner.headers.cookie=`application=literal; ${right.value.observation.owner.headers.cookie}; better-auth.session_data.0=literal-chunk`;
  expect(compareValues(orderedLeft,orderedRight,context)).toContainEqual({path:cookiePath,reason:scaffoldMismatch});
  for(const field of ["metadata","additionalFields","custom","applicationData"]){
    const appLeft={...left.value,[field]:{headers:left.value.observation.owner.headers,issued:left.value.observation.owner.issued}};
    const appRight={...right.value,[field]:{headers:right.value.observation.owner.headers,issued:right.value.observation.owner.issued}};
    expect(compareValues(appLeft,appRight,context)).toContainEqual({path:`${field}.headers.cookie`,reason:"value or type differs"});
  }
});
