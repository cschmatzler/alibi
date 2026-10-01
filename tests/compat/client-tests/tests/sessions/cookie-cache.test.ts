import {expect} from "bun:test";
import {createAuthClient} from "better-auth/client";
import {anonymousClient,organizationClient} from "better-auth/client/plugins";
import {getCookieCache} from "better-auth/cookies";
import {compatScenario,type ScenarioContext} from "../../support/scenario";
import {authProfilePath,type FixtureProfile} from "../../support/profiles";

const secret="compat-test-only-key-not-real-minimum-32chars";
const cookieName="better-auth.session_data";
async function control(ctx:ScenarioContext,mode:string,body:Record<string,unknown>){
  const r=await ctx.rawRequest({path:"/__test/session-cookie-cache/control",method:"POST",json:{mode,...body}});
  expect(r.status).toBe(200);return r.body as {events:Record<string,any>[];user?:unknown};
}
function client(ctx:ScenarioContext,mode:string,name="owner"){
  const actor=ctx.actor(name,`session-cache-${mode}` as FixtureProfile);
  const headers:Headers[]=[];
  const sdk=createAuthClient({baseURL:ctx.baseURL+authProfilePath(`session-cache-${mode}` as FixtureProfile),plugins:[anonymousClient(),organizationClient()],fetchOptions:{customFetchImpl:async(input,init)=>{const r=await actor.fetch(input,init);headers.push(new Headers(r.headers));return r;}}});
  return {sdk,headers,fetch:actor.fetch};
}
function cookiePairs(headers:Headers){return headers.getSetCookie().map(x=>x.split(";")[0]!);}
function assembled(header:string){
  const pairs=new Map(header.split(";").map(pair=>{const i=pair.indexOf("=");return [pair.slice(0,i).trim(),decodeURIComponent(pair.slice(i+1))];}));
  const base=pairs.get(cookieName);if(base)return base;
  return [...pairs].filter(([k])=>/^better-auth\.session_data\.\d+$/.test(k)).sort(([a],[b])=>Number(a.split(".").at(-1))-Number(b.split(".").at(-1))).map(([,v])=>v).join("");
}
async function atom(headers:Headers,effectiveMaxAgeSeconds=300,expectDecoded=true){
  const cookie=cookiePairs(headers).join("; "),token=assembled(cookie);
  expect(token.length).toBeGreaterThan(0);
  const envelope=JSON.parse(Buffer.from(token,"base64url").toString());
  const observedAt=Date.now();
  const decoded=await getCookieCache(new Headers({cookie}),{secret,strategy:"compact"});
  if(expectDecoded)expect(decoded).not.toBeNull();else expect(decoded).toBeNull();
  const rawCookies=headers.getSetCookie().filter(header=>header.startsWith(cookieName+"=")||header.startsWith(cookieName+"."));
  return {compactSessionCache:{token,envelope,decoded,observedAt,effectiveMaxAgeSeconds,rawCookies}};
}
async function response(r:Response){return {status:r.status,body:await r.json()};}

compatScenario("compact cache authenticates the signed token and complete payload while retaining revoked ordinary authority only until explicit bypass",async ctx=>{
  await control(ctx,"standard",{action:"reset"});
  const owner=client(ctx,"standard"),foreign=client(ctx,"standard","foreign");
  const signup=await owner.sdk.signUp.email({email:ctx.uniqueEmail("compact-owner"),name:"Original Cache Owner",password:"password123"});
  expect(signup.error).toBeNull();const original=signup.data!;expect(typeof original.token).toBe("string");
  const issued=owner.headers.at(-1)!,signed=await atom(issued);
  expect(signed.compactSessionCache.decoded!.session).toMatchObject({token:original.token,label:"cache-public-label"});
  expect(signed.compactSessionCache.decoded!.session).not.toHaveProperty("hidden");
  const other=await foreign.sdk.signUp.email({email:ctx.uniqueEmail("compact-foreign"),name:"Foreign Owner",password:"password123"});
  expect(other.error).toBeNull();const foreignBefore=await ctx.readUserState({userId:other.data!.user.id});
  const foreignHeaders=foreign.headers.at(-1)!;
  await control(ctx,"standard",{action:"rename",userId:original.user.id,name:"Authoritative Stored Owner"});
  const cached=await owner.sdk.getSession();expect(cached.data!.user.name).toBe("Original Cache Owner");
  const bypass=await owner.sdk.getSession({query:{disableCookieCache:true,disableRefresh:true}});expect(bypass.data!.user.name).toBe("Authoritative Stored Owner");
  const oldCookies=cookiePairs(issued),foreignCookies=cookiePairs(foreignHeaders);
  const graft=await response(await owner.fetch(ctx.baseURL+authProfilePath("session-cache-standard")+"/get-session",{credentials:"omit",headers:{cookie:[...foreignCookies.filter(p=>p.startsWith("better-auth.session_token=")),...oldCookies.filter(p=>p.startsWith(cookieName+"="))].join("; ")}}));
  expect(graft.status).toBe(200);expect((graft.body as any).user.id).toBe(other.data!.user.id);
  const forged=JSON.parse(JSON.stringify(signed.compactSessionCache.envelope));forged.session.user.id=other.data!.user.id;forged.session.user.name="Forged Foreign Name";
  const badToken=Buffer.from(JSON.stringify(forged)).toString("base64url");
  const tamper=await response(await owner.fetch(ctx.baseURL+authProfilePath("session-cache-standard")+"/get-session",{credentials:"omit",headers:{cookie:[...oldCookies.filter(p=>p.startsWith("better-auth.session_token=")),cookieName+"="+badToken].join("; ")}}));
  expect((tamper.body as any).user.id).toBe(original.user.id);expect((tamper.body as any).user.name).toBe("Authoritative Stored Owner");
  expect(await ctx.readUserState({userId:other.data!.user.id})).toEqual(foreignBefore);
  await control(ctx,"standard",{action:"revoke",token:original.token});
  const before=await ctx.readUserState({userId:original.user.id});expect((before as any).sessions).toEqual([]);
  const retained=await owner.sdk.getSession();expect(retained.data!.session.token).toBe(original.token!);
  const accounts=await owner.sdk.listAccounts();expect(accounts.error).toBeNull();expect(accounts.data!.length).toBe(1);
  const organizations=await owner.sdk.organization.list();expect(organizations.error).toBeNull();expect(organizations.data).toEqual([]);
  const authoritative=await owner.sdk.getSession({query:{disableCookieCache:true}});expect(authoritative.data).toBeNull();
  expect(await ctx.readUserState({userId:original.user.id})).toEqual(before);expect(await ctx.readUserState({userId:other.data!.user.id})).toEqual(foreignBefore);
  return {signup:ctx.snapshot(signup),signed,other:ctx.snapshot(other),foreignBefore,cached:ctx.snapshot(cached),bypass:ctx.snapshot(bypass),graft,tamper,before,retained:ctx.snapshot(retained),accounts:ctx.snapshot(accounts),organizations:ctx.snapshot(organizations),authoritative:ctx.snapshot(authoritative)};
},["GET /get-session","GET /list-accounts","GET /organization/list"]);

compatScenario("compact cache chunking uses real writer limits and canonical server chunk indices with base-cookie precedence",async ctx=>{
  await control(ctx,"standard",{action:"reset"});const owner=client(ctx,"standard");
  const signup=await owner.sdk.signUp.email({email:ctx.uniqueEmail("compact-chunk"),name:"x".repeat(6000),password:"password123"});expect(signup.error).toBeNull();
  const headers=owner.headers.at(-1)!,pairs=cookiePairs(headers),parts=headers.getSetCookie().filter(p=>p.startsWith(cookieName+"."));
  expect(parts.length).toBeGreaterThan(1);for(const part of parts)expect(Buffer.byteLength(part)).toBeLessThanOrEqual(4050);
  const issued=await atom(headers);
  const attributes=parts[0]!.slice(parts[0]!.indexOf(";"));
  const capacity=4050-(cookieName+".99="+attributes).length;
  const values=parts.map(part=>part.split(";")[0]!.slice(part.indexOf("=")+1));
  expect(values.join("")).toBe(issued.compactSessionCache.token);
  values.forEach((value,index)=>expect(value.length).toBe(Math.min(capacity,issued.compactSessionCache.token.length-index*capacity)));
  await control(ctx,"standard",{action:"rename",userId:signup.data!.user.id,name:"Stored Chunk Owner"});
  const token=pairs.find(p=>p.startsWith("better-auth.session_token="))!;
  const chunks=pairs.filter(p=>p.startsWith(cookieName+"."));
  const observations=[];
  for(const [mode,cache,expected]of [
    ["reverse",[...chunks].reverse(),"x".repeat(6000)],
    ["base-precedence",[cookieName+"="+issued.compactSessionCache.token,...chunks.map(p=>p.replace(/=.*/,"=invalid"))],"x".repeat(6000)],
    ["noncanonical",chunks.map(p=>p.replace(cookieName+".0=",cookieName+".00=")),"Stored Chunk Owner"],
    ["missing",chunks.slice(1),"Stored Chunk Owner"],
  ] as const){
    const r=await response(await owner.fetch(ctx.baseURL+authProfilePath("session-cache-standard")+"/get-session",{credentials:"omit",headers:{cookie:[token,...cache].join("; ")}}));
    expect(r.status).toBe(200);expect((r.body as any).user.name).toBe(expected);observations.push({mode,...r});
  }
  const state=await ctx.readUserState({userId:signup.data!.user.id});expect((state as any).sessions.length).toBe(1);
  return {signup:ctx.snapshot(signup),issued,chunkCount:parts.length,observations,state};
},["GET /get-session"]);

compatScenario("compact asynchronous version receives real stored private fields then filtered cache fields and invalidation falls back without mutating foreign state",async ctx=>{
  await control(ctx,"version",{action:"reset"});const owner=client(ctx,"version");
  const signup=await owner.sdk.signUp.email({email:ctx.uniqueEmail("compact-version"),name:"Version Owner",password:"password123"});expect(signup.error).toBeNull();
  const issued=await atom(owner.headers.at(-1)!);
  const cached=await owner.sdk.getSession();expect(cached.error).toBeNull();
  const first=await control(ctx,"version",{action:"state"});expect(first.events.length).toBe(2);expect(first.events[0]!.session.hidden).toBe("cache-server-secret");expect(first.events[1]!.session).not.toHaveProperty("hidden");
  await control(ctx,"version",{action:"rename",userId:signup.data!.user.id,name:"Changed Version Owner"});
  await control(ctx,"version",{action:"policy",version:"v2"});
  const changed=await owner.sdk.getSession();expect(changed.data!.user.name).toBe("Changed Version Owner");const renewed=await atom(owner.headers.at(-1)!);expect(renewed.compactSessionCache.envelope.session.version).toBe("v2");
  const suppressed=await owner.sdk.getSession({query:{disableCookieCache:true,disableRefresh:true}});expect(suppressed.error).toBeNull();expect(owner.headers.at(-1)!.getSetCookie()).toEqual([]);
  const events=await control(ctx,"version",{action:"state"});expect(events.events.length).toBe(4);expect(events.events[2]!.session).not.toHaveProperty("hidden");expect(events.events[3]!.session).not.toHaveProperty("hidden");
  return {signup:ctx.snapshot(signup),issued,cached:ctx.snapshot(cached),first,changed:ctx.snapshot(changed),renewed,suppressed:ctx.snapshot(suppressed),events,state:await ctx.readUserState({userId:signup.data!.user.id})};
},["GET /get-session"]);

for(const mode of ["version-api","version-ordinary"] as const)compatScenario(`compact ${mode} issuance failure rolls email transaction back and does not link the authenticated anonymous account`,async ctx=>{
  await control(ctx,mode,{action:"reset"});const owner=client(ctx,mode);
  const anonymous=await owner.sdk.signIn.anonymous();expect(anonymous.error).toBeNull();
  const before=await ctx.readUserState({userId:anonymous.data!.user.id});const issued=await atom(owner.headers.at(-1)!);
  await control(ctx,mode,{action:"policy",failure:true});
  const email=ctx.uniqueEmail(`compact-failure-${mode}`);
  const signup=await owner.sdk.signUp.email({email,name:"Rejected Replacement",password:"password123"});expect(signup.error!.status).toBe(500);
  if(mode==="version-api")expect(signup.error).toMatchObject({code:"APPLICATION_CACHE_DENIED",message:"Configured cache version rejected issuance"});
  const failureHeaders=owner.headers.at(-1)!.getSetCookie();
  expect(failureHeaders.some(h=>h.startsWith("better-auth.session_token="))).toBe(mode==="version-api");expect(failureHeaders.some(h=>h.startsWith(cookieName+"="))).toBe(false);
  expect(await ctx.readUserState({userId:anonymous.data!.user.id})).toEqual(before);
  const lookup=await control(ctx,mode,{action:"lookup",email});expect(lookup.user).toBeNull();expect(Object.keys(lookup)).toEqual(["user"]);
  const events=await control(ctx,mode,{action:"state"});expect(events.events.some(e=>e.link)).toBe(false);expect(events.events.length).toBe(mode==="version-api"?3:2);
  const session=await owner.sdk.getSession();
  if(mode==="version-api")expect(session.data).toBeNull();else expect(session.data!.user.id).toBe(anonymous.data!.user.id);
  return {anonymous:ctx.snapshot(anonymous),before,issued,signup:ctx.snapshot(signup),lookup,events,session:ctx.snapshot(session),after:await ctx.readUserState({userId:anonymous.data!.user.id})};
},["POST /sign-up/email","GET /get-session"]);

compatScenario("compact browser preference authenticates dontRemember and refreshes a sixty-second browser cache without persistent cookie attributes",async ctx=>{
  await control(ctx,"standard",{action:"reset"});const owner=client(ctx,"standard");
  const email=ctx.uniqueEmail("compact-browser");expect((await owner.sdk.signUp.email({email,name:"Browser Owner",password:"password123"})).error).toBeNull();
  const signed=await owner.sdk.signIn.email({email,password:"password123",rememberMe:false});expect(signed.error).toBeNull();
  const issued=await atom(owner.headers.at(-1)!,60);const lifetime=issued.compactSessionCache.envelope.expiresAt-issued.compactSessionCache.envelope.session.updatedAt;
  expect(lifetime).toBeGreaterThanOrEqual(60000);expect(lifetime).toBeLessThanOrEqual(60010);
  for(const header of owner.headers.at(-1)!.getSetCookie())expect(header).not.toMatch(/(?:Max-Age|Expires)=/i);
  const token=cookiePairs(owner.headers.at(-1)!).find(p=>p.startsWith("better-auth.session_token="))!;
  const invalidResponse=await owner.fetch(ctx.baseURL+authProfilePath("session-cache-standard")+"/get-session",{credentials:"omit",headers:{cookie:token+"; better-auth.dont_remember=true.invalid"}});
  const invalid=await response(invalidResponse);expect(invalid.status).toBe(200);
  const persistent=await atom(invalidResponse.headers);expect(persistent.compactSessionCache.envelope.expiresAt-persistent.compactSessionCache.envelope.session.updatedAt).toBeGreaterThanOrEqual(300000);
  return {signed:ctx.snapshot(signed),issued,invalid,persistent,state:await ctx.readUserState({userId:signed.data!.user.id})};
},["GET /get-session"]);

for(const mode of ["zero","nan","fractional"] as const)compatScenario(`compact ${mode} raw max-age preserves actual writer lifetime and header flooring`,async ctx=>{
  await control(ctx,mode,{action:"reset"});const owner=client(ctx,mode);
  const signup=await owner.sdk.signUp.email({email:ctx.uniqueEmail(`compact-age-${mode}`),name:"Numeric Cache Owner",password:"password123"});expect(signup.error).toBeNull();
  const issued=await atom(owner.headers.at(-1)!,mode==="fractional"?0.5:300);
  const lifetime=issued.compactSessionCache.envelope.expiresAt-issued.compactSessionCache.envelope.session.updatedAt;
  const expected=mode==="fractional"?500:300000;
  expect(lifetime).toBeGreaterThanOrEqual(expected);expect(lifetime).toBeLessThanOrEqual(expected+10);
  expect(owner.headers.at(-1)!.getSetCookie().find(h=>h.startsWith(cookieName+"="))).toContain(`Max-Age=${mode==="fractional"?0:300}`);
  return {signup:ctx.snapshot(signup),issued,state:await ctx.readUserState({userId:signup.data!.user.id})};
},["POST /sign-up/email"]);

for(const mode of ["negative","negative-infinite","date-version"] as const)compatScenario(`compact ${mode} preserves the complete signed writer envelope while published decoding rejects it and the server uses storage`,async ctx=>{
  await control(ctx,mode,{action:"reset"});const owner=client(ctx,mode);
  const signup=await owner.sdk.signUp.email({email:ctx.uniqueEmail(`compact-null-${mode}`),name:"Rejected Cache Envelope Owner",password:"password123"});expect(signup.error).toBeNull();
  const effective=mode==="negative"?-1:mode==="negative-infinite"?-Infinity:300;
  const issued=await atom(owner.headers.at(-1)!,effective,false);
  if(mode==="negative-infinite")expect(issued.compactSessionCache.envelope.expiresAt).toBeNull();
  if(mode==="date-version")expect(issued.compactSessionCache.envelope.session.version).toBe("2026-10-01T00:00:00.000Z");
  if(mode!=="date-version")expect(owner.headers.at(-1)!.getSetCookie().find(h=>h.startsWith(cookieName+"="))).not.toMatch(/(?:Max-Age|Expires)=/i);
  await control(ctx,mode,{action:"rename",userId:signup.data!.user.id,name:"Actual Stored Fallback Owner"});
  const fallback=await owner.sdk.getSession();expect(fallback.data!.user.name).toBe("Actual Stored Fallback Owner");
  const renewed=await atom(owner.headers.at(-1)!,effective,false);
  expect(renewed.compactSessionCache.envelope.session.user.name).toBe("Actual Stored Fallback Owner");
  return {signup:ctx.snapshot(signup),issued,fallback:ctx.snapshot(fallback),renewed,state:await ctx.readUserState({userId:signup.data!.user.id})};
},["GET /get-session"]);

compatScenario("compact infinite Max-Age fails actual cookie emission with empty500 and email signup rolls every new row back",async ctx=>{
  await control(ctx,"infinite",{action:"reset"});const owner=client(ctx,"infinite"),email=ctx.uniqueEmail("compact-infinite");
  const signup=await owner.sdk.signUp.email({email,name:"Infinite Cache Owner",password:"password123"});expect(signup.error!.status).toBe(500);expect(owner.headers.at(-1)!.getSetCookie()).toEqual([]);
  const lookup=await control(ctx,"infinite",{action:"lookup",email});expect(lookup.user).toBeNull();expect(Object.keys(lookup)).toEqual(["user"]);
  const session=await owner.sdk.getSession();expect(session.data).toBeNull();
  return {signup:ctx.snapshot(signup),lookup,session:ctx.snapshot(session)};
},["POST /sign-up/email","GET /get-session"]);
