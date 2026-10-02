import {expect} from "bun:test";
import {createHash} from "node:crypto";
import {verifyPassword} from "better-auth/crypto";
import {compatScenario,type ScenarioContext} from "../../support/scenario";
import type {FixtureProfile} from "../../support/profiles";

type Row=Record<string,any>;
type State={users:Row[];accounts:Row[];sessions:Row[];verifications:Row[];cache:Row[];events:Row[];cacheEvents:Row[];deliveries:Row[]};
const sha=(value:string)=>createHash("sha256").update(value).digest("base64url");
const profile=(mode:string)=>`verification-storage-${mode}` as FixtureProfile;
const jsonDates={createdAt:"2020-01-02T03:04:05.000Z",updatedAt:"2021-02-03T04:05:06.000Z"};
async function call(ctx:ScenarioContext,body:Row){return ctx.rawRequest({path:"/__test/server-api/verification-storage",method:"POST",json:body});}
async function state(ctx:ScenarioContext):Promise<State>{const response=await call(ctx,{operation:"state"});expect(response.status).toBe(200);return response.body as State;}
async function configure(ctx:ScenarioContext,action:Row={},fault:Row={}){const response=await call(ctx,{operation:"configure",action,fault});expect(response.status).toBe(200);return response;}
function sql(s:State){return {users:s.users,accounts:s.accounts,sessions:s.sessions,verifications:s.verifications};}
function observed(value:unknown):any {
  if(Array.isArray(value))return value.map(observed);
  if(value!==null&&typeof value==="object")return Object.fromEntries(Object.entries(value).map(([key,child])=>{
    if(key==="password"&&typeof child==="string"&&child){expect(child).toMatch(/^[a-f0-9]{32}:[a-f0-9]{128}$/);return [key,{token:child,encoding:"hex-lower",saltLength:32,keyLength:128}];}
    return [key,observed(child)];
  }));return value;
}
async function foreign(ctx:ScenarioContext){
  const result=await ctx.actor("storage-foreign").client.signUp.email({email:ctx.uniqueEmail("storage-foreign"),name:"Foreign verification principal",password:"foreign-password123"});expect(result.error).toBeNull();
  const physical=await state(ctx),account=physical.accounts.find(row=>row.userId===result.data!.user.id)!;expect(await verifyPassword({hash:String(account.password),password:"foreign-password123"})).toBe(true);
  return {result,physical:sql(physical)};
}
function unchanged(other:Awaited<ReturnType<typeof foreign>>,s:State){for(const table of ["users","accounts","sessions"] as const)expect(s[table].filter(row=>other.physical[table].some(old=>old.id===row.id))).toEqual(other.physical[table]);}

for(const mode of ["plain","hashed","custom","ordered","numeric","cache","mixed"] as const)compatScenario(`verification storage ${mode} applies real identifier policy before hooks and physical/cache publication`,async ctx=>{
  const other=await foreign(ctx);await configure(ctx);
  const identifier=mode==="ordered"?"email-verification-policy-owner":mode==="numeric"?"12-numeric-policy-owner":"verification-policy-owner";
  const stored=["plain","ordered","numeric"].includes(mode)?identifier:mode==="custom"?`custom:${sha(identifier)}`:sha(identifier);
  const before=await state(ctx),created=await call(ctx,{operation:"create",profile:profile(mode),identifier,data:{value:"actual-issued-proof",...jsonDates}});expect(created.status).toBe(200);
  const candidate=created.body as Row;expect(candidate).toMatchObject({identifier:stored,value:"actual-issued-proof",...jsonDates});expect(Object.hasOwn(candidate,"id")).toBe(mode!=="cache");
  const admitted=await state(ctx);unchanged(other,admitted);expect(admitted.verifications).toHaveLength(mode==="cache"?0:1);expect(admitted.events.map(row=>row.stage)).toEqual(["create-before","create-after"]);
  const {id:_physicalId,...beforeData}=candidate;
  expect(admitted.events[0]!.data).toEqual(beforeData);
  expect(Object.hasOwn(admitted.events[0]!.data,"id")).toBe(false);
  expect(admitted.events[0]!.verifications).toEqual([]);expect(admitted.events[0]!.cache).toEqual([]);expect(admitted.events[1]!.data).toEqual(candidate);
  if(["cache","mixed"].includes(mode)){expect(admitted.cache).toHaveLength(1);expect(admitted.cache[0]).toMatchObject({key:`verification:${stored}`,value:candidate});expect(admitted.cacheEvents).toEqual([{operation:"set",key:`verification:${stored}`,value:candidate,ttl:60}]);expect(admitted.events[1]!.cache).toEqual(admitted.cache);}
  else expect(admitted.cache).toEqual([]);
  const found=await call(ctx,{operation:"find",profile:profile(mode),identifier});expect(found.body).toEqual(candidate);
  const consumed=await call(ctx,{operation:"consume",profile:profile(mode),identifier});expect(consumed.body).toEqual(candidate);
  const replay=await call(ctx,{operation:"consume",profile:profile(mode),identifier});expect(replay.body).toBeNull();const after=await state(ctx);unchanged(other,after);expect(after.verifications).toEqual([]);expect(after.cache).toEqual([]);
  return observed({foreign:other,before,created,admitted,found,consumed,replay,after});
});

compatScenario("verification storage trusted creation mutation retains genuine ID dates and precomputed cache key",async ctx=>{
  const other=await foreign(ctx),mutation={id:"trusted-storage-primary",identifier:"trusted-stored-identifier",value:"trusted-proof",createdAt:"2010-01-01T00:00:00.000Z",updatedAt:"2011-01-01T00:00:00.000Z"};await configure(ctx,{mutation});
  const identifier="original-logical-identifier",created=await call(ctx,{operation:"create",profile:profile("mixed"),identifier,data:{value:"original-proof",...jsonDates}});expect(created.status).toBe(200);expect(created.body).toMatchObject(mutation);
  const s=await state(ctx);unchanged(other,s);expect(s.verifications).toEqual([created.body as Row]);expect(s.cache).toHaveLength(1);expect(s.cache[0]).toMatchObject({key:`verification:${sha(identifier)}`,value:created.body as Row});expect(s.events[0]!.data).toMatchObject({identifier:sha(identifier),value:"original-proof",...jsonDates});expect(s.events[1]!.data).toEqual(created.body);
  const found=await call(ctx,{operation:"find",profile:profile("mixed"),identifier});expect(found.body).toEqual(created.body);
  return observed({foreign:other,created,s,found});
});

for(const mode of ["hashed","cache","mixed"] as const)compatScenario(`verification storage ${mode} expired transformed winner blocks live legacy fallback after atomic invalidation`,async ctx=>{
  const other=await foreign(ctx);await configure(ctx);const identifier="legacy-fallback-owner",past={value:"expired-transformed",expiresAt:"2000-01-01T00:00:00.000Z",...jsonDates},live={value:"live-plain",expiresAt:"2100-01-01T00:00:00.000Z",...jsonDates};
  const seeds=[];
  if(mode==="cache"){for(const [key,data] of [[sha(identifier),past],[identifier,live]] as const)seeds.push(await call(ctx,{operation:"cache-seed",key:`verification:${key}`,value:JSON.stringify({identifier:key,...data})}));}
  else {seeds.push(await call(ctx,{operation:"seed",identifier:sha(identifier),data:past}));seeds.push(await call(ctx,{operation:"seed",identifier,data:live}));}
  const before=await state(ctx),consumed=await call(ctx,{operation:"consume",profile:profile(mode),identifier});expect(consumed.status).toBe(200);expect(consumed.body).toBeNull();const after=await state(ctx);unchanged(other,after);
  if(mode==="cache")expect(after.cache).toEqual([]);else {expect(after.verifications).toHaveLength(1);expect(after.verifications[0]!.identifier).toBe(identifier);expect(after.events.map(row=>row.stage)).toEqual(["delete-before","delete-after"]);}
  const fallback=await call(ctx,{operation:"consume",profile:profile(mode),identifier});expect(mode==="cache"?fallback.body:(fallback.body as Row).value).toBe(mode==="cache"?null:"live-plain");
  return observed({foreign:other,seeds,before,consumed,after,fallback,final:await state(ctx)});
});

compatScenario("verification storage cache find preserves truthy raw data while consume separately hydrates expiry and legacy fallback",async ctx=>{
  const other=await foreign(ctx),observations=[];const identifier="cached-shape-owner",key=`verification:${sha(identifier)}`;
  for(const [kind,raw,expected] of [
    ["ISO reviver",'{"value":"actual","expiresAt":"2100-02-30T24:00:00.1234Z","nested":{"createdAt":"2020-02-30T00:00:00.12345Z"}}',null],
    ["truthy scalar",'"opaque cache value"',null],["empty object",'{}',null],["invalid date",'{"value":"actual","expiresAt":"not a date"}',null],
    ["numeric future",'{"value":"actual","expiresAt":4102444800000}',"actual"],["zero null expiry",'{"value":"actual","expiresAt":null}',null],
    ["numeric string legacy date",'{"value":"actual","expiresAt":"9999"}',"actual"],
  ] as const){
    await configure(ctx);await call(ctx,{operation:"clear-cache"});const seeded=await call(ctx,{operation:"cache-seed",key,value:raw}),found=await call(ctx,{operation:"find",profile:profile("cache"),identifier});expect(found.status).toBe(200);expect(found.body).toBeTruthy();
    const consumed=await call(ctx,{operation:"consume",profile:profile("cache"),identifier});expect(consumed.status).toBe(200);
    if(expected===null)expect(consumed.body).toBeNull();else expect((consumed.body as Row).value).toBe(expected);
    // Cached find deliberately accepts schema-invalid truthy JSON. Preserve its
    // entire returned body as JSON text rather than relabeling raw expiresAt as
    // a genuine Date for the ordinary timestamp contract.
    observations.push({kind,seeded,found:{...found,body:{rawJSON:JSON.stringify(found.body)}},consumed,state:await state(ctx)});
  }
  unchanged(other,await state(ctx));return observed({foreign:other,observations});
});

for(const phase of ["cancel","cache-error","after-error"] as const)compatScenario(`verification storage ${phase} preserves actual create publication and failure phases`,async ctx=>{
  const other=await foreign(ctx);await configure(ctx,phase==="cancel"?{"create-before":"cancel"}:phase==="after-error"?{"create-after":"throw"}:{},phase==="cache-error"?{set:true}:{});
  const before=await state(ctx),created=await call(ctx,{operation:"create",profile:profile("mixed"),identifier:"phase-owner",data:{value:"actual-proof",...jsonDates}}),after=await state(ctx);unchanged(other,after);
  expect(created.status).toBe(phase==="cancel"?200:500);if(phase==="cancel"){expect(created.body).toBeNull();expect(sql(after)).toEqual(sql(before));expect(after.cache).toEqual([]);}
  else{expect(after.verifications).toHaveLength(1);expect(after.cache).toHaveLength(phase==="cache-error"?0:1);}
  expect(after.events.map(row=>row.stage)).toEqual(phase==="after-error"?["create-before","create-after"]:["create-before"]);
  return observed({foreign:other,before,created,after});
});

compatScenario("verification storage mixed update and deletion publish cache before actual database veto and do not mutate plain fallback",async ctx=>{
  const other=await foreign(ctx);await configure(ctx);const identifier="update-delete-owner",created=await call(ctx,{operation:"create",profile:profile("mixed"),identifier,data:{value:"original",...jsonDates}});expect(created.status).toBe(200);
  const seeded=await call(ctx,{operation:"seed",identifier,data:{value:"legacy-plain",...jsonDates}});expect(seeded.status).toBe(200);
  await configure(ctx,{"update-before":"cancel"});const updated=await call(ctx,{operation:"update",profile:profile("mixed"),identifier,data:{value:"cached-patch"}});expect(updated.body).toBeNull();const patched=await state(ctx);unchanged(other,patched);expect(patched.verifications).toMatchObject([{value:"original"},{value:"legacy-plain"}]);expect(patched.cache[0]!.value.value).toBe("cached-patch");expect(patched.events.map(row=>row.stage)).toEqual(["update-before"]);expect(patched.events[0]!.cache).toEqual(patched.cache);
  await configure(ctx,{"delete-before":"cancel"});const denied=await call(ctx,{operation:"delete",profile:profile("mixed"),identifier});expect(denied.status).toBe(200);const vetoed=await state(ctx);expect(vetoed.verifications).toEqual(patched.verifications);expect(vetoed.cache).toEqual([]);expect(vetoed.events[0]!.cache).toEqual([]);
  await configure(ctx);const deleted=await call(ctx,{operation:"delete",profile:profile("mixed"),identifier}),after=await state(ctx);expect(after.verifications).toEqual([seeded.body as Row]);unchanged(other,after);
  return observed({foreign:other,created,seeded,updated,patched,denied,vetoed,deleted,after});
});

compatScenario("verification storage reservation uses logical deterministic primary authority without hooks and denies cache-only storage",async ctx=>{
  const other=await foreign(ctx);await configure(ctx);const identifier="reserve-logical-owner",observations=[];
  for(const mode of ["mixed","hashed","cache"] as const){const result=await call(ctx,{operation:"reserve",profile:profile(mode),identifier,data:{value:"reservation-proof",...jsonDates}});expect(result.status).toBe(mode==="cache"?500:200);if(mode!=="cache")expect(result.body).toBe(mode==="mixed");observations.push({mode,result,state:await state(ctx)});}
  const final=await state(ctx);unchanged(other,final);expect(final.verifications).toHaveLength(1);expect(final.verifications[0]!.id).toBe(sha(`reserve:${identifier}`));expect(final.verifications[0]!.identifier).toBe(sha(identifier));expect(final.events).toEqual([]);expect(final.cache).toHaveLength(1);expect(Object.hasOwn(final.cache[0]!.value,"createdAt")).toBe(false);expect(Object.hasOwn(final.cache[0]!.value,"updatedAt")).toBe(false);
  return observed({foreign:other,observations,final});
});
