import { expect } from "bun:test";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { authProfilePath } from "../../support/profiles";

function record(value:unknown):Record<string,any>{expect(value).not.toBeNull();expect(typeof value).toBe("object");return value as Record<string,any>;}
async function call(ctx:ScenarioContext,input:Record<string,unknown>,profile="server-dispatch"){const response=await ctx.rawRequest({path:`/__test/${profile}/call${input.physicalRequest?"?actual=query":""}`,method:"POST",json:input,...(input.physicalRequest?{headers:{host:"dispatch-owner.example.test",origin:"http://dispatch-owner.example.test"}}:{})});expect(response.status).toBe(200);return record(response.body);}
async function state(ctx:ScenarioContext){const response=await ctx.rawRequest({path:"/__test/server-dispatch/state"});expect(response.status).toBe(200);return record(response.body);}
async function signup(ctx:ScenarioContext,name="owner") {const {client}=ctx.actor(name,"server-dispatch");const response=await client.signUp.email({name,email:ctx.uniqueEmail(name),password:"Correct-Horse-Password-205"});expect(response.error).toBeNull();return record(response.data).user;}

const phases=["normal","patch","patch-existing-headers","cancel","before-error","before-api","matcher-error","after-api","after-error","after-value","handler-error","before-headers","request-patch"] as const;
for(const mode of phases)compatScenario(`server endpoint ${mode} retains actual hook phases patched validation and persisted OTP`,async ctx=>{
  const email=ctx.uniqueEmail(`endpoint-${mode}`);
  const patched=mode==="patch"||mode==="patch-existing-headers";
  const input=patched?{email:["invalid-original"],type:"email-verification",nested:{original:true},actions:["original"],literal:"after-retains"}:mode==="cancel"||mode==="handler-error"?{email:null,type:"wrong-original"}:{email,type:"email-verification"};
  const before=await state(ctx);
  const observed=await call(ctx,{operation:"createVerificationOTP",mode,body:input,...(mode==="request-patch"?{physicalRequest:true}:{}),...(mode==="patch-existing-headers"?{headers:{"x-original":"actual-logical"}}:{})});
  const after=await state(ctx);
  const events=observed.events as Record<string,any>[];
  expect(events[0]?.stage).toBe("user-before");expect(events[0]?.body).toEqual(input);
  expect(events[0]?.current.path).toBeNull();expect(events[0]?.current.body).toEqual(input);
  const stages=events.map(event=>event.stage);
  const writes=!(["cancel","before-error","before-api","matcher-error","handler-error"] as readonly string[]).includes(mode);
  expect(after.verification.length-before.verification.length).toBe(writes?1:0);
  expect(after.apikey).toEqual(before.apikey);expect(after.member).toEqual(before.member);expect(after.organization).toEqual(before.organization);expect(after.session).toEqual(before.session);
  if(writes){const generator=events.find(event=>event.stage==="otp-generator")!;expect(generator.input.email).toBe(patched?"firstpatch@example.test":email.toLowerCase());expect(generator.body).toEqual(patched?{email:"FirstPatch@Example.test",type:"sign-in"}:input);expect(generator.path).toBe("virtual:");expect(generator.current.path).toBe("virtual:");expect(generator.current.body).toEqual(generator.body);}
  if(patched){
    const later=events.find(event=>event.stage==="second-before")!;expect(later.body).toEqual(input);expect(later.headers).toEqual(mode==="patch-existing-headers"?{"x-original":"actual-logical"}:null);
    const afterHook=events.find(event=>event.stage==="user-after")!;expect(afterHook.body).toEqual({email:"FirstPatch@Example.test",type:"sign-in",nested:{original:true,user:true,first:true,second:true},actions:["second"],literal:"after-retains"});expect(afterHook.headers).toEqual({...mode==="patch-existing-headers"?{"x-original":"actual-logical"}:{},"x-user":"patched","x-first":"patched","x-second":"patched"});
    expect(afterHook.current.body).toEqual(input);expect(afterHook.current.headers).toEqual(afterHook.headers);expect(afterHook.current.path).toBeNull();
  }
  if(mode==="cancel"){expect(stages).toEqual(["user-before","first-matcher","first-before"]);expect(observed.result.value).toEqual({headers:{"x-before":"cancel"},response:{cancelled:true,body:input}});}
  if(mode==="before-headers")expect(observed.result.value.headers).toEqual({});
  if(mode==="request-patch"){
    expect(events.find(event=>event.stage==="second-before")?.request.headers["x-physical-patch"]).toBeUndefined();
    expect(events[0]?.request.query).toEqual({actual:"query"});expect(JSON.parse(events[0]?.request.body)).toEqual({operation:"createVerificationOTP",mode,body:input,physicalRequest:true});
    for(const stage of ["otp-generator","user-after","first-after","second-after"])expect(events.find(event=>event.stage===stage)?.request.headers["x-physical-patch"]).toBe("actual-clone");
    const generator=events.find(event=>event.stage==="otp-generator")!;expect(generator.current.request.headers["x-physical-patch"]).toBe("actual-clone");expect(generator.legacyRequest).toEqual(generator.request);
    for(const stage of ["user-before","first-before","second-before","user-after","first-after","second-after"]){const event=events.find(event=>event.stage===stage)!;expect(event.current.request.headers["x-physical-patch"]).toBeUndefined();expect(event.legacyRequest).toEqual(event.current.request);expect(event.current.path).toBeNull();}
  }
  if(["before-error","before-api","matcher-error"].includes(mode))expect(stages.some(stage=>stage.endsWith("-after"))).toBe(false);
  if(mode==="after-error"){expect(stages).toContain("first-after");expect(stages).not.toContain("second-after");}
  if(mode==="after-api"){expect(stages).toContain("second-after");expect(observed.result.body.code).toBe("APP_AFTER");expect(observed.result.headers).toEqual({"x-after":"api-error"});}
  if(mode==="handler-error"){expect(stages).toContain("second-after");expect(observed.result.status).toBe(400);expect(observed.result.body.code).toBe("VALIDATION_ERROR");}
  return {before,observed,after};
});

compatScenario("server endpoint actual API key establishes immediate principal and consumes both verification phases",async ctx=>{
  await call(ctx,{operation:"deleteAllExpiredApiKeys",mode:"reset-app"});
  const owner=await signup(ctx),foreign=await signup(ctx,"foreign");
  const created=await call(ctx,{operation:"createApiKey",body:{configId:"dispatch",userId:owner.id,name:"owned-dispatch-key",remaining:30,rateLimitEnabled:false,metadata:{owner:"application-owner",foreign:"application-foreign"}}});
  expect(created.result.ok).toBe(true);const key=created.result.value.response;
  const headers={"x-api-key":key.key,"user-agent":"Logical-only","x-forwarded-for":"198.51.100.21"};
  const before=await state(ctx);
  const otp=await call(ctx,{operation:"createVerificationOTP",headers,body:{email:ctx.uniqueEmail("virtual"),type:"email-verification"}});
  const events=otp.events as Record<string,any>[];
  expect(events.find(event=>event.stage==="first-before")?.session).toBeNull();
  for(const stage of ["second-matcher","second-before","otp-generator","user-after","first-after","second-after"]){const principal=events.find(event=>event.stage===stage)?.session;expect(principal.user.id).toBe(owner.id);expect(principal.session.token).toBe(key.key);expect(principal.session.ipAddress).toBeNull();expect(principal.session.userAgent).toBeNull();}
  expect(events.find(event=>event.stage==="otp-generator")?.path).toBe("/");
  const verified=await call(ctx,{operation:"verifyApiKey",headers,body:{configId:"dispatch",key:key.key}});
  expect(verified.result.value.response.valid).toBe(true);expect(verified.result.value.response.key.remaining).toBe(27);
  const after=await state(ctx);expect(after.session).toEqual(before.session);expect(after.apikey[0].requestCount).toBe(0);expect(after.apikey[0].remaining).toBe(27);
  const negativeBefore=await state(ctx);
  const rejected=await call(ctx,{operation:"createVerificationOTP",headers:{"x-api-key":"foreign-or-revoked-real-looking-secret"},body:{email:ctx.uniqueEmail("reject"),type:"email-verification"}});
  expect(rejected.result.ok).toBe(false);expect(rejected.result.body.code).toBe("INVALID_API_KEY");expect(rejected.events.map((event:Record<string,unknown>)=>event.stage)).not.toContain("second-before");
  const negativeAfter=await state(ctx);expect(negativeAfter).toEqual(negativeBefore);
  return {owner,foreign,created,before,otp,verified,after,negativeBefore,rejected,negativeAfter};
});

async function keyFor(ctx:ScenarioContext,userId:string,name:string,remaining=30){const created=await call(ctx,{operation:"createApiKey",body:{configId:"dispatch",userId,name,remaining,rateLimitEnabled:false}});expect(created.result.ok).toBe(true);return {created,key:created.result.value.response};}
async function signedSignup(ctx:ScenarioContext,name:string){const receipt:{cookie?:string}={};const result=await ctx.actor(name,"server-dispatch").client.signUp.email({name,email:ctx.uniqueEmail(name),password:"Correct-Horse-Password-205",fetchOptions:{onSuccess({response}){receipt.cookie=response.headers.getSetCookie().map(value=>value.split(";")[0]).join("; ");}}});expect(result.error).toBeNull();expect(receipt.cookie).toBeString();return {user:record(result.data).user,headers:{cookie:receipt.cookie!}};}

compatScenario("server endpoint authenticated logical principal belongs to its actual auth context",async ctx=>{
  await call(ctx,{operation:"deleteAllExpiredApiKeys",mode:"reset-app"});
  const owner=await signup(ctx),issued=await keyFor(ctx,owner.id,"scoped-actual-key");
  const before=await state(ctx);
  const observed=await call(ctx,{operation:"createVerificationOTP",mode:"scope-isolation",headers:{"x-api-key":issued.key.key},body:{email:ctx.uniqueEmail("scope"),type:"sign-in"}});
  expect(observed.result.ok).toBe(true);
  expect(observed.events.find((event:Record<string,any>)=>event.stage==="second-after").session.user.id).toBe(owner.id);
  expect(observed.events.find((event:Record<string,any>)=>event.stage==="other-context-session").session).toBeNull();
  const after=await state(ctx);expect(after.apikey[0].remaining).toBe(29);expect(after.session).toEqual(before.session);
  return {owner,issued,before,observed,after};
});

compatScenario("server endpoint organization members retain scoped authority and reject actual foreign and revoked keys",async ctx=>{
  await call(ctx,{operation:"deleteAllExpiredApiKeys",mode:"reset-app"});
  const owner=await signup(ctx),target=await signup(ctx,"target"),foreign=await signup(ctx,"foreign");
  const owned=await keyFor(ctx,owner.id,"owned-org-key"),foreignKey=await keyFor(ctx,foreign.id,"foreign-org-key"),revokedKey=await keyFor(ctx,owner.id,"revoked-org-key");
  const revoked=await call(ctx,{operation:"updateApiKey",body:{configId:"dispatch",keyId:revokedKey.key.id,userId:owner.id,enabled:false}});expect(revoked.result.ok).toBe(true);expect(revoked.result.value.response.enabled).toBe(false);
  const created=await call(ctx,{operation:"createOrganization",body:{name:"Actual dispatch organization",slug:"actual-dispatch-org",userId:owner.id}});expect(created.result.ok).toBe(true);const org=created.result.value.response;
  const added=await call(ctx,{operation:"addMember",body:{organizationId:org.id,userId:target.id,role:"member"},headers:{"x-api-key":owned.key.key}});expect(added.result.ok).toBe(true);const member=added.result.value.response;expect(member.userId).toBe(target.id);
  const before=await state(ctx);
  const rejected=[];
  for(const [name,headers] of [["guest",{}],["foreign",{"x-api-key":foreignKey.key.key}],["revoked",{"x-api-key":revokedKey.key.key}]] as const){const denial=await call(ctx,{operation:"removeMember",body:{organizationId:org.id,memberIdOrEmail:member.id},headers});expect(denial.result.ok).toBe(false);expect(denial.result.status).toBe(name==="foreign"?400:401);if(name==="revoked")expect(denial.result.body.code).toBe("KEY_DISABLED");rejected.push(denial);}
  const protectedState=await state(ctx);expect(protectedState.member).toEqual(before.member);expect(protectedState.organization).toEqual(before.organization);expect(protectedState.session).toEqual(before.session);expect(protectedState.verification).toEqual(before.verification);
  expect(protectedState.apikey.find((key:Record<string,any>)=>key.id===foreignKey.key.id).remaining).toBe(29);expect(protectedState.apikey.find((key:Record<string,any>)=>key.id===owned.key.id).remaining).toBe(29);
  expect(protectedState.apikey.find((key:Record<string,any>)=>key.id===revokedKey.key.id)).toEqual(before.apikey.find((key:Record<string,any>)=>key.id===revokedKey.key.id));
  const removed=await call(ctx,{operation:"removeMember",body:{organizationId:org.id,memberIdOrEmail:member.id},headers:{"x-api-key":owned.key.key}});expect(removed.result.ok).toBe(true);expect(removed.result.value.response.member.id).toBe(member.id);
  const final=await state(ctx);expect(final.member).toHaveLength(1);expect(final.member[0].userId).toBe(owner.id);expect(final.apikey.find((key:Record<string,any>)=>key.id===owned.key.id).remaining).toBe(28);expect(final.session).toEqual(before.session);
  return {owner,target,foreign,owned,foreignKey,revokedKey,revoked,created,added,before,rejected,protectedState,removed,final};
});

compatScenario("server endpoint JWT uses genuine signed and virtual principals with independent JOSE verification",async ctx=>{
  const {createLocalJWKSet,jwtVerify}=await import("jose");
  await call(ctx,{operation:"deleteAllExpiredApiKeys",mode:"reset-app"});
  const signed=await signedSignup(ctx,"jwt-owner"),issued=await keyFor(ctx,signed.user.id,"jwt-dispatch-key");
  const before=await state(ctx);
  const guestMissing=await call(ctx,{operation:"getToken"});expect(guestMissing.result.status).toBe(400);
  const guestEmpty=await call(ctx,{operation:"getToken",headers:{}});expect(guestEmpty.result.status).toBe(401);
  const physical=await call(ctx,{operation:"getToken",headers:signed.headers});expect(physical.result.ok).toBe(true);
  const jwks=await call(ctx,{operation:"getJwks"});expect(jwks.result.ok).toBe(true);
  const verifiedPhysical=await jwtVerify(physical.result.value.response.token,createLocalJWKSet(jwks.result.value.response));expect(verifiedPhysical.payload.sub).toBe(signed.user.id);expect(verifiedPhysical.payload.email).toBe(signed.user.email);
  const virtual=await call(ctx,{operation:"getToken",headers:{"x-api-key":issued.key.key}});expect(virtual.result.ok).toBe(true);const verifiedVirtual=await jwtVerify(virtual.result.value.response.token,createLocalJWKSet(jwks.result.value.response));expect(verifiedVirtual.payload.sub).toBe(signed.user.id);
  const explicit=await call(ctx,{operation:"signJWT",body:{payload:{iat:100,exp:4102444800,sub:"application-subject",custom:["a","b"]}}});expect(explicit.result.ok).toBe(true);const verifiedExplicit=await jwtVerify(explicit.result.value.response.token,createLocalJWKSet(jwks.result.value.response));expect(verifiedExplicit.payload.custom).toEqual(["a","b"]);
  const serverVerified=await call(ctx,{operation:"verifyJWT",body:{token:explicit.result.value.response.token}});expect(serverVerified.result.value.response.payload).toEqual(verifiedExplicit.payload);
  const invalid=await call(ctx,{operation:"verifyJWT",body:{token:`${explicit.result.value.response.token}tampered`}});expect(invalid.result.value.response.payload).toBeNull();
  const after=await state(ctx);expect(after.session).toEqual(before.session);expect(after.apikey[0].remaining).toBe(29);
  return {signed,issued,before,guestMissing,guestEmpty,physical,jwks,verifiedPhysical,virtual,verifiedVirtual,explicit,verifiedExplicit,serverVerified,invalid,after};
});

compatScenario("server endpoint OTT consumes once and publishes actual cookies without a physical request",async ctx=>{
  await call(ctx,{operation:"deleteAllExpiredApiKeys",mode:"reset-app"});
  const signed=await signedSignup(ctx,"ott-owner"),issued=await keyFor(ctx,signed.user.id,"ott-dispatch-key");
  const before=await state(ctx);
  const guest=await call(ctx,{operation:"generateOneTimeToken",headers:{}});expect(guest.result.status).toBe(401);
  const generated=await call(ctx,{operation:"generateOneTimeToken",headers:signed.headers});expect(generated.result.ok).toBe(true);
  const stored=await state(ctx);expect(stored.verification).toHaveLength(1);
  const verified=await call(ctx,{operation:"verifyOneTimeToken",body:{token:generated.result.value.response.token}});expect(verified.result.ok).toBe(true);expect(verified.result.value.response.user.id).toBe(signed.user.id);expect(verified.result.value.headers["set-cookie"]).toContain("better-auth.session_token=");
  const cookie=verified.result.value.headers["set-cookie"].split(";")[0];const restored=await ctx.rawRequest({path:`${authProfilePath("server-dispatch")}/get-session`,headers:{cookie},actor:"restored-ott"});expect(restored.status).toBe(200);expect(record(restored.body).user.id).toBe(signed.user.id);
  const consumed=await state(ctx);expect(consumed.verification).toEqual([]);
  const replay=await call(ctx,{operation:"verifyOneTimeToken",body:{token:generated.result.value.response.token}});expect(replay.result.status).toBe(400);expect(await state(ctx)).toEqual(consumed);
  const virtual=await call(ctx,{operation:"generateOneTimeToken",headers:{"x-api-key":issued.key.key}});expect(virtual.result.ok).toBe(true);
  const virtualRejected=await call(ctx,{operation:"verifyOneTimeToken",body:{token:virtual.result.value.response.token}});expect(virtualRejected.result.status).toBe(400);expect(virtualRejected.result.message).toBe("Session not found");
  const after=await state(ctx);expect(after.session).toEqual(before.session);expect(after.verification).toEqual([]);expect(after.apikey[0].remaining).toBe(29);
  return {signed,issued,before,guest,generated,stored,verified,restored,consumed,replay,virtual,virtualRejected,after};
});

compatScenario("server endpoint factor operations execute actual crypto and decrypt real enrolled backup codes",async ctx=>{
  const {hotpAtCounter}=await import("../two-factor/totp-helper");
  await call(ctx,{operation:"deleteAllExpiredApiKeys",mode:"reset-app"});
  const signed=await signedSignup(ctx,"factor-owner"),issued=await keyFor(ctx,signed.user.id,"factor-dispatch-key");
  const enabled=await ctx.rawRequest({path:`${authProfilePath("server-dispatch")}/two-factor/enable`,method:"POST",actor:"factor-owner",headers:signed.headers,json:{password:"Correct-Horse-Password-205"}});expect(enabled.status).toBe(200);
  const before=await state(ctx);
  const viewed=await call(ctx,{operation:"viewBackupCodes",headers:{"x-api-key":issued.key.key},body:{userId:signed.user.id}});expect(viewed.result.ok).toBe(true);expect(viewed.result.value.response.backupCodes).toEqual(record(enabled.body).backupCodes);expect(viewed.result.value.response.backupCodes).toEqual(["application-backup-one","application-backup-two"]);
  const missing=await call(ctx,{operation:"viewBackupCodes",body:{userId:"missing-real-user"}});expect(missing.result.ok).toBe(false);
  const secret="application-owned-totp-secret-205";const counter=Math.floor(Date.now()/30_000);
  const generated=await call(ctx,{operation:"generateTOTP",body:{secret}});expect(generated.result.ok).toBe(true);const expected=await hotpAtCounter(new TextEncoder().encode(secret),6,counter);expect(generated.result.value.response.code).toBe(expected);
  const after=await state(ctx);expect(after.member).toEqual(before.member);expect(after.organization).toEqual(before.organization);expect(after.session).toEqual(before.session);expect(after.verification).toEqual(before.verification);expect(after.apikey[0].remaining).toBe(29);
  return {signed,issued,before,viewed,missing,generated,after};
});

compatScenario("server endpoint API key schema failures retain nested ordered errors before callback quota or storage effects",async ctx=>{
  await call(ctx,{operation:"deleteAllExpiredApiKeys",mode:"reset-app"});
  const owner=await signup(ctx),issued=await keyFor(ctx,owner.id,"schema-owned-key");
  const before=await state(ctx);
  const cases=[
    {operation:"verifyApiKey",body:{key:issued.key.key,configId:"dispatch",permissions:{resource:["read",4]}},message:"[body.permissions.resource.1] Invalid input: expected string, received number"},
    {operation:"verifyApiKey",body:{key:issued.key.key,permissions:{resource:"read"}},message:"[body.permissions.resource] Invalid input: expected array, received string"},
    {operation:"verifyApiKey",body:{key:null,configId:1,permissions:null},message:"[body.configId] Invalid input: expected string, received number; [body.key] Invalid input: expected string, received null; [body.permissions] Invalid input: expected record, received null"},
    {operation:"createApiKey",body:{name:7,prefix:false,userId:[],expiresIn:"wrong"},message:"[body.name] Invalid input: expected string, received number; [body.expiresIn] Invalid input: expected number, received string; [body.prefix] Invalid input: expected string, received boolean"},
    {operation:"updateApiKey",body:{keyId:null,enabled:"true"},message:"[body.keyId] Invalid input: expected string, received null; [body.enabled] Invalid input: expected boolean, received string"},
  ];
  const rejected=[];
  for(const input of cases){const observed=await call(ctx,{operation:input.operation,body:input.body});expect(observed.result.ok).toBe(false);expect(observed.result.status).toBe(400);expect(observed.result.body).toEqual({message:input.message,code:"VALIDATION_ERROR"});expect(observed.events.map((event:Record<string,any>)=>event.stage)).not.toContain("api-key-validator");expect(observed.events.map((event:Record<string,any>)=>event.stage)).toContain("second-after");expect(await state(ctx)).toEqual(before);rejected.push(observed);}
  const verified=await call(ctx,{operation:"verifyApiKey",body:{key:issued.key.key,configId:"dispatch"}});expect(verified.result.ok).toBe(true);expect(verified.result.value.response.valid).toBe(true);expect(verified.result.value.response.key.remaining).toBe(29);
  const after=await state(ctx);expect(after.apikey[0].remaining).toBe(29);expect(after.session).toEqual(before.session);expect(after.verification).toEqual(before.verification);expect(after.organization).toEqual(before.organization);expect(after.member).toEqual(before.member);
  return {owner,issued,before,rejected,verified,after};
});

for(const [mode,physicalRequest] of [["hash-phase",true],["hash-phase",false],["hash-phase-deny",true]] as const)compatScenario(`server endpoint ${mode} physical=${physicalRequest} hashes in its actual raw and handler frames`,async ctx=>{
  const {createHash}=await import("node:crypto");
  const {verifyPassword}=await import("better-auth/crypto");
  const password="Actual-Phase-Hash-Password-205",digest=createHash("sha1").update(password).digest("hex").toUpperCase();
  const before=await state(ctx),body={email:ctx.uniqueEmail("hash-frame"),type:"sign-in"};
  const observed=await call(ctx,{operation:"createVerificationOTP",mode,body,...physicalRequest?{physicalRequest:true}:{}});
  const hashes=observed.events.filter((event:Record<string,any>)=>event.stage==="original-hash") as Record<string,any>[];
  expect(hashes.map(event=>event.phase)).toEqual(mode==="hash-phase-deny"?["before","after"]:["before","handler","after"]);
  for(const event of hashes){
    expect(event.verified).toBe(true);expect(event.hash.token).toMatch(/^[a-f0-9]{32}:[a-f0-9]{128}$/);
    const [salt,key]=event.hash.token.split(":");expect(event.hash).toEqual({token:event.hash.token,salt:{token:salt,length:32},derivedKey:{token:key,length:128},encoding:"hex-lower"});
    expect(await verifyPassword({hash:event.hash.token,password})).toBe(true);expect(await verifyPassword({hash:event.hash.token,password:"Actual-Foreign-Password-205"})).toBe(false);
    expect(event.path).toBe(event.phase==="handler"?"virtual:":null);
    if(physicalRequest){expect(event.request.query).toEqual({actual:"query"});expect(event.request.headers["x-physical-patch"]).toBe(event.phase==="handler"?"actual-clone":undefined);expect(JSON.parse(event.request.body)).toEqual({operation:"createVerificationOTP",mode,body,physicalRequest:true});}
    else expect(event.request).toBeNull();
  }
  expect(observed.ranges).toEqual([{method:"GET",path:`/range/${digest.slice(0,5)}`,query:"",headers:{addPadding:"true",userAgent:"BetterAuth Password Checker",authorization:null,cookie:null},body:""}]);
  expect(JSON.stringify(observed.ranges)).not.toContain(password);expect(JSON.stringify(observed.ranges)).not.toContain(digest.slice(5));
  if(mode==="hash-phase-deny"){expect(observed.result.ok).toBe(false);expect(observed.result.status).toBe(400);expect(observed.result.body.code).toBe("PASSWORD_COMPROMISED");}
  else {expect(observed.result.ok).toBe(true);expect(observed.result.value.response).toBe("591307");}
  const after=await state(ctx);expect(after.verification.length-before.verification.length).toBe(mode==="hash-phase-deny"?0:1);
  expect(after.apikey).toEqual(before.apikey);expect(after.member).toEqual(before.member);expect(after.organization).toEqual(before.organization);expect(after.session).toEqual(before.session);
  return {before,observed,after};
});


const dispatchSecret="compat-test-only-key-not-real-minimum-32chars";
async function cacheReceipt(headers:Headers){
  const {createHmac}=await import("node:crypto"),{getCookieCache}=await import("better-auth/cookies");
  const rawCookies=headers.getSetCookie().filter(raw=>raw.startsWith("better-auth.session_data="));expect(rawCookies).toHaveLength(1);
  const token=decodeURIComponent(rawCookies[0]!.split(";")[0]!.slice("better-auth.session_data=".length));
  const envelope=JSON.parse(Buffer.from(token,"base64url").toString()),observedAt=Date.now();
  expect(envelope.signature).toBe(createHmac("sha256",dispatchSecret).update(JSON.stringify({...envelope.session,expiresAt:envelope.expiresAt})).digest("base64url"));
  const decoded=await getCookieCache(new Headers({cookie:rawCookies[0]!.split(";")[0]!}),{secret:dispatchSecret,strategy:"compact"});expect(decoded).not.toBeNull();
  return {compactSessionCache:{token,envelope,decoded,observedAt,effectiveMaxAgeSeconds:300,rawCookies}};
}
for(const mode of ["ordinary","cached","cached-version"] as const)compatScenario(`server endpoint ${mode} signed organization handler keeps session local while actual API key middleware shares principal`,async ctx=>{
  const compact=mode!=="ordinary",versioned=mode==="cached-version";
  const {createHmac}=await import("node:crypto"),{createLocalJWKSet,jwtVerify}=await import("jose");
  const profile=versioned?"server-dispatch-cache-version":compact?"server-dispatch-cache":"server-dispatch";
  const invoke=(input:Record<string,unknown>)=>call(ctx,input,profile);
  const read=async()=>{const result=await ctx.rawRequest({path:`/__test/${profile}/state`});expect(result.status).toBe(200);return record(result.body);};
  await invoke({operation:"deleteAllExpiredApiKeys",mode:"reset-app"});
  async function issue(name:string){
    let headers:Headers|undefined;
    const response=await ctx.actor(name,profile).client.signUp.email({name,email:ctx.uniqueEmail(name),password:"Correct-Horse-Password-205",fetchOptions:{onSuccess({response}){headers=new Headers(response.headers);}}});expect(response.error).toBeNull();expect(headers).toBeDefined();
    const result=record(response.data),rawCookies=headers!.getSetCookie(),cookie=rawCookies.map(raw=>raw.split(";")[0]).join("; ");
    const signed=decodeURIComponent(rawCookies.find(raw=>raw.startsWith("better-auth.session_token="))!.split(";")[0]!.slice("better-auth.session_token=".length));
    expect(signed).toBe(`${result.token}.${createHmac("sha256",dispatchSecret).update(result.token).digest("base64")}`);
    const issued=compact?await cacheReceipt(headers!):null;
    if(issued){expect(issued.compactSessionCache.decoded!.user.id).toBe(result.user.id);expect(issued.compactSessionCache.decoded!.session.token).toBe(result.token);}
    return {result,response:{headers:{"set-cookie":headers!.get("set-cookie")}},headers:{cookie},issued};
  }
  const owner=await issue("composed-owner"),target=await issue("composed-target"),foreign=await issue("composed-foreign");
  const before=await read();
  const token=await invoke({operation:"getToken",headers:owner.headers});expect(token.result.ok).toBe(true);
  const jwks=await invoke({operation:"getJwks"});expect(jwks.result.ok).toBe(true);
  const verifier=createLocalJWKSet(jwks.result.value.response);
  const verified=await jwtVerify(token.result.value.response.token,verifier);expect(verified.payload.sub).toBe(owner.result.user.id);expect(verified.payload.email).toBe(owner.result.user.email);
  async function laterSessionRead(actor:string,path:string,headers:Record<string,string>,previous:{token:string;payload:typeof verified.payload}){
    const previousSecond=previous.payload.iat!;expect(Number.isInteger(previousSecond)).toBe(true);
    while(Math.floor(Date.now()/1000)<=previousSecond)await Bun.sleep(Math.max(1,(previousSecond+1)*1000-Date.now()));
    const startedAt=Date.now(),response=await ctx.actor(actor).fetch(path,{method:"GET",headers}),body=await response.json(),finishedAt=Date.now();
    const rawJwt=response.headers.get("set-auth-jwt");expect(rawJwt).toBeString();
    const signed=await jwtVerify(rawJwt!,verifier),iat=signed.payload.iat!,exp=signed.payload.exp!;
    expect(Number.isInteger(iat)).toBe(true);expect(iat).toBeGreaterThan(previousSecond);
    expect(iat).toBeGreaterThanOrEqual(Math.floor(startedAt/1000));expect(iat).toBeLessThanOrEqual(Math.floor(finishedAt/1000));expect(exp-iat).toBe(900);
    expect(signed.payload.sub).toBe(owner.result.user.id);expect(signed.payload.sub).not.toBe(foreign.result.user.id);expect(signed.payload.email).toBe(owner.result.user.email);
    expect(signed.payload).toEqual({...previous.payload,iat,exp});
    expect(rawJwt).not.toBe(previous.token);
    return {status:response.status,location:response.headers.get("location"),body,jwt:{token:rawJwt!,header:signed.protectedHeader,payload:signed.payload},issuanceWindow:{startedAt:new Date(startedAt).toISOString(),finishedAt:new Date(finishedAt).toISOString()}};
  }
  const generated=await invoke({operation:"generateOneTimeToken",headers:owner.headers});expect(generated.result.ok).toBe(true);
  const consumed=await invoke({operation:"verifyOneTimeToken",body:{token:generated.result.value.response.token}});expect(consumed.result.ok).toBe(true);expect(consumed.result.value.response.user.id).toBe(owner.result.user.id);
  const {splitSetCookieHeader}=await import("better-auth/cookies");
  const restoredHeaders=new Headers();for(const raw of splitSetCookieHeader(consumed.result.value.headers["set-cookie"]))restoredHeaders.append("set-cookie",raw);
  const restoredCookies=restoredHeaders.getSetCookie(),restoredCache=compact?await cacheReceipt(restoredHeaders):null;
  const restored=await laterSessionRead("actual-restored-owner",`${authProfilePath(profile)}/get-session`,{cookie:restoredCookies.map(raw=>raw.split(";")[0]).join("; ")},{token:token.result.value.response.token,payload:verified.payload});expect(restored.status).toBe(200);expect(record(restored.body).session.token).toBe(owner.result.token);
  const consumedState=await read(),replay=await invoke({operation:"verifyOneTimeToken",body:{token:generated.result.value.response.token}});expect(replay.result.status).toBe(400);expect(await read()).toEqual(consumedState);
  for(const operation of [token,generated])for(const stage of ["user-after","first-after","second-after"]){const event=operation.events.find((event:Record<string,any>)=>event.stage===stage);expect(Object.keys(event.session).sort()).toEqual(["session","user"]);expect(Object.keys(event.current.session).sort()).toEqual(["session","user"]);expect(event.session.user.id).toBe(owner.result.user.id);expect(event.session.session.token).toBe(owner.result.token);expect(event.session.updatedAt).toBeUndefined();expect(event.session.version).toBeUndefined();}
  const created=await invoke({operation:"createOrganization",headers:owner.headers,body:{name:"Actual scoped composed organization",slug:"actual-composed-signed-org"}});expect(created.result.ok).toBe(true);const organization=created.result.value.response;
  for(const stage of ["user-before","first-before","second-before","user-after","first-after","second-after"]){const event=created.events.find((event:Record<string,any>)=>event.stage===stage);expect(event.session).toBeNull();expect(event.current.session).toBeNull();}
  const createdSession=await laterSessionRead("actual-created-session",`${authProfilePath(profile)}/get-session?disableCookieCache=true&disableRefresh=true`,owner.headers,restored.jwt);expect(createdSession.status).toBe(200);expect(record(createdSession.body).session.activeOrganizationId).toBe(organization.id);
  const added=await invoke({operation:"addMember",headers:owner.headers,body:{organizationId:organization.id,userId:target.result.user.id,role:"member"}});expect(added.result.ok).toBe(true);
  const protectedBefore=await read(),denied=await invoke({operation:"removeMember",headers:foreign.headers,body:{organizationId:organization.id,memberIdOrEmail:added.result.value.response.id}});expect(denied.result.ok).toBe(false);expect(denied.result.status).toBe(400);const protectedAfter=await read();expect(protectedAfter).toEqual(protectedBefore);
  const removed=await invoke({operation:"removeMember",headers:owner.headers,body:{organizationId:organization.id,memberIdOrEmail:added.result.value.response.id}});expect(removed.result.ok).toBe(true);
  const deleted=await invoke({operation:"deleteOrganization",headers:owner.headers,body:{organizationId:organization.id}});expect(deleted.result.ok).toBe(true);
  const deletedSession=await laterSessionRead("actual-deleted-session",`${authProfilePath(profile)}/get-session?disableCookieCache=true&disableRefresh=true`,owner.headers,createdSession.jwt);expect(deletedSession.status).toBe(200);expect(record(deletedSession.body).session.activeOrganizationId).toBe(compact?organization.id:null);
  const trustedCreated=await invoke({operation:"createOrganization",body:{name:"Actual supplied composed organization",slug:"actual-composed-supplied-org",userId:owner.result.user.id}});expect(trustedCreated.result.ok).toBe(true);
  const trustedAdded=await invoke({operation:"addMember",body:{organizationId:trustedCreated.result.value.response.id,userId:target.result.user.id,role:"member"}});expect(trustedAdded.result.ok).toBe(true);
  for(const operation of [added,removed,deleted,trustedCreated,trustedAdded])for(const stage of ["user-before","first-before","second-before","user-after","first-after","second-after"]){const event=operation.events.find((event:Record<string,any>)=>event.stage===stage);expect(event.session).toBeNull();expect(event.current.session).toBeNull();}
  const key=await invoke({operation:"createApiKey",body:{configId:"dispatch",userId:owner.result.user.id,name:"composed-virtual-owner",remaining:30,rateLimitEnabled:false}});expect(key.result.ok).toBe(true);
  const virtualHeaders={"x-api-key":key.result.value.response.key};
  const virtualRemoved=await invoke({operation:"removeMember",headers:virtualHeaders,body:{organizationId:trustedCreated.result.value.response.id,memberIdOrEmail:trustedAdded.result.value.response.id}});expect(virtualRemoved.result.ok).toBe(true);
  const virtualDeleted=await invoke({operation:"deleteOrganization",headers:virtualHeaders,body:{organizationId:trustedCreated.result.value.response.id}});expect(virtualDeleted.result.ok).toBe(true);
  for(const operation of [virtualRemoved,virtualDeleted]){expect(operation.events.find((event:Record<string,any>)=>event.stage==="first-before").session).toBeNull();for(const stage of ["second-before","user-after","first-after","second-after"]){const event=operation.events.find((event:Record<string,any>)=>event.stage===stage);expect(event.session.user.id).toBe(owner.result.user.id);expect(event.session.session.token).toBe(key.result.value.response.key);expect(event.session).toEqual(event.current.session);expect(event.session.session.ipAddress).toBeNull();expect(event.session.session.userAgent).toBeNull();}}
  const after=await read();for(const session of after.session){const original=before.session.find((row:Record<string,any>)=>row.id===session.id);expect(original).toBeDefined();expect(session).toEqual({...original,updatedAt:session.userId===owner.result.user.id?session.updatedAt:original.updatedAt,activeOrganizationId:session.userId===owner.result.user.id&&compact?organization.id:original.activeOrganizationId});if(session.userId===owner.result.user.id){expect(Date.parse(session.updatedAt)).toBe(Date.parse(record(deletedSession.body).session.updatedAt));expect(Date.parse(session.updatedAt)).toBeGreaterThanOrEqual(Date.parse(original.updatedAt));}}expect(after.organization).toEqual([]);expect(after.member).toEqual([]);expect(after.verification).toEqual([]);expect(after.apikey).toHaveLength(1);expect(after.apikey[0].remaining).toBe(28);
  if(versioned){
    for(const operation of [token,generated,created,added,denied,removed,deleted]){
      const versions=operation.events.filter((event:Record<string,any>)=>event.stage==="cache-version");expect(versions).toHaveLength(1);
      const event=versions[0];expect(event.current.method).toBe("GET");expect(event.current.query).toEqual({});expect(event.current.session).toBeNull();
      expect(event.current.request).toBeNull();
      expect(event.session.token).toBe(operation===denied?foreign.result.token:owner.result.token);
      expect(event.user.id).toBe(operation===denied?foreign.result.user.id:owner.result.user.id);
    }
    const published=consumed.events.filter((event:Record<string,any>)=>event.stage==="cache-version");expect(published).toHaveLength(1);expect(published[0].current.method).toBe("POST");expect(published[0].current.query).toBeNull();expect(published[0].current.request).toBeNull();
    for(const operation of [virtualRemoved,virtualDeleted])expect(operation.events.filter((event:Record<string,any>)=>event.stage==="cache-version")).toEqual([]);
  }
  return {mode,compact,owner,target,foreign,before,token,jwks,verified,generated,consumed,restoredCache,restored,consumedState,replay,created,createdSession,added,protectedBefore,denied,protectedAfter,removed,deleted,deletedSession,trustedCreated,trustedAdded,key,virtualRemoved,virtualDeleted,after};
},[],20_000);


compatScenario("server endpoint nested getter retains its real incoming POST request and authenticated header owner",async ctx=>{
  const {createHmac}=await import("node:crypto"),{createLocalJWKSet,jwtVerify}=await import("jose");
  const profile="server-dispatch-cache-version" as const;
  async function issue(name:string){
    let headers:Headers|undefined;const signup=await ctx.actor(name,profile).client.signUp.email({name,email:ctx.uniqueEmail(name),password:"Correct-Horse-Password-205",fetchOptions:{onSuccess({response}){headers=new Headers(response.headers);}}});expect(signup.error).toBeNull();expect(headers).toBeDefined();
    const result=record(signup.data),rawCookies=headers!.getSetCookie(),signed=decodeURIComponent(rawCookies.find(raw=>raw.startsWith("better-auth.session_token="))!.split(";")[0]!.slice("better-auth.session_token=".length));expect(signed).toBe(`${result.token}.${createHmac("sha256",dispatchSecret).update(result.token).digest("base64")}`);
    return {signup,result,issued:await cacheReceipt(headers!),headers:{cookie:rawCookies.map(raw=>raw.split(";")[0]).join("; ")}};
  }
  const owner=await issue("incoming-owner"),foreign=await issue("incoming-foreign");
  const read=async()=>record((await ctx.rawRequest({path:`/__test/${profile}/state`})).body),before=await read();
  const input={operation:"getToken",physicalRequest:true,logicalRequestHeaders:true};
  async function incoming(name:string,cookie?:string){const response=await ctx.rawRequest({path:`/__test/${profile}/call?actual=query`,method:"POST",actor:name,headers:{host:"dispatch-owner.example.test",origin:"http://dispatch-owner.example.test",...(cookie?{cookie}:{})},json:input});expect(response.status).toBe(200);return record(response.body);}
  const owned=await incoming("incoming-read",owner.headers.cookie),foreignRead=await incoming("foreign-incoming-read",foreign.headers.cookie);expect(owned.result.ok).toBe(true);expect(foreignRead.result.ok).toBe(true);
  const jwks=await call(ctx,{operation:"getJwks"},profile);expect(jwks.result.ok).toBe(true);const verifier=createLocalJWKSet(jwks.result.value.response);
  const ownedVerified=await jwtVerify(owned.result.value.response.token,verifier),foreignVerified=await jwtVerify(foreignRead.result.value.response.token,verifier);expect(ownedVerified.payload.sub).toBe(owner.result.user.id);expect(foreignVerified.payload.sub).toBe(foreign.result.user.id);expect(foreignVerified.payload.sub).not.toBe(owner.result.user.id);
  for(const [observed,principal] of [[owned,owner],[foreignRead,foreign]] as const){
    const versions=observed.events.filter((event:Record<string,any>)=>event.stage==="cache-version");expect(versions).toHaveLength(1);const event=versions[0];expect(event.user.id).toBe(principal.result.user.id);expect(event.session.token).toBe(principal.result.token);
    expect(event.current.method).toBe("GET");expect(event.current.query).toEqual({});expect(event.current.body).toBeNull();expect(event.current.session).toBeNull();expect(event.current.request.method).toBe("POST");expect(event.current.request.query).toEqual({actual:"query"});expect(event.current.request.body).toBe(JSON.stringify(input));expect(event.current.headers).toEqual(event.current.request.headers);expect(event.current.request.headers["content-length"]).toBe(String(Buffer.byteLength(JSON.stringify(input))));
    for(const stage of ["user-before","user-after"]){const callback=observed.events.find((event:Record<string,any>)=>event.stage===stage);expect(callback.request.body).toBe(JSON.stringify(input));expect(callback.current.request).toEqual(callback.legacyRequest);}
  }
  const guest=await incoming("incoming-guest");expect(guest.result.ok).toBe(false);expect(guest.result.status).toBe(401);expect(guest.events.filter((event:Record<string,any>)=>event.stage==="cache-version")).toEqual([]);
  const after=await read();expect(after).toEqual(before);
  return {input,owner,foreign,before,owned,foreignRead,jwks,ownedVerified,foreignVerified,guest,after};
});
