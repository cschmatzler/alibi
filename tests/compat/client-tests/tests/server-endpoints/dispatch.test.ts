import { expect } from "bun:test";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { authProfilePath } from "../../support/profiles";

function record(value:unknown):Record<string,any>{expect(value).not.toBeNull();expect(typeof value).toBe("object");return value as Record<string,any>;}
async function call(ctx:ScenarioContext,input:Record<string,unknown>){const response=await ctx.rawRequest({path:"/__test/server-dispatch/call",method:"POST",json:input,...(input.physicalRequest?{headers:{host:"dispatch-owner.example.test",origin:"http://dispatch-owner.example.test"}}:{})});expect(response.status).toBe(200);return record(response.body);}
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
