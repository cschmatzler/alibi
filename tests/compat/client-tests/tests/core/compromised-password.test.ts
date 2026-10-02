import {expect} from "bun:test";
import {createAuthClient} from "better-auth/client";
import {createTracingFetch,type TraceEntry} from "../../support/trace";
import {createHash} from "node:crypto";
import {verifyPassword} from "better-auth/crypto";
import {compatScenario,type ScenarioContext} from "../../support/scenario";
import type {FixtureProfile} from "../../support/profiles";

type Row=Record<string,unknown>;
type State={users:Row[];accounts:Row[];sessions:Row[];verifications:Row[];events:Row[];receipts:Row[]};
const DEFAULT_MESSAGE="The password you entered has been compromised. Please choose a different password.";
const RETRY_MESSAGE="Failed to check password. Please try again later.";
const password="Compromised-é-Password123";
function sha1(value:string) {return createHash("sha1").update(value,"utf8").digest("hex").toUpperCase();}
function suffix(value:string) {return sha1(value).slice(5);}
async function control(ctx:ScenarioContext,body:Row,actor?:string) {
  if(!actor)return ctx.rawRequest({path:"/__test/compromised-password",method:"POST",json:body});
  const response=await ctx.actor(actor,body.profile as FixtureProfile).fetch(ctx.baseURL+"/__test/compromised-password",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});
  return {status:response.status,location:response.headers.get("location"),body:await response.json() as unknown};
}
async function range(ctx:ScenarioContext,body="",status=200,contentType="text/plain") {
  const result=await control(ctx,{operation:"range",body,status,contentType});expect(result.status).toBe(200);return result;
}
async function state(ctx:ScenarioContext) {
  const result=await ctx.rawRequest({path:"/__test/compromised-password/state"});expect(result.status).toBe(200);return result.body as State;
}
function hash(value:unknown) {
  if(typeof value!=="string"||value==="")return value;
  expect(value).toMatch(/^[a-f0-9]{32}:[a-f0-9]{128}$/);
  const [salt,key]=value.split(":");return {token:value,salt:{token:salt,length:32},derivedKey:{token:key,length:128},encoding:"hex-lower"};
}
function observed(s:State) {
  return {...s,accounts:s.accounts.map(row=>({...row,password:hash(row.password)})),
    verifications:s.verifications.map(row=>{
      if(typeof row.identifier==="string"&&row.identifier.startsWith("reset-password:"))return {...row,identifier:{prefix:"reset-password:",token:row.identifier.slice(15)},value:{userId:row.value}};
      if(typeof row.value==="string"&&/^\d{6}:\d+$/.test(row.value)) {const [otp,attempts]=row.value.split(":");return {...row,value:{token:otp,length:6,attempts,separator:":"}};}
      return row;
    }),events:s.events.map(event=>({...event,...typeof event.hash==="string"?{hash:hash(event.hash)}:{},
      ...typeof event.otp==="string"?{otp:{token:event.otp,length:event.otp.length}}:{},
      ...typeof event.code==="string"&&/^\d{6}$/.test(event.code)?{code:{token:event.code,length:6}}:{}}))};
}
function rows(s:State) {return {users:s.users,accounts:s.accounts,sessions:s.sessions,verifications:s.verifications};}
function stages(s:State) {return s.events.map(event=>event.stage);}
function receipt(s:State,pw:string,count=1) {
  expect(s.receipts).toHaveLength(count);
  for(const r of s.receipts)expect(r).toEqual({method:"GET",path:`/range/${sha1(pw).slice(0,5)}`,query:"",headers:{addPadding:"true",userAgent:"BetterAuth Password Checker",authorization:null,cookie:null},body:""});
  expect(JSON.stringify(s.receipts)).not.toContain(pw);expect(JSON.stringify(s.receipts)).not.toContain(suffix(pw));
}
async function foreign(ctx:ScenarioContext) {
  await range(ctx);
  const signup=await ctx.actor("foreign","pwned-default").client.signUp.email({email:ctx.uniqueEmail("pwned-foreign"),name:"Unrelated Principal",password:"foreign-password123"});
  expect(signup.error).toBeNull();return {signup,state:await ctx.readUserState({userId:signup.data!.user.id})};
}
async function unchanged(ctx:ScenarioContext,other:Awaited<ReturnType<typeof foreign>>) {expect(await ctx.readUserState({userId:other.signup.data!.user.id})).toEqual(other.state);}

compatScenario("compromised password signup denies before real hashing and user creation with prefix-only HTTP",async ctx=>{
  const other=await foreign(ctx),configured=await range(ctx,`${suffix(password)}:4\r\n`),before=await state(ctx);
  const rejected=await ctx.actor("rejected","pwned-default").client.signUp.email({email:ctx.uniqueEmail("pwned-denied"),name:"Denied Principal",password});
  expect(rejected.error).toMatchObject({status:400,code:"PASSWORD_COMPROMISED",message:DEFAULT_MESSAGE});
  const after=await state(ctx);expect(rows(after)).toEqual(rows(before));expect(stages(after)).toEqual(["range"]);receipt(after,password);
  const configuredClean=await range(ctx,`${suffix(password)}:0\n`),accepted=await ctx.actor("accepted","pwned-default").client.signUp.email({email:ctx.uniqueEmail("pwned-clean"),name:"Admitted Principal",password});
  expect(accepted.error).toBeNull();const admitted=await state(ctx);expect(stages(admitted)).toEqual(["range","hash-enter","hash-result","user-create"]);receipt(admitted,password);
  const credential=admitted.accounts.find(row=>row.userId===accepted.data!.user.id)!;
  expect(await verifyPassword({hash:String(credential.password),password})).toBe(true);expect(admitted.events[2]!.hash).toBe(credential.password);
  expect(admitted.users.filter(row=>row.id===accepted.data!.user.id)).toHaveLength(1);expect(admitted.sessions.filter(row=>row.userId===accepted.data!.user.id)).toHaveLength(1);
  await unchanged(ctx,other);return {foreign:other,configured,before:observed(before),rejected,after:observed(after),configuredClean,accepted,admitted:observed(admitted)};
},["POST /sign-up/email"]);

compatScenario("published compromised password helper retains exact first-match canonical counts and media errors",async ctx=>{
  const other=await foreign(ctx),before=await state(ctx),s=suffix(password),observations=[];
  const cases:[string,string,boolean|null,number?,string?][]=[
    ["positive",`${s}:1`,true],["zero",`${s}:0`,false],["max-safe",`${s}:9007199254740991`,true],
    ["lowercase",`${s.toLowerCase()}:2\r\n`,true],["LF",`other:bad\n${s}:1\n`,true],
    ["first-zero",`${s}:0\n${s}:7`,false],["first-positive",`${s}:3\n${s}:0`,true],
    ["absent","01234567890123456789012345678901234:bad\n",false],
    ...["","01","+1","-0","-1"," 1","1 ","1\t","1.0","1e0","NaN","Infinity","9007199254740992","1\r"].map(value=>[`invalid-${JSON.stringify(value)}`,`${s}:${value}`,null] as [string,string,null]),
    ["JSON-string",JSON.stringify(`${s}:2\r\n`),true,200,"application/json"],
    ["JSON-object",'{"matching":"ignored"}',null,200,"application/json"],
    ["JSON-number","1e500",null],["JSON-null","null",null],["binary",`${s}:1`,null,200,"application/octet-stream"],
    ["provider-status",'{"service":"unavailable"}',null,503,"application/json"],
  ];
  for(const [kind,body,compromised,status=200,media="text/plain"] of cases) {
    const configured=await range(ctx,body,status,media),result=await control(ctx,{operation:"helper",password}),after=await state(ctx);
    expect(rows(after)).toEqual(rows(before));expect(stages(after)).toEqual(["range"]);receipt(after,password);
    if(compromised===null) {expect(result.status).toBe(500);expect(result.body).toEqual({message:status===503?"Failed to check password. Status: 503":RETRY_MESSAGE});}
    else {expect(result.status).toBe(200);expect(result.body).toEqual({compromised});}
    observations.push({kind,body,status,media,configured,result,after:observed(after)});
  }
  await unchanged(ctx,other);return {foreign:other,before:observed(before),observations};
});

compatScenario("compromised hash policy options retain disabled empty custom paths and message fallback",async ctx=>{
  const other=await foreign(ctx),observations=[];
  for(const profile of ["pwned-disabled","pwned-empty","pwned-custom","pwned-wildcard","pwned-message","pwned-empty-message"] as const) {
    const configured=await range(ctx,`${suffix(password)}:3`),before=await state(ctx),result=await ctx.actor(profile,profile).client.signUp.email({email:ctx.uniqueEmail(profile),name:"Configured Policy",password}),after=await state(ctx);
    if(profile==="pwned-message"||profile==="pwned-empty-message") {
      expect(result.error).toMatchObject({status:400,code:"PASSWORD_COMPROMISED",message:profile==="pwned-message"?"Application forbids leaked passwords":DEFAULT_MESSAGE});
      expect(rows(after)).toEqual(rows(before));expect(stages(after)).toEqual(["range"]);receipt(after,password);
    } else {expect(result.error).toBeNull();expect(after.receipts).toEqual([]);expect(stages(after)).toEqual(["hash-enter","hash-result","user-create"]);
      const account=after.accounts.find(row=>row.userId===result.data!.user.id)!;expect(await verifyPassword({hash:String(account.password),password})).toBe(true);}
    observations.push({profile,configured,before:observed(before),result,after:observed(after)});
  }
  await unchanged(ctx,other);return {foreign:other,observations};
},["POST /sign-up/email"]);

compatScenario("compromise check hashes raw Unicode before genuine normalized scrypt and signup duplicate guards",async ctx=>{
  const other=await foreign(ctx),pw="Ｐａｓｓｗｏｒｄ１２３",normalized=pw.normalize("NFKC"),configured=await range(ctx,`${suffix(normalized)}:7`),owner=ctx.actor("unicode","pwned-default"),email=ctx.uniqueEmail("raw-pwned");
  const signup=await owner.client.signUp.email({email,name:"Unicode Principal",password:pw});expect(signup.error).toBeNull();const admitted=await state(ctx);receipt(admitted,pw);const credential=admitted.accounts.find(row=>row.userId===signup.data!.user.id)!;
  expect(await verifyPassword({hash:String(credential.password),password:normalized})).toBe(true);
  const deniedConfig=await range(ctx,`${suffix(pw)}:7`),duplicate=await owner.client.signUp.email({email,name:"Duplicate",password:pw});
  expect(duplicate.error?.code).toBe("USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL");const guarded=await state(ctx);expect(rows(guarded)).toEqual(rows(admitted));expect(guarded.receipts).toEqual([]);expect(guarded.events).toEqual([]);
  const noAuto=ctx.actor("no-auto","pwned-no-auto"),safeEmail=ctx.uniqueEmail("enumeration");await range(ctx);
  const physical=await noAuto.client.signUp.email({email:safeEmail,name:"Physical Principal",password:pw});expect(physical.error).toBeNull();
  const safeBefore=await state(ctx),safeConfig=await range(ctx,`${suffix(pw)}:7`),safeDuplicate=await noAuto.client.signUp.email({email:safeEmail,name:"Synthetic Principal",password:pw});
  expect(safeDuplicate.error?.code).toBe("PASSWORD_COMPROMISED");const safeAfter=await state(ctx);expect(rows(safeAfter)).toEqual(rows(safeBefore));expect(stages(safeAfter)).toEqual(["range"]);receipt(safeAfter,pw);
  await unchanged(ctx,other);return {foreign:other,configured,signup,admitted:observed(admitted),deniedConfig,duplicate,guarded:observed(guarded),physical,safeBefore:observed(safeBefore),safeConfig,safeDuplicate,safeAfter:observed(safeAfter)};
},["POST /sign-up/email"]);

compatScenario("compromised change password follows authentication but precedes current-password verification without revocation",async ctx=>{
  const other=await foreign(ctx);await range(ctx);const owner=ctx.actor("owner","pwned-default"),email=ctx.uniqueEmail("change-pwned"),original="original-password123";
  const signup=await owner.client.signUp.email({email,name:"Password Owner",password:original});expect(signup.error).toBeNull();
  const configured=await range(ctx,`${suffix(password)}:8`),before=await state(ctx);
  const unauth=await ctx.actor("anonymous","pwned-default").client.changePassword({currentPassword:original,newPassword:password,revokeOtherSessions:true});expect(unauth.error?.status).toBe(401);
  const noCalls=await state(ctx);expect(noCalls.receipts).toEqual([]);expect(rows(noCalls)).toEqual(rows(before));
  const wrong=await owner.client.changePassword({currentPassword:"incorrect-password123",newPassword:password,revokeOtherSessions:true});expect(wrong.error?.code).toBe("PASSWORD_COMPROMISED");
  const guarded=await state(ctx);expect(rows(guarded)).toEqual(rows(before));receipt(guarded,password);
  const checkAgain=await range(ctx,`${suffix(password)}:8`);
  const rejected=await owner.client.changePassword({currentPassword:original,newPassword:password,revokeOtherSessions:true});expect(rejected.error?.code).toBe("PASSWORD_COMPROMISED");
  const after=await state(ctx);expect(rows(after)).toEqual(rows(before));expect(stages(after)).toEqual(["range"]);receipt(after,password);
  const session=await owner.client.getSession();expect(session.data?.user.id).toBe(signup.data!.user.id);
  const clean=await range(ctx,`${suffix(password)}:0`),accepted=await owner.client.changePassword({currentPassword:original,newPassword:password});expect(accepted.error).toBeNull();
  const admitted=await state(ctx);receipt(admitted,password);expect(stages(admitted)).toEqual(["range","hash-enter","hash-result"]);
  const account=admitted.accounts.find(row=>row.userId===signup.data!.user.id)!;expect(await verifyPassword({hash:String(account.password),password})).toBe(true);expect(admitted.events[2]!.hash).toBe(account.password);
  await unchanged(ctx,other);return {foreign:other,signup,configured,before:observed(before),unauth,noCalls:observed(noCalls),wrong,guarded:observed(guarded),checkAgain,rejected,after:observed(after),session,clean,accepted,admitted:observed(admitted)};
},["POST /change-password"]);

for(const mode of ["compromised","malformed","provider-error"] as const) compatScenario(`password reset ${mode} burns its genuine proof before hash rejection and preserves credentials sessions and callback isolation`,async ctx=>{
  const other=await foreign(ctx);await range(ctx);const owner=ctx.actor("owner","pwned-default"),email=ctx.uniqueEmail(`reset-${mode}`);
  const signup=await owner.client.signUp.email({email,name:"Reset Owner",password:"original-password123"});expect(signup.error).toBeNull();
  const requested=await owner.client.requestPasswordReset({email,redirectTo:"/pwned-reset"});expect(requested.error).toBeNull();const delivered=await state(ctx),delivery=delivered.events.find(event=>event.stage==="reset-delivery")!,token=String(delivery.token);
  const proof=delivered.verifications.find(row=>row.identifier===`reset-password:${token}`)!;expect(proof.value).toBe(signup.data!.user.id);expect(Date.parse(String(proof.expiresAt))-Date.parse(String(proof.createdAt))).toBeGreaterThanOrEqual(3599000);expect(Date.parse(String(proof.expiresAt))-Date.parse(String(proof.createdAt))).toBeLessThanOrEqual(3600000);
  const configured=await range(ctx,`${suffix(password)}:${mode==="malformed"?"01":"2"}`,mode==="provider-error"?503:200),before=await state(ctx),rejected=await owner.client.resetPassword({token,newPassword:password});
  expect(rejected.error).toMatchObject({status:mode==="compromised"?400:500,message:mode==="compromised"?DEFAULT_MESSAGE:mode==="provider-error"?"Failed to check password. Status: 503":RETRY_MESSAGE});
  const after=await state(ctx);expect(after.users).toEqual(before.users);expect(after.accounts).toEqual(before.accounts);expect(after.sessions).toEqual(before.sessions);expect(after.verifications).toEqual(before.verifications.filter(row=>row.id!==proof.id));expect(stages(after)).toEqual(["range"]);receipt(after,password);
  const replay=await owner.client.resetPassword({token,newPassword:password});expect(replay.error?.code).toBe("INVALID_TOKEN");expect(await state(ctx)).toEqual(after);
  const session=await owner.client.getSession();expect(session.data?.user.id).toBe(signup.data!.user.id);
  const clean=await range(ctx),freshRequest=await owner.client.requestPasswordReset({email,redirectTo:"/pwned-reset"});expect(freshRequest.error).toBeNull();const freshState=await state(ctx),fresh=String(freshState.events.find(event=>event.stage==="reset-delivery")!.token);
  const clear=await range(ctx,`${suffix(password)}:0`),accepted=await owner.client.resetPassword({token:fresh,newPassword:password});expect(accepted.error).toBeNull();const admitted=await state(ctx);
  expect(stages(admitted)).toEqual(["range","hash-enter","hash-result","password-reset"]);receipt(admitted,password);expect(admitted.sessions.filter(row=>row.userId===signup.data!.user.id)).toEqual([]);
  const account=admitted.accounts.find(row=>row.userId===signup.data!.user.id)!;expect(await verifyPassword({hash:String(account.password),password})).toBe(true);expect(admitted.events[2]!.hash).toBe(account.password);
  await unchanged(ctx,other);return {foreign:other,signup,requested,delivered:observed(delivered),configured,before:observed(before),rejected,after:observed(after),replay,session,clean,freshRequest,freshState:observed(freshState),clear,accepted,admitted:observed(admitted)};
},["POST /request-password-reset","POST /reset-password"]);

compatScenario("compromised admin create preserves actual pre-hash user creation and set-password keeps configured original hashing",async ctx=>{
  const other=await foreign(ctx);await range(ctx);const owner=ctx.actor("admin","pwned-default"),email=ctx.uniqueEmail("pwned-admin"),signup=await owner.client.signUp.email({email,name:"Administrator",password:"admin-password123"});expect(signup.error).toBeNull();
  const promoted=await ctx.promoteAdmin({email}),configured=await range(ctx,`${suffix(password)}:7`),before=await state(ctx),targetEmail=ctx.uniqueEmail("admin-created-pwned");
  const forbidden=await ctx.actor("outsider","pwned-default").client.admin.createUser({email:targetEmail,name:"Target",password});expect(forbidden.error?.status).toBe(401);const guarded=await state(ctx);expect(rows(guarded)).toEqual(rows(before));expect(guarded.events).toEqual([]);expect(guarded.receipts).toEqual([]);
  const rejected=await owner.client.admin.createUser({email:targetEmail,name:"Created Before Check",password});expect(rejected.error?.code).toBe("PASSWORD_COMPROMISED");const after=await state(ctx);
  expect(after.users).toHaveLength(before.users.length+1);const created=after.users.find(row=>row.email===targetEmail)!;expect(created).toMatchObject({name:"Created Before Check",role:"user"});
  expect(after.accounts).toEqual(before.accounts);expect(after.sessions).toEqual(before.sessions);expect(after.verifications).toEqual(before.verifications);expect(stages(after)).toEqual(["user-create","range"]);receipt(after,password);
  const reset=await range(ctx,`${suffix(password)}:7`),setRejected=await owner.client.admin.setUserPassword({userId:String(created.id),newPassword:password});expect(setRejected.error?.code).toBe("PASSWORD_COMPROMISED");const denied=await state(ctx);expect(rows(denied)).toEqual(rows(after));expect(stages(denied)).toEqual(["range"]);receipt(denied,password);
  const clean=await range(ctx,`${suffix(password)}:0`),setAccepted=await owner.client.admin.setUserPassword({userId:String(created.id),newPassword:password});expect(setAccepted.error).toBeNull();const admitted=await state(ctx);
  expect(stages(admitted)).toEqual(["range","hash-enter","hash-result"]);receipt(admitted,password);const account=admitted.accounts.find(row=>row.userId===created.id)!;expect(account.accountId).toBe(created.id);expect(account.providerId).toBe("credential");expect(admitted.events[2]!.hash).toBe(account.password);expect(await verifyPassword({hash:String(account.password),password})).toBe(true);
  await unchanged(ctx,other);return {foreign:other,signup,promoted,configured,before:observed(before),forbidden,guarded:observed(guarded),rejected,after:observed(after),reset,setRejected,denied:observed(denied),clean,setAccepted,admitted:observed(admitted)};
},["POST /admin/create-user","POST /admin/set-user-password"]);

compatScenario("compromised server-only set-password uses actual virtual handler identity without a public URL",async ctx=>{
  const other=await foreign(ctx),observations=[];
  for(const profile of ["pwned-default","pwned-custom","pwned-virtual"] as const) {
    await range(ctx);const actor=ctx.actor(profile,profile),signup=await actor.client.signUp.email({email:ctx.uniqueEmail(profile),name:"Server Password Owner",password:"original-password123"});expect(signup.error).toBeNull();
    const initial=await state(ctx),credential=initial.accounts.find(row=>row.userId===signup.data!.user.id)!,cleared=await control(ctx,{operation:"clear-password",accountId:credential.id});expect(cleared.status).toBe(200);
    const configured=await range(ctx,`${suffix(password)}:8`),before=await state(ctx),result=await control(ctx,{operation:"set",profile,newPassword:password},profile),after=await state(ctx);
    if(profile==="pwned-virtual") {expect(result.status).toBe(400);expect(result.body).toMatchObject({code:"PASSWORD_COMPROMISED",message:DEFAULT_MESSAGE});expect(rows(after)).toEqual(rows(before));expect(stages(after)).toEqual(["range"]);receipt(after,password);}
    else {expect(result.status).toBe(200);expect(result.body).toEqual({status:true});expect(after.receipts).toEqual([]);expect(stages(after)).toEqual(["hash-enter","hash-result"]);const account=after.accounts.find(row=>row.id===credential.id)!;expect(await verifyPassword({hash:String(account.password),password})).toBe(true);expect(after.events[1]!.hash).toBe(account.password);}
    const publicAttempt=await ctx.rawRequest({actor:profile,path:`/__test/profiles/${profile}/api/auth/set-password`,method:"POST",json:{newPassword:password}});expect(publicAttempt.status).toBe(404);
    observations.push({profile,signup,initial:observed(initial),cleared,configured,before:observed(before),result,after:observed(after),publicAttempt});
  }
  await unchanged(ctx,other);return {foreign:other,observations};
});

compatScenario("compromised custom signin path checks actual missing-user timing hash but stored password verification never checks",async ctx=>{
  const other=await foreign(ctx);await range(ctx);const actor=ctx.actor("stored","pwned-custom"),email=ctx.uniqueEmail("signin-check"),signup=await actor.client.signUp.email({email,name:"Stored User",password});expect(signup.error).toBeNull();
  const configured=await range(ctx,`${suffix(password)}:5`),before=await state(ctx),signin=await ctx.actor("returning","pwned-custom").client.signIn.email({email,password});expect(signin.error).toBeNull();const returning=await state(ctx);expect(returning.events).toEqual([]);expect(returning.receipts).toEqual([]);expect(returning.accounts).toEqual(before.accounts);
  const missing=await ctx.actor("missing","pwned-custom").client.signIn.email({email:ctx.uniqueEmail("absent"),password});expect(missing.error?.code).toBe("PASSWORD_COMPROMISED");const after=await state(ctx);expect(rows(after)).toEqual(rows(returning));expect(stages(after)).toEqual(["range"]);receipt(after,password);
  await unchanged(ctx,other);return {foreign:other,signup,configured,before:observed(before),signin,returning:observed(returning),missing,after:observed(after)};
},["POST /sign-in/email"]);

for(const method of ["email-otp","phone-number"] as const) compatScenario(`compromised ${method} reset consumes actual delivered proof before checking and retains foreign credentials`,async ctx=>{
  const other=await foreign(ctx);await range(ctx);const owner=ctx.actor("owner","pwned-default"),email=ctx.uniqueEmail(method),phoneNumber="+15550001351",signup=await owner.client.signUp.email({email,name:"OTP Password Owner",password:"original-password123",...method==="phone-number"?{phoneNumber}:{}});expect(signup.error).toBeNull();
  async function issue() {
    const result=method==="email-otp"?await owner.client.emailOtp.requestPasswordReset({email}):await ctx.rawRequest({path:"/__test/profiles/pwned-default/api/auth/phone-number/request-password-reset",method:"POST",json:{phoneNumber}});
    if("error" in result)expect(result.error).toBeNull();else expect(result.status).toBe(200);
    const delivered=await state(ctx),delivery=delivered.events.findLast(event=>event.stage===(method==="email-otp"?"email-otp":"phone-reset-otp"))!;
    return {result,state:delivered,proof:String(method==="email-otp"?delivery.otp:delivery.code)};
  }
  async function reset(proof:string) {
    return method==="email-otp"?owner.client.emailOtp.resetPassword({email,otp:proof,password}):ctx.rawRequest({path:"/__test/profiles/pwned-default/api/auth/phone-number/reset-password",method:"POST",json:{phoneNumber,otp:proof,newPassword:password}});
  }
  const issued=await issue(),configured=await range(ctx,`${suffix(password)}:6`),before=await state(ctx),rejected=await reset(issued.proof);
  if("error" in rejected)expect(rejected.error?.code).toBe("PASSWORD_COMPROMISED");else {expect(rejected.status).toBe(400);expect(rejected.body).toMatchObject({code:"PASSWORD_COMPROMISED"});}
  const after=await state(ctx);expect(after.users).toEqual(before.users);expect(after.accounts).toEqual(before.accounts);expect(after.sessions).toEqual(before.sessions);expect(after.verifications).toHaveLength(before.verifications.length-1);expect(stages(after)).toEqual(["range"]);receipt(after,password);
  const replay=await reset(issued.proof);if("error" in replay)expect(replay.error?.status).toBe(400);else expect(replay.status).toBe(400);expect(await state(ctx)).toEqual(after);
  const clean=await range(ctx),fresh=await issue(),clear=await range(ctx,`${suffix(password)}:0`),accepted=await reset(fresh.proof);
  if("error" in accepted)expect(accepted.error).toBeNull();else expect(accepted.status).toBe(200);
  const admitted=await state(ctx);expect(stages(admitted)).toEqual(["range","hash-enter","hash-result","password-reset"]);receipt(admitted,password);expect(admitted.sessions.filter(row=>row.userId===signup.data!.user.id)).toEqual([]);
  const account=admitted.accounts.find(row=>row.userId===signup.data!.user.id)!;expect(await verifyPassword({hash:String(account.password),password})).toBe(true);expect(admitted.events[2]!.hash).toBe(account.password);
  await unchanged(ctx,other);return {foreign:other,signup,issued:{...issued,state:observed(issued.state),proof:{token:issued.proof,length:6}},configured,before:observed(before),rejected,after:observed(after),replay,clean,fresh:{...fresh,state:observed(fresh.state),proof:{token:fresh.proof,length:6}},clear,accepted,admitted:observed(admitted)};
},[`POST /${method}/reset-password`]);

compatScenario("concurrent compromised reset consumes one physical proof and sends exactly one range request",async ctx=>{
  const other=await foreign(ctx);await range(ctx);const owner=ctx.actor("owner","pwned-default"),email=ctx.uniqueEmail("pwned-reset-race"),signup=await owner.client.signUp.email({email,name:"Concurrent Owner",password:"original-password123"});expect(signup.error).toBeNull();
  const requested=await owner.client.requestPasswordReset({email,redirectTo:"/pwned-race"});expect(requested.error).toBeNull();const delivered=await state(ctx),token=String(delivered.events.find(event=>event.stage==="reset-delivery")!.token),proof=delivered.verifications.find(row=>row.identifier===`reset-password:${token}`)!;
  const configured=await range(ctx,`${suffix(password)}:8`),before=await state(ctx);
  const outcomes=await Promise.all([0,1].map(async()=>{
    const entries:TraceEntry[]=[],path="/__test/profiles/pwned-default/api/auth",client=createAuthClient({baseURL:ctx.baseURL+path,fetchOptions:{customFetchImpl:createTracingFetch(ctx.baseURL,"racer",entries,path)}});
    return {entries,result:await client.resetPassword({token,newPassword:password})};
  }));
  outcomes.sort((left,right)=>Number(right.result.error?.code==="PASSWORD_COMPROMISED")-Number(left.result.error?.code==="PASSWORD_COMPROMISED"));ctx.recordTransport(outcomes.flatMap(outcome=>outcome.entries));
  const results=outcomes.map(outcome=>outcome.result);expect(results[0]!.error?.code).toBe("PASSWORD_COMPROMISED");expect(results[1]!.error?.code).toBe("INVALID_TOKEN");
  const after=await state(ctx);expect(after.users).toEqual(before.users);expect(after.accounts).toEqual(before.accounts);expect(after.sessions).toEqual(before.sessions);expect(after.verifications).toEqual(before.verifications.filter(row=>row.id!==proof.id));expect(stages(after)).toEqual(["range"]);receipt(after,password);
  const replay=await owner.client.resetPassword({token,newPassword:password});expect(replay.error?.code).toBe("INVALID_TOKEN");expect(await state(ctx)).toEqual(after);
  await unchanged(ctx,other);return {foreign:other,signup,requested,delivered:observed(delivered),configured,before:observed(before),results,after:observed(after),replay};
},["POST /reset-password"]);

compatScenario("expired reset and OTP proofs reject before compromised-password HTTP or original hash callbacks",async ctx=>{
  const other=await foreign(ctx),observations=[];
  for(const method of ["reset","email-otp","phone-number"] as const) {
    await range(ctx);const owner=ctx.actor(method,"pwned-default"),email=ctx.uniqueEmail(`expired-${method}`),phoneNumber="+15550001352",signup=await owner.client.signUp.email({email,name:"Expired Proof Owner",password:"original-password123",...method==="phone-number"?{phoneNumber}:{}});expect(signup.error).toBeNull();
    const requested=method==="reset"?await owner.client.requestPasswordReset({email,redirectTo:"/pwned-expired"}):method==="email-otp"?await owner.client.emailOtp.requestPasswordReset({email}):await ctx.rawRequest({path:"/__test/profiles/pwned-default/api/auth/phone-number/request-password-reset",method:"POST",json:{phoneNumber}});
    if("error" in requested)expect(requested.error).toBeNull();else expect(requested.status).toBe(200);
    const delivered=await state(ctx),delivery=delivered.events.findLast(event=>event.stage===(method==="reset"?"reset-delivery":method==="email-otp"?"email-otp":"phone-reset-otp"))!,proof=String(method==="reset"?delivery.token:method==="email-otp"?delivery.otp:delivery.code),identifier=method==="reset"?`reset-password:${proof}`:method==="email-otp"?`forget-password-otp-${email}`:`${phoneNumber}-request-password-reset`;
    expect(delivered.verifications.filter(row=>row.identifier===identifier)).toHaveLength(1);
    const expired=await ctx.rawRequest({path:"/__test/verification-state",method:"POST",json:{action:"expire",identifier,expiresAt:"2001-01-01T00:00:00.000Z"}});expect(expired.status).toBe(200);
    const configured=await range(ctx,`${suffix(password)}:9`),before=await state(ctx);expect(before.verifications.find(row=>row.identifier===identifier)!.expiresAt).toBe("2001-01-01T00:00:00.000Z");
    async function reset() {return method==="reset"?owner.client.resetPassword({token:proof,newPassword:password}):method==="email-otp"?owner.client.emailOtp.resetPassword({email,otp:proof,password}):ctx.rawRequest({path:"/__test/profiles/pwned-default/api/auth/phone-number/reset-password",method:"POST",json:{phoneNumber,otp:proof,newPassword:password}});}
    const rejected=await reset();if("error" in rejected)expect(rejected.error?.status).toBe(400);else expect(rejected.status).toBe(400);
    const after=await state(ctx);expect(after.users).toEqual(before.users);expect(after.accounts).toEqual(before.accounts);expect(after.sessions).toEqual(before.sessions);expect(after.events).toEqual([]);expect(after.receipts).toEqual([]);
    const replay=await reset();if("error" in replay)expect(replay.error?.status).toBe(400);else expect(replay.status).toBe(400);expect(await state(ctx)).toEqual(after);
    observations.push({method,signup,requested,delivered:observed(delivered),proof:method==="reset"?proof:{token:proof,length:6},expired,configured,before:observed(before),rejected,after:observed(after),replay});
  }
  await unchanged(ctx,other);return {foreign:other,observations};
},["POST /reset-password","POST /email-otp/reset-password","POST /phone-number/reset-password"]);

compatScenario("clean range result preserves real original hash callback rejection after reset proof consumption",async ctx=>{
  const other=await foreign(ctx);await range(ctx);const owner=ctx.actor("owner","pwned-default"),email=ctx.uniqueEmail("original-hash-policy"),signup=await owner.client.signUp.email({email,name:"Original Hash Owner",password:"original-password123"});expect(signup.error).toBeNull();
  const requested=await owner.client.requestPasswordReset({email,redirectTo:"/original-hash"});expect(requested.error).toBeNull();const delivered=await state(ctx),token=String(delivered.events.find(event=>event.stage==="reset-delivery")!.token),proof=delivered.verifications.find(row=>row.identifier===`reset-password:${token}`)!;
  const configured=await control(ctx,{operation:"range",body:`${suffix(password)}:0`,hashFailure:true}),before=await state(ctx),rejected=await owner.client.resetPassword({token,newPassword:password});
  expect(rejected.error).toMatchObject({status:403,code:"ORIGINAL_HASH_REJECTED",message:"Original password hash rejected"});const after=await state(ctx);
  expect(after.users).toEqual(before.users);expect(after.accounts).toEqual(before.accounts);expect(after.sessions).toEqual(before.sessions);expect(after.verifications).toEqual(before.verifications.filter(row=>row.id!==proof.id));expect(stages(after)).toEqual(["range","hash-enter","hash-result"]);receipt(after,password);
  expect(await verifyPassword({hash:String(after.events[2]!.hash),password})).toBe(true);
  const replay=await owner.client.resetPassword({token,newPassword:password});expect(replay.error?.code).toBe("INVALID_TOKEN");expect(await state(ctx)).toEqual(after);
  await unchanged(ctx,other);return {foreign:other,signup,requested,delivered:observed(delivered),configured,before:observed(before),rejected,after:observed(after),replay};
},["POST /reset-password"]);
