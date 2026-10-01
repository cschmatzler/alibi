import { expect } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { twoFactorClient } from "better-auth/client/plugins";
import { symmetricDecrypt } from "better-auth/crypto";
import { z } from "zod";
import { compatScenario } from "../../support/scenario";
import { authProfilePath } from "../../support/profiles";
import { createTracingFetch, type TraceEntry } from "../../support/trace";

const controlSchema=z.object({delivery:z.object({userId:z.string(),otp:z.string()}).nullable(),row:z.object({id:z.string(),identifier:z.string(),value:z.string(),expiresAt:z.string()}).nullable(),generations:z.number().int(),receipts:z.array(z.object({phase:z.string(),input:z.string()}))});
const secret=["compat","test","only","key","not","real","minimum","32chars"].join("-");
for(const profile of ["two-factor-otp-plain","two-factor-otp-hashed","two-factor-otp-encrypted","two-factor-otp-custom-hash","two-factor-otp-custom-cipher"] as const){
  compatScenario(`two-factor ${profile} delivers and persists its configured OTP before real enrollment, login, expiry and replay checks`,async ctx=>{
    const client=(name:string)=>createAuthClient({baseURL:`${ctx.baseURL}${authProfilePath(profile)}`,plugins:[twoFactorClient()],fetchOptions:{customFetchImpl:ctx.actor(name,profile).fetch}});
    const owner=client("owner"),foreign=client("foreign");const email=ctx.uniqueEmail("otp-owner"),password="password123";
    const signup=await owner.signUp.email({email,password,name:"OTP Owner"});expect(signup.error).toBeNull();if(!signup.data)throw new Error("owner required");
    const other=await foreign.signUp.email({email:ctx.uniqueEmail("foreign"),password,name:"Foreign Owner"});expect(other.error).toBeNull();if(!other.data)throw new Error("foreign required");
    const foreignBefore=await ctx.readUserState({userId:other.data.user.id});
    const original=await owner.getSession();expect(original.data?.user.twoFactorEnabled).toBe(false);
    const control=async(extra:Record<string,unknown>={})=>controlSchema.parse((await ctx.rawRequest({path:"/__test/two-factor-otp-config",method:"POST",json:{profile,email,...extra}})).body);
    const started=Date.now();const sent=await owner.twoFactor.sendOtp({});const finished=Date.now();expect(sent.error).toBeNull();const stored=await control();if(!stored.delivery||!stored.row)throw new Error("real stored delivery required");
    const code=stored.delivery.otp;expect(stored.delivery.userId).toBe(signup.data.user.id);expect(code).toMatch(/^\d+$/);expect(code).toHaveLength(profile.endsWith("plain")?6:profile.endsWith("encrypted")?8:profile.endsWith("hashed")?4:3);
    const period=profile.endsWith("hashed")?30_000:profile.includes("custom")?60_000:180_000;expect(Date.parse(stored.row.expiresAt)).toBeGreaterThanOrEqual(started+period);expect(Date.parse(stored.row.expiresAt)).toBeLessThanOrEqual(finished+period);
    const [representation,counter]=stored.row.value.split(":");expect(counter).toBe("0");if(!representation)throw new Error("stored representation required");
    if(profile.endsWith("plain"))expect(representation).toBe(code);
    else if(profile.endsWith("hashed"))expect(representation).toBe(Buffer.from(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(code))).toString("base64url"));
    else if(profile.endsWith("encrypted"))expect(await symmetricDecrypt({key:secret,data:representation})).toBe(code);
    else expect(representation).toBe(`${profile.endsWith("custom-hash")?"hash":"cipher"}-${code.split("").reverse().join("")}`);
    const wrongOwner=await foreign.twoFactor.verifyOtp({code});expect(wrongOwner.error?.code).toBe("OTP_HAS_EXPIRED");expect((await control()).row).toEqual(stored.row);
    const wrong=await owner.twoFactor.verifyOtp({code:"wrong"});expect(wrong.error?.code).toBe("INVALID_CODE");expect((await control()).row?.value).toBe(`${representation}:1`);
    const verified=await owner.twoFactor.verifyOtp({code});expect(verified.error).toBeNull();expect(verified.data?.user.twoFactorEnabled).toBe(true);expect(verified.data?.token).not.toBe(original.data?.session.token);
    const current=await owner.getSession();expect(current.data?.session.token).toBe(verified.data?.token);expect(current.data?.user.id).toBe(signup.data.user.id);
    const state=z.object({twoFactorExists:z.boolean(),sessions:z.array(z.object({token:z.string()}))}).parse(await ctx.readUserState({userId:signup.data.user.id}));expect(state.twoFactorExists).toBe(false);expect(state.sessions).toHaveLength(1);expect(state.sessions[0]?.token).toBe(verified.data?.token);
    const consumed=await control({identifier:stored.row.identifier});expect(consumed.row).toBeNull();const replay=await owner.twoFactor.verifyOtp({code});expect(replay.error?.code).toBe("OTP_HAS_EXPIRED");
    expect(consumed.receipts.map(row=>row.phase)).toEqual(profile.endsWith("custom-hash")?["hash","send","hash","hash"]:profile.endsWith("custom-cipher")?["encrypt","send","decrypt","decrypt"]:["send"]);
    expect(consumed.receipts[0]?.input).toBe(code);if(profile.endsWith("custom-hash"))expect(consumed.receipts.slice(2).map(row=>row.input)).toEqual(["wrong",code]);if(profile.endsWith("custom-cipher"))expect(consumed.receipts.slice(2).map(row=>row.input)).toEqual([representation,representation]);
    await owner.twoFactor.sendOtp({});const expiring=await control();if(!expiring.row||!expiring.delivery)throw new Error("expiring delivery required");await control({identifier:expiring.row.identifier,expire:true});const expired=await owner.twoFactor.verifyOtp({code:expiring.delivery.otp});expect(expired.error?.code).toBe("OTP_HAS_EXPIRED");expect((await owner.getSession()).data?.session.token).toBe(verified.data?.token);
    await owner.signOut();const signIn=await owner.signIn.email({email,password,rememberMe:false});expect(signIn.data).toMatchObject({twoFactorRedirect:true});await owner.twoFactor.sendOtp({});const pending=await control();if(!pending.delivery||!pending.row)throw new Error("pending delivery required");const complete=await owner.twoFactor.verifyOtp({code:pending.delivery.otp});expect(complete.error).toBeNull();expect(complete.data?.user.id).toBe(signup.data.user.id);expect((await owner.getSession()).data?.session.token).toBe(complete.data?.token);expect((await control({identifier:pending.row.identifier})).row).toBeNull();
    expect(await ctx.readUserState({userId:other.data.user.id})).toEqual(foreignBefore);
    return ctx.snapshot({signup,other,foreignBefore,original,sent,wrongOwner,wrong,verified,current,state,replay,expired,signIn,complete,storage:{mode:profile,digits:code.length,initialCounter:counter,receiptPhases:consumed.receipts.map(row=>row.phase)}});
  }, ["POST /two-factor/send-otp", "POST /two-factor/verify-otp"]);
}

compatScenario("two-factor OTP enable uses an authoritative owner, validates method before password verification and succeeds with disabled TOTP without a factor",async ctx=>{
  const profile="two-factor-otp-hashed";const client=(name:string)=>createAuthClient({baseURL:`${ctx.baseURL}${authProfilePath(profile)}`,plugins:[twoFactorClient()],fetchOptions:{customFetchImpl:ctx.actor(name,profile).fetch}});
  let originalCookie="";
  const owner=createAuthClient({baseURL:`${ctx.baseURL}${authProfilePath(profile)}`,plugins:[twoFactorClient()],fetchOptions:{customFetchImpl:async(input,init)=>{
    const response=await ctx.actor("owner",profile).fetch(input,init);const url=input instanceof Request?input.url:input.toString();
    if(url.endsWith("/sign-up/email"))originalCookie=response.headers.getSetCookie().find(value=>value.split("=")[0]?.endsWith(".session_token"))?.split(";")[0]??"";
    return response;
  }}}),guest=client("guest"),email=ctx.uniqueEmail("otp-enable"),password="password123";
  const deniedGuest=await ctx.actor("guest",profile).fetch(`${ctx.baseURL}${authProfilePath(profile)}/two-factor/enable`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({password:null,method:"invalid"})});expect(deniedGuest.status).toBe(400);const guestBody=await deniedGuest.json();expect(guestBody).toMatchObject({code:"VALIDATION_ERROR"});
  const validGuest=await guest.twoFactor.enable({password,method:"otp"});expect(validGuest.error).toMatchObject({status:401,code:"UNAUTHORIZED",message:"Unauthorized"});
  const signup=await owner.signUp.email({email,password,name:"OTP Enable"});expect(signup.error).toBeNull();if(!signup.data)throw new Error("owner required");const original=await owner.getSession();
  const invalid=await ctx.actor("owner",profile).fetch(`${ctx.baseURL}${authProfilePath(profile)}/two-factor/enable`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({password:"wrong",method:"invalid"})});expect(invalid.status).toBe(400);const invalidBody=await invalid.json();expect(invalidBody).toMatchObject({code:"VALIDATION_ERROR"});
  const wrong=await owner.twoFactor.enable({password:"wrong",method:"otp"});expect(wrong.error?.code).toBe("INVALID_PASSWORD");const totp=await owner.twoFactor.enable({password});expect(totp.error?.code).toBe("TOTP_NOT_CONFIGURED");
  const malformedSend=await ctx.actor("owner",profile).fetch(`${ctx.baseURL}${authProfilePath(profile)}/two-factor/send-otp`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({trustDevice:null})});expect(malformedSend.status).toBe(400);const malformedSendBody=await malformedSend.json();expect(malformedSendBody).toMatchObject({code:"VALIDATION_ERROR"});
  const untouched=controlSchema.parse((await ctx.rawRequest({path:"/__test/two-factor-otp-config",method:"POST",json:{profile,email}})).body);expect(untouched.delivery).toBeNull();expect(untouched.generations).toBe(0);
  const enable=await owner.twoFactor.enable({password,method:"otp"});expect(enable.error).toBeNull();expect(enable.data).toEqual({method:"otp"});const current=await owner.getSession();expect(current.data?.user.twoFactorEnabled).toBe(true);expect(current.data?.session.token).not.toBe(original.data?.session.token);
  const state=z.object({twoFactorExists:z.boolean(),sessions:z.array(z.object({token:z.string()}))}).parse(await ctx.readUserState({userId:signup.data.user.id}));expect(state.twoFactorExists).toBe(false);expect(state.sessions).toHaveLength(1);expect(state.sessions[0]?.token).toBe(current.data?.session.token);
  expect(originalCookie).not.toBe("");const old=await guest.getSession({fetchOptions:{headers:{cookie:originalCookie}}});expect(old.data).toBeNull();
  return ctx.snapshot({guestBody,validGuest,signup,original,invalidBody,wrong,totp,malformedSendBody,enable,current,state,old});
}, ["POST /two-factor/enable", "POST /two-factor/send-otp"]);

for (const profile of ["two-factor-otp-hashed", "two-factor-otp-encrypted"] as const) {
  compatScenario(`two-factor ${profile} applies decimal-prefix counters, fractional or zero-default budgets and consumes the exhausted row`, async ctx => {
    const owner=createAuthClient({baseURL:`${ctx.baseURL}${authProfilePath(profile)}`,plugins:[twoFactorClient()],fetchOptions:{customFetchImpl:ctx.actor("owner",profile).fetch}});
    const email=ctx.uniqueEmail("otp-counter");const signup=await owner.signUp.email({email,password:"password123",name:"Counter Owner"});expect(signup.error).toBeNull();if(!signup.data)throw new Error("owner required");
    const enable=await owner.twoFactor.enable({password:"password123",method:"otp"});expect(enable.error).toBeNull();expect((await owner.signOut()).error).toBeNull();const pending=await owner.signIn.email({email,password:"password123"});expect(pending.data).toMatchObject({twoFactorRedirect:true});
    const control=async(extra:Record<string,unknown>={})=>controlSchema.parse((await ctx.rawRequest({path:"/__test/two-factor-otp-config",method:"POST",json:{profile,email,...extra}})).body);
    const counters: Array<[string,string]>=[["-1.5suffix","0"],["-"+"9".repeat(400),"-Infinity"],["Infinity","1"],["\ufeff+1.9","2"],["0x10","1"],["1:ignored","2"]];
    const observations=[];
    for(const [counter,expected] of counters){
      expect((await owner.twoFactor.sendOtp({})).error).toBeNull();const before=await control({counter});if(!before.row)throw new Error("actual row required");
      const wrong=await owner.twoFactor.verifyOtp({code:"wrong"});expect(wrong.error?.code).toBe("INVALID_CODE");const after=await control();expect(after.row?.value).toBe(`${before.row.value.split(":")[0]}:${expected}`);observations.push({counter,next:after.row?.value.split(":")[1],wrong});
    }
    expect((await owner.twoFactor.sendOtp({})).error).toBeNull();const nearLimit=profile.endsWith("hashed")?"2junk":"4junk";const atLimit=profile.endsWith("hashed")?"3":"5";const before=await control({counter:nearLimit});if(!before.row||!before.delivery)throw new Error("delivery required");
    const wrong=await owner.twoFactor.verifyOtp({code:"wrong"});expect(wrong.error?.code).toBe("INVALID_CODE");expect((await control()).row?.value.split(":")[1]).toBe(atLimit);
    const exhausted=await owner.twoFactor.verifyOtp({code:before.delivery.otp});expect(exhausted.error?.code).toBe("TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE");expect((await control({identifier:before.row.identifier})).row).toBeNull();const replay=await owner.twoFactor.verifyOtp({code:before.delivery.otp});expect(replay.error?.code).toBe("OTP_HAS_EXPIRED");
    const state=await ctx.readUserState({userId:signup.data.user.id});expect(z.object({user:z.object({twoFactorEnabled:z.boolean()}),twoFactorExists:z.boolean(),sessions:z.array(z.unknown())}).parse(state)).toMatchObject({user:{twoFactorEnabled:true},twoFactorExists:false});
    expect((await owner.twoFactor.sendOtp({})).error).toBeNull();const renewed=await control();if(!renewed.delivery||!renewed.row)throw new Error("renewed delivery required");const completion=await owner.twoFactor.verifyOtp({code:renewed.delivery.otp});expect(completion.error).toBeNull();expect(completion.data?.user.id).toBe(signup.data.user.id);const finalState=z.object({sessions:z.array(z.object({token:z.string(),userId:z.string()}))}).parse(await ctx.readUserState({userId:signup.data.user.id}));expect(finalState.sessions).toHaveLength(1);expect(finalState.sessions[0]?.token).toBe(completion.data?.token);expect(finalState.sessions[0]?.userId).toBe(signup.data.user.id);
    return ctx.snapshot({signup,enable,pending,observations,wrong,exhausted,replay,state,completion,finalState});
  }, ["POST /two-factor/enable", "POST /two-factor/send-otp", "POST /two-factor/verify-otp"]);
}

compatScenario("two-factor OTP resends retain generations until the newest code is consumed once under concurrent requests",async ctx=>{
  const profile="two-factor-otp-plain",email=ctx.uniqueEmail("otp-race");let raceCookie="";const owner=createAuthClient({baseURL:`${ctx.baseURL}${authProfilePath(profile)}`,plugins:[twoFactorClient()],fetchOptions:{customFetchImpl:async(input,init)=>{const response=await ctx.actor("owner",profile).fetch(input,init);const cookie=response.headers.getSetCookie().find(value=>value.split("=")[0]?.endsWith(".session_token"));if(cookie)raceCookie=cookie.split(";")[0]??"";return response;}}});
  const signup=await owner.signUp.email({email,password:"password123",name:"Race Owner"});expect(signup.error).toBeNull();if(!signup.data)throw new Error("owner required");
  const enabled=await owner.twoFactor.enable({password:"password123",method:"otp"});expect(enabled.error).toBeNull();expect(raceCookie).not.toBe("");
  // Concurrent completion order is unspecified. Each official SDK request keeps
  // a complete canonical transport record; accepted/rejected order is semantic.
  const control=async(extra:Record<string,unknown>={})=>controlSchema.parse((await ctx.rawRequest({path:"/__test/two-factor-otp-config",method:"POST",json:{profile,email,...extra}})).body);
  expect((await owner.twoFactor.sendOtp({})).error).toBeNull();const first=await control();if(!first.row)throw new Error("first generation required");expect(first.generations).toBe(1);
  expect((await owner.twoFactor.sendOtp({})).error).toBeNull();const latest=await control();if(!latest.row||!latest.delivery)throw new Error("latest generation required");expect(latest.row.id).not.toBe(first.row.id);expect(latest.generations).toBe(2);
  const outcomes=await Promise.all(Array.from({length:2},async()=>{
    const entries:TraceEntry[]=[];
    const racer=createAuthClient({baseURL:`${ctx.baseURL}${authProfilePath(profile)}`,plugins:[twoFactorClient()],fetchOptions:{headers:{cookie:raceCookie},customFetchImpl:createTracingFetch(ctx.baseURL,"otp-race",entries,authProfilePath(profile))}});
    return {result:await racer.twoFactor.verifyOtp({code:latest.delivery!.otp}),entries};
  }));
  outcomes.sort((left,right)=>Number(left.result.error!==null)-Number(right.result.error!==null));
  expect(outcomes.every(outcome=>outcome.entries.length===1)).toBe(true);ctx.recordTransport(outcomes.flatMap(outcome=>outcome.entries));
  const results=outcomes.map(outcome=>outcome.result);const success=results.filter(result=>result.error===null);const denied=results.filter(result=>result.error!==null);expect(success).toHaveLength(1);expect(denied).toHaveLength(1);expect(denied[0]?.error?.code).toBe("OTP_HAS_EXPIRED");
  const consumed=await control({identifier:latest.row.identifier});expect(consumed.row).toBeNull();expect(consumed.generations).toBe(0);const state=z.object({twoFactorExists:z.boolean(),sessions:z.array(z.object({token:z.string()}))}).parse(await ctx.readUserState({userId:signup.data.user.id}));expect(state.sessions).toHaveLength(1);expect(state.sessions[0]?.token).toBe(success[0]?.data?.token);expect(state.twoFactorExists).toBe(false);
  return ctx.snapshot({signup,enabled,success:success[0],denied:denied[0],state,generations:[first.generations,latest.generations,consumed.generations]});
}, ["POST /two-factor/enable", "POST /two-factor/send-otp", "POST /two-factor/verify-otp"]);


compatScenario("two-factor nonpositive OTP lengths fail before storage or delivery while retaining body and session validation", async ctx => {
  const observations = [];
  for (const profile of ["two-factor-otp-zero", "two-factor-otp-negative"] as const) {
    const client = (name:string) => createAuthClient({baseURL:`${ctx.baseURL}${authProfilePath(profile)}`,plugins:[twoFactorClient()],fetchOptions:{customFetchImpl:ctx.actor(name,profile).fetch}});
    const owner = client("owner"), guest = client("guest"), email = ctx.uniqueEmail(profile);
    const denied = await guest.twoFactor.sendOtp({}); expect(denied.error?.code).toBe("INVALID_TWO_FACTOR_COOKIE");
    const signup = await owner.signUp.email({email,password:"password123",name:"Nonpositive OTP Owner"});
    expect(signup.error).toBeNull(); if (!signup.data) throw new Error("owner required");
    const original = await owner.getSession(), before = await ctx.readUserState({userId:signup.data.user.id});
    const malformed = await ctx.actor("owner",profile).fetch(`${ctx.baseURL}${authProfilePath(profile)}/two-factor/send-otp`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({trustDevice:null})});
    expect(malformed.status).toBe(400); const malformedBody = await malformed.json(); expect(malformedBody).toMatchObject({code:"VALIDATION_ERROR"});
    const failed = await owner.twoFactor.sendOtp({}); expect(failed.error?.status).toBe(500);
    const actual = await ctx.rawRequest({path:"/__test/two-factor-otp-config",method:"POST",json:{profile,email}});
    expect(actual.status).toBe(200); const stored = controlSchema.parse(actual.body);
    expect(stored).toEqual({delivery:null,row:null,generations:0,receipts:[]});
    expect(await ctx.readUserState({userId:signup.data.user.id})).toEqual(before);
    const current = await owner.getSession(); expect(current.data?.session.token).toBe(original.data?.session.token); expect(current.data?.user.twoFactorEnabled).toBe(false);
    observations.push({profile,denied,signup,original,malformedBody,failed,stored,current,before});
  }
  return ctx.snapshot(observations);
}, ["POST /two-factor/send-otp"]);
