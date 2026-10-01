import { expect } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { passkeyClient } from "@better-auth/passkey/client";
import { decodeCBOR, encodeCBOR, type CBORType } from "@levischuck/tiny-cbor";
import { z } from "zod";
import { Authenticator } from "../../support/authenticator";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { authProfilePath } from "../../support/profiles";

// Both encodings round-trip exactly; every value remains in the observations.
function registration(value: any): any {
  const clientData=JSON.parse(Buffer.from(value.response.clientDataJSON,"base64url").toString());
  expect(Buffer.from(JSON.stringify(clientData)).toString("base64url")).toBe(value.response.clientDataJSON);
  const encoded=Buffer.from(value.response.attestationObject,"base64url");const decoded=decodeCBOR(Uint8Array.from(encoded));
  expect(Buffer.from(encodeCBOR(decoded)).equals(encoded)).toBe(true);
  function cbor(value: CBORType, key?:string|number):unknown {
    if(value instanceof Map)return [...value].map(([key,child])=>[key,cbor(child,key)]);
    if(value instanceof Uint8Array)return key==="sig"?{token:Buffer.from(value).toString("base64url")}:Buffer.from(value).toString("base64");
    if(Array.isArray(value))return value.map(child=>cbor(child));
    return value;
  }
  return {...value,response:{...value.response,clientDataJSON:{...clientData,origin:{url:clientData.origin}},attestationObject:cbor(decoded)}};
}
async function setup(ctx:ScenarioContext){
  const requests:any[]=[];
  const make=(name:string)=>createAuthClient({baseURL:`${ctx.baseURL}${authProfilePath("passkey-first")}`,plugins:[passkeyClient()],fetchOptions:{customFetchImpl:async(input,init)=>{
    const request=new Request(input,init);
    if(new URL(request.url).pathname.endsWith("/passkey/verify-registration"))requests.push(await request.clone().json());
    return ctx.actor(name,"passkey-first").fetch(request);
  }}});
  const owner=make("registration-owner"),foreign=make("registration-foreign");
  const signup=await owner.signUp.email({email:ctx.uniqueEmail("registration-owner"),name:"Registration Owner",password:"password123"});expect(signup.error).toBeNull();
  let foreignCookies:string[]=[];const foreignSignup=await foreign.signUp.email({email:ctx.uniqueEmail("registration-foreign"),name:"Registration Foreign",password:"password123"},{onSuccess({response}){foreignCookies=response.headers.getSetCookie();}});expect(foreignSignup.error).toBeNull();
  const context=ctx.uniqueToken("source-registration");
  const enrollmentResponse=await ctx.actor("registration-owner","passkey-first").fetch(`${ctx.baseURL}/__test/passkey-enrollment`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({context,mode:"normal",userId:foreignSignup.data!.user.id})});expect(enrollmentResponse.status).toBe(200);
  const enrollment=await enrollmentResponse.json();expect(enrollment.userId).toBe(signup.data!.user.id);
  await owner.signOut();const before=await ctx.readUserState({userId:signup.data!.user.id}),foreignBefore=await ctx.readUserState({userId:foreignSignup.data!.user.id});
  const events=async()=>{const response=await ctx.rawRequest({path:"/__test/passkey-registration-events"});expect(response.status).toBe(200);return z.object({events:z.array(z.record(z.string(),z.any()))}).parse(response.body).events;};
  const state=async()=>{const response=await ctx.rawRequest({path:`/__test/passkey-state?userId=${encodeURIComponent(signup.data!.user.id)}`});expect(response.status).toBe(200);return response.body;};
  let challengeCookies:string[]=[];const options=async()=>{const result=await owner.$fetch("/passkey/generate-register-options",{method:"GET",query:{context},onSuccess({response}){challengeCookies=response.headers.getSetCookie();}});expect(result.error).toBeNull();return result;};
  const foreignHeaders=()=>({cookie:[...foreignCookies,...challengeCookies].map(cookie=>cookie.split(";")[0]).join("; ")});
  const submitted=()=>requests.map(row=>({...row,response:registration(row.response)}));
  return {owner,foreign,signup,foreignSignup,context,enrollment,before,foreignBefore,events,state,options,requests,submitted,foreignHeaders};
}
for(const mode of ["none-uv-absent","packed-uv-absent","packed-uv-absent-backed"] as const)compatScenario(`passkey ${mode} registration verifies genuine credential before callback session and signed authentication`,async ctx=>{
  const fixture=await setup(ctx),options=await fixture.options(),device=new Authenticator();
  const backed=mode.endsWith("backed");
  const response={...device.register(options.data,ctx.baseURL,{userVerified:false,attestation:mode.startsWith("packed")?"packed":"none",backupEligible:backed,backedUp:backed}),applicationMarker:"original-registration-proof",userId:fixture.foreignSignup.data!.user.id};
  const accepted=await fixture.owner.$fetch("/passkey/verify-registration",{method:"POST",body:{response,createSession:true,context:"forged-context",userId:fixture.foreignSignup.data!.user.id}});expect(accepted.error).toBeNull();
  expect(accepted.data).toMatchObject({userId:fixture.signup.data!.user.id,credentialID:response.id,counter:0,deviceType:backed?"multiDevice":"singleDevice",backedUp:backed,user:{id:fixture.signup.data!.user.id},session:{userId:fixture.signup.data!.user.id}});
  const events=await fixture.events();expect(events).toHaveLength(2);expect(events[1]).toMatchObject({stage:"verified",context:fixture.context,userId:fixture.signup.data!.user.id,counter:0,deviceType:backed?"multiDevice":"singleDevice",backedUp:backed});
  expect(events[1]!.clientData).toEqual(fixture.requests[0].response);expect(fixture.requests[0].response).toEqual(response);
  const current=await fixture.owner.getSession();expect(current.data?.user.id).toBe(fixture.signup.data!.user.id);
  const registeredSession=z.object({session:z.object({id:z.string(),token:z.string()})}).parse(accepted.data);expect(current.data?.session.id).toBe(registeredSession.session.id);expect(current.data?.session.token).toBe(registeredSession.session.token);
  const listed=await fixture.owner.$fetch("/passkey/list-user-passkeys",{method:"GET"});expect(listed.data).toMatchObject([{credentialID:response.id,counter:0}]);
  const replay=await fixture.owner.$fetch("/passkey/verify-registration",{method:"POST",body:{response,createSession:true}});expect(replay.error).toMatchObject({status:400,code:"CHALLENGE_NOT_FOUND"});expect(await fixture.events()).toEqual([]);
  const enrolled=await fixture.state();expect(enrolled).toMatchObject({passkeys:[{userId:fixture.signup.data!.user.id,counter:0}],sessions:{count:1},challenges:{count:0}});
  await fixture.owner.signOut();
  const challenge=await fixture.owner.$fetch("/passkey/generate-authenticate-options",{method:"GET"});expect(challenge.error).toBeNull();
  const authenticated=await fixture.owner.$fetch("/passkey/verify-authentication",{method:"POST",body:{response:device.authenticate(challenge.data,ctx.baseURL,{userVerified:false,backupEligible:backed,backedUp:backed})}});expect(authenticated.error).toBeNull();expect(authenticated.data).toMatchObject({user:{id:fixture.signup.data!.user.id},session:{userId:fixture.signup.data!.user.id}});
  const authenticatedCurrent=await fixture.owner.getSession();expect(authenticatedCurrent.data?.user.id).toBe(fixture.signup.data!.user.id);
  const authenticatedSession=z.object({session:z.object({id:z.string(),token:z.string()})}).parse(authenticated.data);expect(authenticatedCurrent.data?.session.id).toBe(authenticatedSession.session.id);expect(authenticatedCurrent.data?.session.token).toBe(authenticatedSession.session.token);
  const authenticatedList=await fixture.owner.$fetch("/passkey/list-user-passkeys",{method:"GET"});expect(authenticatedList.data).toMatchObject([{credentialID:response.id,userId:fixture.signup.data!.user.id,counter:1,deviceType:backed?"multiDevice":"singleDevice",backedUp:backed}]);
  const ownerAfter=await ctx.readUserState({userId:fixture.signup.data!.user.id});
  const after=await fixture.state();expect(after).toMatchObject({passkeys:[{userId:fixture.signup.data!.user.id,counter:1}],sessions:{count:1},challenges:{count:0}});
  const foreignAfter=await ctx.readUserState({userId:fixture.foreignSignup.data!.user.id});expect(foreignAfter).toEqual(fixture.foreignBefore);
  return {signup:fixture.signup,foreignSignup:fixture.foreignSignup,enrollment:fixture.enrollment,options,before:fixture.before,accepted,current,listed,events:events.map(row=>row.stage==="verified"?{...row,clientData:registration(row.clientData)}:row),submitted:fixture.submitted(),replay,enrolled,challenge,authenticated,authenticatedCurrent,authenticatedList,ownerAfter,after,foreignBefore:fixture.foreignBefore,foreignAfter};
},["POST /passkey/verify-registration","POST /passkey/verify-authentication"]);

compatScenario("passkey registration rejects actual packed signature failures malformed proofs flags origins and wrong owner before writes",async ctx=>{
  const fixture=await setup(ctx),device=new Authenticator(),outputs=[];
  for(const mode of ["signature","signature-der","presence","backup-flags","rp","origin-host","origin-port","origin-case","challenge","malformed-key","foreign-owner"] as const){
    const options=await fixture.options();
    const flags={attestation:"packed" as const,...(mode==="signature"?{badSignature:true}:mode==="signature-der"?{malformedSignature:true}:mode==="presence"?{userPresent:false}:mode==="backup-flags"?{backedUp:true}:mode==="rp"?{rpId:"foreign.fixture.test"}:mode==="malformed-key"?{malformedKey:true}:{})};
    const origin=mode==="origin-host"?"http://foreign.fixture.test":mode==="origin-port"?ctx.baseURL.replace(/:\d+$/,":1"):mode==="origin-case"?ctx.baseURL.replace("localhost","LOCALHOST"):ctx.baseURL;
    const response=device.register(mode==="challenge"?{...options.data as object,challenge:"wrong-registration-challenge"}:options.data,origin,flags);
    let cookies:string[]=[];const result=await(mode==="foreign-owner"?fixture.foreign:fixture.owner).$fetch("/passkey/verify-registration",{method:"POST",body:{response,createSession:true},...(mode==="foreign-owner"?{headers:fixture.foreignHeaders()}:{}),onResponse({response}){cookies=response.headers.getSetCookie();}});
    expect(result.error).toMatchObject({status:mode==="signature"?400:mode==="foreign-owner"?401:500,code:mode==="foreign-owner"?"YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY":"FAILED_TO_VERIFY_REGISTRATION"});expect(cookies).toEqual([]);
    const events=await fixture.events();expect(events).toHaveLength(1);expect(events[0]).toMatchObject({stage:"resolved",context:fixture.context,userId:fixture.signup.data!.user.id});
    const replay=await fixture.owner.$fetch("/passkey/verify-registration",{method:"POST",body:{response,createSession:true}});expect(replay.error).toMatchObject({status:400,code:"CHALLENGE_NOT_FOUND"});expect(await fixture.events()).toEqual([]);
    const state=await fixture.state();expect(state).toEqual({passkeys:[],sessions:{count:0},challenges:{count:0}});
    expect(await ctx.readUserState({userId:fixture.signup.data!.user.id})).toEqual(fixture.before);expect(await ctx.readUserState({userId:fixture.foreignSignup.data!.user.id})).toEqual(fixture.foreignBefore);
    outputs.push({mode,options,result,cookies,events,replay,state});
  }
  return {signup:fixture.signup,foreignSignup:fixture.foreignSignup,enrollment:fixture.enrollment,before:fixture.before,foreignBefore:fixture.foreignBefore,outputs,submitted:fixture.submitted(),after:await ctx.readUserState({userId:fixture.signup.data!.user.id}),foreignAfter:await ctx.readUserState({userId:fixture.foreignSignup.data!.user.id})};
},["POST /passkey/verify-registration"]);
