import { expect } from "bun:test";
import { Cookie } from "tough-cookie";
import { createAuthClient } from "better-auth/client";
import { passkeyClient } from "@better-auth/passkey/client";
import { decodeCBOR, decodePartialCBOR, encodeCBOR, type CBORType } from "@levischuck/tiny-cbor";
import { z } from "zod";
import { Authenticator } from "../../support/authenticator";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { type FixtureProfile, authProfilePath } from "../../support/profiles";

// Both encodings round-trip exactly; every value remains in the observations.
function registration(value: any): any {
  const clientData=JSON.parse(Buffer.from(value.response.clientDataJSON,"base64url").toString());
  expect(Buffer.from(JSON.stringify(clientData)).toString("base64url")).toBe(value.response.clientDataJSON);
  const encoded=Buffer.from(value.response.attestationObject,"base64url");let decoded:CBORType,length:number;
  try{[decoded,length]=decodePartialCBOR(Uint8Array.from(encoded),0);}catch{
    expect(Buffer.from(encoded.toString("base64"),"base64").equals(encoded)).toBe(true);
    return {...value,response:{...value.response,clientDataJSON:{...clientData,origin:{url:clientData.origin}},attestationObject:{bytes:encoded.toString("base64")}}};
  }
  const prefix=Buffer.from(encodeCBOR(decoded)),canonical=prefix.length===length&&encoded.subarray(0,length).equals(prefix),remainder=encoded.subarray(length);if(canonical){expect(prefix.length).toBe(length);expect(encoded.subarray(0,length).equals(prefix)).toBe(true);expect(Buffer.concat([prefix,remainder]).equals(encoded)).toBe(true);}else{expect(Buffer.from(encoded.toString("base64"),"base64").equals(encoded)).toBe(true);expect(Buffer.concat([encoded.subarray(0,length),remainder]).equals(encoded)).toBe(true);}
  function cbor(value: CBORType, key?:string|number):unknown {
    if(value instanceof Map)return [...value].map(([key,child])=>[key,cbor(child,key)]);
    if(value instanceof Uint8Array)return key==="sig"?{token:Buffer.from(value).toString("base64url")}:Buffer.from(value).toString("base64");
    if(Array.isArray(value))return value.map(child=>cbor(child));
    return value;
  }
  return {...value,response:{...value.response,clientDataJSON:{...clientData,origin:{url:clientData.origin}},attestationObject:!canonical?{cbor:cbor(decoded),bytes:encoded.toString("base64")}:remainder.length?{cbor:cbor(decoded),trailingBytes:remainder.toString("base64")}:cbor(decoded)}};
}
function authentication(value:any,options:any):any {
  const clientData=JSON.parse(Buffer.from(value.response.clientDataJSON,"base64url").toString());
  expect(Buffer.from(JSON.stringify(clientData)).toString("base64url")).toBe(value.response.clientDataJSON);
  expect(value.response.userHandle).toBe(options.user.id);
  const generatedId=Buffer.from(value.response.userHandle,"base64url").toString();expect(Buffer.from(generatedId).toString("base64url")).toBe(value.response.userHandle);
  return {...value,response:{...value.response,clientDataJSON:{...clientData,origin:{url:clientData.origin}},userHandle:{id:value.response.userHandle,decoded:{id:generatedId}},signature:{token:value.response.signature}}};
}
async function setup(ctx:ScenarioContext,profile:FixtureProfile="passkey-first"){
  const requests:any[]=[],authenticationRequests:any[]=[];
  const make=(name:string)=>createAuthClient({baseURL:`${ctx.baseURL}${authProfilePath(profile)}`,plugins:[passkeyClient()],fetchOptions:{customFetchImpl:async(input,init)=>{
    const request=new Request(input,init);
    if(new URL(request.url).pathname.endsWith("/passkey/verify-registration"))requests.push(await request.clone().json());
    if(new URL(request.url).pathname.endsWith("/passkey/verify-authentication"))authenticationRequests.push(await request.clone().json());
    return ctx.actor(name,profile).fetch(request);
  }}});
  const owner=make("registration-owner"),foreign=make("registration-foreign");
  const signup=await owner.signUp.email({email:ctx.uniqueEmail("registration-owner"),name:"Registration Owner",password:"password123"});expect(signup.error).toBeNull();
  let foreignCookies:string[]=[];const foreignSignup=await foreign.signUp.email({email:ctx.uniqueEmail("registration-foreign"),name:"Registration Foreign",password:"password123"},{onSuccess({response}){foreignCookies=response.headers.getSetCookie();}});expect(foreignSignup.error).toBeNull();
  const context=ctx.uniqueToken("source-registration");
  const enrollmentResponse=await ctx.actor("registration-owner",profile).fetch(`${ctx.baseURL}/__test/passkey-enrollment`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({context,mode:"normal",userId:foreignSignup.data!.user.id})});expect(enrollmentResponse.status).toBe(200);
  const enrollment=await enrollmentResponse.json();expect(enrollment.userId).toBe(signup.data!.user.id);
  await owner.signOut();const before=await ctx.readUserState({userId:signup.data!.user.id}),foreignBefore=await ctx.readUserState({userId:foreignSignup.data!.user.id});
  const events=async()=>{const response=await ctx.rawRequest({path:"/__test/passkey-registration-events"});expect(response.status).toBe(200);return z.object({events:z.array(z.record(z.string(),z.any()))}).parse(response.body).events;};
  const state=async()=>{const response=await ctx.rawRequest({path:`/__test/passkey-state?userId=${encodeURIComponent(signup.data!.user.id)}`});expect(response.status).toBe(200);return response.body;};
  let challengeCookies:string[]=[];const options=async()=>{const result=await owner.$fetch("/passkey/generate-register-options",{method:"GET",query:{context},onSuccess({response}){challengeCookies=response.headers.getSetCookie();}});expect(result.error).toBeNull();return result;};
  const foreignHeaders=()=>({cookie:[...foreignCookies,...challengeCookies].map(cookie=>cookie.split(";")[0]).join("; ")});
  const submitted=()=>requests.map(row=>({...row,response:registration(row.response)}));
  return {owner,foreign,signup,foreignSignup,context,enrollment,before,foreignBefore,events,state,options,requests,authenticationRequests,submitted,foreignHeaders};
}
for(const mode of ["none-uv-absent","packed-uv-absent","packed-uv-absent-backed","eddsa-none-uv-absent","eddsa-packed-uv-absent"] as const)compatScenario(`passkey ${mode} registration verifies genuine credential before callback session and signed authentication`,async ctx=>{
  const fixture=await setup(ctx),options=await fixture.options(),registrationOptions=options.data,device=new Authenticator(mode.startsWith("eddsa")?"Ed25519":"ES256");
  const backed=mode.endsWith("backed");
  const response={...device.register(options.data,ctx.baseURL,{userVerified:false,attestation:mode.includes("packed")?"packed":"none",backupEligible:backed,backedUp:backed}),applicationMarker:"original-registration-proof",userId:fixture.foreignSignup.data!.user.id};
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
  const authenticationFailures=[];
  if(mode==="eddsa-packed-uv-absent"){
    const beforeFailure=await fixture.state(),ownerBeforeFailure=await ctx.readUserState({userId:fixture.signup.data!.user.id});
    for(const failure of ["signature","signature-length"] as const){
      const options=await fixture.owner.$fetch("/passkey/generate-authenticate-options",{method:"GET"});expect(options.error).toBeNull();
      const proof=device.authenticate(options.data,ctx.baseURL,{userVerified:false,counter:2,...(failure==="signature"?{badSignature:true}:{malformedSignature:true})});
      const denied=await fixture.owner.$fetch("/passkey/verify-authentication",{method:"POST",body:{response:proof}});expect(denied.error).toMatchObject({status:401,code:"AUTHENTICATION_FAILED"});
      const replay=await fixture.owner.$fetch("/passkey/verify-authentication",{method:"POST",body:{response:proof}});expect(replay.error).toMatchObject({status:400,code:"CHALLENGE_NOT_FOUND"});
      const state=await fixture.state();expect(state).toEqual(beforeFailure);expect(await ctx.readUserState({userId:fixture.signup.data!.user.id})).toEqual(ownerBeforeFailure);
      const original=fixture.authenticationRequests.at(-2);expect(original).toEqual({response:proof});expect(fixture.authenticationRequests.at(-1)).toEqual(original);
      expect(Buffer.from(proof.response.signature,"base64url")).toHaveLength(failure==="signature"?64:1);
      authenticationFailures.push({failure,options,proof:authentication(proof,registrationOptions),denied,replay,state});
    }
  }
  const ownerAfter=await ctx.readUserState({userId:fixture.signup.data!.user.id});
  const after=await fixture.state();expect(after).toMatchObject({passkeys:[{userId:fixture.signup.data!.user.id,counter:1}],sessions:{count:1},challenges:{count:0}});
  const foreignAfter=await ctx.readUserState({userId:fixture.foreignSignup.data!.user.id});expect(foreignAfter).toEqual(fixture.foreignBefore);
  return {signup:fixture.signup,foreignSignup:fixture.foreignSignup,enrollment:fixture.enrollment,options,before:fixture.before,accepted,current,listed,events:events.map(row=>row.stage==="verified"?{...row,clientData:registration(row.clientData)}:row),submitted:fixture.submitted(),replay,enrolled,challenge,authenticated,authenticatedCurrent,authenticatedList,authenticationFailures,authenticationSubmitted:fixture.authenticationRequests.map(row=>({...row,response:authentication(row.response,registrationOptions)})),ownerAfter,after,foreignBefore:fixture.foreignBefore,foreignAfter};
},["POST /passkey/verify-registration","POST /passkey/verify-authentication"]);

compatScenario("passkey registration rejects actual packed signature failures malformed proofs flags origins and wrong owner before writes",async ctx=>{
  const fixture=await setup(ctx),device=new Authenticator(),outputs=[];
  for(const mode of ["signature","signature-der","presence","backup-flags","rp","origin-host","origin-port","origin-case","challenge","malformed-key","foreign-owner","eddsa-signature","eddsa-signature-length","eddsa-foreign-owner"] as const){
    const options=await fixture.options();
    const flags={attestation:"packed" as const,...((mode==="signature"||mode==="eddsa-signature")?{badSignature:true}:(mode==="signature-der"||mode==="eddsa-signature-length")?{malformedSignature:true}:mode==="presence"?{userPresent:false}:mode==="backup-flags"?{backedUp:true}:mode==="rp"?{rpId:"foreign.fixture.test"}:mode==="malformed-key"?{malformedKey:true}:{})};
    const origin=mode==="origin-host"?"http://foreign.fixture.test":mode==="origin-port"?ctx.baseURL.replace(/:\d+$/,":1"):mode==="origin-case"?ctx.baseURL.replace("localhost","LOCALHOST"):ctx.baseURL;
    const response=(mode.startsWith("eddsa")?new Authenticator("Ed25519"):device).register(mode==="challenge"?{...options.data as object,challenge:"wrong-registration-challenge"}:options.data,origin,flags);
    let cookies:string[]=[];const result=await(mode.endsWith("foreign-owner")?fixture.foreign:fixture.owner).$fetch("/passkey/verify-registration",{method:"POST",body:{response,createSession:true},...(mode.endsWith("foreign-owner")?{headers:fixture.foreignHeaders()}:{}),onResponse({response}){cookies=response.headers.getSetCookie();}});
    expect(result.error).toMatchObject({status:(mode==="signature"||mode.startsWith("eddsa-signature"))?400:mode.endsWith("foreign-owner")?401:500,code:mode.endsWith("foreign-owner")?"YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY":"FAILED_TO_VERIFY_REGISTRATION"});expect(cookies).toEqual([]);
    const events=await fixture.events();expect(events).toHaveLength(1);expect(events[0]).toMatchObject({stage:"resolved",context:fixture.context,userId:fixture.signup.data!.user.id});
    const replay=await fixture.owner.$fetch("/passkey/verify-registration",{method:"POST",body:{response,createSession:true}});expect(replay.error).toMatchObject({status:400,code:"CHALLENGE_NOT_FOUND"});expect(await fixture.events()).toEqual([]);
    const state=await fixture.state();expect(state).toEqual({passkeys:[],sessions:{count:0},challenges:{count:0}});
    expect(await ctx.readUserState({userId:fixture.signup.data!.user.id})).toEqual(fixture.before);expect(await ctx.readUserState({userId:fixture.foreignSignup.data!.user.id})).toEqual(fixture.foreignBefore);
    outputs.push({mode,options,result,cookies,events,replay,state});
  }
  return {signup:fixture.signup,foreignSignup:fixture.foreignSignup,enrollment:fixture.enrollment,before:fixture.before,foreignBefore:fixture.foreignBefore,outputs,submitted:fixture.submitted(),after:await ctx.readUserState({userId:fixture.signup.data!.user.id}),foreignAfter:await ctx.readUserState({userId:fixture.foreignSignup.data!.user.id})};
},["POST /passkey/verify-registration"]);

for(const algorithm of ["Ed448","Ed25519Curve8"] as const)compatScenario(`passkey ${algorithm} none enrollment retains original owner while genuine and invalid signed authentication reject before writes`,async ctx=>{
  const fixture=await setup(ctx),options=await fixture.options(),device=new Authenticator(algorithm);
  const initialCounter=algorithm==="Ed25519Curve8"?25:0;
  const proof={...device.register(options.data,ctx.baseURL,{userVerified:false,counter:initialCounter}),userId:fixture.foreignSignup.data!.user.id};
  if(algorithm==="Ed25519Curve8"){
    const attestation=decodeCBOR(Uint8Array.from(Buffer.from(proof.response.attestationObject,"base64url")));if(!(attestation instanceof Map))throw new Error("actual attestation required");
    const data=Buffer.from(attestation.get("authData") as Uint8Array);data[32]=data[32]!|0x80;
    attestation.set("authData",Buffer.concat([data,Buffer.from(encodeCBOR(new Map([["application",new Map([["flag",true]])]])))]));
    proof.response.attestationObject=Buffer.concat([Buffer.from(encodeCBOR(attestation)),Buffer.from([0])]).toString("base64url");
    const clientData=JSON.parse(Buffer.from(proof.response.clientDataJSON,"base64url").toString());clientData.tokenBinding={status:"supported"};proof.response.clientDataJSON=Buffer.from(JSON.stringify(clientData)).toString("base64url");
  }
  const accepted=await fixture.owner.$fetch("/passkey/verify-registration",{method:"POST",body:{response:proof,createSession:true,userId:fixture.foreignSignup.data!.user.id,context:"foreign-context"}});expect(accepted.error).toBeNull();expect(accepted.data).toMatchObject({userId:fixture.signup.data!.user.id,credentialID:proof.id,counter:initialCounter,user:{id:fixture.signup.data!.user.id},session:{userId:fixture.signup.data!.user.id}});
  if(algorithm==="Ed25519Curve8"){
    const [decoded]=decodePartialCBOR(Uint8Array.from(Buffer.from(proof.response.attestationObject,"base64url")),0);const attestation=decoded as Map<string,CBORType>;
    const data=Buffer.from(attestation.get("authData") as Uint8Array),start=55+data.readUInt16BE(53),[rawKey]=decodePartialCBOR(Uint8Array.from(data.subarray(start)),0);
    if(!(rawKey instanceof Map))throw new Error("actual raw key required");expect(rawKey.get(1)).toBe(1);expect(rawKey.get(3)).toBe(-8);expect(rawKey.get(-1)).toBe(8);
    expect(Buffer.from(z.object({publicKey:z.string()}).parse(accepted.data).publicKey,"base64")).toEqual(Buffer.from(encodeCBOR(rawKey)));
    expect(accepted.data).not.toHaveProperty("credential");
  }
  const events=await fixture.events();expect(events).toHaveLength(2);expect(events[1]).toMatchObject({stage:"verified",userId:fixture.signup.data!.user.id,context:fixture.context});expect(events[1]!.clientData).toEqual(fixture.requests[0].response);expect(fixture.requests[0]).toEqual({response:proof,createSession:true,userId:fixture.foreignSignup.data!.user.id,context:"foreign-context"});
  const current=await fixture.owner.getSession();expect(current.data?.user.id).toBe(fixture.signup.data!.user.id);const issued=z.object({session:z.object({id:z.string(),token:z.string()})}).parse(accepted.data);expect(current.data?.session.id).toBe(issued.session.id);expect(current.data?.session.token).toBe(issued.session.token);
  const listed=await fixture.owner.$fetch("/passkey/list-user-passkeys",{method:"GET"});expect(listed.data).toMatchObject([{credentialID:proof.id,userId:fixture.signup.data!.user.id,counter:initialCounter}]);
  const replay=await fixture.owner.$fetch("/passkey/verify-registration",{method:"POST",body:{response:proof,createSession:true}});expect(replay.error).toMatchObject({status:400,code:"CHALLENGE_NOT_FOUND"});expect(await fixture.events()).toEqual([]);
  await fixture.owner.signOut();const enrolled=await fixture.state(),ownerBefore=await ctx.readUserState({userId:fixture.signup.data!.user.id});expect(enrolled).toMatchObject({passkeys:[{userId:fixture.signup.data!.user.id,counter:initialCounter}],sessions:{count:0},challenges:{count:0}});
  const authenticator=createAuthClient({baseURL:`${ctx.baseURL}${authProfilePath("passkey-auth-accept")}`,plugins:[passkeyClient()],fetchOptions:{customFetchImpl:async(input,init)=>{
    const request=new Request(input,init);if(new URL(request.url).pathname.endsWith("/passkey/verify-authentication"))fixture.authenticationRequests.push(await request.clone().json());return ctx.actor("ed448-authentication","passkey-auth-accept").fetch(request);
  }}});
  const attempts=[];
  for(const mode of ["genuine","signature","length"] as const){
    const challenge=await authenticator.$fetch("/passkey/generate-authenticate-options",{method:"GET"});expect(challenge.error).toBeNull();
    const assertion=device.authenticate(challenge.data,ctx.baseURL,{userVerified:false,counter:initialCounter+1,...(mode==="signature"?{badSignature:true}:mode==="length"?{malformedSignature:true}:{})});expect(Buffer.from(assertion.response.signature,"base64url")).toHaveLength(mode==="length"?1:algorithm==="Ed448"?114:64);
    let cookies:string[]=[];const denied=await authenticator.$fetch("/passkey/verify-authentication",{method:"POST",body:{response:assertion},onResponse({response}){cookies=response.headers.getSetCookie();}});expect(denied.error).toMatchObject({status:400,code:"AUTHENTICATION_FAILED"});expect(cookies).toEqual([]);
    const replay=await authenticator.$fetch("/passkey/verify-authentication",{method:"POST",body:{response:assertion}});expect(replay.error).toMatchObject({status:400,code:"CHALLENGE_NOT_FOUND"});expect(fixture.authenticationRequests.at(-2)).toEqual({response:assertion});expect(fixture.authenticationRequests.at(-1)).toEqual({response:assertion});expect(await fixture.events()).toEqual([]);
    const authenticationEvents=await ctx.rawRequest({path:"/__test/passkey-authentication-events"});expect(authenticationEvents.status).toBe(200);expect(authenticationEvents.body).toEqual([]);
    const state=await fixture.state();expect(state).toEqual(enrolled);expect(await ctx.readUserState({userId:fixture.signup.data!.user.id})).toEqual(ownerBefore);expect(await ctx.readUserState({userId:fixture.foreignSignup.data!.user.id})).toEqual(fixture.foreignBefore);
    attempts.push({mode,challenge,assertion:authentication(assertion,options.data),denied,cookies,replay,authenticationEvents,state});
  }
  return {signup:fixture.signup,foreignSignup:fixture.foreignSignup,enrollment:fixture.enrollment,options,accepted,current,listed,events:events.map(row=>row.stage==="verified"?{...row,clientData:registration(row.clientData)}:row),submitted:fixture.submitted(),replay,enrolled,ownerBefore,attempts,authenticationSubmitted:fixture.authenticationRequests.map(row=>({...row,response:authentication(row.response,options.data)})),ownerAfter:await ctx.readUserState({userId:fixture.signup.data!.user.id}),foreignBefore:fixture.foreignBefore,foreignAfter:await ctx.readUserState({userId:fixture.foreignSignup.data!.user.id})};
},["POST /passkey/verify-registration","POST /passkey/verify-authentication"]);

for(const algorithm of ["Ed448","Ed25519Curve8"] as const)compatScenario(`passkey ${algorithm} packed self attestation rejects genuine false and malformed signatures before callback enrollment or session`,async ctx=>{
  const fixture=await setup(ctx),device=new Authenticator(algorithm),attempts=[];
  for(const mode of ["genuine","signature","length"] as const){
    const options=await fixture.options(),proof=device.register(options.data,ctx.baseURL,{userVerified:false,attestation:"packed",...(mode==="signature"?{badSignature:true}:mode==="length"?{malformedSignature:true}:{})});
    const attestation=decodeCBOR(Uint8Array.from(Buffer.from(proof.response.attestationObject,"base64url")));if(!(attestation instanceof Map))throw new Error("actual attestation map required");const statement=attestation.get("attStmt");if(!(statement instanceof Map))throw new Error("actual statement map required");const signature=statement.get("sig");if(!(signature instanceof Uint8Array))throw new Error("actual signature bytes required");expect(signature).toHaveLength(mode==="length"?1:algorithm==="Ed448"?114:64);
    let cookies:string[]=[];const denied=await fixture.owner.$fetch("/passkey/verify-registration",{method:"POST",body:{response:proof,createSession:true},onResponse({response}){cookies=response.headers.getSetCookie();}});expect(denied.error).toMatchObject({status:500,code:"FAILED_TO_VERIFY_REGISTRATION"});expect(cookies).toEqual([]);
    const events=await fixture.events();expect(events).toHaveLength(1);expect(events[0]).toMatchObject({stage:"resolved",userId:fixture.signup.data!.user.id,context:fixture.context});expect(fixture.requests.at(-1)).toEqual({response:proof,createSession:true});
    const replay=await fixture.owner.$fetch("/passkey/verify-registration",{method:"POST",body:{response:proof,createSession:true}});expect(replay.error).toMatchObject({status:400,code:"CHALLENGE_NOT_FOUND"});expect(await fixture.events()).toEqual([]);
    const state=await fixture.state();expect(state).toEqual({passkeys:[],sessions:{count:0},challenges:{count:0}});expect(await ctx.readUserState({userId:fixture.signup.data!.user.id})).toEqual(fixture.before);expect(await ctx.readUserState({userId:fixture.foreignSignup.data!.user.id})).toEqual(fixture.foreignBefore);
    attempts.push({mode,options,denied,cookies,events,replay,state});
  }
  return {signup:fixture.signup,foreignSignup:fixture.foreignSignup,enrollment:fixture.enrollment,before:fixture.before,foreignBefore:fixture.foreignBefore,attempts,submitted:fixture.submitted(),ownerAfter:await ctx.readUserState({userId:fixture.signup.data!.user.id}),foreignAfter:await ctx.readUserState({userId:fixture.foreignSignup.data!.user.id})};
},["POST /passkey/verify-registration"]);

compatScenario("passkey raw curve8 none admission validates the actual ceremony before callback persistence and owner issuance",async ctx=>{
  const fixture=await setup(ctx),device=new Authenticator("Ed25519Curve8"),attempts=[];
  for(const mode of ["presence","backup-flags","rp","origin-case","challenge","client-type","token-binding","statement","statement-null","outer-indefinite","statement-indefinite","duplicate-fmt","duplicate-auth-data","boolean-map-key","array-map-key","finite-half-statement","huge-integer-statement","numeric-map-key-collision","nan-map-key-collision","signed-zero-map-key-collision","key-nonminimal","authdata-tail","extensions-tail","extensions-missing","extensions-scalar","extensions-array-numbers","credential-type","foreign-owner","expired"] as const){
    const options=await fixture.options();
    const proof=device.register(mode==="challenge"?{...options.data as object,challenge:"wrong-raw-none-challenge"}:options.data,mode==="origin-case"?ctx.baseURL.replace("localhost","LOCALHOST"):ctx.baseURL,{userVerified:false,...(mode==="presence"?{userPresent:false}:mode==="backup-flags"?{backedUp:true}:mode==="rp"?{rpId:"foreign.fixture.test"}:{})});
    const attestation=decodeCBOR(Uint8Array.from(Buffer.from(proof.response.attestationObject,"base64url"))) as Map<string,CBORType>;
    let data=Buffer.from(attestation.get("authData") as Uint8Array);
    if(mode==="key-nonminimal"){const start=55+data.readUInt16BE(53)+8;expect(data[start]).toBe(0x58);expect(data[start+1]).toBe(32);data=Buffer.concat([data.subarray(0,start),Buffer.from([0x59,0,32]),data.subarray(start+2)]);}
    if(mode==="authdata-tail")data=Buffer.concat([data,Buffer.from([0])]);
    if(mode.startsWith("extensions")){
      data[32]=data[32]!|0x80;
      if(mode!=="extensions-missing")data=Buffer.concat([data,Buffer.from(encodeCBOR(mode==="extensions-scalar"?9:mode==="extensions-array-numbers"?[9]:new Map([["application",true]])))]);
      if(mode==="extensions-tail")data=Buffer.concat([data,Buffer.from([0])]);
    }
    attestation.set("authData",data);
    if(mode==="statement")attestation.set("attStmt",new Map([["unexpected",true]]));
    if(mode==="statement-null")attestation.set("attStmt",null);
    proof.response.attestationObject=Buffer.from(encodeCBOR(attestation)).toString("base64url");
    if(mode==="outer-indefinite"){const encoded=Buffer.from(proof.response.attestationObject,"base64url");expect(encoded[0]).toBe(0xa3);proof.response.attestationObject=Buffer.concat([Buffer.from([0xbf]),encoded.subarray(1),Buffer.from([0xff])]).toString("base64url");}
    if(mode==="statement-indefinite"){const encoded=Buffer.from(proof.response.attestationObject,"base64url"),label=Buffer.from(encodeCBOR("attStmt")),start=encoded.indexOf(label)+label.length;expect(encoded[start]).toBe(0xa0);proof.response.attestationObject=Buffer.concat([encoded.subarray(0,start),Buffer.from([0x9f,0xff]),encoded.subarray(start+1)]).toString("base64url");}
    if(mode==="duplicate-fmt"||mode==="duplicate-auth-data"||mode==="boolean-map-key"||mode==="array-map-key"){
      const encoded=Buffer.from(proof.response.attestationObject,"base64url");expect(encoded[0]).toBe(0xa3);
      const key=mode==="duplicate-fmt"?"fmt":mode==="duplicate-auth-data"?"authData":mode==="boolean-map-key"?true:[];
      const value=mode==="duplicate-fmt"?"none":mode==="duplicate-auth-data"?data:9;
      proof.response.attestationObject=Buffer.concat([Buffer.from([0xa4]),encoded.subarray(1),Buffer.from(encodeCBOR(key)),Buffer.from(encodeCBOR(value))]).toString("base64url");
    }
    if(mode.endsWith("collision")){
      const encoded=Buffer.from(proof.response.attestationObject,"base64url");expect(encoded[0]).toBe(0xa3);
      const extra=mode==="numeric-map-key-collision"?[1,9,0xfa,0x3f,0x80,0,0,9]:mode==="nan-map-key-collision"?[0xf9,0x7e,0,9,0xfa,0x7f,0xc0,0,0,9]:[0,9,0xfa,0x80,0,0,0,9];
      proof.response.attestationObject=Buffer.concat([Buffer.from([0xa5]),encoded.subarray(1),Buffer.from(extra)]).toString("base64url");
    }
    if(mode==="finite-half-statement"||mode==="huge-integer-statement"){
      const encoded=Buffer.from(proof.response.attestationObject,"base64url"),label=Buffer.from(encodeCBOR("attStmt")),start=encoded.indexOf(label)+label.length;expect(encoded[start]).toBe(0xa0);
      const value=mode==="finite-half-statement"?[0xf9,0x3c,0x00]:[0x1b,0x00,0x20,0,0,0,0,0,0];
      proof.response.attestationObject=Buffer.concat([encoded.subarray(0,start),Buffer.from(value),encoded.subarray(start+1)]).toString("base64url");
    }
    const cd=JSON.parse(Buffer.from(proof.response.clientDataJSON,"base64url").toString());
    if(mode==="client-type")cd.type="webauthn.get";
    if(mode==="token-binding")cd.tokenBinding={status:"unexpected"};
    proof.response.clientDataJSON=Buffer.from(JSON.stringify(cd)).toString("base64url");
    if(mode==="credential-type")proof.type="password";
    let expired:unknown=null;
    if(mode==="expired"){
      const clock=await ctx.rawRequest({path:"/__test/passkey-challenge-clock",method:"POST",json:{expiresAt:"2000-01-01T00:00:00.000Z"}});expect(clock.status).toBe(200);expect(clock.body).toEqual({updated:true});expired=clock;
    }
    let cookies:string[]=[];
    const denied=await(mode==="foreign-owner"?fixture.foreign:fixture.owner).$fetch("/passkey/verify-registration",{method:"POST",body:{response:proof,createSession:true},...(mode==="foreign-owner"?{headers:fixture.foreignHeaders()}:{}),onResponse({response}){cookies=response.headers.getSetCookie();}});
    expect(denied.error,mode).toMatchObject({status:mode==="foreign-owner"?401:mode==="expired"?400:500,code:mode==="foreign-owner"?"YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY":mode==="expired"?"CHALLENGE_NOT_FOUND":"FAILED_TO_VERIFY_REGISTRATION"});expect(cookies).toEqual([]);
    const events=await fixture.events();expect(events).toHaveLength(1);expect(events[0]).toMatchObject({stage:"resolved",context:fixture.context,userId:fixture.signup.data!.user.id});expect(fixture.requests.at(-1)).toEqual({response:proof,createSession:true});
    const replay=await fixture.owner.$fetch("/passkey/verify-registration",{method:"POST",body:{response:proof,createSession:true}});expect(replay.error).toMatchObject({status:400,code:"CHALLENGE_NOT_FOUND"});expect(await fixture.events()).toEqual([]);
    const state=await fixture.state();expect(state).toEqual({passkeys:[],sessions:{count:0},challenges:{count:0}});expect(await ctx.readUserState({userId:fixture.signup.data!.user.id})).toEqual(fixture.before);expect(await ctx.readUserState({userId:fixture.foreignSignup.data!.user.id})).toEqual(fixture.foreignBefore);
    attempts.push({mode,options,expired,denied,cookies,events,replay,state});
  }
  return {signup:fixture.signup,foreignSignup:fixture.foreignSignup,enrollment:fixture.enrollment,before:fixture.before,foreignBefore:fixture.foreignBefore,attempts,submitted:fixture.submitted(),ownerAfter:await ctx.readUserState({userId:fixture.signup.data!.user.id}),foreignAfter:await ctx.readUserState({userId:fixture.foreignSignup.data!.user.id})};
},["POST /passkey/verify-registration"]);

compatScenario("passkey raw none source iterable extensions and primitive statements preserve actual enrollment and callbacks",async ctx=>{
  const fixture=await setup(ctx),outputs=[];
  for(const mode of ["statement-array","statement-string","statement-number","infinite-half-statement","tag-statement","lossy-text-key"] as const){
    const options=await fixture.options(),proof=new Authenticator("Ed25519Curve8",Buffer.from(`compat-raw-none-${mode}`)).register(options.data,ctx.baseURL,{userVerified:false});
    const attestation=decodeCBOR(Uint8Array.from(Buffer.from(proof.response.attestationObject,"base64url"))) as Map<string,CBORType>;
    const data=Buffer.from(attestation.get("authData") as Uint8Array);data[32]=data[32]!|0x80;
    attestation.set("authData",Buffer.concat([data,Buffer.from(encodeCBOR(mode==="statement-array"?[["application",true]]:mode==="statement-string"?"ab":new Map([["application",new Map([["flag",true]])]])))]));
    attestation.set("attStmt",mode==="statement-array"?["unexpected"]:mode==="statement-string"?"unexpected":9);
    proof.response.attestationObject=Buffer.from(encodeCBOR(attestation)).toString("base64url");
    if(mode==="infinite-half-statement"||mode==="tag-statement"){
      const encoded=Buffer.from(proof.response.attestationObject,"base64url"),label=Buffer.from(encodeCBOR("attStmt")),start=encoded.indexOf(label)+label.length;expect(encoded[start]).toBe(9);
      const value=mode==="infinite-half-statement"?[0xf9,0x7c,0x00]:[0xd8,0x63,0x09];
      proof.response.attestationObject=Buffer.concat([encoded.subarray(0,start),Buffer.from(value),encoded.subarray(start+1)]).toString("base64url");
    }
    if(mode==="lossy-text-key"){
      const encoded=Buffer.from(proof.response.attestationObject,"base64url");expect(encoded[0]).toBe(0xa3);
      proof.response.attestationObject=Buffer.concat([Buffer.from([0xa4]),encoded.subarray(1),Buffer.from([0x61,0xff,0x09])]).toString("base64url");
    }
    const result=await fixture.owner.$fetch("/passkey/verify-registration",{method:"POST",body:{response:proof,createSession:true}});expect(result.error,mode).toBeNull();expect(result.data).toMatchObject({userId:fixture.signup.data!.user.id,credentialID:proof.id,counter:0,user:{id:fixture.signup.data!.user.id},session:{userId:fixture.signup.data!.user.id}});
    const events=await fixture.events();expect(events).toHaveLength(2);expect(events[1]).toMatchObject({stage:"verified",userId:fixture.signup.data!.user.id,context:fixture.context});expect(events[1]!.clientData).toEqual(proof);expect(fixture.requests.at(-1)).toEqual({response:proof,createSession:true});
    const current=await fixture.owner.getSession(),issued=z.object({session:z.object({id:z.string(),token:z.string()})}).parse(result.data);expect(current.data?.session.id).toBe(issued.session.id);expect(current.data?.session.token).toBe(issued.session.token);expect(current.data?.user.id).toBe(fixture.signup.data!.user.id);
    const replay=await fixture.owner.$fetch("/passkey/verify-registration",{method:"POST",body:{response:proof,createSession:true}});expect(replay.error).toMatchObject({status:400,code:"CHALLENGE_NOT_FOUND"});expect(await fixture.events()).toEqual([]);
    await fixture.owner.signOut();const state=await fixture.state();const stored=z.object({passkeys:z.array(z.object({userId:z.string(),counter:z.number()})),sessions:z.object({count:z.number()}),challenges:z.object({count:z.number()})}).parse(state);expect(stored.passkeys).toHaveLength(outputs.length+1);expect(stored.passkeys.every(row=>row.userId===fixture.signup.data!.user.id&&row.counter===0)).toBe(true);expect(stored.sessions).toEqual({count:0});expect(stored.challenges).toEqual({count:0});expect(await ctx.readUserState({userId:fixture.signup.data!.user.id})).toEqual(fixture.before);expect(await ctx.readUserState({userId:fixture.foreignSignup.data!.user.id})).toEqual(fixture.foreignBefore);
    outputs.push({mode,options,result,events:events.map(row=>row.stage==="verified"?{...row,clientData:registration(row.clientData)}:row),current,replay,state});
  }
  return {signup:fixture.signup,foreignSignup:fixture.foreignSignup,enrollment:fixture.enrollment,before:fixture.before,foreignBefore:fixture.foreignBefore,outputs,submitted:fixture.submitted(),ownerAfter:await ctx.readUserState({userId:fixture.signup.data!.user.id}),foreignAfter:await ctx.readUserState({userId:fixture.foreignSignup.data!.user.id})};
},["POST /passkey/verify-registration"]);

for(const profile of ["passkey-first-trusted-origin","passkey-first-configured-origin"] as const)compatScenario(`passkey raw none ${profile} verifies current request origin and configured precedence`,async ctx=>{
 const alternate="http://localhost:49190";
  const storedRows=async(userId:string)=>{const response=await ctx.rawRequest({path:`/__test/passkey-registration-state?userId=${encodeURIComponent(userId)}`});expect(response.status).toBe(200);return z.object({rows:z.array(z.object({id:z.string(),name:z.string().nullable(),publicKey:z.string(),userId:z.string(),credentialID:z.string(),counter:z.number(),deviceType:z.string(),backedUp:z.number(),transports:z.string().nullable(),createdAt:z.string().datetime(),aaguid:z.string().nullable()}).strict())}).parse(response.body).rows;};
  const fixture=await setup(ctx,profile),configured=profile==="passkey-first-configured-origin",observations=[];
  for(const mode of ["base-proof-alternate-header","alternate-proof-base-header","wrong-owner","base-control","alternate-control"] as const){
   const before=await fixture.state(),beforeRows=await storedRows(fixture.signup.data!.user.id),foreignRows=await storedRows(fixture.foreignSignup.data!.user.id),ownerBefore=await ctx.readUserState({userId:fixture.signup.data!.user.id}),foreignBefore=await ctx.readUserState({userId:fixture.foreignSignup.data!.user.id});
   const options=await fixture.options();
   const proofOrigin=mode==="alternate-proof-base-header"||mode==="alternate-control"||mode==="wrong-owner"&&!configured?alternate:ctx.baseURL;
   const requestOrigin=mode==="base-proof-alternate-header"||mode==="alternate-control"||mode==="wrong-owner"?alternate:ctx.baseURL;
   const proof=new Authenticator("Ed25519Curve8",Buffer.from(`actual-origin-${profile}-${mode}`)).register(options.data,proofOrigin,{userVerified:false});
   let cookies:string[]=[];
   const result=await(mode==="wrong-owner"?fixture.foreign:fixture.owner).$fetch("/passkey/verify-registration",{method:"POST",headers:{...(mode==="wrong-owner"?fixture.foreignHeaders():{}),origin:requestOrigin},body:{response:proof,createSession:true,userId:fixture.foreignSignup.data!.user.id,context:"forged-body-origin-context"},onResponse({response}){cookies=response.headers.getSetCookie();}});
   const accepted=mode!=="wrong-owner"&&proofOrigin===(configured?ctx.baseURL:requestOrigin);
   const events=await fixture.events();expect(events[0]).toMatchObject({stage:"resolved",userId:fixture.signup.data!.user.id,context:fixture.context});
   expect(fixture.requests.at(-1)).toEqual({response:proof,createSession:true,userId:fixture.foreignSignup.data!.user.id,context:"forged-body-origin-context"});
   let current:unknown=null;
   if(accepted){
    expect(result.error,`${profile}:${mode}`).toBeNull();expect(result.data).toMatchObject({credentialID:proof.id,userId:fixture.signup.data!.user.id,counter:0,user:{id:fixture.signup.data!.user.id},session:{userId:fixture.signup.data!.user.id}});expect(cookies).not.toEqual([]);
    expect(events).toHaveLength(2);expect(events[1]).toMatchObject({stage:"verified",userId:fixture.signup.data!.user.id,context:fixture.context});expect(events[1]!.clientData).toEqual(proof);
    const session=await fixture.owner.getSession(),issued=z.object({session:z.object({id:z.string(),token:z.string()})}).parse(result.data);expect(session.data?.user.id).toBe(fixture.signup.data!.user.id);expect(session.data?.session.id).toBe(issued.session.id);expect(session.data?.session.token).toBe(issued.session.token);current=ctx.snapshot(session);
   }else{
    expect(result.error,`${profile}:${mode}`).toMatchObject({status:mode==="wrong-owner"?401:500,code:mode==="wrong-owner"?"YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY":"FAILED_TO_VERIFY_REGISTRATION"});expect(cookies).toEqual([]);expect(events).toHaveLength(1);expect(await fixture.state()).toEqual(before);expect(await ctx.readUserState({userId:fixture.signup.data!.user.id})).toEqual(ownerBefore);
   }
   const replay=await fixture.owner.$fetch("/passkey/verify-registration",{method:"POST",headers:{origin:requestOrigin},body:{response:proof,createSession:true}});expect(replay.error).toMatchObject({status:400,code:"CHALLENGE_NOT_FOUND"});expect(await fixture.events()).toEqual([]);
   if(accepted)await fixture.owner.signOut();
   const after=await fixture.state();expect(after).toMatchObject({sessions:{count:0},challenges:{count:0}});expect(await ctx.readUserState({userId:fixture.signup.data!.user.id})).toEqual(ownerBefore);expect(await ctx.readUserState({userId:fixture.foreignSignup.data!.user.id})).toEqual(foreignBefore);
   const rows=await storedRows(fixture.signup.data!.user.id);expect(await storedRows(fixture.foreignSignup.data!.user.id)).toEqual(foreignRows);
   if(accepted){expect(rows).toHaveLength(beforeRows.length+1);expect(rows.find(row=>row.credentialID===proof.id)).toMatchObject({userId:fixture.signup.data!.user.id,counter:0});expect(rows.filter(row=>row.credentialID!==proof.id)).toEqual(beforeRows);}else {expect(after).toEqual(before);expect(rows).toEqual(beforeRows);}
   observations.push({mode,proofOrigin:{url:proofOrigin},requestOrigin:{url:requestOrigin},before,beforeRows,foreignRows,ownerBefore,foreignBefore,options,result,events:events.map(row=>row.stage==="verified"?{...row,clientData:registration(row.clientData)}:row),current,replay,after,rows,ownerAfter:await ctx.readUserState({userId:fixture.signup.data!.user.id}),foreignAfter:await ctx.readUserState({userId:fixture.foreignSignup.data!.user.id})});
  }
  return {alternate,profile,signup:fixture.signup,foreignSignup:fixture.foreignSignup,enrollment:fixture.enrollment,observations,submitted:fixture.submitted()};
},["POST /passkey/verify-registration"]);

// Primary raw-key authority owner. Original COSE tags and signed bytes are
// retained; typed siblings exercise the same state/callback lifecycle.
for (const [attestation, algorithm, statementAlgorithm] of [
  ["none","Ed25519Alg7",-7], ["none","Ed25519",-8], ["none","ES256",-7],
  ["packed","Ed25519Alg7",-7], ["packed","Ed25519",-8], ["packed","ES256",-7],
  ["packed","Ed25519Alg7",-8],
] as const)
compatScenario(`passkey raw authority ${algorithm} ${attestation}${attestation === "packed" && algorithm === "Ed25519Alg7" && statementAlgorithm === -8 ? " statement8" : ""} preserves signed tags and full lifecycle`, async ctx => {
  const fixture = await setup(ctx), device = new Authenticator(algorithm);
  const rows = async (userId: string) => { const result = await ctx.rawRequest({path:`/__test/passkey-registration-state?userId=${encodeURIComponent(userId)}`}); expect(result.status).toBe(200); return result.body; };
  const foreignRows = await rows(fixture.foreignSignup.data!.user.id);
  const outputs: any[] = [];
  for (const failure of ["owner", "rp", "origin", "challenge", ...(attestation === "packed" ? ["signature", "short-signature"] : [])]) {
    const options = await fixture.options();
    const proof = device.register(failure === "challenge" ? {...options.data as object,challenge:"wrong-raw-authority-challenge"} : options.data, failure === "origin" ? "http://foreign.fixture.test" : ctx.baseURL,
      {attestation,statementAlgorithm,userVerified:false,counter:25,...(failure === "rp" ? {rpId:"foreign.fixture.test"} : failure === "signature" ? {badSignature:true} : failure === "short-signature" ? {malformedSignature:true} : {})});
    let cookies: string[] = [];
    const result = await (failure === "owner" ? fixture.foreign : fixture.owner).$fetch("/passkey/verify-registration", {method:"POST",body:{response:proof,createSession:true},...(failure === "owner" ? {headers:fixture.foreignHeaders()} : {}),onResponse({response}){cookies=response.headers.getSetCookie();}});
    expect(result.error).toMatchObject({status:failure === "owner" ? 401 : failure === "signature" || failure === "short-signature" && algorithm !== "ES256" ? 400 : 500});
    expect(cookies).toEqual([]); const events=await fixture.events();expect(events).toHaveLength(1);expect(events[0]!.stage).toBe("resolved");
    const replay=await fixture.owner.$fetch("/passkey/verify-registration",{method:"POST",body:{response:proof,createSession:true}});expect(replay.error).toMatchObject({status:400,code:"CHALLENGE_NOT_FOUND"});expect(await fixture.events()).toEqual([]);
    const state=await fixture.state(),ownerRows=await rows(fixture.signup.data!.user.id);expect(ownerRows).toEqual({rows:[]});expect(state).toEqual({passkeys:[],sessions:{count:0},challenges:{count:0}});
    expect(await ctx.readUserState({userId:fixture.signup.data!.user.id})).toEqual(fixture.before);expect(await ctx.readUserState({userId:fixture.foreignSignup.data!.user.id})).toEqual(fixture.foreignBefore);expect(await rows(fixture.foreignSignup.data!.user.id)).toEqual(foreignRows);
    outputs.push({failure,options,proof:registration(proof),result,cookies,events,replay,state,ownerRows});
  }
  const options=await fixture.options(), proof=device.register(options.data,ctx.baseURL,{attestation,statementAlgorithm,userVerified:false,counter:25});
  const accepted=await fixture.owner.$fetch("/passkey/verify-registration",{method:"POST",body:{response:proof,createSession:true,userId:fixture.foreignSignup.data!.user.id,context:"foreign-body-authority"}});expect(accepted.error).toBeNull();
  const events=await fixture.events();expect(events).toHaveLength(2);expect(events[1]!.clientData).toEqual(proof);expect(events[1]).toMatchObject({userId:fixture.signup.data!.user.id,context:fixture.context,counter:25});
  const saved=await rows(fixture.signup.data!.user.id);expect(saved).toMatchObject({rows:[{credentialID:proof.id,userId:fixture.signup.data!.user.id,counter:25}]});
  const attestationObject=decodeCBOR(Uint8Array.from(Buffer.from(proof.response.attestationObject,"base64url"))) as Map<string,CBORType>;
  const authData=attestationObject.get("authData") as Uint8Array;
  const keyStart=55+Buffer.from(proof.id,"base64url").length;
  expect(Buffer.from(authData.subarray(keyStart)).toString("base64")).toBe((saved as any).rows[0].publicKey);
  const key=decodeCBOR(Uint8Array.from(Buffer.from((saved as any).rows[0].publicKey,"base64")));expect(key).toBeInstanceOf(Map);expect((key as Map<number,CBORType>).get(3)).toBe(algorithm === "Ed25519" ? -8 : -7);expect((key as Map<number,CBORType>).get(-1)).toBe(algorithm === "ES256" ? 1 : 6);
  const current=await fixture.owner.getSession();expect(current.data?.user.id).toBe(fixture.signup.data!.user.id);expect(current.data?.session.token).toBe((accepted.data as any).session.token);
  await fixture.owner.signOut();
  const authClient=(actor:string)=>createAuthClient({baseURL:`${ctx.baseURL}${authProfilePath("passkey-auth-accept")}`,plugins:[passkeyClient()],fetchOptions:{customFetchImpl:(input,init)=>ctx.actor(actor,"passkey-auth-accept").fetch(input,init)}});
  const auth=authClient("raw-authority-auth"),authForeign=authClient("raw-authority-foreign");
  const authEvents=async()=>{const result=await ctx.rawRequest({path:"/__test/passkey-authentication-events"});expect(result.status).toBe(200);return result.body as any[];};
  const assertions:any[]=[];
  for(const failure of ["rp","origin","challenge","signature","short-signature","counter","success","stale-counter","next-success"]){
    const before=await rows(fixture.signup.data!.user.id),ownerBefore=await ctx.readUserState({userId:fixture.signup.data!.user.id}),beforeEvents=await authEvents();
    const challenge=await auth.$fetch("/passkey/generate-authenticate-options",{method:"GET"});expect(challenge.error).toBeNull();
    const assertion={...device.authenticate(failure==="challenge"?{...challenge.data as object,challenge:"wrong-raw-auth-challenge"}:challenge.data,failure==="origin"?"http://foreign.fixture.test":ctx.baseURL,{userVerified:false,counter:failure==="counter"?25:failure==="next-success"?27:26,...(failure==="rp"?{rpId:"foreign.fixture.test"}:failure==="signature"?{badSignature:true}:failure==="short-signature"?{malformedSignature:true}:{})}),userId:fixture.foreignSignup.data!.user.id};
    let cookies:string[]=[];const result=await auth.$fetch("/passkey/verify-authentication",{method:"POST",body:{response:assertion,userId:fixture.foreignSignup.data!.user.id},onResponse({response}){cookies=response.headers.getSetCookie();}});
    const success=failure==="success"||failure==="next-success",afterEvents=await authEvents();let session:any=null;
    if(success){
      expect(result.error).toBeNull();expect(result.data).toMatchObject({user:{id:fixture.signup.data!.user.id},session:{userId:fixture.signup.data!.user.id}});expect(cookies.length).toBeGreaterThan(0);
      expect(afterEvents).toHaveLength(beforeEvents.length+1);const event=afterEvents.at(-1);expect(event.clientData).toEqual(assertion);expect(event.facts).toMatchObject({newCounter:failure==="success"?26:27,credentialID:proof.id,userVerified:false,credentialDeviceType:"singleDevice",credentialBackedUp:false});expect(event.storedPasskey.counter).toBe(failure==="success"?25:26);expect(event.sessions).toEqual({count:0});expect(event.challenges).toEqual({count:0});
      session=await auth.getSession();expect(session.data?.user.id).toBe(fixture.signup.data!.user.id);expect(session.data?.session.token).toBe((result.data as any).session.token);
      await auth.signOut();
    }else{
      expect(result.error).toMatchObject({status:failure==="signature"||failure==="short-signature"&&algorithm!=="ES256"?401:400,code:"AUTHENTICATION_FAILED"});expect(cookies).toEqual([]);expect(afterEvents).toEqual(beforeEvents);expect(await rows(fixture.signup.data!.user.id)).toEqual(before);expect(await ctx.readUserState({userId:fixture.signup.data!.user.id})).toEqual(ownerBefore);
    }
    const replay=await auth.$fetch("/passkey/verify-authentication",{method:"POST",body:{response:assertion}});expect(replay.error).toMatchObject({status:400,code:"CHALLENGE_NOT_FOUND"});expect(await authEvents()).toEqual(afterEvents);
    const after=await rows(fixture.signup.data!.user.id);if(success)expect(after).toEqual({rows:(before as any).rows.map((row:any)=>({...row,counter:failure==="success"?26:27}))});
    expect(await rows(fixture.foreignSignup.data!.user.id)).toEqual(foreignRows);expect(await ctx.readUserState({userId:fixture.foreignSignup.data!.user.id})).toEqual(fixture.foreignBefore);expect(await authForeign.getSession()).toMatchObject({data:null});
    assertions.push({failure,before,ownerBefore,challenge,assertion:authentication(assertion,options.data),result,cookies:cookies.map(raw=>{const cookie=Cookie.parse(raw);if(!cookie)throw new Error("Invalid issued cookie");return {key:cookie.key,token:cookie.value,path:cookie.path??null,domain:cookie.domain??null,httpOnly:cookie.httpOnly,secure:cookie.secure,sameSite:cookie.sameSite??null,maxAge:cookie.maxAge??null,expiresAt:cookie.maxAge===undefined&&cookie.expires instanceof Date?cookie.expires.toISOString():null,extensions:cookie.extensions??[]};}),events:afterEvents.map(event=>({...event,facts:{...event.facts,origin:{url:event.facts.origin}},clientData:authentication(event.clientData,options.data)})),session,replay,after});
  }
  return {algorithm,attestation,signup:fixture.signup,foreignSignup:fixture.foreignSignup,foreignBefore:fixture.foreignBefore,foreignRows,outputs,options,proof:registration(proof),accepted,events:events.map(row=>row.stage==="verified"?{...row,clientData:registration(row.clientData)}:row),saved,current,submitted:fixture.submitted(),assertions,final:await fixture.state()};
},["POST /passkey/verify-registration","POST /passkey/verify-authentication"]);
