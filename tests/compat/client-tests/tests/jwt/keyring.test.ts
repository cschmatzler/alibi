import { expect } from "bun:test";
import { createHmac } from "node:crypto";
import { createAuthClient } from "better-auth/client";
import { jwtClient } from "better-auth/client/plugins";
import { compactVerify, importJWK, jwtVerify, type JWK } from "jose";
import { getCookieCache } from "better-auth/cookies";
import { z } from "zod";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { authProfilePath, type FixtureProfile } from "../../support/profiles";

const profile: FixtureProfile = "jwt-keyring-standard";
function client(ctx: ScenarioContext, actor: string, mode: FixtureProfile = profile) {
  return createAuthClient({baseURL:ctx.baseURL+authProfilePath(mode),plugins:[jwtClient()],fetchOptions:{customFetchImpl:ctx.actor(actor,mode).fetch,headers:{"x-keyring-proof":"application-marker"}}});
}
async function control(ctx: ScenarioContext, value: Record<string,unknown> = {}, mode: FixtureProfile = profile) {
  const result=await ctx.rawRequest({path:"/__test/jwt-keyring",method:"POST",json:{profile:mode,operation:"state",...value},headers:{"x-keyring-proof":"server-marker"}});
  expect(result.status).toBe(200);
  return result;
}
const stateSchema=z.object({keys:z.array(z.object({id:z.string(),publicKey:z.union([z.record(z.string(),z.unknown()),z.string()]),privateKeyEncrypted:z.boolean(),createdAt:z.string(),expiresAt:z.string().nullable(),alg:z.string().nullable(),crv:z.string().nullable()})),events:z.array(z.record(z.string(),z.unknown()))});
async function state(ctx: ScenarioContext, mode: FixtureProfile = profile) { const result=await control(ctx,{},mode);return stateSchema.parse(result.body); }
async function signed(ctx: ScenarioContext, payload: Record<string,unknown>, options: Record<string,unknown> = {}, mode: FixtureProfile = profile) {
  return ctx.rawRequest({path:"/__test/jwt-keyring",method:"POST",json:{profile:mode,operation:"sign",payload,...options},headers:{"x-keyring-proof":"server-marker"}});
}
async function verified(token: string, keys: JWK[], ctx: ScenarioContext, audience: string = ctx.baseURL) {
  const header=JSON.parse(Buffer.from(token.split(".")[0]!,"base64url").toString());
  const key=keys.find(key=>key.kid===header.kid);
  expect(key).toBeDefined();expect(key!.d).toBeUndefined();
  const result=await jwtVerify(token,await importJWK(key!,header.alg),{algorithms:[header.alg],issuer:ctx.baseURL,audience});
  return {header:result.protectedHeader,payload:result.payload};
}
async function token(result: Awaited<ReturnType<typeof signed>>) {
  expect(result.status).toBe(200);return z.object({token:z.string()}).parse(result.body).token;
}

compatScenario("application JWT keyring public callbacks retain request context explicit errors and unchanged owned storage",async ctx=>{
  await control(ctx,{operation:"reset"});
  const owner=client(ctx,"owner"),foreign=client(ctx,"foreign"),guest=client(ctx,"guest");
  const signup=await owner.signUp.email({email:ctx.uniqueEmail("keyring-errors-owner"),password:"password123",name:"Keyring Owner"});expect(signup.error).toBeNull();
  const other=await foreign.signUp.email({email:ctx.uniqueEmail("keyring-errors-foreign"),password:"password123",name:"Keyring Foreign"});expect(other.error).toBeNull();
  const ownerBefore=await ctx.readUserState({userId:signup.data!.user.id}),foreignBefore=await ctx.readUserState({userId:other.data!.user.id});
  const failures=[];
  for(const operation of ["read","create"]){
    for(const kind of ["ordinary","api","api500"]){
      await control(ctx,{operation:"reset"});
      await control(ctx,{operation:"failure",failure:{operation,kind}});
      const rejected=await guest.jwks();expect(rejected.error?.status).toBe(kind==="api"?403:500);
      if(kind!=="ordinary")expect(rejected.error).toMatchObject({code:"APPLICATION_KEYRING_DENIED",message:"application denied keys"});
      const observed=await state(ctx);expect(observed.keys).toEqual([]);
      expect(observed.events).toHaveLength(operation==="read"?1:2);
      for(const event of observed.events)expect(event.context).toEqual({path:"/jwks",method:"GET",marker:"application-marker",hasCookie:false});
      expect(await ctx.readUserState({userId:signup.data!.user.id})).toEqual(ownerBefore);expect(await ctx.readUserState({userId:other.data!.user.id})).toEqual(foreignBefore);
      expect((await ctx.rawRequest({path:"/__test/jwks-state"})).body).toEqual([]);
      failures.push({operation,kind,rejected:ctx.snapshot(rejected),observed});
    }
  }
  await control(ctx,{operation:"reset"});
  const keys=await guest.jwks();expect(keys.error).toBeNull();
  const original=await state(ctx);expect(original.keys).toHaveLength(1);expect(original.keys[0]!.privateKeyEncrypted).toBe(true);
  const callbackFailures=[];
  for(const operation of ["payload","subject","read"]){
    for(const kind of ["ordinary","api","api500"]){for(const entry of ["token","session-header"]){
      await control(ctx,{operation:"clear-events"});await control(ctx,{operation:"failure",failure:{operation,kind}});
      const rejected=entry==="token"?await owner.token():await owner.getSession();expect(rejected.error?.status).toBe(kind==="api"?403:500);
      if(kind!=="ordinary")expect(rejected.error).toMatchObject({code:"APPLICATION_KEYRING_DENIED",message:"application denied keys"});
      const observed=await state(ctx);expect(observed.keys).toEqual(original.keys);
      expect(observed.events.map(event=>event.operation)).toEqual(operation==="payload"?["payload"]:operation==="subject"?["payload","subject"]:["payload","subject","read"]);
      expect(await ctx.readUserState({userId:signup.data!.user.id})).toEqual(ownerBefore);expect(await ctx.readUserState({userId:other.data!.user.id})).toEqual(foreignBefore);
      callbackFailures.push({operation,kind,entry,rejected:ctx.snapshot(rejected),observed});
    }}
  }
  await control(ctx,{operation:"failure",failure:null});
  const success=await owner.token();expect(success.error).toBeNull();
  const checked=await verified(success.data!.token,keys.data!.keys as JWK[],ctx);expect(checked.payload.sub).toBe(signup.data!.user.email);
  const signout=await owner.signOut();expect(signout.error).toBeNull();
  const beforeReplay=await state(ctx),replay=await owner.token();expect(replay.error?.status).toBe(401);expect(await state(ctx)).toEqual(beforeReplay);
  expect(await ctx.readUserState({userId:other.data!.user.id})).toEqual(foreignBefore);
  return {signup:ctx.snapshot(signup),other:ctx.snapshot(other),ownerBefore,foreignBefore,failures,keys,original,callbackFailures,success,checked,signout,replay,beforeReplay,ownerAfter:await ctx.readUserState({userId:signup.data!.user.id}),foreignAfter:await ctx.readUserState({userId:other.data!.user.id})};
},["GET /jwks","GET /token","GET /get-session","POST /sign-up/email","POST /sign-out"]);

compatScenario("application JWT keyring session payload subject defaults and public signatures use the actual external persisted keys",async ctx=>{
  await control(ctx,{operation:"reset"});const observations=[];
  for(const mode of ["jwt-keyring-standard","jwt-keyring-empty-subject","jwt-keyring-null-subject"] as const){
    await control(ctx,{operation:"clear-events"},mode);
    const owner=client(ctx,"owner-"+mode,mode),foreign=client(ctx,"foreign-"+mode,mode),guest=client(ctx,"guest-"+mode,mode);
    const signup=await owner.signUp.email({email:ctx.uniqueEmail(mode),password:"password123",name:"External Keys Owner"});expect(signup.error).toBeNull();
    const other=await foreign.signUp.email({email:ctx.uniqueEmail(mode+"-foreign"),password:"password123",name:"External Keys Foreign"});expect(other.error).toBeNull();
    const foreignBefore=await ctx.readUserState({userId:other.data!.user.id});
    const denied=await guest.token();expect(denied.error?.status).toBe(401);expect((await state(ctx,mode)).events).toEqual([]);
    const keys=await guest.jwks();expect(keys.error).toBeNull();
    const created=await state(ctx,mode);expect(created.keys).toHaveLength(1);expect(created.keys[0]!.privateKeyEncrypted).toBe(true);expect(created.events.map(event=>event.operation)).toEqual(["read","create","read"]);
    await control(ctx,{operation:"clear-events"},mode);
    const issued=await owner.token();expect(issued.error).toBeNull();
    const checked=await verified(issued.data!.token,keys.data!.keys as JWK[],ctx);
    expect(checked.payload.application).toBe("external-keyring");
    expect(checked.payload.sub).toBe(mode==="jwt-keyring-empty-subject"?"":mode==="jwt-keyring-null-subject"?signup.data!.user.id:signup.data!.user.email);
    expect(checked.payload.snapshot).toMatchObject({user:{id:signup.data!.user.id,email:signup.data!.user.email},session:{userId:signup.data!.user.id,token:signup.data!.token}});
    const after=await state(ctx,mode);expect(after.keys).toEqual(created.keys);expect(after.events.map(event=>event.operation)).toEqual(["payload","subject","read"]);
    expect(after.events[2]!.context).toEqual({path:"/token",method:"GET",marker:"application-marker",hasCookie:true});
    const serverVerified=await control(ctx,{operation:"verify",token:issued.data!.token},mode);
    expect(serverVerified.body).toEqual({payload:mode==="jwt-keyring-empty-subject"?null:checked.payload});
    const wrongAudience=await signed(ctx,{sub:"server-owner",exp:4102444800,aud:"foreign-audience"},{},mode);
    const wrong=await control(ctx,{operation:"verify",token:await token(wrongAudience)},mode);expect(wrong.body).toEqual({payload:null});
    const signout=await owner.signOut();expect(signout.error).toBeNull();const beforeReplay=await state(ctx,mode),replay=await owner.token();expect(replay.error?.status).toBe(401);expect(await state(ctx,mode)).toEqual(beforeReplay);
    expect(await ctx.readUserState({userId:other.data!.user.id})).toEqual(foreignBefore);
    expect((await ctx.rawRequest({path:"/__test/jwks-state"})).body).toEqual([]);
    observations.push({mode,signup:ctx.snapshot(signup),other:ctx.snapshot(other),foreignBefore,denied,keys,created,issued,checked,after,serverVerified,wrongAudience,wrong,signout,replay,beforeReplay,ownerAfter:await ctx.readUserState({userId:signup.data!.user.id}),foreignAfter:await ctx.readUserState({userId:other.data!.user.id})});
  }
  return {observations};
},["GET /jwks","GET /token","POST /sign-up/email","POST /sign-out"]);

compatScenario("application JWT keyring pinning resolved keys RSA modulus grace corruption and installed rows remain observable",async ctx=>{
  const mode: FixtureProfile="jwt-keyring-plain";await control(ctx,{operation:"reset"},mode);const owner=client(ctx,"owner",mode),foreign=client(ctx,"foreign",mode),guest=client(ctx,"guest",mode);
  const signup=await owner.signUp.email({email:ctx.uniqueEmail("keyring-rotation-owner"),password:"password123",name:"Rotation Owner"});expect(signup.error).toBeNull();
  const other=await foreign.signUp.email({email:ctx.uniqueEmail("keyring-rotation-foreign"),password:"password123",name:"Rotation Foreign"});expect(other.error).toBeNull();const foreignBefore=await ctx.readUserState({userId:other.data!.user.id});
  const jwks=await guest.jwks();expect(jwks.error).toBeNull();const original=await state(ctx,mode);expect(original.keys).toHaveLength(1);expect(original.keys[0]!.privateKeyEncrypted).toBe(false);
  const firstId=original.keys[0]!.id;const firstPublic=original.keys[0]!.publicKey as JWK;expect(firstPublic.kty).toBe("RSA");expect(Buffer.from(firstPublic.n!,"base64url")).toHaveLength(384);
  expect(Date.parse(original.keys[0]!.expiresAt!)-Date.parse(original.keys[0]!.createdAt)).toBe(3600000);
  const payload={sub:"installed-key-owner",iat:100,exp:4102444800,custom:{protected:"retained"}};
  const primary=await signed(ctx,payload,{header:{typ:"application+jwt",cty:"application/json",alg:"HS256",kid:"untrusted-header"}},mode);const primaryToken=await token(primary);const primaryChecked=await verified(primaryToken,jwks.data!.keys as JWK[],ctx);
  expect(primaryChecked.header).toMatchObject({alg:"RS256",kid:firstId,typ:"application+jwt",cty:"application/json"});
  const extra=await signed(ctx,payload,{signingAlgorithm:"ES256"},mode);const extraToken=await token(extra);const extraState=await state(ctx,mode);expect(extraState.keys).toHaveLength(2);expect(extraState.keys[1]!.alg).toBe("ES256");expect(extraState.keys[1]!.privateKeyEncrypted).toBe(false);
  const both=await guest.jwks();expect(both.error).toBeNull();const extraChecked=await verified(extraToken,both.data!.keys as JWK[],ctx);expect(extraChecked.header.alg).toBe("ES256");
  await control(ctx,{operation:"clear-events"},mode);
  const reused=await signed(ctx,payload,{operation:"resolve-sign",signingKeyId:firstId},mode);const reusedToken=await token(reused);const reusedState=await state(ctx,mode);expect(reusedState.events.map(event=>event.operation)).toEqual(["read"]);expect(reusedState.keys).toEqual(extraState.keys);
  const reusedChecked=await verified(reusedToken,both.data!.keys as JWK[],ctx);expect(reusedChecked.header.kid).toBe(firstId);
  const rejected=[];
  for(const options of [{signingKeyId:"missing"},{signingKeyId:firstId,signingAlgorithm:"ES256"},{signingAlgorithm:"PS256"},{header:{crit:[]}},{header:{crit:["application-required"],"application-required":true}},{header:{crit:["b64"],b64:false}}]){
    const response=await signed(ctx,payload,options,mode);expect(response.status).toBe(500);expect(response.body).toEqual({message:"Internal server error"});expect((await state(ctx,mode)).keys).toEqual(extraState.keys);rejected.push({options,response});
  }
  const oldExpiry=new Date(Date.now()-1800000).toISOString();for(const key of extraState.keys)await control(ctx,{operation:"expire",id:key.id,expiresAt:oldExpiry},mode);
  const rotated=await signed(ctx,payload,{},mode);const rotatedToken=await token(rotated);const withinGrace=await guest.jwks();expect(withinGrace.data!.keys).toHaveLength(3);const rotatedState=await state(ctx,mode);expect(rotatedState.keys).toHaveLength(3);
  const rotatedChecked=await verified(rotatedToken,withinGrace.data!.keys as JWK[],ctx);expect(rotatedChecked.header.alg).toBe("RS256");expect(rotatedChecked.header.kid).not.toBe(firstId);
  const oldVerified=await verified(primaryToken,withinGrace.data!.keys as JWK[],ctx);expect(oldVerified.payload).toEqual(primaryChecked.payload);
  const expiredPinned=await signed(ctx,payload,{signingKeyId:firstId},mode);expect(expiredPinned.status).toBe(500);expect((await state(ctx,mode)).keys).toEqual(rotatedState.keys);
  const retiredExpiry=new Date(Date.now()-7200000).toISOString();for(const key of extraState.keys)await control(ctx,{operation:"expire",id:key.id,expiresAt:retiredExpiry},mode);
  const afterGrace=await guest.jwks();expect(afterGrace.data!.keys).toHaveLength(1);
  const privateVerification=await control(ctx,{operation:"verify",token:primaryToken},mode);expect(privateVerification.body).toEqual({payload:primaryChecked.payload});
  const activeId=rotatedState.keys[2]!.id;await control(ctx,{operation:"corrupt",id:activeId,field:"private"},mode);
  const brokenPrivate=await owner.token();expect(brokenPrivate.error?.status).toBe(500);const privateState=await state(ctx,mode);expect(privateState.keys).toHaveLength(3);expect(await ctx.readUserState({userId:other.data!.user.id})).toEqual(foreignBefore);
  await control(ctx,{operation:"corrupt",id:activeId,field:"public"},mode);
  const brokenPublic=await guest.jwks();expect(brokenPublic.error?.status).toBe(500);const corruptVerification=await control(ctx,{operation:"verify",token:rotatedToken},mode);expect(corruptVerification.body).toEqual({payload:null});const corruptState=await state(ctx,mode);expect(corruptState.keys[2]!.publicKey).toBe("corrupt");
  await control(ctx,{operation:"delete",id:activeId},mode);const retired=await guest.jwks();expect(retired.data!.keys).toEqual([]);expect((await state(ctx,mode)).keys).toHaveLength(2);
  for(const key of extraState.keys)await control(ctx,{operation:"delete",id:key.id},mode);
  const recovered=await guest.jwks();expect(recovered.error).toBeNull();const recoveredState=await state(ctx,mode);expect(recoveredState.keys).toHaveLength(1);const recovery=await owner.token();expect(recovery.error).toBeNull();const recoveryChecked=await verified(recovery.data!.token,recovered.data!.keys as JWK[],ctx);
  const legacy=await control(ctx,{operation:"legacy",id:recoveredState.keys[0]!.id},mode);const legacyState=await state(ctx,mode);expect(legacyState.keys[0]!.alg).toBeNull();expect(legacyState.keys[0]!.crv).toBeNull();
  const legacyJwks=await guest.jwks();expect(legacyJwks.data!.keys[0]!.alg).toBe("RS256");const legacyIssued=await signed(ctx,payload,{signingKeyId:recoveredState.keys[0]!.id,signingAlgorithm:"RS256"},mode);const legacyChecked=await verified(await token(legacyIssued),legacyJwks.data!.keys as JWK[],ctx);expect(legacyChecked.header.kid).toBe(recoveredState.keys[0]!.id);
  await control(ctx,{operation:"clear-events"},mode);
  const createStartedAt=Date.now();
  const manuallyCreated=await control(ctx,{operation:"create"},mode);
  const createFinishedAt=Date.now();
  expect(manuallyCreated.body).toEqual({created:true});
  const manualState=await state(ctx,mode);
  expect(manualState.keys).toHaveLength(2);
  expect(manualState.keys[0]).toEqual(legacyState.keys[0]);
  expect(manualState.events.map(event=>event.operation)).toEqual(["create"]);
  expect(manualState.events[0]!.context).toEqual({path:"/__test/jwt-keyring",method:"POST",marker:"server-marker",hasCookie:false});
  const {id:manualId,createdAt,expiresAt,...manualKey}=manualState.keys[1]!;
  expect(createdAt).toBe(new Date(createdAt).toISOString());
  expect(expiresAt).toBe(new Date(expiresAt!).toISOString());
  expect(Date.parse(createdAt)).toBeGreaterThanOrEqual(createStartedAt);
  expect(Date.parse(createdAt)).toBeLessThanOrEqual(createFinishedAt);
  const lifetimeMilliseconds=Date.parse(expiresAt!)-Date.parse(createdAt);
  expect(lifetimeMilliseconds).toBe(3600000);
  expect(manualState.events[0]!.key).toEqual({...manualKey,createdAt,expiresAt});
  // Key generation can take different amounts of time on each server. Check
  // its actual request clock above, then compare the complete key and lifetime.
  const manualObservation={
    keys:[manualState.keys[0],{id:manualId,...manualKey,lifetimeMilliseconds}],
    events:[{...manualState.events[0],key:{...manualKey,lifetimeMilliseconds}}],
  };
  const manualJwks=await guest.jwks();expect(manualJwks.data!.keys).toHaveLength(2);const manualIssued=await signed(ctx,payload,{signingKeyId:manualState.keys[1]!.id},mode);const manualChecked=await verified(await token(manualIssued),manualJwks.data!.keys as JWK[],ctx);expect(manualChecked.header.kid).toBe(manualState.keys[1]!.id);expect((await state(ctx,mode)).keys).toEqual(manualState.keys);
  expect(await ctx.readUserState({userId:other.data!.user.id})).toEqual(foreignBefore);expect((await ctx.rawRequest({path:"/__test/jwks-state"})).body).toEqual([]);
  return {signup:ctx.snapshot(signup),other:ctx.snapshot(other),foreignBefore,jwks,original,primary,primaryChecked,extra,extraState,both,extraChecked,reused,reusedState,reusedChecked,rejected,rotated,withinGrace,rotatedState,rotatedChecked,oldVerified,expiredPinned,afterGrace,privateVerification,brokenPrivate,privateState,brokenPublic,corruptVerification,corruptState,retired,recovered,recoveredState,recovery,recoveryChecked,legacy,legacyState,legacyJwks,legacyIssued,legacyChecked,manuallyCreated,manualState:manualObservation,manualJwks,manualIssued,manualChecked,foreignAfter:await ctx.readUserState({userId:other.data!.user.id})};
},["GET /jwks","GET /token","POST /sign-up/email"]);

compatScenario("application JWT keyring simultaneous first public requests create and persist both actual signing keys",async ctx=>{
  await control(ctx,{operation:"reset"});await control(ctx,{operation:"race-arm"});
  const first=ctx.rawRequest({path:authProfilePath(profile)+"/jwks",headers:{"x-keyring-proof":"race-first"}});
  const second=ctx.rawRequest({path:authProfilePath(profile)+"/jwks",headers:{"x-keyring-proof":"race-second"}});
  const initial=await first;expect(initial.status).toBe(200);const firstKeys=z.object({keys:z.array(z.record(z.string(),z.unknown())).length(1)}).parse(initial.body).keys as JWK[];
  const released=await control(ctx,{operation:"race-release"});
  const concurrent=await second;expect(concurrent.status).toBe(200);const keys=z.object({keys:z.array(z.record(z.string(),z.unknown())).length(2)}).parse(concurrent.body).keys as JWK[];
  const persisted=await state(ctx);expect(persisted.keys).toHaveLength(2);expect(new Set(persisted.keys.map(key=>key.id)).size).toBe(2);expect(persisted.keys.map(key=>key.privateKeyEncrypted)).toEqual([true,true]);
  expect(persisted.events.map(event=>event.operation)).toEqual(["read","read","create","read","create","read"]);
  expect(persisted.events.filter(event=>event.operation==="create").map(event=>(event.context as any).marker)).toEqual(["race-first","race-second"]);
  expect(keys[0]!.kid).toBe(firstKeys[0]!.kid);expect(keys.map(key=>key.kid)).toEqual(persisted.keys.map(key=>key.id));
  const signatures=[];for(const key of keys){const issued=await signed(ctx,{sub:"simultaneous-owner",exp:4102444800},{signingKeyId:key.kid});const checked=await verified(await token(issued),keys,ctx);expect(checked.header.kid).toBe(key.kid);signatures.push({issued,checked});}
  expect((await state(ctx)).keys).toEqual(persisted.keys);expect((await ctx.rawRequest({path:"/__test/jwks-state"})).body).toEqual([]);
  return {initial,released,concurrent,persisted,signatures,after:await state(ctx)};
},["GET /jwks"]);

compatScenario("application JWT keyring configured numeric date and duration expirations retain precise values and reject nonfinite options",async ctx=>{
  await control(ctx,{operation:"reset"});
  const guest=client(ctx,"guest");const jwks=await guest.jwks();expect(jwks.error).toBeNull();const original=await state(ctx);
  const cases=[
    {expiration:{number:4102444800.25},expected:4102444800.25},
    {expiration:{number:0},expected:0},
    {expiration:{number:-12.25},expected:-12.25},
    {expiration:{date:"2100-01-01T00:00:00.999Z"},expected:4102444800},
    {expiration:{date:"1969-12-31T23:59:59.999Z"},expected:-1},
    {expiration:{source:"0.5s",milliseconds:500},expected:101},
    {expiration:{source:"-0.5s",milliseconds:-500},expected:100},
    {expiration:{source:"1.5 seconds ago",milliseconds:-1500},expected:99},
    {expiration:{source:"1 mo",milliseconds:2592000000},expected:2592100},
    {expiration:{source:"+2 years",milliseconds:63115200000},expected:63115300},
  ];
  const observations=[];
  for(const item of cases){
    const issued=await signed(ctx,{sub:"configured-expiration-owner",iat:100},{expiration:item.expiration});const value=await token(issued);
    const header=JSON.parse(Buffer.from(value.split(".")[0]!,"base64url").toString());
    const key=(jwks.data!.keys as JWK[]).find(key=>key.kid===header.kid)!;
    const checked=await compactVerify(value,await importJWK(key,header.alg),{algorithms:[header.alg]});
    const payload=JSON.parse(new TextDecoder().decode(checked.payload));expect(payload.exp).toBe(item.expected);expect(payload.iat).toBe(100);expect(payload.sub).toBe("configured-expiration-owner");
    const serverVerified=await control(ctx,{operation:"verify",token:value});expect(serverVerified.body).toEqual({payload:item.expected===4102444800.25||item.expected===4102444800?payload:null});
    expect((await state(ctx)).keys).toEqual(original.keys);observations.push({expiration:item.expiration,issued,header:checked.protectedHeader,payload,serverVerified});
  }
  const rejected=[];
  for(const expiration of [{nan:true},{nonfinite:"positive"},{nonfinite:"negative"}]){
    const issued=await signed(ctx,{sub:"configured-expiration-owner",iat:100},{expiration});expect(issued.status).toBe(500);expect(issued.body).toEqual({message:"Internal server error"});
    const overridden=await signed(ctx,{sub:"configured-expiration-owner",iat:100,exp:4102444800},{expiration});const checked=await verified(await token(overridden),jwks.data!.keys as JWK[],ctx);expect(checked.payload.exp).toBe(4102444800);
    expect((await state(ctx)).keys).toEqual(original.keys);rejected.push({expiration,issued,overridden,checked});
  }
  expect((await ctx.rawRequest({path:"/__test/jwks-state"})).body).toEqual([]);
  return {jwks,original,observations,rejected,after:await state(ctx)};
},["GET /jwks"]);

compatScenario("application JWT keyring compact cached principal owns get-session headers and token signing through stored session revocation",async ctx=>{
  const mode:FixtureProfile="jwt-keyring-cache";await control(ctx,{operation:"reset"},mode);
  const owner=client(ctx,"owner",mode),foreign=client(ctx,"foreign",mode),guest=client(ctx,"guest",mode);
  const receipts:Headers[]=[];
  const signup=await owner.signUp.email({email:ctx.uniqueEmail("keyring-cache-owner"),password:"password123",name:"Original Cached JWT Owner"},{onSuccess({response}){receipts.push(new Headers(response.headers));}});expect(signup.error).toBeNull();
  const other=await foreign.signUp.email({email:ctx.uniqueEmail("keyring-cache-foreign"),password:"password123",name:"Foreign Cached JWT Owner"});expect(other.error).toBeNull();const foreignBefore=await ctx.readUserState({userId:other.data!.user.id});
  const cookie=receipts[0]!.getSetCookie().map(value=>value.split(";")[0]!).join("; ");
  const cache=await getCookieCache(new Headers({cookie}),{secret:"compat-test-only-key-not-real-minimum-32chars",strategy:"compact",isSecure:false});expect(cache!.session.token).toBe(signup.data!.token!);expect(cache!.user.name).toBe("Original Cached JWT Owner");
  const cacheToken=decodeURIComponent(cookie.split("; ").find(value=>value.startsWith("better-auth.session_data="))!.split("=").slice(1).join("="));
  const compactSessionCache={token:cacheToken,envelope:JSON.parse(Buffer.from(cacheToken,"base64url").toString()),decoded:cache,observedAt:Date.now(),effectiveMaxAgeSeconds:300,rawCookies:receipts[0]!.getSetCookie().filter(value=>value.startsWith("better-auth.session_data="))};
  const jwks=await guest.jwks();expect(jwks.error).toBeNull();const created=await state(ctx,mode);
  const renamed=await ctx.rawRequest({path:"/__test/session-cookie-cache/control",method:"POST",json:{mode:"standard",action:"rename",userId:signup.data!.user.id,name:"Authoritative JWT Owner"}});expect(renamed.status).toBe(200);
  await control(ctx,{operation:"clear-events"},mode);
  const cached=await owner.getSession({fetchOptions:{onSuccess({response}){receipts.push(new Headers(response.headers));}}});expect(cached.data!.user.name).toBe("Original Cached JWT Owner");
  const header=receipts[1]!.get("set-auth-jwt");expect(header).not.toBeNull();expect(receipts[1]!.get("access-control-expose-headers")).toBe("set-auth-jwt");
  const checked=await verified(header!,jwks.data!.keys as JWK[],ctx);expect(checked.payload).toMatchObject({id:signup.data!.user.id,name:"Original Cached JWT Owner",sub:signup.data!.user.id});
  const cachedState=await state(ctx,mode);expect(cachedState.events.map(event=>event.operation)).toEqual(["read"]);expect(cachedState.keys).toEqual(created.keys);
  const bypass=await owner.getSession({query:{disableCookieCache:true,disableRefresh:true},fetchOptions:{onSuccess({response}){receipts.push(new Headers(response.headers));}}});expect(bypass.data!.user.name).toBe("Authoritative JWT Owner");
  const bypassChecked=await verified(receipts[2]!.get("set-auth-jwt")!,jwks.data!.keys as JWK[],ctx);expect(bypassChecked.payload).toMatchObject({name:"Authoritative JWT Owner"});
  const revoked=await ctx.rawRequest({path:"/__test/session-cookie-cache/control",method:"POST",json:{mode:"standard",action:"revoke",token:signup.data!.token}});expect(revoked.status).toBe(200);const revokedOwner=await ctx.readUserState({userId:signup.data!.user.id});expect((revokedOwner as any).sessions).toEqual([]);
  // Default EdDSA tokens repeat for the same principal within one second.
  // Make the post-revocation issuance a real later lifecycle phase, rather
  // than coupling token identity to which backend crosses a clock boundary.
  const cachedIat=z.number().int().parse(checked.payload.iat);
  const remaining=(cachedIat+1)*1000-Date.now();expect(remaining).toBeLessThanOrEqual(1000);
  if(remaining>0)await Bun.sleep(remaining+5);
  const retained=await owner.token();expect(retained.error).toBeNull();const retainedChecked=await verified(retained.data!.token,jwks.data!.keys as JWK[],ctx);expect(retainedChecked.payload).toMatchObject({id:signup.data!.user.id,name:"Original Cached JWT Owner",sub:signup.data!.user.id});
  expect(retainedChecked.payload.iat!).toBeGreaterThan(cachedIat);expect(retained.data!.token).not.toBe(header!);expect(retainedChecked.payload.exp!-retainedChecked.payload.iat!).toBe(900);
  const beforeDenial=await state(ctx,mode),denied=await guest.token();expect(denied.error?.status).toBe(401);expect(await state(ctx,mode)).toEqual(beforeDenial);
  const cleared=await owner.getSession({query:{disableCookieCache:true,disableRefresh:true},fetchOptions:{onSuccess({response}){receipts.push(new Headers(response.headers));}}});expect(cleared.data).toBeNull();expect(receipts[3]!.get("set-auth-jwt")).toBeNull();
  const replay=await owner.token();expect(replay.error?.status).toBe(401);expect((await state(ctx,mode)).keys).toEqual(created.keys);expect(await ctx.readUserState({userId:signup.data!.user.id})).toEqual(revokedOwner);expect(await ctx.readUserState({userId:other.data!.user.id})).toEqual(foreignBefore);
  return {signup:ctx.snapshot(signup),other:ctx.snapshot(other),foreignBefore,compactSessionCache,jwks,created,renamed,cached:ctx.snapshot(cached),checked,cachedState,bypass:ctx.snapshot(bypass),bypassChecked,revoked,revokedOwner,retained,retainedChecked,beforeDenial,denied,cleared:ctx.snapshot(cleared),replay,receipts,after:await state(ctx,mode),foreignAfter:await ctx.readUserState({userId:other.data!.user.id})};
},["GET /jwks","GET /token","GET /get-session","POST /sign-up/email"]);

compatScenario("application JWT keyring remote discovery refuses local JWKS without signing or writing any key store",async ctx=>{
  await control(ctx,{operation:"reset"});
  const cleared=await ctx.rawRequest({path:"/__test/jwt-remote",method:"POST",json:{operation:"clear"}});expect(cleared.status).toBe(200);
  const before=await ctx.rawRequest({path:"/__test/jwt-remote"}),keysBefore=await ctx.rawRequest({path:"/__test/jwks-state"});expect(keysBefore.body).toEqual([]);expect((await state(ctx)).keys).toEqual([]);
  const responses=[];
  for(const mode of ["jwt-remote-raw","jwt-remote-result","jwt-remote-error"] as const){
    const rejected=await ctx.rawRequest({path:authProfilePath(mode)+"/jwks"});expect(rejected.status).toBe(404);expect(rejected.body).toBeNull();responses.push({mode,rejected});
    expect((await ctx.rawRequest({path:"/__test/jwt-remote"})).body).toEqual(before.body);expect((await ctx.rawRequest({path:"/__test/jwks-state"})).body).toEqual(keysBefore.body);expect((await state(ctx)).keys).toEqual([]);
  }
  return {cleared,before,keysBefore,responses,after:await state(ctx)};
},["GET /jwks"]);

compatScenario("application JWT keyring custom cached callbacks retain the complete hook snapshot while nested middleware receives the completed session",async ctx=>{
  const mode:FixtureProfile="jwt-keyring-custom-cache";await control(ctx,{operation:"reset"},mode);
  const owner=client(ctx,"owner",mode),foreign=client(ctx,"foreign",mode),guest=client(ctx,"guest",mode);
  const receipts:Headers[]=[];
  const signup=await owner.signUp.email({email:ctx.uniqueEmail("keyring-custom-cache-owner"),password:"password123",name:"Custom Cached Owner"},{onSuccess({response}){receipts.push(new Headers(response.headers));}});expect(signup.error).toBeNull();
  const other=await foreign.signUp.email({email:ctx.uniqueEmail("keyring-custom-cache-foreign"),password:"password123",name:"Custom Cached Foreign"});expect(other.error).toBeNull();
  const foreignBefore=await ctx.readUserState({userId:other.data!.user.id});
  const cookie=receipts[0]!.getSetCookie().map(value=>value.split(";")[0]!).join("; ");
  const cache=await getCookieCache(new Headers({cookie}),{secret:"compat-test-only-key-not-real-minimum-32chars",strategy:"compact",isSecure:false});expect(cache).not.toBeNull();
  const cacheToken=decodeURIComponent(cookie.split("; ").find(value=>value.startsWith("better-auth.session_data="))!.split("=").slice(1).join("="));
  const compactSessionCache={token:cacheToken,envelope:JSON.parse(Buffer.from(cacheToken,"base64url").toString()),decoded:cache,observedAt:Date.now(),effectiveMaxAgeSeconds:300,rawCookies:receipts[0]!.getSetCookie().filter(value=>value.startsWith("better-auth.session_data="))};
  const jwks=await guest.jwks();expect(jwks.error).toBeNull();const original=await state(ctx,mode);
  const renamed=await ctx.rawRequest({path:"/__test/session-cookie-cache/control",method:"POST",json:{mode:"standard",action:"rename",userId:signup.data!.user.id,name:"Updated Custom Owner"}});expect(renamed.status).toBe(200);
  const ownerBefore=await ctx.readUserState({userId:signup.data!.user.id});
  await control(ctx,{operation:"clear-events"},mode);
  const cached=await owner.getSession({fetchOptions:{onSuccess({response}){receipts.push(new Headers(response.headers));}}});expect(cached.data!.user.name).toBe("Custom Cached Owner");
  const header=receipts[1]!.get("set-auth-jwt");expect(header).not.toBeNull();const cachedChecked=await verified(header!,jwks.data!.keys as JWK[],ctx);
  const snapshot=z.object({user:z.record(z.string(),z.unknown()),session:z.record(z.string(),z.unknown()),updatedAt:z.string(),updatedAtType:z.literal("number"),version:z.string()}).strict().parse(cachedChecked.payload.snapshot);
  expect(Date.parse(snapshot.updatedAt)).toBe(cache!.updatedAt);expect(snapshot.version).toBe(cache!.version!);expect(snapshot.version).toBe("1");
  expect({user:snapshot.user,session:snapshot.session}).toEqual(JSON.parse(JSON.stringify(cached.data)));
  expect(cachedChecked.payload.sub).toBe(`${signup.data!.user.email}|version:1|clock:number`);
  const cachedState=await state(ctx,mode);expect(cachedState.events.map(event=>event.operation)).toEqual(["payload","subject","read"]);
  for(const event of cachedState.events.filter(event=>event.operation!=="read"))expect(event.session).toEqual(snapshot);
  expect(cachedState.events[2]!.context).toEqual({path:"/get-session",method:"GET",marker:"application-marker",hasCookie:true});expect(cachedState.keys).toEqual(original.keys);
  await control(ctx,{operation:"clear-events"},mode);
  const nested=await owner.token();expect(nested.error).toBeNull();const nestedChecked=await verified(nested.data!.token,jwks.data!.keys as JWK[],ctx);
  expect(nestedChecked.payload.snapshot).toEqual({user:snapshot.user,session:snapshot.session});expect(nestedChecked.payload.sub).toBe(`${signup.data!.user.email}|version:absent|clock:undefined`);
  const nestedState=await state(ctx,mode);expect(nestedState.events.map(event=>event.operation)).toEqual(["payload","subject","read"]);
  for(const event of nestedState.events.filter(event=>event.operation!=="read"))expect(event.session).toEqual(nestedChecked.payload.snapshot);
  expect(nestedState.events[2]!.context).toEqual({path:"/token",method:"GET",marker:"application-marker",hasCookie:true});
  // An authenticated older envelope can omit version. Retain the exact real
  // issued identity/clock and use independent HMAC to authenticate that format.
  const legacyEnvelope=JSON.parse(Buffer.from(cacheToken,"base64url").toString());delete legacyEnvelope.session.version;
  legacyEnvelope.signature=createHmac("sha256","compat-test-only-key-not-real-minimum-32chars").update(JSON.stringify({...legacyEnvelope.session,expiresAt:legacyEnvelope.expiresAt})).digest("base64url");
  const legacyToken=Buffer.from(JSON.stringify(legacyEnvelope)).toString("base64url");
  const legacyCookie=cookie.split("; ").map(value=>value.startsWith("better-auth.session_data=")?`better-auth.session_data=${legacyToken}`:value).join("; ");
  const legacyDecoded=await getCookieCache(new Headers({cookie:legacyCookie}),{secret:"compat-test-only-key-not-real-minimum-32chars",strategy:"compact",isSecure:false});expect(legacyDecoded).not.toBeNull();expect(Object.hasOwn(legacyDecoded!,"version")).toBe(false);
  const legacyCache={compactSessionCache:{token:legacyToken,envelope:legacyEnvelope,decoded:legacyDecoded,observedAt:Date.now(),effectiveMaxAgeSeconds:300}};
  await control(ctx,{operation:"clear-events"},mode);
  const legacyHeaders:Headers[]=[];const legacy=await owner.getSession({fetchOptions:{headers:{cookie:legacyCookie,"x-keyring-proof":"legacy-marker"},onSuccess({response}){legacyHeaders.push(new Headers(response.headers));}}});expect(legacy.error).toBeNull();
  const legacyChecked=await verified(legacyHeaders[0]!.get("set-auth-jwt")!,jwks.data!.keys as JWK[],ctx);
  const {version:removedVersion,...versionlessSnapshot}=snapshot;expect(removedVersion).toBe("1");expect(legacyChecked.payload.snapshot).toEqual(versionlessSnapshot);expect(legacyChecked.payload.sub).toBe(`${signup.data!.user.email}|version:absent|clock:number`);
  const legacyState=await state(ctx,mode);expect(legacyState.events.map(event=>event.operation)).toEqual(["payload","subject","read"]);for(const event of legacyState.events.filter(event=>event.operation!=="read"))expect(event.session).toEqual(versionlessSnapshot);
  await control(ctx,{operation:"clear-events"},mode);
  const bypass=await owner.getSession({query:{disableCookieCache:true,disableRefresh:true},fetchOptions:{onSuccess({response}){receipts.push(new Headers(response.headers));}}});expect(bypass.data!.user.name).toBe("Updated Custom Owner");
  const bypassChecked=await verified(receipts[2]!.get("set-auth-jwt")!,jwks.data!.keys as JWK[],ctx);expect(bypassChecked.payload.snapshot).toEqual(JSON.parse(JSON.stringify(bypass.data)));expect(bypassChecked.payload.sub).toBe(`${signup.data!.user.email}|version:absent|clock:undefined`);
  const bypassState=await state(ctx,mode);for(const event of bypassState.events.filter(event=>event.operation!=="read"))expect(event.session).toEqual(bypassChecked.payload.snapshot);
  expect(await ctx.readUserState({userId:signup.data!.user.id})).toEqual(ownerBefore);expect(await ctx.readUserState({userId:other.data!.user.id})).toEqual(foreignBefore);expect((await state(ctx,mode)).keys).toEqual(original.keys);expect((await ctx.rawRequest({path:"/__test/jwks-state"})).body).toEqual([]);
  return {signup:ctx.snapshot(signup),other:ctx.snapshot(other),foreignBefore,compactSessionCache,jwks,original,renamed,ownerBefore,cached:ctx.snapshot(cached),cachedChecked,cachedState,nested,nestedChecked,nestedState,legacyCache,legacy:ctx.snapshot(legacy),legacyHeaders,legacyChecked,legacyState,bypass:ctx.snapshot(bypass),bypassChecked,bypassState,receipts,ownerAfter:await ctx.readUserState({userId:signup.data!.user.id}),foreignAfter:await ctx.readUserState({userId:other.data!.user.id})};
},["GET /jwks","GET /token","GET /get-session","POST /sign-up/email"]);

compatScenario("application JWT keyring server-only signing and verification preserve an absent HTTP request and the real virtual endpoint context",async ctx=>{
  await control(ctx,{operation:"reset"});const owner=client(ctx,"owner"),foreign=client(ctx,"foreign"),guest=client(ctx,"guest");
  const signup=await owner.signUp.email({email:ctx.uniqueEmail("keyring-server-owner"),password:"password123",name:"Server JWT Owner"});expect(signup.error).toBeNull();
  const other=await foreign.signUp.email({email:ctx.uniqueEmail("keyring-server-foreign"),password:"password123",name:"Server JWT Foreign"});expect(other.error).toBeNull();
  const ownerBefore=await ctx.readUserState({userId:signup.data!.user.id}),foreignBefore=await ctx.readUserState({userId:other.data!.user.id});
  const payload={sub:"server-owned-subject",iat:100,exp:4102444800,application:{scope:"server-only"}};
  const issued=await signed(ctx,payload,{operation:"api-sign",absentRequest:true});const issuedToken=await token(issued);const issuedState=await state(ctx);
  expect(issuedState.keys).toHaveLength(1);expect(issuedState.events.map(event=>event.operation)).toEqual(["read","read","create"]);
  for(const event of issuedState.events)expect(event.context).toEqual({path:"virtual:",method:null,marker:null,hasCookie:false});
  const jwks=await guest.jwks();expect(jwks.error).toBeNull();const checked=await verified(issuedToken,jwks.data!.keys as JWK[],ctx);expect(checked.payload).toMatchObject(payload);
  const verifiedContexts=[];
  for(const absentRequest of [true,false]){
    await control(ctx,{operation:"clear-events"});const accepted=await control(ctx,{operation:"verify",token:issuedToken,absentRequest});expect(accepted.body).toEqual({payload:checked.payload});const acceptedState=await state(ctx);expect(acceptedState.events.map(event=>event.operation)).toEqual(["read"]);
    expect(acceptedState.events[0]!.context).toEqual({path:"virtual:",method:absentRequest?null:"POST",marker:absentRequest?null:"server-marker",hasCookie:false});expect(acceptedState.keys).toEqual(issuedState.keys);
    await control(ctx,{operation:"clear-events"});const wrong=await control(ctx,{operation:"verify",token:issuedToken,issuer:"https://wrong.invalid",absentRequest});expect(wrong.body).toEqual({payload:null});const wrongState=await state(ctx);expect(wrongState.events.map(event=>event.operation)).toEqual(["read"]);expect(wrongState.events[0]!.context).toEqual(acceptedState.events[0]!.context);
    verifiedContexts.push({absentRequest,accepted,acceptedState,wrong,wrongState});
  }
  expect(await ctx.readUserState({userId:signup.data!.user.id})).toEqual(ownerBefore);expect(await ctx.readUserState({userId:other.data!.user.id})).toEqual(foreignBefore);expect((await ctx.rawRequest({path:"/__test/jwks-state"})).body).toEqual([]);
  return {signup:ctx.snapshot(signup),other:ctx.snapshot(other),ownerBefore,foreignBefore,issued,issuedState,jwks,checked,verifiedContexts,ownerAfter:await ctx.readUserState({userId:signup.data!.user.id}),foreignAfter:await ctx.readUserState({userId:other.data!.user.id})};
},["GET /jwks","POST /sign-up/email"]);
