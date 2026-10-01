import { createAuthClient } from "better-auth/client";
import { passkeyClient } from "@better-auth/passkey/client";
import { Authenticator } from "../../support/authenticator";
import { expect } from "bun:test";
import { compatScenario, type ScenarioContext } from "../../support/scenario";

async function owners(ctx: ScenarioContext) {
  const owner=ctx.actor("origin-owner"),foreign=ctx.actor("origin-foreign");
  const signup=await owner.client.signUp.email({email:ctx.uniqueEmail("origin-owner"),password:"password123",name:"Origin Owner",username:"origin_owner"});
  const foreignSignup=await foreign.client.signUp.email({email:ctx.uniqueEmail("origin-foreign"),password:"password123",name:"Foreign Owner"});
  expect(signup.error).toBeNull();expect(foreignSignup.error).toBeNull();
  const foreignBefore=await ctx.readUserState({userId:foreignSignup.data!.user.id});
  return {owner,foreign,signup,foreignSignup,foreignBefore};
}

compatScenario("core cookie origin validation uses canonical HTTP origin and rejects foreign authorities before session writes",async ctx=>{
  const fixture=await owners(ctx),results=[];
  const wrong=new URL("http://localhost:49192"),lookalike=new URL("http://localhost.evil.invalid:49192");
  const table:[string,boolean][]=[[ctx.baseURL,true],[ctx.baseURL.replace("http://localhost","HTTP://LOCALHOST"),true],[`${ctx.baseURL}/ignored`,true],[`${ctx.baseURL}?ignored`,true],[ctx.baseURL.replace("://","://userinfo@"),true],[wrong.origin,false],[lookalike.origin,false]];
  for(const [origin,allowed] of table){
    const before=await ctx.readUserState({userId:fixture.signup.data!.user.id}) as {sessions:{token:string}[]};
    const result=await fixture.owner.client.signIn.email({email:fixture.signup.data!.user.email,password:"password123"},{headers:{origin}});
    const after=await ctx.readUserState({userId:fixture.signup.data!.user.id}) as {sessions:{token:string}[]};
    let current:unknown=null;
    if(allowed){expect(result.error,origin).toBeNull();expect(result.data!.user.id).toBe(fixture.signup.data!.user.id);expect(after.sessions).toHaveLength(before.sessions.length+1);expect(after.sessions.filter(row=>row.token!==result.data!.token)).toEqual(before.sessions);const session=await fixture.owner.client.getSession();expect(session.data?.session.token).toBe(result.data!.token!);expect(session.data?.user.id).toBe(fixture.signup.data!.user.id);current=session;}
    else{expect(result.error).toMatchObject({status:403,code:"INVALID_ORIGIN"});expect(after).toEqual(before);}
    const foreignAfter=await ctx.readUserState({userId:fixture.foreignSignup.data!.user.id});expect(foreignAfter).toEqual(fixture.foreignBefore);
    results.push({origin:{url:origin},allowed,before,result,current,after,foreignAfter});
  }
  const foreignCurrent=await fixture.foreign.client.getSession();expect(foreignCurrent.data?.session.token).toBe(fixture.foreignSignup.data!.token!);
  return {signup:fixture.signup,foreignSignup:fixture.foreignSignup,foreignBefore:fixture.foreignBefore,results,foreignCurrent};
},["POST /sign-in/email"]);

const redirectScenarios = [
  "core redirect validation rejects inner encoded path separators and controls while retaining query and fragment semantics",
  "core redirect controls reject path controls while preserving encoded query and fragment values",
  "core redirect controls reject authority-shaped paths while permitting owned safe paths",
  "core redirect controls preserve whitespace absolute callbacks and explicit empty callbacks",
] as const;
for (const [group, scenarioName] of redirectScenarios.entries()) {
compatScenario(scenarioName,async ctx=>{
  const fixture=await owners(ctx),results=[];
  // Keep the complete twelve-value matrix for both real login methods. Each
  // bounded owner observes fewer password hashes before comparing fresh rows.
  const table:[string,boolean][]=[["/safe/inner%2fnext",false],[`${ctx.baseURL.replace("http://localhost","HTTP://LOCALHOST")}/done`,true],["/safe/inner%5Cnext",false],["/safe\u0085next",false],["/safe?query=%2f",true],["/safe#fragment=%5C",true],["/%2fnext",false],["//evil.invalid",false],["/safe/path",true],[` ${ctx.baseURL}/done`,true],[`\t${ctx.baseURL.replace("http://localhost","HTTP://LOCALHOST")}/done`,true],["",true]].slice(group * 3, group * 3 + 3) as [string, boolean][];
  for(const method of ["email","username"] as const)for(const [callbackURL,allowed] of table){
    const before=await ctx.readUserState({userId:fixture.signup.data!.user.id}) as {sessions:{token:string}[]};
    const result=method==="email"?await fixture.owner.client.signIn.email({email:fixture.signup.data!.user.email,password:"password123",callbackURL}):await fixture.owner.client.signIn.username({username:"origin_owner",password:"password123",callbackURL});
    const after=await ctx.readUserState({userId:fixture.signup.data!.user.id}) as {sessions:{token:string}[]};let current:unknown=null;
    if(allowed){expect(result.error,callbackURL).toBeNull();expect(result.data!.user.id).toBe(fixture.signup.data!.user.id);expect(after.sessions).toHaveLength(before.sessions.length+1);expect(after.sessions.filter(row=>row.token!==result.data!.token)).toEqual(before.sessions);const session=await fixture.owner.client.getSession();expect(session.data?.session.token).toBe(result.data!.token!);current=session;}
    else{expect(result.error,callbackURL).toMatchObject({status:403,code:"INVALID_CALLBACK_URL"});expect(after).toEqual(before);}
    const foreignAfter=await ctx.readUserState({userId:fixture.foreignSignup.data!.user.id});expect(foreignAfter).toEqual(fixture.foreignBefore);
    results.push({method,callbackURL,allowed,before,result,current,after,foreignAfter});
  }
  const foreignCurrent=await fixture.foreign.client.getSession();expect(foreignCurrent.data?.session.token).toBe(fixture.foreignSignup.data!.token!);
  return {signup:fixture.signup,foreignSignup:fixture.foreignSignup,foreignBefore:fixture.foreignBefore,results,foreignCurrent};
},["POST /sign-in/email","POST /sign-in/username"]);
}

compatScenario("core canonical origin guard preserves exact ES256 WebAuthn proof origins and consumed challenges",async ctx=>{
  const fixture=await owners(ctx),uppercase=ctx.baseURL.replace("http://localhost","HTTP://LOCALHOST");
  const client=createAuthClient({baseURL:ctx.baseURL,plugins:[passkeyClient()],fetchOptions:{customFetchImpl:fixture.owner.fetch}});
  const authenticator=new Authenticator(),registrations=[];
  const rows=async()=>{const result=await client.$fetch("/passkey/list-user-passkeys",{method:"GET"});expect(result.error).toBeNull();return result.data as {id:string;credentialID:string;userId:string;counter:number}[];};
  const state=async()=>{const result=await ctx.rawRequest({path:`/__test/passkey-state?userId=${fixture.signup.data!.user.id}`});expect(result.status).toBe(200);return result.body as {challenges:{count:number}};};
  for(const mode of ["base-proof-uppercase-header","uppercase-proof-base-header","uppercase-control"] as const){
    const before=await rows(),beforeState=await state(),ownerBefore=await ctx.readUserState({userId:fixture.signup.data!.user.id});
    const options=await client.$fetch("/passkey/generate-register-options",{method:"GET"});expect(options.error).toBeNull();
    const proofOrigin=mode==="base-proof-uppercase-header"?ctx.baseURL:uppercase,requestOrigin=mode==="uppercase-proof-base-header"?ctx.baseURL:uppercase;
    const proof=authenticator.register(options.data,proofOrigin);
    let foreignOrigin:unknown=null;
    if(mode==="uppercase-control"){
      const issued=await state();
      const denied=await client.$fetch("/passkey/verify-registration",{method:"POST",headers:{origin:"https://foreign-origin.example"},body:{response:proof,name:"Exact Origin Device"}});
      expect(denied.error).toMatchObject({status:403,code:"INVALID_ORIGIN"});
      expect(await state()).toEqual(issued);expect(await rows()).toEqual(before);expect(await ctx.readUserState({userId:fixture.signup.data!.user.id})).toEqual(ownerBefore);expect(await ctx.readUserState({userId:fixture.foreignSignup.data!.user.id})).toEqual(fixture.foreignBefore);
      foreignOrigin={issued,denied,after:await state()};
    }
    const result=await client.$fetch("/passkey/verify-registration",{method:"POST",headers:{origin:requestOrigin},body:{response:proof,name:"Exact Origin Device"}});
    const after=await rows(),afterState=await state();expect(afterState.challenges).toEqual(beforeState.challenges);
    if(mode==="uppercase-control"){expect(result.error).toBeNull();expect(after).toHaveLength(before.length+1);expect(after[0]).toMatchObject({userId:fixture.signup.data!.user.id,credentialID:proof.id,counter:0});}
    else{expect(result.error).toMatchObject({status:500,code:"FAILED_TO_VERIFY_REGISTRATION"});expect(after).toEqual(before);}
    const replay=await client.$fetch("/passkey/verify-registration",{method:"POST",headers:{origin:requestOrigin},body:{response:proof}});expect(replay.error).toMatchObject({status:400,code:"CHALLENGE_NOT_FOUND"});expect(await rows()).toEqual(after);
    expect(await ctx.readUserState({userId:fixture.signup.data!.user.id})).toEqual(ownerBefore);expect(await ctx.readUserState({userId:fixture.foreignSignup.data!.user.id})).toEqual(fixture.foreignBefore);
    registrations.push({mode,proofOrigin:{url:proofOrigin},requestOrigin:{url:requestOrigin},before,beforeState,ownerBefore,options,foreignOrigin,result,after,afterState,replay});
  }
  const authentications=[];
  for(const mode of ["base-control","base-proof-uppercase-header","uppercase-proof-base-header","uppercase-control"] as const){
    const before=await rows(),beforeState=await state(),ownerBefore=await ctx.readUserState({userId:fixture.signup.data!.user.id}) as {sessions:{token:string}[]};
    const options=await client.$fetch("/passkey/generate-authenticate-options",{method:"GET"});expect(options.error).toBeNull();
    const proofOrigin=mode==="uppercase-proof-base-header"||mode==="uppercase-control"?uppercase:ctx.baseURL,requestOrigin=mode==="base-proof-uppercase-header"||mode==="uppercase-control"?uppercase:ctx.baseURL;
    const proof=authenticator.authenticate(options.data,proofOrigin);
    let foreignOrigin:unknown=null;
    if(mode==="base-control"){
      const issued=await state();
      const denied=await client.$fetch("/passkey/verify-authentication",{method:"POST",headers:{origin:"https://foreign-origin.example"},body:{response:proof}});
      expect(denied.error).toMatchObject({status:403,code:"INVALID_ORIGIN"});
      expect(await state()).toEqual(issued);expect(await rows()).toEqual(before);expect(await ctx.readUserState({userId:fixture.signup.data!.user.id})).toEqual(ownerBefore);expect(await ctx.readUserState({userId:fixture.foreignSignup.data!.user.id})).toEqual(fixture.foreignBefore);
      foreignOrigin={issued,denied,after:await state()};
    }
    const result=await client.$fetch("/passkey/verify-authentication",{method:"POST",headers:{origin:requestOrigin},body:{response:proof}});
    const after=await rows(),afterState=await state(),ownerAfter=await ctx.readUserState({userId:fixture.signup.data!.user.id}) as {sessions:{token:string}[]};expect(afterState.challenges).toEqual(beforeState.challenges);let current:unknown=null;
    if(mode.endsWith("control")){expect(result.error).toBeNull();const session=await fixture.owner.client.getSession();expect(session.data?.user.id).toBe(fixture.signup.data!.user.id);expect(ownerAfter.sessions).toHaveLength(ownerBefore.sessions.length+1);expect(ownerAfter.sessions.filter(row=>row.token!==session.data!.session.token)).toEqual(ownerBefore.sessions);expect(after[0]!.counter).toBe(Buffer.from(proof.response.authenticatorData,"base64url").readUInt32BE(33));current=session;}
    else{expect(result.error).toMatchObject({status:400,code:"AUTHENTICATION_FAILED"});expect(after).toEqual(before);expect(ownerAfter).toEqual(ownerBefore);}
    const replay=await client.$fetch("/passkey/verify-authentication",{method:"POST",headers:{origin:requestOrigin},body:{response:proof}});expect(replay.error).toMatchObject({status:400,code:"CHALLENGE_NOT_FOUND"});expect(await rows()).toEqual(after);expect(await ctx.readUserState({userId:fixture.signup.data!.user.id})).toEqual(ownerAfter);expect(await ctx.readUserState({userId:fixture.foreignSignup.data!.user.id})).toEqual(fixture.foreignBefore);
    authentications.push({mode,proofOrigin:{url:proofOrigin},requestOrigin:{url:requestOrigin},before,beforeState,ownerBefore,options,foreignOrigin,result,after,afterState,ownerAfter,current,replay});
  }
  return {signup:fixture.signup,foreignSignup:fixture.foreignSignup,foreignBefore:fixture.foreignBefore,registrations,authentications,foreignAfter:await ctx.readUserState({userId:fixture.foreignSignup.data!.user.id})};
},["POST /passkey/verify-registration","POST /passkey/verify-authentication"]);
