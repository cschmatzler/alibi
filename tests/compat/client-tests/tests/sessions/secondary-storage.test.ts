import {expect} from "bun:test";
import {createAuthClient} from "better-auth/client";
import {multiSessionClient, oneTimeTokenClient} from "better-auth/client/plugins";
import {apiKeyClient} from "@better-auth/api-key/client";
import {compatScenario} from "../../support/scenario";

for (const mode of ["only","preserve-only","combined","preserved"] as const) {
  const profile=`session-secondary-${mode}` as const;
  compatScenario(`secondary session ${mode} maintains real cache and physical session effects`,async ctx=>{
    const owner=ctx.actor("owner",profile),second=ctx.actor("second",profile),foreign=ctx.actor("foreign",profile);
    const extended=(name:string)=>createAuthClient({baseURL:ctx.baseURL,plugins:[multiSessionClient(),oneTimeTokenClient(),apiKeyClient()],fetchOptions:{customFetchImpl:ctx.actor(name,profile).fetch}});
    const capabilities=extended("owner");
    const email=ctx.uniqueEmail(profile);
    const signup=await owner.client.signUp.email({email,name:"Secondary owner",password:"password123"});
    const login=await second.client.signIn.email({email,password:"password123"});
    const other=await foreign.client.signUp.email({email:ctx.uniqueEmail("foreign"),name:"Foreign owner",password:"password123"});
    expect(signup.error).toBeNull();expect(login.error).toBeNull();expect(other.error).toBeNull();
    const current=await owner.client.getSession(),secondCurrent=await second.client.getSession();
    expect(current.error).toBeNull();expect(secondCurrent.error).toBeNull();
    const token=current.data!.session.token,userId=current.data!.user.id;
    const read=()=>ctx.readUserState({userId}) as Promise<{sessions:unknown[]}>;
    const initial=await read();expect(initial.sessions.length).toBe(mode==="combined"||mode==="preserved"?2:0);
    const control=async(action:string)=>{const response=await ctx.rawRequest({path:"/__test/secondary-session/control",method:"POST",json:{profile,token,action}});expect(response.status).toBe(200);return response.body;};
    const cached=await control("state");expect(cached).toEqual({present:true});
    const denied=await foreign.client.revokeSession({token});expect(denied.error).toBeNull();
    const unchanged=await owner.client.getSession();expect(unchanged.data?.session.token).toBe(token);
    const listed=await owner.client.listSessions();expect(listed.data?.length).toBe(2);
    const devices=await capabilities.multiSession.listDeviceSessions();expect(devices.error).toBeNull();expect(devices.data?.length).toBe(1);
    const selected=await extended("foreign").multiSession.setActive({sessionToken:token});expect(selected.error?.status).toBe(401);
    const key=await capabilities.apiKey.create({name:"Secondary-session machine"});expect(key.error).toBeNull();
    const machine=await extended("machine").getSession({fetchOptions:{headers:{"x-api-key":key.data!.key}}});expect(machine.error).toBeNull();expect(machine.data?.user.id).toBe(userId);
    expect((await read()).sessions).toEqual(initial.sessions);
    const handoff=await capabilities.oneTimeToken.generate();expect(handoff.error).toBeNull();
    const accepted=await extended("receiver").oneTimeToken.verify({token:handoff.data!.token});expect(accepted.error).toBeNull();expect(accepted.data?.session.token).toBe(token);
    const replay=await extended("replay").oneTimeToken.verify({token:handoff.data!.token});expect(replay.error?.status).toBe(400);
    expect((await read()).sessions).toEqual(initial.sessions);
    const rotate=await owner.client.changePassword({currentPassword:"password123",newPassword:"changedPassword123!",revokeOtherSessions:true});expect(rotate.error).toBeNull();
    const afterRotate=await owner.client.getSession(),revokedSecond=await second.client.getSession();
    expect(afterRotate.data?.user.id).toBe(userId);expect(revokedSecond.data).toBeNull();
    const rotatedRows=await read();expect(rotatedRows.sessions.length).toBe(mode==="only"||mode==="preserve-only"?0:mode==="preserved"?3:1);
    const rotatedToken=afterRotate.data!.session.token;
    const removal=await ctx.rawRequest({path:"/__test/secondary-session/control",method:"POST",json:{profile,token:rotatedToken,action:"remove"}});expect(removal.status).toBe(200);
    const missing=await owner.client.getSession();expect(Boolean(missing.data)).toBe(mode==="combined");
    // Combined fallback authenticates, but listing remains secondary authoritative.
    const missingList=mode==="combined"?await owner.client.listSessions():null;
    if(missingList)expect(missingList.data).toEqual([]);
    const foreignAlive=await foreign.client.getSession();expect(foreignAlive.data?.user.id).toBe(other.data!.user.id);
    const signedOut=await foreign.client.signOut();expect(signedOut.error).toBeNull();
    const afterOut=await foreign.client.getSession();expect(afterOut.data).toBeNull();
    const foreignRows=await ctx.readUserState({userId:other.data!.user.id}) as {sessions:unknown[]};
    expect(foreignRows.sessions.length).toBe(mode==="preserved"?1:0);
    return {signup:ctx.snapshot(signup),login:ctx.snapshot(login),other:ctx.snapshot(other),current:ctx.snapshot(current),secondCurrent:ctx.snapshot(secondCurrent),initial,cached,denied:ctx.snapshot(denied),unchanged:ctx.snapshot(unchanged),listed:ctx.snapshot(listed),devices:ctx.snapshot(devices),selected:ctx.snapshot(selected),key:ctx.snapshot(key),machine:ctx.snapshot(machine),handoff:ctx.snapshot(handoff),accepted:ctx.snapshot(accepted),replay:ctx.snapshot(replay),rotate:ctx.snapshot(rotate),afterRotate:ctx.snapshot(afterRotate),revokedSecond:ctx.snapshot(revokedSecond),rotatedRows,missing:ctx.snapshot(missing),missingList:ctx.snapshot(missingList),foreignAlive:ctx.snapshot(foreignAlive),signedOut:ctx.snapshot(signedOut),afterOut:ctx.snapshot(afterOut),foreignRows,final:await read()};
  });
}

compatScenario("secondary configured session fields preserve typed defaults transformations and hidden output without SQL rows",async ctx=>{
  const owner=ctx.actor("configured-owner","session-fields-secondary"),email=ctx.uniqueEmail("secondary-configured-fields");
  const signup=await owner.client.signUp.email({email,name:"Configured secondary owner",password:"password123"});expect(signup.error).toBeNull();
  const initial=await owner.client.getSession();expect(initial.error).toBeNull();
  expect(initial.data?.session).toMatchObject({label:"initial",serverOnly:"locked",payload:{initial:true},activeOrganizationId:"declared-without-plugin"});
  expect(initial.data?.session).not.toHaveProperty("hidden");
  const state=async()=>{const response=await ctx.rawRequest({path:`/__test/session-field-state?email=${encodeURIComponent(email)}`});expect(response.status).toBe(200);expect(response.body).toEqual([]);return response;};
  const before=await state();
  const changed=await owner.client.$fetch("/update-session",{method:"POST",body:{label:"secondary-updated",hidden:"hidden-secondary-secret",transformed:"uppercase",validated:"  trimmed  ",number:7,payload:{nested:["actual",null,7]}}});expect(changed.error).toBeNull();
  expect((changed.data as {session:unknown}).session).toMatchObject({label:"secondary-updated",transformed:"stage:uppercase",validated:"trimmed",number:7,payload:{nested:["actual",null,7]}});
  expect((changed.data as {session:unknown}).session).not.toHaveProperty("hidden");
  const read=await owner.client.getSession();expect(read.error).toBeNull();expect(read.data?.session).toMatchObject({label:"secondary-updated",number:7});
  const after=await state();
  return {signup:ctx.snapshot(signup),initial:ctx.snapshot(initial),before,changed:ctx.snapshot(changed),read:ctx.snapshot(read),after};
},["POST /update-session"]);
