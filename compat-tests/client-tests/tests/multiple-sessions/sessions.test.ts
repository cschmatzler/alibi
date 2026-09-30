import {expect} from "bun:test";
import {z} from "zod";
import {createAuthClient} from "better-auth/client";
import {multiSessionClient} from "better-auth/client/plugins";
import {compatScenario} from "../../support/scenario";
import {authProfilePath} from "../../support/profiles";

type Context = Parameters<Parameters<typeof compatScenario>[1]>[0];
type Profile = "multi-session" | "multi-session-limited";
function multiClient(ctx:Context, profile:Profile="multi-session", actor="browser") {
  return createAuthClient({baseURL:`${ctx.baseURL}${authProfilePath(profile)}`, plugins:[multiSessionClient()], fetchOptions:{customFetchImpl:ctx.actor(actor,profile).fetch}});
}
const stateSchema=z.object({user:z.object({id:z.string()}).passthrough().nullable(),accounts:z.array(z.unknown()),sessions:z.array(z.object({id:z.string(),token:z.string(),userId:z.string(),expiresAt:z.string()}))});

compatScenario("multiple browser sessions retain accounts switch active identity and revoke with fallback",async ctx=>{
  const client=multiClient(ctx);
  const alice=await client.signUp.email({email:ctx.uniqueEmail("multi-alice"),password:"password123",name:"Alice"});
  expect(alice.error).toBeNull();
  const bob=await client.signUp.email({email:ctx.uniqueEmail("multi-bob"),password:"password123",name:"Bob"});
  expect(bob.error).toBeNull();
  if(!alice.data || !bob.data || !alice.data.token || !bob.data.token) throw new Error("two user sessions expected");
  const list=await client.multiSession.listDeviceSessions();
  expect(list.error).toBeNull();
  expect(list.data).toHaveLength(2);
  expect(list.data?.map(item=>item.user.id)).toEqual([bob.data.user.id,alice.data.user.id]);
  const select=await client.multiSession.setActive({sessionToken:alice.data.token});
  expect(select.error).toBeNull();
  expect(select.data?.session.token).toBe(alice.data.token);
  const active=await client.getSession();
  expect(active.data?.user.id).toBe(alice.data.user.id);
  const outsider=await multiClient(ctx,"multi-session","outsider").multiSession.setActive({sessionToken:alice.data.token});
  expect(outsider.error?.code).toBe("INVALID_SESSION_TOKEN");
  const otherClient=multiClient(ctx,"multi-session","outsider");
  const other=await otherClient.signUp.email({email:ctx.uniqueEmail("multi-outsider"),password:"password123",name:"Other Browser"});
  expect(other.error).toBeNull();
  const foreignRevoke=await otherClient.multiSession.revoke({sessionToken:alice.data.token});
  expect(foreignRevoke.error?.code).toBe("INVALID_SESSION_TOKEN");
  const unchanged=stateSchema.parse(await ctx.readUserState({userId:alice.data.user.id}));
  expect(unchanged.sessions).toHaveLength(1);
  expect(unchanged.sessions[0]?.token).toBe(alice.data.token);
  expect((await otherClient.getSession()).data?.user.id).toBe(other.data?.user.id);
  await otherClient.signOut();
  expect(stateSchema.parse(await ctx.readUserState({userId:alice.data.user.id}))).toEqual(unchanged);
  const revoke=await client.multiSession.revoke({sessionToken:alice.data.token});
  expect(revoke.data?.status).toBe(true);
  const fallback=await client.getSession();
  expect(fallback.data?.user.id).toBe(bob.data.user.id);
  const old=stateSchema.parse(await ctx.readUserState({userId:alice.data.user.id}));
  expect(old.user?.id).toBe(alice.data.user.id);
  expect(old.sessions).toHaveLength(0);
  const replay=await client.multiSession.setActive({sessionToken:alice.data.token});
  expect(replay.error?.code).toBe("INVALID_SESSION_TOKEN");
  const remaining=await client.multiSession.listDeviceSessions();
  expect(remaining.data).toHaveLength(1);
  const signout=await client.signOut();
  expect(signout.error).toBeNull();
  const after=await client.multiSession.listDeviceSessions();
  expect(after.data).toEqual([]);
  const bobState=stateSchema.parse(await ctx.readUserState({userId:bob.data.user.id}));
  expect(bobState.sessions).toHaveLength(0);
  return {alice,bob,list,select,active,outsider,other,foreignRevoke,unchanged,revoke,fallback,old,replay,remaining,signout,after,bobState};
},["GET /multi-session/list-device-sessions","POST /multi-session/set-active","POST /multi-session/revoke","POST /sign-out"]);

compatScenario("multiple sessions rotate same-user login and honor configured browser account limit",async ctx=>{
  const client=multiClient(ctx,"multi-session-limited");
  const email=ctx.uniqueEmail("multi-limit-first");
  const first=await client.signUp.email({email,password:"password123",name:"First"});
  expect(first.error).toBeNull();
  const second=await client.signUp.email({email:ctx.uniqueEmail("multi-limit-second"),password:"password123",name:"Second"});
  expect(second.error).toBeNull();
  const third=await client.signUp.email({email:ctx.uniqueEmail("multi-limit-third"),password:"password123",name:"Third"});
  expect(third.error).toBeNull();
  if(!first.data || !second.data || !third.data) throw new Error("three accounts expected");
  const list=await client.multiSession.listDeviceSessions();
  expect(list.data).toHaveLength(2);
  expect(list.data?.map(item=>item.user.id)).toEqual([second.data.user.id,first.data.user.id]);
  const active=await client.getSession();
  expect(active.data?.user.id).toBe(third.data.user.id);
  const missingCookie=await client.multiSession.setActive({sessionToken:third.data.token!});
  expect(missingCookie.error?.code).toBe("INVALID_SESSION_TOKEN");
  const rotated=await client.signIn.email({email,password:"password123"});
  expect(rotated.error).toBeNull();
  expect(rotated.data?.token).not.toBe(first.data.token);
  const state=stateSchema.parse(await ctx.readUserState({userId:first.data.user.id}));
  expect(state.sessions).toHaveLength(1);
  expect(state.sessions.at(0)?.token).toBe(rotated.data?.token);
  const replay=await client.multiSession.setActive({sessionToken:first.data.token!});
  expect(replay.error?.code).toBe("INVALID_SESSION_TOKEN");
  const refreshed=await client.multiSession.listDeviceSessions();
  expect(refreshed.data).toHaveLength(2);
  expect(new Set(refreshed.data?.map(item=>item.user.id)).size).toBe(2);
  const signout=await client.signOut();
  expect(signout.error).toBeNull();
  const after=[];
  for(const [index,account] of [first,second,third].entries()) {
    const persisted=stateSchema.parse(await ctx.readUserState({userId:account.data!.user.id}));
    expect(persisted.user?.id).toBe(account.data!.user.id);
    expect(persisted.sessions).toHaveLength(index===2 ? 1 : 0);
    if(index===2)expect(persisted.sessions[0]?.token).toBe(third.data.token!);
    after.push(persisted);
  }
  expect((await client.multiSession.listDeviceSessions()).data).toEqual([]);
  expect((await client.getSession()).data).toBeNull();
  return {first,second,third,list,active,missingCookie,rotated,state,replay,refreshed,signout,after};
},["POST /sign-in/email"]);

compatScenario("multiple sessions reject invalid selection bodies and expire browser proofs without retiring another owner",async ctx=>{
  const profile="multi-session";
  const client=multiClient(ctx);
  const first=await client.signUp.email({email:ctx.uniqueEmail("multi-expired"),password:"password123",name:"Expired Owner"});
  const liveEmail=ctx.uniqueEmail("multi-live");
  const secondSignup=await client.signUp.email({email:liveEmail,password:"password123",name:"Live Owner"});
  expect(secondSignup.error).toBeNull();
  const second=await client.signIn.email({email:liveEmail,password:"password123",rememberMe:false});
  expect(first.error).toBeNull();
  expect(second.error).toBeNull();
  if(!first.data?.token || !second.data?.token)throw new Error("two persisted sessions expected");
  const selected=await client.multiSession.setActive({sessionToken:first.data.token});
  expect(selected.error).toBeNull();
  expect(selected.data?.user.id).toBe(first.data.user.id);
  const original=stateSchema.parse(await ctx.readUserState({userId:first.data.user.id}));
  const unauthenticated=await ctx.actor("visitor",profile).fetch(`${ctx.baseURL}${authProfilePath(profile)}/multi-session/revoke`,{method:"POST",headers:{"content-type":"application/json"},body:"{}"});
  expect(unauthenticated.status).toBe(400);
  const unauthenticatedBody=await unauthenticated.json();
  expect(unauthenticatedBody).toMatchObject({code:"VALIDATION_ERROR"});
  const invalid=[];
  for(const route of ["set-active","revoke"]) {
    for(const body of [{},{sessionToken:null},{sessionToken:7},{sessionToken:false},{sessionToken:[]}]) {
      const response=await ctx.actor("browser",profile).fetch(`${ctx.baseURL}${authProfilePath(profile)}/multi-session/${route}`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});
      const value=await response.json();
      expect(response.status).toBe(400);
      expect(value).toMatchObject({code:"VALIDATION_ERROR"});
      expect(stateSchema.parse(await ctx.readUserState({userId:first.data.user.id}))).toEqual(original);
      invalid.push({status:response.status,body:value});
    }
  }
  const expired=await ctx.rawRequest({path:"/__test/expire-session",method:"POST",json:{token:first.data.token,expiresAt:"2000-01-01T00:00:00.000Z"}});
  expect(expired.status).toBe(200);
  const list=await client.multiSession.listDeviceSessions();
  expect(list.error).toBeNull();
  expect(list.data?.map(item=>item.user.id)).toEqual([second.data.user.id]);
  const missing=await client.multiSession.setActive({sessionToken:first.data.token});
  expect(missing.error?.code).toBe("INVALID_SESSION_TOKEN");
  const live=stateSchema.parse(await ctx.readUserState({userId:second.data.user.id}));
  expect(live.sessions).toHaveLength(1);
  expect(live.sessions[0]?.token).toBe(second.data.token);
  const fallback=await client.multiSession.setActive({sessionToken:second.data.token});
  expect(fallback.error).toBeNull();
  expect((await client.getSession()).data?.user.id).toBe(second.data.user.id);
  const revoke=await client.multiSession.revoke({sessionToken:second.data.token});
  expect(revoke.error).toBeNull();
  expect((await client.getSession()).data).toBeNull();
  expect((await client.multiSession.listDeviceSessions()).data).toEqual([]);
  expect(stateSchema.parse(await ctx.readUserState({userId:second.data.user.id})).sessions).toHaveLength(0);
  return {first,secondSignup,second,selected,original,unauthenticated:{status:unauthenticated.status,body:unauthenticatedBody},invalid,expired,list,missing,live,fallback,revoke};
});
