import {expect} from "bun:test";
import {z} from "zod";
import {compatScenario, type ScenarioContext} from "../../support/scenario";
import type {FixtureProfile} from "../../support/profiles";

compatScenario("update-session validates records before authentication and rejects immutable empty or unsupported media patches without state changes",async ctx=>{
  const guest=ctx.actor("guest").client;
  const unauthenticated=await guest.$fetch("/update-session",{method:"POST",body:{label:"guest"}});
  expect(unauthenticated.error).toMatchObject({status:401,code:"UNAUTHORIZED",message:"Unauthorized"});
  const malformed=await ctx.rawRequest({actor:"guest",path:"/api/auth/update-session",method:"POST",json:[]});
  expect(malformed.status).toBe(400);
  expect(malformed.body).toEqual({code:"VALIDATION_ERROR",message:"[body] Invalid input: expected record, received array"});
  const user=ctx.actor("owner").client;
  const email=ctx.uniqueEmail("update-session-default");
  const signup=await user.signUp.email({email,name:"Session Owner",password:"password123"});
  expect(signup.error).toBeNull();
  const before=await ctx.readUserState({userId: z.object({user:z.object({id:z.string()})}).parse(signup.data).user.id});
  const empty=await user.$fetch("/update-session",{method:"POST",body:{}});
  expect(empty.error).toMatchObject({status:400,message:"No fields to update"});
  const immutable=await user.$fetch("/update-session",{method:"POST",body:{id:"forged-session",token:"forged-token",userId:"forged-owner",expiresAt:"2099-01-01T00:00:00.000Z"}});
  expect(immutable.error).toMatchObject({status:400,message:"No fields to update"});
  const foreignScope=await user.$fetch("/update-session",{method:"POST",body:{activeOrganizationId:"forged-organization"}});
  expect(foreignScope.error).toMatchObject({status:400,code:"FIELD_NOT_ALLOWED",message:"activeOrganizationId is not allowed to be set"});
  const media=await ctx.rawRequest({actor:"owner",path:"/api/auth/update-session",method:"POST",headers:{"content-type":"text/plain"},body:"{}"});
  expect(media.status).toBe(415);
  expect(media.body).toEqual({code:"UNSUPPORTED_MEDIA_TYPE",message:'Content-Type "text/plain" is not allowed. Allowed types: application/json'});
  expect(await ctx.readUserState({userId: z.object({user:z.object({id:z.string()})}).parse(signup.data).user.id})).toEqual(before);
  return {unauthenticated:ctx.snapshot(unauthenticated),malformed,signup:ctx.snapshot(signup),empty:ctx.snapshot(empty),immutable:ctx.snapshot(immutable),foreignScope:ctx.snapshot(foreignScope),media,before};
});

const stateRow=z.object({id:z.string(),token:z.string(),userId:z.string(),updatedAt:z.string(),label:z.string().nullable(),hidden:z.string().nullable(),serverOnly:z.string().nullable(),transformed:z.string().nullable(),validated:z.string().nullable(),callback:z.string().nullable(),number:z.number().nullable(),payload:z.unknown(),activeOrganizationId:z.string().nullable(),activeTeamId:z.string().nullable(),impersonatedBy:z.string().nullable()});
const responseSession=z.object({session:z.object({id:z.string(),token:z.string(),userId:z.string(),label:z.string().nullable(),serverOnly:z.string().nullable(),callback:z.string().nullable(),payload:z.unknown()}).passthrough()});
async function fieldsScenario(ctx:ScenarioContext,profile:FixtureProfile){
  const actor=ctx.actor("owner",profile);
  const email=ctx.uniqueEmail(`update-${profile}`);
  const signup=await actor.client.signUp.email({email,name:"Application Owner",password:"password123"});
  expect(signup.error).toBeNull();
  const get=await actor.client.getSession();
  expect(get.error).toBeNull();
  const initial=responseSession.parse(get.data).session;
  expect(initial).toMatchObject({label:"initial",serverOnly:"locked",callback:"callback-created",payload:{initial:true},transformed:"generated-without-default",validated:"stored:"});
  expect(initial).not.toHaveProperty("hidden");
  expect(initial.activeOrganizationId).toBe(profile==="session-fields-plugins"?"adapter:configured-default-org":"declared-without-plugin");
  const read=async(target=email)=>{
    const result=await ctx.rawRequest({path:`/__test/session-field-state?email=${encodeURIComponent(target)}`});
    expect(result.status).toBe(200);
    return z.array(stateRow).parse(result.body);
  };
  const first=await read();
  expect(first[0]).toMatchObject({id:initial.id,hidden:"server-secret"});
  const other=ctx.actor("other",profile).client;
  const otherEmail=ctx.uniqueEmail(`foreign-${profile}`);
  const otherSignup=await other.signUp.email({email:otherEmail,name:"Other Owner",password:"password123"});
  expect(otherSignup.error).toBeNull();
  const otherSession=responseSession.parse((await other.getSession()).data).session;
  const sameOwner=ctx.actor("same-owner-second-token",profile).client;
  expect((await sameOwner.signIn.email({email,password:"password123"})).error).toBeNull();
  const sameOwnerSession=responseSession.parse((await sameOwner.getSession()).data).session;
  const otherBefore=await read(otherEmail);
  const allBefore=await read();
  const unrelatedBefore=allBefore.find(row=>row.id===sameOwnerSession.id);
  expect(unrelatedBefore).toBeDefined();
  const payload={"$serde_json::private::Number":"literal",empty:{},nested:{list:[1,"value"]}};
  const update=await actor.client.$fetch("/update-session",{method:"POST",body:{label:"changed",hidden:"updated-secret",transformed:"uppercase",validated:" trimmed ",number:7,payload,token:otherSession.token,userId:otherSession.userId,id:otherSession.id,expiresAt:"2099-01-01T00:00:00.000Z"}});
  expect(update.error).toBeNull();
  const changed=responseSession.parse(update.data).session;
  expect(changed).toMatchObject({id:initial.id,token:initial.token,userId:initial.userId,label:"changed",transformed:"stage:stage:uppercase",validated:"stored:trimmed",number:7,payload,callback:"callback-created"});
  expect(changed).not.toHaveProperty("hidden");
  const after=await read();
  expect(after.find(row=>row.id===initial.id)).toMatchObject({hidden:"updated-secret",payload,label:"changed",transformed:"stage:stage:uppercase",validated:"stored:trimmed",number:7});
  expect(after.find(row=>row.id===sameOwnerSession.id)).toEqual(unrelatedBefore);
  expect(await read(otherEmail)).toEqual(otherBefore);
  const invalid=await actor.client.$fetch("/update-session",{method:"POST",body:{label:"must-not-save",validated:" "}});
  expect(invalid.error).toMatchObject({status:400,code:"VALIDATION_ERROR",message:"configured validation rejected the value"});
  const forbidden=await actor.client.$fetch("/update-session",{method:"POST",body:{label:"must-not-save",serverOnly:[]}});
  expect(forbidden.error).toMatchObject({status:400,code:"FIELD_NOT_ALLOWED",message:"serverOnly is not allowed to be set"});
  expect(await read()).toEqual(after);
  const falsy=await actor.client.$fetch("/update-session",{method:"POST",body:{label:null,serverOnly:false}});
  expect(falsy.error).toBeNull();
  expect(responseSession.parse(falsy.data).session).toMatchObject({label:null,serverOnly:"locked"});
  const raw=async(body:string)=>{
    const response=await actor.fetch(`${ctx.baseURL}/__test/profiles/${profile}/api/auth/update-session`,{method:"POST",headers:{"content-type":"application/json"},body});
    const result={status:response.status,body:await response.json()};
    expect(result.status).toBe(200);
    return result;
  };
  const numeric=[];
  for(const [literal,expected]of [["1e20","1.0e+20"],["1e-20","1.0e-20"],["1e999","Inf"],["-0","0.0"]] as const) {
    const result=await raw(`{"label":${literal}}`);
    expect(responseSession.parse(result.body).session.label).toBe(expected);
    expect((await read()).find(row=>row.id===initial.id)?.label).toBe(expected);
    numeric.push(result);
  }
  const callbacks=[];
  for(const [literal,expected]of [["1e999","stored:Infinity"],["-1e999","stored:-Infinity"],["-0","stored:-0"]] as const) {
    const result=await raw(`{"validated":${literal}}`);
    expect(responseSession.parse(result.body).session.validated).toBe(expected);
    callbacks.push(result);
  }
  const omitted=await actor.client.$fetch("/update-session",{method:"POST",body:{transformed:"omit"}});
  expect(omitted.error).toBeNull();
  expect(responseSession.parse(omitted.data).session.transformed).toBe("stage:stage:uppercase");
  const omittedBinding=await actor.client.$fetch("/update-session",{method:"POST",body:{transformed:"omit-at-binding"}});
  expect(omittedBinding.error).toBeNull();
  expect(responseSession.parse(omittedBinding.data).session.transformed).toBe("stage:stage:uppercase");
  expect((await read()).find(row=>row.id===initial.id)?.transformed).toBe("stage:stage:uppercase");
  const undefinedHook=await actor.client.$fetch("/update-session",{method:"POST",body:{transformed:"omit",label:"restore-undefined"}});
  expect(undefinedHook.error).toBeNull();
  expect(responseSession.parse(undefinedHook.data).session.transformed).toBe("stage:hook-current");
  const errorBefore=await read();
  const transformError=await actor.client.$fetch("/update-session",{method:"POST",body:{label:"must-not-save",transformed:"throw-at-binding"}});
  expect(transformError.error?.status).toBe(500);
  expect(await read()).toEqual(errorBefore);
  const transformedHook=await actor.client.$fetch("/update-session",{method:"POST",body:{transformed:"hook-input"}});
  expect(transformedHook.error).toBeNull();
  expect(responseSession.parse(transformedHook.data).session.transformed).toBe("stage:hook-current");
  expect((await read()).find(row=>row.id===initial.id)?.transformed).toBe("stage:hook-current");
  const hook=await actor.client.$fetch("/update-session",{method:"POST",body:{label:"native-hook"}});
  expect(hook.error).toBeNull();
  expect(responseSession.parse(hook.data).session.label).toBe("model-override");
  const readAfter=(await actor.client.getSession());
  expect(responseSession.parse(readAfter.data).session.label).toBe("model-override");
  expect(await read(otherEmail)).toEqual(otherBefore);
  expect((await read()).find(row=>row.id===sameOwnerSession.id)).toEqual(unrelatedBefore);
  let pluginRejections=[];
  if(profile==="session-fields") {
    const explicit=await actor.client.$fetch("/update-session",{method:"POST",body:{activeOrganizationId:"declared-update"}});
    expect(explicit.error).toBeNull();
    expect(responseSession.parse(explicit.data).session.activeOrganizationId).toBe("declared-update");
    expect((await read()).find(row=>row.id===initial.id)?.activeOrganizationId).toBe("declared-update");
    pluginRejections.push(ctx.snapshot(explicit));
  }
  if(profile==="session-fields-plugins") {
    for(const name of ["activeOrganizationId","activeTeamId","impersonatedBy"]) {
      const result=await actor.client.$fetch("/update-session",{method:"POST",body:{[name]:otherSession.userId}});
      expect(result.error).toMatchObject({status:400,code:"FIELD_NOT_ALLOWED",message:`${name} is not allowed to be set`});
      pluginRejections.push(ctx.snapshot(result));
    }
  }
  const browser=ctx.actor("browser-session",profile).client;
  expect((await browser.signIn.email({email,password:"password123",rememberMe:false})).error).toBeNull();
  const browserSession=responseSession.parse((await browser.getSession()).data).session;
  const browserUpdate=await browser.$fetch("/update-session",{method:"POST",body:{label:"browser-session"}});
  expect(browserUpdate.error).toBeNull();
  expect(responseSession.parse(browserUpdate.data).session.id).toBe(browserSession.id);
  const cancelBefore=await read();
  const cancelled=await browser.$fetch("/update-session",{method:"POST",body:{label:"cancel-before"}});
  expect(cancelled.error).toMatchObject({status:401,code:"FAILED_TO_GET_SESSION",message:"Failed to get session"});
  expect(await read()).toEqual(cancelBefore);
  expect((await browser.getSession()).data).toBeNull();
  const deleted=await actor.client.$fetch("/update-session",{method:"POST",body:{label:"delete-before"}});
  expect(deleted.error).toMatchObject({status:401,code:"FAILED_TO_GET_SESSION",message:"Failed to get session"});
  expect((await read()).some(row=>row.id===initial.id)).toBe(false);
  expect((await actor.client.getSession()).data).toBeNull();
  expect((await sameOwner.getSession()).error).toBeNull();
  expect(await read(otherEmail)).toEqual(otherBefore);
  return {signup:ctx.snapshot(signup),get:ctx.snapshot(get),first,otherSignup:ctx.snapshot(otherSignup),otherBefore,allBefore,update:ctx.snapshot(update),after,invalid:ctx.snapshot(invalid),forbidden:ctx.snapshot(forbidden),falsy:ctx.snapshot(falsy),numeric,callbacks,omitted:ctx.snapshot(omitted),omittedBinding:ctx.snapshot(omittedBinding),undefinedHook:ctx.snapshot(undefinedHook),transformError:ctx.snapshot(transformError),transformedHook:ctx.snapshot(transformedHook),hook:ctx.snapshot(hook),readAfter:ctx.snapshot(readAfter),pluginRejections,browserUpdate:ctx.snapshot(browserUpdate),cancelled:ctx.snapshot(cancelled),deleted:ctx.snapshot(deleted),remaining:await read()};
}
for(const profile of ["session-fields","session-fields-plugins"] as const)compatScenario(`update-session ${profile} persists configured fields only for the current token with defaults policies callbacks and deletion failure`,ctx=>fieldsScenario(ctx,profile),["POST /update-session"]);
