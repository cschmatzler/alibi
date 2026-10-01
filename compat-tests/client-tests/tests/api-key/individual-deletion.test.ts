import { expect } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { apiKeyClient } from "@better-auth/api-key/client";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { createTracingFetch, type TraceEntry } from "../../support/trace";
import { z } from "zod";

type Profile="api-key-automatic"|"api-key-automatic-deferred";
const path=(profile:Profile)=>`/__test/profiles/${profile}/api/auth`;
const eventsSchema=z.array(z.object({kind:z.string()}).passthrough());
const rowsSchema=z.array(z.object({id:z.string(),referenceId:z.string(),remaining:z.number().nullable(),expiresAt:z.string().nullable()}).passthrough());
async function control(ctx:ScenarioContext,json:Record<string,unknown>){const response=await ctx.rawRequest({path:"/__test/api-key-background/control",method:"POST",json});expect(response.status).toBe(200);return eventsSchema.parse(response.body);}
async function rows(ctx:ScenarioContext){const response=await ctx.rawRequest({path:"/__test/api-key-background/state"});expect(response.status).toBe(200);return rowsSchema.parse(response.body);}
const count=(events:z.infer<typeof eventsSchema>,kind:string)=>events.filter(value=>value.kind===kind);
async function setup(ctx:ScenarioContext,profile:Profile,condition:"expired"|"exhausted"){
 await control(ctx,{action:"reset"});await control(ctx,{action:"restore"});
 const make=(name:string)=>createAuthClient({baseURL:`${ctx.baseURL}${path(profile)}`,plugins:[apiKeyClient()],fetchOptions:{customFetchImpl:ctx.actor(name,profile).fetch}});
 const owner=make("row-owner"),foreign=make("row-foreign");
 const signup=await owner.signUp.email({name:"Row Owner",email:ctx.uniqueEmail("row-owner"),password:"password123"});expect(signup.error).toBeNull();
 const other=await foreign.signUp.email({name:"Row Foreign",email:ctx.uniqueEmail("row-foreign"),password:"password123"});expect(other.error).toBeNull();
 const force=await ctx.rawRequest({path:`/__test/api-key-background/cleanup?profile=${profile}`,method:"POST"});expect(force.body).toEqual({success:true,error:null});
 const target=await owner.apiKey.create({name:"target"}),retained=await foreign.apiKey.create({name:"foreign-control"});expect(target.error).toBeNull();expect(retained.error).toBeNull();
 if(!signup.data||!other.data||!target.data||!retained.data)throw new Error("real users and credentials required");
 const forbidden=await foreign.apiKey.get({query:{id:target.data.id}});expect(forbidden.error).not.toBeNull();
 await control(ctx,condition==="expired"?{action:"expire",keyId:target.data.id}:{action:"quota",keyId:target.data.id,remaining:0});
 const before=await rows(ctx),ownerState=await ctx.readUserState({userId:signup.data.user.id}),foreignState=await ctx.readUserState({userId:other.data.user.id});
 expect(before).toHaveLength(2);expect(before.find(row=>row.id===target.data.id)?.referenceId).toBe(signup.data.user.id);
 return {owner,foreign,signup,other,target,retained,forbidden,before,ownerState,foreignState};
}
async function preserve(ctx:ScenarioContext,fixture:Awaited<ReturnType<typeof setup>>){expect(await ctx.readUserState({userId:fixture.signup.data!.user.id})).toEqual(fixture.ownerState);expect(await ctx.readUserState({userId:fixture.other.data!.user.id})).toEqual(fixture.foreignState);}
function observed(fixture:Awaited<ReturnType<typeof setup>>){const{owner,foreign,...value}=fixture;return value;}
const error=(condition:"expired"|"exhausted")=>({status:condition==="expired"?401:429,code:condition==="expired"?"KEY_EXPIRED":"USAGE_EXCEEDED"});

for(const condition of ["expired","exhausted"] as const)compatScenario(`api-key deferred individual ${condition} deletion rejects before the actual write and ignored completion cannot cancel ownership-safe cleanup`,async ctx=>{
 const fixture=await setup(ctx,"api-key-automatic-deferred",condition);await control(ctx,{action:"configure",hold:true,observer:"ignore"});
 const result=await fixture.owner.getSession({fetchOptions:{headers:{"x-api-key":fixture.target.data!.key}}});expect(result.error).toMatchObject(error(condition));
 const paused=await control(ctx,{action:"wait",kind:"row-delete-enter",count:1});expect(count(paused,"row-delete-enter")).toEqual([{kind:"row-delete-enter",profile:"api-key-automatic-deferred",serial:2,key:{id:fixture.target.data!.id}}]);expect(count(paused,"background-register")).toHaveLength(1);expect(count(paused,"cleanup-enter")).toHaveLength(1);expect(count(paused,"row-delete-complete")).toEqual([]);expect(await rows(ctx)).toEqual(fixture.before);await preserve(ctx,fixture);
 await control(ctx,{action:"release"});const completed=await control(ctx,{action:"wait",kind:"row-delete-complete",count:1});expect(count(completed,"row-delete-complete")).toEqual([{kind:"row-delete-complete",serial:2,success:true}]);expect(count(completed,"background-complete")).toEqual([]);
 const after=await rows(ctx);expect(after).toEqual(fixture.before.filter(row=>row.id!==fixture.target.data!.id));await preserve(ctx,fixture);
 const retry=await fixture.owner.getSession({fetchOptions:{headers:{"x-api-key":fixture.target.data!.key}}});expect(retry.error).toMatchObject({status:401,code:"INVALID_API_KEY"});expect(await rows(ctx)).toEqual(after);
 return ctx.snapshot({...observed(fixture),result,paused,completed,after,retry});
},["GET /get-session"]);

for(const condition of ["expired","exhausted"] as const)compatScenario(`api-key awaited individual ${condition} deletion waits for actual adapter release and rejects without observer registration`,async ctx=>{
 const fixture=await setup(ctx,"api-key-automatic",condition);await control(ctx,{action:"configure",hold:true,observer:"observe"});let finished=false;
 const pending=fixture.owner.getSession({fetchOptions:{headers:{"x-api-key":fixture.target.data!.key}}}).then(result=>{finished=true;return result;});let paused:z.infer<typeof eventsSchema>|undefined;
 try{paused=await control(ctx,{action:"wait",kind:"row-delete-enter",count:1});expect(await rows(ctx)).toEqual(fixture.before);await preserve(ctx,fixture);expect(finished).toBe(false);expect(count(paused,"background-register")).toEqual([]);expect(count(paused,"row-delete-complete")).toEqual([]);}
 finally{const entries:TraceEntry[]=[];const release=await createTracingFetch(ctx.baseURL,"row-delete-release",entries)("/__test/api-key-background/control",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({action:"release"})});expect(release.status).toBe(200);eventsSchema.parse(await release.json());ctx.recordTransport(entries);}
 const result=await pending;expect(result.error).toMatchObject(error(condition));const completed=await control(ctx,{action:"wait",kind:"row-delete-complete",count:1}),after=await rows(ctx);expect(after).toEqual(fixture.before.filter(row=>row.id!==fixture.target.data!.id));await preserve(ctx,fixture);
 return ctx.snapshot({...observed(fixture),paused,result,completed,after});
},["GET /get-session"]);

compatScenario("api-key deferred individual storage failure resolves caught completion retains the exact row and awaited retry preserves failure then deletes only its owner",async ctx=>{
 const fixture=await setup(ctx,"api-key-automatic-deferred","exhausted");await control(ctx,{action:"veto"});await control(ctx,{action:"configure",hold:true,observer:"observe"});
 const deferred=await fixture.owner.getSession({fetchOptions:{headers:{"x-api-key":fixture.target.data!.key}}});expect(deferred.error).toMatchObject(error("exhausted"));const paused=await control(ctx,{action:"wait",kind:"row-delete-enter",count:1});expect(await rows(ctx)).toEqual(fixture.before);
 await control(ctx,{action:"release"});const failed=await control(ctx,{action:"wait",kind:"background-complete",count:1});expect(count(failed,"row-delete-complete")).toEqual([{kind:"row-delete-complete",serial:2,success:false}]);expect(count(failed,"background-complete")).toEqual([{kind:"background-complete",fulfilled:true}]);expect(await rows(ctx)).toEqual(fixture.before);await preserve(ctx,fixture);
 await control(ctx,{action:"configure"});const defaultClient=createAuthClient({baseURL:`${ctx.baseURL}${path("api-key-automatic")}`,fetchOptions:{customFetchImpl:ctx.actor("awaited-retry","api-key-automatic").fetch}});
 const awaited=await defaultClient.getSession({fetchOptions:{headers:{"x-api-key":fixture.target.data!.key}}});expect(awaited.error?.status).toBe(500);expect(await rows(ctx)).toEqual(fixture.before);
 await control(ctx,{action:"restore"});const retry=await defaultClient.getSession({fetchOptions:{headers:{"x-api-key":fixture.target.data!.key}}});expect(retry.error).toMatchObject(error("exhausted"));const after=await rows(ctx);expect(after).toEqual(fixture.before.filter(row=>row.id!==fixture.target.data!.id));await preserve(ctx,fixture);
 return ctx.snapshot({...observed(fixture),deferred,paused,failed,awaited,retry,after});
},["GET /get-session"]);

compatScenario("api-key rejected individual completion handler cannot cancel deletion while genuine application 403 retains exact response authority",async ctx=>{
 const fixture=await setup(ctx,"api-key-automatic-deferred","expired");await control(ctx,{action:"configure",hold:true,observer:"throw"});
 const ordinary=await fixture.owner.getSession({fetchOptions:{headers:{"x-api-key":fixture.target.data!.key}}});expect(ordinary.error?.status).toBe(500);const paused=await control(ctx,{action:"wait",kind:"row-delete-enter",count:1});expect(await rows(ctx)).toEqual(fixture.before);
 await control(ctx,{action:"configure",hold:true,observer:"api"});const domain=await fixture.owner.getSession({fetchOptions:{headers:{"x-api-key":fixture.target.data!.key}}});expect(domain.error).toMatchObject({status:403,code:"BACKGROUND_TASK_DENIED",message:"Application background observer denied"});const rejected=await control(ctx,{action:"wait",kind:"row-delete-enter",count:2});expect(count(rejected,"background-register")).toHaveLength(2);expect(count(rejected,"cleanup-enter")).toHaveLength(1);expect(await rows(ctx)).toEqual(fixture.before);await preserve(ctx,fixture);
 await control(ctx,{action:"release",serial:2});const firstCompleted=await control(ctx,{action:"wait",kind:"row-delete-complete",count:1});expect(count(firstCompleted,"row-delete-complete")).toEqual([{kind:"row-delete-complete",serial:2,success:true}]);expect(await rows(ctx)).toEqual(fixture.before.filter(row=>row.id!==fixture.target.data!.id));
 await control(ctx,{action:"release",serial:3});const completed=await control(ctx,{action:"wait",kind:"row-delete-complete",count:2});expect(count(completed,"row-delete-complete")).toEqual([{kind:"row-delete-complete",serial:2,success:true},{kind:"row-delete-complete",serial:3,success:true}]);expect(count(completed,"background-complete")).toEqual([]);const after=await rows(ctx);expect(after).toEqual(fixture.before.filter(row=>row.id!==fixture.target.data!.id));await preserve(ctx,fixture);
 return ctx.snapshot({...observed(fixture),ordinary,paused,domain,rejected,firstCompleted,completed,after});
},["GET /get-session"]);

compatScenario("api-key trusted individual deletion checks permissions before exhaustion and preserves deferred versus awaited storage failures",async ctx=>{
 const fixture=await setup(ctx,"api-key-automatic-deferred","exhausted");
 const verify=async(profile:Profile,permissions?:Record<string,string[]>)=>{const response=await ctx.rawRequest({path:`/__test/api-key-background/verify?profile=${profile}`,method:"POST",json:{key:fixture.target.data!.key,...(permissions?{permissions}:{})}});expect(response.status).toBe(200);return response.body;};
 const denied=await verify("api-key-automatic-deferred",{resource:["read"]});expect(denied).toEqual({valid:false,error:{code:"KEY_NOT_FOUND",message:"API Key not found"},key:null});const permissionEvents=await control(ctx,{action:"wait",kind:"cleanup-complete",count:1});expect(count(permissionEvents,"row-delete-enter")).toEqual([]);expect(count(permissionEvents,"background-register")).toEqual([]);expect(await rows(ctx)).toEqual(fixture.before);
 await control(ctx,{action:"veto"});await control(ctx,{action:"configure",hold:true,observer:"observe"});
 const deferred=await verify("api-key-automatic-deferred");expect(deferred).toEqual({valid:false,error:{code:"USAGE_EXCEEDED",message:"API Key has reached its usage limit"},key:null});const paused=await control(ctx,{action:"wait",kind:"row-delete-enter",count:1});expect(await rows(ctx)).toEqual(fixture.before);
 await control(ctx,{action:"release"});const completed=await control(ctx,{action:"wait",kind:"background-complete",count:1});expect(count(completed,"row-delete-complete")).toEqual([{kind:"row-delete-complete",serial:2,success:false}]);expect(count(completed,"background-complete")).toEqual([{kind:"background-complete",fulfilled:true}]);expect(await rows(ctx)).toEqual(fixture.before);
 await control(ctx,{action:"configure"});const awaited=await verify("api-key-automatic");expect(awaited).toEqual({valid:false,error:{code:"INVALID_API_KEY",message:{code:"INVALID_API_KEY",message:"Invalid API key."}},key:null});expect(await rows(ctx)).toEqual(fixture.before);await preserve(ctx,fixture);
 await control(ctx,{action:"restore"});const retry=await verify("api-key-automatic");expect(retry).toEqual(deferred);const after=await rows(ctx);expect(after).toEqual(fixture.before.filter(row=>row.id!==fixture.target.data!.id));await preserve(ctx,fixture);
 return ctx.snapshot({...observed(fixture),denied,permissionEvents,deferred,paused,completed,awaited,retry,after});
},[]);
