import { expect } from "bun:test";
import { z } from "zod";
import { createTracingFetch, type TraceEntry } from "../../support/trace";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
const row = z.object({ id: z.string() }).passthrough();
const snapshot = z.object({
  organizations: z.array(row),
  members: z.array(row),
  users: z.array(row),
  sessions: z.array(row),
});
const receipt = z.object({
  phase: z.string(),
  organization: z.record(z.string(), z.unknown()),
  newRole:z.string().nullable(),
  previousRole:z.string().nullable(),
  user: z.object({ id: z.string(), email: z.string(), name: z.string() }),
  member: z.object({
    id: z.string(),
    organizationId: z.string(),
    userId: z.string(),
    role: z.string(),
  }),
  snapshot,
});
const stateSchema = z.object({ receipts: z.array(receipt), snapshot });
const organization = z
  .object({
    id: z.string(),
    name: z.string(),
    slug: z.string(),
    logo: z.string().nullable(),
    metadata: z.unknown().optional(),
  })
  .passthrough();
async function configure(ctx: ScenarioContext, mode: string) {
  expect(
    (
      await ctx.rawRequest({
        path: "/__test/organization-member-role-hooks-configure",
        method: "POST",
        json: { mode },
      })
    ).status,
  ).toBe(200);
}
async function state(ctx: ScenarioContext, waitFor?: string) {
  const result = await ctx.rawRequest({
    path:
      "/__test/organization-member-role-hooks-state" +
      (waitFor ? `?waitFor=${waitFor}` : ""),
  });
  expect(result.status).toBe(200);
  return stateSchema.parse(result.body);
}
async function signup(ctx: ScenarioContext, name: string) {
  const actor = ctx.actor(name, "org-member-role-hooks"),
    email = ctx.uniqueEmail(name);
  const result = await actor.client.signUp.email({
    name,
    email,
    password: "password123",
  });
  expect(result.error).toBeNull();
  return {
    ...actor,
    email,
    userId: z.object({ user: z.object({ id: z.string() }) }).parse(result.data)
      .user.id,
  };
}
type Actor = Awaited<ReturnType<typeof signup>>;
async function create(ctx: ScenarioContext, actor: Actor, name: string) {
  const result = await actor.client.$fetch("/organization/create", {
    method: "POST",
    body: {
      name,
      slug: ctx.uniqueToken(name),
      logo: "https://example.test/original.png",
      metadata: { original: true },
    },
  });
  expect(result.error).toBeNull();
  return organization.parse(result.data);
}
const memberSchema=z.object({id:z.string(),organizationId:z.string(),userId:z.string(),role:z.string()}).passthrough();
async function setup(ctx:ScenarioContext,name:string) {
 const owner=await signup(ctx,`${name}-owner`),target=await signup(ctx,`${name}-target`),foreign=await signup(ctx,`${name}-foreign`);
 const org=await create(ctx,owner,`${name}-org`),other=await create(ctx,foreign,`${name}-other`);
 const invitation=await owner.client.$fetch("/organization/invite-member",{method:"POST",body:{organizationId:org.id,email:target.email,role:"member"}});
 expect(invitation.error).toBeNull();const invitationId=z.object({id:z.string()}).parse(invitation.data).id;
 const accepted=await target.client.$fetch("/organization/accept-invitation",{method:"POST",body:{invitationId}});
 expect(accepted.error).toBeNull();const member=memberSchema.parse(z.object({member:memberSchema}).parse(accepted.data).member);
 const sibling=ctx.actor(`${name}-sibling`,"org-member-role-hooks");expect((await sibling.client.signIn.email({email:target.email,password:"password123"})).error).toBeNull();
 return {owner,target,foreign,org,other,member,sibling};
}
function update(actor:Actor,organizationId:string,memberId:string,role:string|string[]="admin") {
 return actor.client.$fetch("/organization/update-member-role",{method:"POST",body:{organizationId,memberId,role}});
}
function stable(before:Awaited<ReturnType<typeof state>>,after:Awaited<ReturnType<typeof state>>,memberId:string) {
 expect(after.snapshot.members.filter(row=>row.id!==memberId)).toEqual(before.snapshot.members.filter(row=>row.id!==memberId));
 for(const key of ["organizations","users","sessions"] as const)expect(after.snapshot[key]).toEqual(before.snapshot[key]);
}
compatScenario("organization member role callbacks use the target user and normalized initial role with source patch fallback",async ctx=>{
 const {owner,target,org,member}=await setup(ctx,"role-patches"),observations=[];
 const read=await owner.client.$fetch("/organization/get-organization",{query:{organizationId:org.id}});expect(read.error).toBeNull();
 const rawOrganization=organization.parse(ctx.snapshot(read.data));
 for(const [mode,expected] of [["record","admin,member,admin"],["empty","admin,member,admin"],["absent","admin,member,admin"],["patch","hook-unregistered-role"]] as const){
  await configure(ctx,mode);const before=await state(ctx);const result=await update(owner,org.id,member.id,[" admin ,member ","admin"]);
  expect(result.error).toBeNull();expect(memberSchema.parse(result.data).role).toBe(expected);const after=await state(ctx);
  expect(after.receipts.map(row=>row.phase)).toEqual(["before-role","after-role"]);
  const first=after.receipts[0]!,last=after.receipts[1]!;
  expect(first.newRole).toBe("admin,member,admin");expect(first.previousRole).toBeNull();expect(last.newRole).toBeNull();
  expect(first.user).toEqual({id:target.userId,email:target.email,name:"role-patches-target"});expect(last.user).toEqual(first.user);
  expect(first.member).toEqual(memberSchema.parse(before.snapshot.members.find(row=>row.id===member.id)));
  expect(last.member).toEqual(memberSchema.parse(after.snapshot.members.find(row=>row.id===member.id)));expect(last.previousRole).toBe(first.member.role);
  expect(first.organization).toEqual(rawOrganization);expect(last.organization).toEqual(first.organization);
  expect(first.organization.metadata).toBe('{"original":true}');
  expect(after.snapshot.members.find(row=>row.id===member.id)).toHaveProperty("role",expected);stable(before,after,member.id);
  observations.push({before,result:ctx.snapshot(result),after});
 }
 await configure(ctx,"record");const beforeDenied=await state(ctx);const denied=await update(target,org.id,member.id,"member");
 expect(denied.error).toMatchObject({status:403});expect(await state(ctx)).toEqual(beforeDenied);
 return {observations,denied:ctx.snapshot(denied),beforeDenied};
},["POST /organization/update-member-role"]);
compatScenario("organization member role callback errors distinguish no write from a committed role change",async ctx=>{
 const {owner,org,member}=await setup(ctx,"role-errors"),observations=[];
 for(const phase of ["before-role","after-role"]){await configure(ctx,`reject-${phase}`);const before=await state(ctx),result=await update(owner,org.id,member.id);
  expect(result.error).toMatchObject({status:400,code:"ROLE_HOOK_REJECTED",message:`Rejected ${phase}`});const after=await state(ctx);
  expect(after.receipts.map(row=>row.phase)).toEqual(phase==="before-role"?["before-role"]:["before-role","after-role"]);
  if(phase==="before-role")expect(after.snapshot).toEqual(before.snapshot);else {expect(after.snapshot.members.find(row=>row.id===member.id)).toHaveProperty("role","admin");stable(before,after,member.id);}
  observations.push({before,result:ctx.snapshot(result),after});
 }
 return observations;
},["POST /organization/update-member-role"]);
compatScenario("organization member role validation and foreign authorization reject before any callback or write",async ctx=>{
 const {owner,target,foreign,org,other,member}=await setup(ctx,"role-guards");await configure(ctx,"reject-before-role");const before=await state(ctx),observations=[];
 for(const [actor,orgId,role,status] of [[owner,org.id,"unknown-role",400],[foreign,org.id,"admin",400],[owner,other.id,"admin",400],[target,org.id,"admin",403]] as const){
  const result=await update(actor,orgId,member.id,role);expect(result.error).toMatchObject({status});expect(await state(ctx)).toEqual(before);observations.push(ctx.snapshot(result));
 }
 return {before,observations};
},["POST /organization/update-member-role"]);
compatScenario("organization member role after callback keeps original target snapshots across independent writes",async ctx=>{
 const {owner,target,org,member}=await setup(ctx,"role-snapshots");await configure(ctx,"mutate-target");const before=await state(ctx),result=await update(owner,org.id,member.id);
 expect(result.error).toBeNull();const after=await state(ctx);expect(after.receipts.map(row=>row.phase)).toEqual(["before-role","after-role"]);
 expect(after.receipts[1]!.user).toEqual(after.receipts[0]!.user);expect(after.receipts[1]!.user.name).toBe("role-snapshots-target");expect(after.receipts[1]!.previousRole).toBe("member");
 expect(after.snapshot.users.find(row=>row.id===target.userId)).toHaveProperty("name","Stored Target Name");expect(after.snapshot.members.find(row=>row.id===member.id)).toHaveProperty("role","admin");
 expect(after.snapshot.organizations).toEqual(before.snapshot.organizations);expect(after.snapshot.sessions).toEqual(before.snapshot.sessions);
 expect(after.snapshot.users.filter(row=>row.id!==target.userId)).toEqual(before.snapshot.users.filter(row=>row.id!==target.userId));
 expect(after.snapshot.members.filter(row=>row.id!==member.id)).toEqual(before.snapshot.members.filter(row=>row.id!==member.id));
 await configure(ctx,"record");const repeat=await update(owner,org.id,member.id,"member");expect(repeat.error).toBeNull();const repeated=await state(ctx);expect(repeated.receipts[0]!.user.name).toBe("Stored Target Name");expect(repeated.receipts[0]!.member.role).toBe("admin");
 return {before,result:ctx.snapshot(result),after,repeat:ctx.snapshot(repeat),repeated};
},["POST /organization/update-member-role"]);
compatScenario("organization member role before callback deletion yields actual missing-member rejection without after callback",async ctx=>{
 const {owner,org,member}=await setup(ctx,"role-delete");await configure(ctx,"delete-row");const before=await state(ctx),result=await update(owner,org.id,member.id);
 expect(result.error).toMatchObject({status:400,code:"MEMBER_NOT_FOUND",message:"Member not found"});const after=await state(ctx);expect(after.receipts.map(row=>row.phase)).toEqual(["before-role"]);expect(after.snapshot.members.find(row=>row.id===member.id)).toBeUndefined();stable(before,after,member.id);
 return {before,result:ctx.snapshot(result),after};
},["POST /organization/update-member-role"]);
compatScenario("organization member role update awaits async callback before changing the stored role",async ctx=>{
 const {owner,org,member}=await setup(ctx,"role-await");await configure(ctx,"pause-before");const before=await state(ctx);let completed=false;
 const pending=update(owner,org.id,member.id).then(result=>{completed=true;return result;});let paused:Awaited<ReturnType<typeof state>>|undefined;const trace:TraceEntry[]=[];
 try{paused=await state(ctx,"before-role");expect(paused.receipts.map(row=>row.phase)).toEqual(["before-role"]);expect(completed).toBe(false);expect(paused.snapshot).toEqual(before.snapshot);}
 finally{const release=await createTracingFetch(ctx.baseURL,"role-hook-release",trace)("/__test/organization-member-role-hooks-release",{method:"POST"});expect(release.status).toBe(200);expect(await release.json()).toEqual({released:true});}
 const result=await pending;ctx.recordTransport(trace);expect(result.error).toBeNull();const after=await state(ctx);expect(after.receipts.map(row=>row.phase)).toEqual(["before-role","after-role"]);expect(after.snapshot.members.find(row=>row.id===member.id)).toHaveProperty("role","admin");stable(before,after,member.id);
 return {before,paused,result:ctx.snapshot(result),after};
},["POST /organization/update-member-role"]);
