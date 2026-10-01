/** Application-owned callbacks over the unchanged pinned removal handler. */
import {betterAuth} from "better-auth";
import {organization} from "better-auth/plugins";
import {APIError} from "better-auth/api";
import type {Database} from "bun:sqlite";
export function organizationMemberRemovalHooksFixture(database:Database,shared:Parameters<typeof betterAuth>[0],origin:string) {
 let mode="record",release:(()=>void)|undefined,gate=Promise.resolve();const receipts:unknown[]=[];
 function snapshot(){return {
  organizations:database.query("SELECT id,name,slug,logo,metadata FROM organization ORDER BY slug,id").all(),
  members:database.query("SELECT m.id,m.organizationId,m.userId,m.role FROM member m JOIN organization o ON o.id=m.organizationId JOIN user u ON u.id=m.userId ORDER BY o.slug,u.email,m.id").all(),
  users:database.query("SELECT id,email,name FROM user ORDER BY email,id").all(),
  sessions:database.query("SELECT s.id,s.userId,s.activeOrganizationId,s.activeTeamId FROM session s JOIN user u ON u.id=s.userId ORDER BY u.email,s.createdAt,s.id").all(),
  teams:database.query("SELECT id,organizationId,name,memberCount FROM team ORDER BY name,id").all(),
  teamMembers:database.query("SELECT m.id,m.teamId,m.userId FROM teamMember m JOIN team t ON t.id=m.teamId JOIN user u ON u.id=m.userId ORDER BY t.name,u.email,m.id").all(),
 };}
 type Hooks=NonNullable<NonNullable<Parameters<typeof organization>[0]>["organizationHooks"]>;
 type Context=Parameters<NonNullable<Hooks["beforeRemoveMember"]>>[0];
 async function note(phase:string,context:Context){await Promise.resolve();receipts.push({phase,...structuredClone(context),snapshot:snapshot()});if(mode===`reject-${phase}`)throw new APIError("BAD_REQUEST",{code:"MEMBER_REMOVAL_HOOK_REJECTED",message:`Rejected ${phase}`});}
 const hooks={async beforeRemoveMember(context:Context){await note("before-remove",context);if(mode==="pause-before")await gate;const ctx=await profiles.get("org-member-removal-hooks")!.$context;
  if(mode==="delete-row")await ctx.adapter.delete({model:"member",where:[{field:"id",value:context.member.id}]});
  if(mode==="mutate-target"){await ctx.adapter.update({model:"user",where:[{field:"id",value:context.user.id}],update:{name:"Stored Removal Target"}});await ctx.adapter.update({model:"member",where:[{field:"id",value:context.member.id}],update:{role:"stored-independent-role"}});}
 },async afterRemoveMember(context:Context){await note("after-remove",context);}};
 const profiles=new Map(["org-member-removal-hooks","org-member-removal-hooks-teams-disabled","org-member-removal-hooks-page-one","org-member-removal-hooks-team-page-one"].map(name=>[name,betterAuth({...shared,database,baseURL:origin,basePath:`/__test/profiles/${name}/api/auth`,...(name.endsWith("team-page-one")?{advanced:{...shared.advanced,database:{...shared.advanced?.database,defaultFindManyLimit:1}}}:{}),plugins:[organization({organizationHooks:hooks,membershipLimit:name==="org-member-removal-hooks-page-one"?1:100,teams:{enabled:!name.endsWith("teams-disabled"),defaultTeam:{enabled:false}}})]})] as const));
 return {profiles,
  configure(body:Record<string,unknown>){release?.();mode=typeof body.mode==="string"?body.mode:"record";receipts.length=0;gate=new Promise<void>(resolve=>release=resolve);return Response.json({configured:true});},
  release(){release?.();return Response.json({released:true});},
  async state(waitFor:string|null){for(let attempt=0;waitFor&&attempt<100&&!receipts.some(receipt=>(receipt as {phase:string}).phase===waitFor);attempt++)await Bun.sleep(10);return Response.json({receipts,snapshot:snapshot()});},
  async server(request:Request){const body=await request.json() as {memberIdOrEmail:string;organizationId?:string};try{return Response.json(await profiles.get("org-member-removal-hooks")!.api.removeMember({headers:request.headers,body}));}catch(error){if(error instanceof APIError)return Response.json(error.body,{status:error.statusCode,headers:error.headers});throw error;}},
 };
}
