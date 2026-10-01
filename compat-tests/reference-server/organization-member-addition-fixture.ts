/** Privileged application control invoking the unchanged published auth.api.addMember. */
import {betterAuth} from "better-auth";
import {organization} from "better-auth/plugins";
import {APIError} from "better-auth/api";
import type {Database} from "bun:sqlite";
export function organizationMemberAdditionFixture(database:Database,shared:Parameters<typeof betterAuth>[0],origin:string){
 let mode="off",patch:{organizationId?:string;userId?:string}={};const receipts:unknown[]=[];
 let release:(()=>void)|undefined,gate=Promise.resolve();
 function snapshot(){return {
  organizations:database.query("SELECT id,name,slug,logo,metadata FROM organization ORDER BY slug,id").all(),
  members:database.query("SELECT m.id,m.organizationId,m.userId,m.role FROM member m JOIN organization o ON o.id=m.organizationId JOIN user u ON u.id=m.userId ORDER BY o.slug,u.email,m.createdAt,m.rowid").all(),
  users:database.query("SELECT id,email,name FROM user ORDER BY email,id").all(),
  sessions:database.query("SELECT s.id,s.userId,s.activeOrganizationId,s.activeTeamId FROM session s JOIN user u ON u.id=s.userId ORDER BY u.email,s.createdAt,s.id").all(),
  teams:database.query("SELECT id,organizationId,name,memberCount FROM team ORDER BY name,id").all(),
  teamMembers:database.query("SELECT m.id,m.teamId,m.userId FROM teamMember m JOIN team t ON t.id=m.teamId JOIN user u ON u.id=m.userId ORDER BY t.name,u.email,m.id").all(),
 };}
 type Hooks=NonNullable<NonNullable<Parameters<typeof organization>[0]>["organizationHooks"]>;
 type Before=Parameters<NonNullable<Hooks["beforeAddMember"]>>[0];
 type After=Parameters<NonNullable<Hooks["afterAddMember"]>>[0];
 async function note(phase:string,context:Before|After){await Promise.resolve();receipts.push({phase,...structuredClone(context),snapshot:snapshot()});if(mode===`reject-${phase}`)throw new APIError("BAD_REQUEST",{code:"ADDITION_HOOK_REJECTED",message:`Rejected ${phase}`});if(mode===`public500-${phase}`)throw new APIError("INTERNAL_SERVER_ERROR",{code:"PUBLIC_ADDITION_500",message:`Explicit public ${phase} error`});}
 const hooks={async beforeAddMember(context:Before){if(mode==="off")return;await note("before-add",context);if(mode==="pause-before")await gate;
  const ctx=await profiles.get("org-member-addition")!.$context;
  if(mode==="mutate-target")await ctx.adapter.update({model:"user",where:[{field:"id",value:context.user.id}],update:{name:"Stored Addition Target"}});
  if(mode==="sql-before-error")await ctx.adapter.update({model:"user",where:[{field:"id",value:context.user.id}],update:{name:"Attempted Before Name"}});
  if(mode==="patch-role")return {data:{role:"hook-unregistered-role"}};
  if(mode==="patch-empty")return {data:{role:""}};
  if(mode.startsWith("patch-target"))return {data:patch};
 },async afterAddMember(context:After){if(mode==="off")return;await note("after-add",context);if(mode==="sql-after-error"){const ctx=await profiles.get("org-member-addition")!.$context;await ctx.adapter.update({model:"user",where:[{field:"id",value:context.user.id}],update:{name:"Attempted After Name"}});}}};
 const names=["org-member-addition","org-member-addition-no-team","org-member-addition-limit-one","org-member-addition-zero","org-member-addition-none","org-member-addition-team-limit","org-member-addition-team-callback","org-member-addition-team-page-one","org-member-addition-team-page-zero"];
 const profiles=new Map(names.map(name=>[name,betterAuth({...shared,database,baseURL:origin,basePath:`/__test/profiles/${name}/api/auth`,...(name.includes("team-page")?{advanced:{...shared.advanced,database:{...shared.advanced?.database,defaultFindManyLimit:name.endsWith("zero")?0:1}}}:{}),plugins:[organization({organizationHooks:hooks,membershipLimit:name.endsWith("limit-one")?1:name==="org-member-addition-zero"?0:name==="org-member-addition-none"?undefined:100,teams:{enabled:name!=="org-member-addition-no-team",defaultTeam:{enabled:false},...(name==="org-member-addition-team-limit"?{maximumMembersPerTeam:0}:{}),...(name.includes("team-callback")||name.includes("team-page")?{maximumMembersPerTeam:async context=>{receipts.push({phase:"team-limit",context:structuredClone(context),snapshot:snapshot()});if(mode==="reject-team-limit"||mode==="patch-target-reject-team-limit")throw new APIError("FORBIDDEN",{code:"TEAM_LIMIT_POLICY_REJECTED",message:"Actual team-limit rejection"});return 1;}}:{})}})]})]));
 return {profiles,
  async configure(body:Record<string,unknown>){release?.();mode=typeof body.mode==="string"?body.mode:"record";patch={...(typeof body.organizationId==="string"?{organizationId:body.organizationId}:{}),...(typeof body.patchUserId==="string"?{userId:body.patchUserId}:{})};receipts.length=0;gate=new Promise<void>(resolve=>{release=resolve;});
   for(const name of ["addition_guard_member","addition_guard_team","addition_guard_cleanup","addition_guard_user"])database.exec(`DROP TRIGGER IF EXISTS ${name}`);
   database.exec("CREATE TABLE IF NOT EXISTS __test_addition_guard(userId TEXT,organizationId TEXT,teamId TEXT);DELETE FROM __test_addition_guard");
   if(mode.startsWith("sql-")){const user=database.query("SELECT id FROM user WHERE id=?").get(String(body.userId)),org=database.query("SELECT id FROM organization WHERE id=?").get(String(body.organizationId));if(!user||!org)throw new Error("Guard requires actual target user and organization");database.query("INSERT INTO __test_addition_guard(userId,organizationId,teamId) VALUES(?,?,?)").run(String(body.userId),String(body.organizationId),typeof body.teamId==="string"?body.teamId:null);
    if(mode==="sql-member-abort")database.exec("CREATE TRIGGER addition_guard_member BEFORE INSERT ON member WHEN NEW.userId=(SELECT userId FROM __test_addition_guard) BEGIN SELECT RAISE(ABORT,'actual admission member veto'); END");
    if(mode==="sql-team-abort")database.exec("CREATE TRIGGER addition_guard_team BEFORE INSERT ON teamMember WHEN NEW.userId=(SELECT userId FROM __test_addition_guard) BEGIN SELECT RAISE(ABORT,'actual admission team veto'); END");
    if(mode==="sql-cleanup-abort")database.exec("CREATE TRIGGER addition_guard_cleanup BEFORE DELETE ON member WHEN OLD.userId=(SELECT userId FROM __test_addition_guard) BEGIN SELECT RAISE(ABORT,'actual admission cleanup veto'); END");
    if(mode==="sql-before-error"||mode==="sql-after-error")database.exec("CREATE TRIGGER addition_guard_user BEFORE UPDATE ON user WHEN OLD.id=(SELECT userId FROM __test_addition_guard) BEGIN SELECT RAISE(ABORT,'actual admission callback veto'); END");
   }return Response.json({configured:true});},
  release(){release?.();return Response.json({released:true});},
  async state(waitFor:string|null){for(let n=0;waitFor&&n<100&&!receipts.some(value=>(value as {phase:string}).phase===waitFor);n++)await Bun.sleep(10);return Response.json({receipts,snapshot:snapshot()});},
  async server(request:Request){const input=await request.json() as {profile?:string;useHeaders?:boolean;body:Parameters<ReturnType<typeof organization>["endpoints"]["addMember"]>[0]["body"]};const auth=profiles.get(input.profile??"org-member-addition");if(!auth)return new Response(null,{status:404});try{return Response.json(await auth.api.addMember({body:input.body,...(input.useHeaders?{headers:request.headers}:{})}));}catch(error){if(error instanceof APIError){return error.body?Response.json(error.body,{status:error.statusCode}):new Response(null,{status:error.statusCode});}return new Response(null,{status:500});}},
  async seed(body:Record<string,unknown>){const ctx=await profiles.get("org-member-addition")!.$context;const organizationId=String(body.organizationId),userId=String(body.userId);if(!database.query("SELECT id FROM organization WHERE id=?").get(organizationId)||!database.query("SELECT id FROM user WHERE id=?").get(userId))throw new Error("Actual seed owners required");if(body.action==="padding"){for(let n=0;n<Number(body.count);n++){const user=await ctx.internalAdapter.createUser({email:`admission-padding-${n}@example.test`,name:`Admission padding ${n}`,emailVerified:false});await ctx.adapter.create({model:"member",data:{organizationId,userId:user.id,role:"member",createdAt:new Date()}});}}else if(body.action==="detach"){await ctx.adapter.deleteMany({model:"member",where:[{field:"organizationId",value:organizationId},{field:"userId",value:userId}]});}else throw new Error("Unknown actual setup action");return Response.json({seeded:true});},
 };
}
