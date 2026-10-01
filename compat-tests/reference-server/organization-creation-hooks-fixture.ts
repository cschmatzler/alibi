import type { organizationTransportProbe } from "./organization-transport-probe";
/** Configured callbacks are application-owned; HTTP authentication remains pinned. */
import {betterAuth} from "better-auth";
import {organization} from "better-auth/plugins";
import {APIError} from "better-auth/api";
import type {Database} from "bun:sqlite";

export function organizationCreationHooksFixture(database:Database,shared:Parameters<typeof betterAuth>[0],origin:string, transport:ReturnType<typeof organizationTransportProbe>) {
  let plan:Record<string,unknown>={mode:"record"};
  const receipts:unknown[]=[];
  let release:(()=>void)|undefined;
  let gate=Promise.resolve();
  function snapshot() {
    return {
      organizations:database.query('SELECT id,name,slug,logo,metadata FROM organization ORDER BY slug,id').all(),
      members:database.query('SELECT m.id,m.organizationId,m.userId,m.role FROM member m JOIN organization o ON o.id=m.organizationId JOIN user u ON u.id=m.userId ORDER BY o.slug,u.email,m.id').all(),
      teams:database.query('SELECT t.id,t.organizationId,t.name FROM team t JOIN organization o ON o.id=t.organizationId ORDER BY o.slug,t.name,t.id').all(),
      teamMembers:database.query('SELECT m.id,m.teamId,m.userId FROM teamMember m JOIN team t ON t.id=m.teamId JOIN organization o ON o.id=t.organizationId JOIN user u ON u.id=m.userId ORDER BY o.slug,t.name,u.email,m.id').all(),
      sessions:database.query('SELECT s.id,s.userId,s.activeOrganizationId,s.activeTeamId FROM session s JOIN user u ON u.id=s.userId ORDER BY u.email,s.createdAt,s.id').all(),
      users:database.query('SELECT id,email,name FROM user ORDER BY email,id').all(),
    };
  }
  type User={id:string;email:string;name:string};
  async function note(phase:string,data:{user:User;organization?:unknown;member?:unknown;team?:Record<string,unknown>}) {
    await Promise.resolve();
    const {user,...rest}=data;
    receipts.push({phase,user:{id:user.id,email:user.email,name:user.name},...rest,snapshot:snapshot()});
    if(plan.mode===`reject-${phase}`)throw new APIError("BAD_REQUEST",{code:"CREATION_HOOK_REJECTED",message:`Rejected ${phase}`});
  }
  const hooks={
    async beforeCreateOrganization(data:{organization:Record<string,unknown>;user:User}) {
      await note("before-org",data);
      if(plan.mode==="patch")return {data:{id:plan.id,name:"Hooked Organization",slug:`${data.organization.slug}-hooked`,logo:null,metadata:{guard:"hooked"}}};
      if(plan.mode==="clear-metadata")return {data:{metadata:null,logo:null}};
      if(plan.mode==="empty-metadata")return {data:{metadata:{}}};
      if(plan.mode==="absent-metadata")return {data:{name:"Patched Without Metadata"}};
      if(plan.mode==="empty-name")return {data:{name:""}};
    },
    async beforeAddMember(data:{organization:Record<string,unknown>;member:Record<string,unknown>;user:User}) {
      await note("before-member",data);
      if(plan.mode==="patch")return {data:{role:"member"}};
      if(plan.mode==="empty-member")return {data:{role:"",id:"ignored-member-id"}};
      if(plan.mode==="member-authority")return {data:{userId:plan.userId,organizationId:plan.organizationId,role:"member"}};
    },
    async afterAddMember(data:{organization:Record<string,unknown>;member:Record<string,unknown>;user:User}) {
      await note("after-member",data);
      if(plan.mode==="stored-member"){
        const context=await profiles.get("org-creation-hooks")!.$context;
        await context.adapter.update({model:"member",where:[{field:"id",value:String(data.member.id)}],update:{role:"admin"}});
      }
      if(plan.mode==="pause-after-member")await gate;
    },
    async beforeCreateTeam(data:{organization:Record<string,unknown>;team:Record<string,unknown>;user?:User}) {
      if(!data.user)throw new Error("Creation team hook needs the actual user");
      await note("before-team",{...data,user:data.user});
    },
    async afterCreateTeam(data:{organization:Record<string,unknown>;team:Record<string,unknown>;user?:User}) {
      if(!data.user)throw new Error("Creation team hook needs the actual user");
      await note("after-team",{...data,user:data.user,team:{id:data.team.id,organizationId:data.team.organizationId,name:data.team.name}});
    },
    async afterCreateOrganization(data:{organization:Record<string,unknown>;member:Record<string,unknown>;user:User}) {
      await note("after-org",data);
    },
  };
  const profiles=new Map(["org-creation-hooks","org-creation-hooks-no-team","org-creation-hooks-denied"].map(name=>[name,betterAuth({
    ...shared,database,baseURL:origin,basePath:`/__test/profiles/${name}/api/auth`,
    plugins:[transport.plugin,organization({allowUserToCreateOrganization:name!=="org-creation-hooks-denied",teams:{enabled:name!=="org-creation-hooks-no-team"},organizationHooks:hooks})],
  })]));
  return {
    profiles,
    configure(body:Record<string,unknown>) {
      release?.();plan=body;receipts.length=0;
      gate=new Promise<void>(resolve=>{release=resolve;});
      return Response.json({configured:true});
    },
    release(){release?.();return Response.json({released:true});},
    async state(waitFor:string|null){
      for(let attempt=0;waitFor && attempt<100 && !receipts.some(receipt=>(receipt as {phase:string}).phase===waitFor);attempt++)await Bun.sleep(10);
      return Response.json({receipts,snapshot:snapshot()});
    },
    async server(body:Record<string,unknown>){
      const profile=profiles.get(String(body.profile));
      if(!profile)return Response.json({message:"Unknown fixture profile"},{status:400});
      try {return Response.json(await profile.api.createOrganization({body:{name:String(body.name),slug:String(body.slug),userId:String(body.userId),
        ...(body.logo===undefined?{}:{logo:body.logo as string|null}),...(body.metadata===undefined?{}:{metadata:body.metadata as Record<string,unknown>}),
      }}));}catch(error){const result=error as {statusCode?:number;body?:unknown};return Response.json(result.body??null,{status:result.statusCode??500});}
    },
  };
}
