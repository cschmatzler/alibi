/** Immutable real compact-cache configurations and actual callback/state controls. */
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { APIError } from "better-auth/api";
import { anonymous, organization } from "better-auth/plugins";
import { Database } from "bun:sqlite";
import { getMigrations } from "better-auth/db/migration";
export async function sessionCookieCacheFixture(base: BetterAuthOptions, database: Database) {
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  const states = new Map<string, {version:string; failure:boolean; sequence:number; events:unknown[]}>();
  const modes = ["standard","disabled","version","version-api","version-ordinary","zero","nan","fractional","negative","infinite","negative-infinite","date-version"] as const;
  for (const mode of modes) {
    const state = {version:"1", failure:false, sequence:0, events:[] as unknown[]}; states.set(mode,state);
    const callback = async (session: Record<string,unknown>, user: Record<string,unknown>) => {
      await Promise.resolve();
      state.events.push({mode,session:structuredClone(session),user:structuredClone(user)});
      if(state.failure && !user.isAnonymous) {
        if(mode==="version-api")throw new APIError("INTERNAL_SERVER_ERROR",{code:"APPLICATION_CACHE_DENIED",message:"Configured cache version rejected issuance"});
        throw new Error("Configured cache version rejected issuance");
      }
      return state.version;
    };
    const maxAge = mode==="zero"?0:mode==="nan"?NaN:mode==="fractional"?0.5:mode==="negative"?-1:mode==="infinite"?Infinity:mode==="negative-infinite"?-Infinity:300;
    const options: BetterAuthOptions = {...base,basePath:`/__test/profiles/session-cache-${mode}/api/auth`,
      plugins:[organization(),anonymous({generateRandomEmail:()=>`cache-anonymous-${mode}-${++state.sequence}@fixture.test`,generateName:()=>"Cache Anonymous",onLinkAccount:async ({anonymousUser,newUser})=>{await Promise.resolve();state.events.push({mode,link:{anonymousUser,newUser}});}})],
      session:{additionalFields:{hidden:{type:"string",defaultValue:"cache-server-secret",returned:false},label:{type:"string",defaultValue:"cache-public-label"}},cookieCache:{enabled:mode!=="disabled",strategy:"compact",maxAge,version:mode.startsWith("version")?callback:mode==="date-version"?"2026-10-01T00:00:00.000Z":"1"}},
    };
    await(await getMigrations(options)).runMigrations();
    const path=options.basePath!;profiles.set(path,betterAuth(options));
  }
  return {profiles,async handle(request:Request){
    if(new URL(request.url).pathname!=="/__test/session-cookie-cache/control")return null;
    const body=await request.json() as {mode:string;action:string;version?:string;failure?:boolean;userId?:string;token?:string;name?:string;email?:string};
    const state=states.get(body.mode),auth=profiles.get(`/__test/profiles/session-cache-${body.mode}/api/auth`);
    if(!state||!auth)return Response.json({error:"Unknown cache profile"},{status:400});
    const context=await auth.$context;
    if(body.action==="reset"){state.version="1";state.failure=false;state.sequence=0;state.events.length=0;}
    else if(body.action==="policy"){if(body.version!==undefined)state.version=body.version;if(body.failure!==undefined)state.failure=body.failure;}
    else if(body.action==="rename"){if(!body.userId||typeof body.name!=="string")return Response.json({error:"Invalid rename"},{status:400});await context.internalAdapter.updateUser(body.userId,{name:body.name});}
    else if(body.action==="revoke"){if(!body.token)return Response.json({error:"Invalid token"},{status:400});await context.internalAdapter.deleteSession(body.token);}
    else if(body.action==="lookup"){if(typeof body.email!=="string")return Response.json({error:"Invalid lookup"},{status:400});return Response.json({user:await context.adapter.findOne({model:"user",where:[{field:"email",value:body.email}]})});}
    else if(body.action!=="state")return Response.json({error:"Unknown action"},{status:400});
    return Response.json({events:state.events});
  }};
}
