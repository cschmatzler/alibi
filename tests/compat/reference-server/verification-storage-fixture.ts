/** Actual installed internalAdapter policy with real SQLite and secondary values. */
import {betterAuth, type BetterAuthOptions} from "better-auth";
import {getMigrations} from "better-auth/db/migration";
import {runWithTransaction} from "@better-auth/core/context";
import {emailOTP, magicLink, oneTimeToken} from "better-auth/plugins";
import type {Database} from "bun:sqlite";
import {createHash} from "node:crypto";

type Row=Record<string,unknown>;
const hash=(value:string)=>createHash("sha256").update(value).digest("base64url");
export const VERIFICATION_PROFILES=["verification-storage-plain","verification-storage-hashed","verification-storage-custom","verification-storage-ordered","verification-storage-numeric","verification-storage-cache","verification-storage-mixed","verification-storage-no-cleanup","verification-storage-limit"] as const;
export async function createVerificationStorageFixture(database:Database,shared:BetterAuthOptions) {
  const events:Row[]=[],cacheEvents:Row[]=[],deliveries:Row[]=[];
  const cache=new Map<string,{value:string;expiresAt:Date}>();
  let action:Row={},fault:Row={};
  const secondaryStorage={
    async set(key:string,value:string,ttl:number) {
      cacheEvents.push({operation:"set",key,value:JSON.parse(value),ttl});
      if(fault.set)throw new Error("verification cache set rejected");
      cache.set(key,{value,expiresAt:new Date(Date.now()+ttl*1000)});
    },
    async get(key:string) {
      cacheEvents.push({operation:"get",key});const entry=cache.get(key);
      if(!entry)return null;if(entry.expiresAt.getTime()<=Date.now()){cache.delete(key);return null;}return entry.value;
    },
    async delete(key:string) {
      cacheEvents.push({operation:"delete",key});if(fault.delete)throw new Error("verification cache delete rejected");cache.delete(key);
    },
    async getAndDelete(key:string) {
      cacheEvents.push({operation:"consume",key});const entry=cache.get(key);cache.delete(key);
      return entry&&entry.expiresAt.getTime()>Date.now()?entry.value:null;
    },
  };
  const profiles=new Map<string,ReturnType<typeof betterAuth>>();
  const decoded=(raw:string)=>{try{return JSON.parse(raw);}catch{return {raw};}};
  const cacheState=()=>[...cache].sort(([left],[right])=>left<right?-1:left>right?1:0).map(([key,entry])=>({key,value:decoded(entry.value),expiresAt:entry.expiresAt}));
  // The actual shared SQLite connection also exposes transaction-local rows.
  // A cache-only instance deliberately has no verification adapter schema.
  const verificationRows=()=>database.query("SELECT * FROM verification ORDER BY createdAt ASC").all().map(value=>{
    const row={...value as Row};for(const key of ["createdAt","updatedAt","expiresAt"])row[key]=new Date(row[key] as string|number);return row;
  });
  const sqlState=async()=> {
    const context=await profiles.get("verification-storage-plain")!.$context;
    const read=(model:"user"|"account"|"session")=>context.adapter.findMany<Row>({model,limit:5000,sortBy:{field:"createdAt",direction:"asc"}});
    return {users:await read("user"),accounts:await read("account"),sessions:await read("session"),verifications:verificationRows()};
  };
  const before=async(stage:string,data:Row)=> {
    events.push({stage,data:{...data},cache:cacheState(),verifications:verificationRows()});
    if(action[stage]==="cancel")return false;
    if(action[stage]==="throw")throw new Error(`verification ${stage} rejected`);
    if(stage==="create-before"&&action.mutation) {
      const mutation={...action.mutation as Row};
      for(const key of ["createdAt","updatedAt","expiresAt"] as const)if(typeof mutation[key]==="string")mutation[key]=new Date(mutation[key]);
      return {data:mutation};
    }
    if(stage==="update-before"&&action.updateMutation)return {data:action.updateMutation as Row};
  };
  const after=async(stage:string,data:Row|null)=> {
    events.push({stage,data,cache:cacheState(),verifications:verificationRows()});
    if(action[stage]==="throw")throw new Error(`verification ${stage} rejected`);
  };
  for(const name of VERIFICATION_PROFILES) {
    const useCache=name==="verification-storage-cache"||name==="verification-storage-mixed";
    const identifier=name==="verification-storage-custom"?{hash:async(value:string)=>"custom:"+hash(value)}:
      name==="verification-storage-ordered"?{default:"hashed" as const,overrides:{"email-":"plain" as const,"email-verification-":"hashed" as const}}:
      name==="verification-storage-numeric"?{default:"plain" as const,overrides:{"12":"hashed" as const,"1":"plain" as const}}:
      name==="verification-storage-plain"||name==="verification-storage-no-cleanup"||name==="verification-storage-limit"?"plain" as const:"hashed" as const;
    const options={...shared,database,basePath:`/__test/profiles/${name}/api/auth`,
      advanced:{...shared.advanced,database:{...shared.advanced?.database,defaultFindManyLimit:name==="verification-storage-limit"?2:100}},
      verification:{storeIdentifier:identifier,storeInDatabase:name==="verification-storage-mixed",disableCleanup:name==="verification-storage-no-cleanup"},
      ...useCache?{secondaryStorage}:{},session:{...shared.session,storeSessionInDatabase:true},
      databaseHooks:{verification:{create:{before:async data=>before("create-before",data),after:async data=>after("create-after",data)},
        update:{before:async data=>before("update-before",data),after:async data=>after("update-after",data)},
        delete:{before:async data=>before("delete-before",data),after:async data=>after("delete-after",data)}}},
      emailAndPassword:{...shared.emailAndPassword,enabled:true,async sendResetPassword(delivery){deliveries.push({type:"reset",...delivery});}},
      plugins:[emailOTP({async sendVerificationOTP(delivery){deliveries.push({type:"otp",...delivery});}}),
        magicLink({async sendMagicLink(delivery){deliveries.push({type:"magic",...delivery});},generateToken:async email=>"magic-proof:"+hash(email)}),
        oneTimeToken({generateToken:async session=>"ott-proof:"+hash(session.user.email??session.user.id)})],
    } satisfies BetterAuthOptions;
    await(await getMigrations(options)).runMigrations();profiles.set(name,betterAuth(options));
  }
  return {profiles,reset(){cache.clear();events.length=0;cacheEvents.length=0;deliveries.length=0;action={};fault={};},
    async handle(request:Request):Promise<Response|undefined> {
      const url=new URL(request.url);
      if(url.pathname!=="/__test/server-api/verification-storage"||request.method!=="POST")return;
      const body=await request.json() as Row;
      const instance=profiles.get(String(body.profile??"verification-storage-plain"));if(!instance)return Response.json({message:"unknown profile"},{status:400});
      const context=await instance.$context,adapter=context.internalAdapter;
      const identifier=String(body.identifier??"");
      const data=()=>({...body.data as Row,identifier,
        expiresAt:typeof (body.data as Row|undefined)?.expiresAt==="string"?new Date(String((body.data as Row).expiresAt)):new Date(Date.now()+Number(body.expiresInMs??60500))});
      try {
        let result:unknown;
        switch(body.operation) {
          case "configure":action=body.action as Row??{};fault=body.fault as Row??{};events.length=0;cacheEvents.length=0;deliveries.length=0;result={status:true};break;
          case "clear-cache":cache.clear();result={status:true};break;
          case "state":result={...await sqlState(),cache:cacheState(),events,cacheEvents,deliveries};break;
          case "create":result=await adapter.createVerificationValue(data() as Parameters<typeof adapter.createVerificationValue>[0]);break;
          case "find":result=await adapter.findVerificationValue(identifier);break;
          case "consume":result=await adapter.consumeVerificationValue(identifier);break;
          case "delete":await adapter.deleteVerificationByIdentifier(identifier);result={status:true};break;
          case "update":{
            const patch={...body.data as Row};if(typeof patch.expiresAt==="string")patch.expiresAt=new Date(patch.expiresAt);
            result=await adapter.updateVerificationByIdentifier(identifier,patch);break;
          }
          case "reserve":result=await adapter.reserveVerificationValue(data() as Parameters<typeof adapter.reserveVerificationValue>[0]);break;
          case "cache-seed":cache.set(String(body.key),{value:String(body.value),expiresAt:new Date(Date.now()+60500)});result={status:true};break;
          case "seed":result=await context.adapter.create({model:"verification",data:data(),forceAllowId:true});break;
          case "transaction":result=await runWithTransaction(context.adapter,async()=> {
            const created=await adapter.createVerificationValue(data() as Parameters<typeof adapter.createVerificationValue>[0]);
            if(body.rollback)throw new Error("verification transaction rejected");return created;
          });break;
          default:return Response.json({message:"unknown fixture operation"},{status:400});
        }
        return Response.json(result??null);
      } catch(error) {
        return Response.json({message:error instanceof Error?error.message:String(error)},{status:500});
      }
    },
  };
}
