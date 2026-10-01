import type { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { twoFactor } from "better-auth/plugins";

type Event = {kind:string; serial:number; user?:{id:string;email:string|null;twoFactorEnabled:boolean}; otp?:string; ok?:boolean};
type Delivery = {serial:number;profile:string;userId:string;otp:string;release:()=>void};
export function createTwoFactorDeliveryFixture(base:Parameters<typeof betterAuth>[0],database:Database){
 const events:Event[]=[];const deliveries=new Map<number,Delivery>();const listeners=new Set<()=>void>();let next=0;
 const event=(value:Event)=>{events.push(value);for(const listener of listeners)listener();};
 const wait=async(predicate:()=>boolean)=>{if(predicate())return;await new Promise<void>(resolve=>{const listener=()=>{if(predicate()){listeners.delete(listener);resolve();}};listeners.add(listener);listener();});};
 const profiles=new Map(["default","observe","ignore","throw"].map(mode=>{
  const profile=`two-factor-delivery-${mode}`;
  const handler=(completion:Promise<unknown>)=>{const serial=[...deliveries.values()].filter(value=>value.profile===profile).at(-1)!.serial;event({kind:"register",serial});if(mode==="observe")void completion.then(()=>event({kind:"complete",serial,ok:true}),()=>event({kind:"complete",serial,ok:false}));if(mode==="throw")throw new Error("application OTP background observer rejected");};
  const auth=betterAuth({...base,basePath:`/__test/profiles/${profile}/api/auth`,advanced:{...base.advanced,...(mode==="default"?{}:{backgroundTasks:{handler}})},plugins:[twoFactor({otpOptions:{sendOTP:async({user,otp})=>{
   const serial=++next;let release!:()=>void;const gate=new Promise<void>(resolve=>release=resolve);deliveries.set(serial,{serial,profile,userId:user.id,otp,release});
   const snapshot={id:user.id,email:user.email??null,twoFactorEnabled:!!user.twoFactorEnabled};event({kind:"entered",serial,user:snapshot,otp});await gate;event({kind:"finished",serial,user:snapshot,otp});throw new Error("application OTP delivery rejected");
  }}})]});return [profile,auth] as const;
 }));
 return async(request:Request,url:URL):Promise<Response|undefined>=>{
  for(const [profile,auth]of profiles)if(url.pathname.startsWith(`/__test/profiles/${profile}/api/auth/`))return auth.handler(request);
  if(url.pathname!=="/__test/two-factor-delivery"||request.method!=="POST")return;
  const body=await request.json() as {action:string;profile?:string;serial?:number;kind?:string;userId?:string;identifier?:string};
  if(body.action==="reset"){for(const value of deliveries.values())value.release();await wait(()=>events.filter(value=>value.kind==="finished").length===deliveries.size&&[...deliveries.values()].filter(value=>value.profile.endsWith("observe")).every(value=>events.some(event=>event.kind==="complete"&&event.serial===value.serial)));events.length=0;deliveries.clear();next=0;}
  if(body.action==="wait"){await wait(()=>events.some(value=>value.kind===body.kind&&(body.serial===undefined||value.serial===body.serial)));if(body.kind==="entered"&&body.serial&&deliveries.get(body.serial)?.profile!=="two-factor-delivery-default")await wait(()=>events.some(value=>value.kind==="register"&&value.serial===body.serial));}
  if(body.action==="release"){const delivery=deliveries.get(body.serial!);if(!delivery)throw new Error("actual delivery required");delivery.release();await wait(()=>events.some(value=>value.kind==="finished"&&value.serial===body.serial));if(delivery.profile.endsWith("observe"))await wait(()=>events.some(value=>value.kind==="complete"&&value.serial===body.serial));}
  if(body.action==="expire"){if(typeof body.identifier!=="string")throw new Error("actual identifier required");database.query("UPDATE verification SET expiresAt=? WHERE identifier=?").run(new Date(0).toISOString(),body.identifier);}
  const selected=body.userId?[...deliveries.values()].filter(value=>value.userId===body.userId):[...deliveries.values()];
  const rows=body.userId?database.query("SELECT * FROM verification WHERE identifier LIKE ? OR identifier IN(SELECT '2fa-otp-'||identifier FROM verification WHERE value=? AND identifier LIKE '2fa-%') ORDER BY createdAt,id").all(`2fa-otp-${body.userId}!%`,body.userId):[];
  const challenges=body.userId?database.query("SELECT * FROM verification WHERE value=? AND identifier LIKE '2fa-%' ORDER BY createdAt,id").all(body.userId):[];
  return Response.json({events,challenges,deliveries:selected.map(({release,...value})=>value),rows});
 };
}
