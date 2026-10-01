import { expect } from "bun:test";
import { verifyPassword } from "better-auth/crypto";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import type { FixtureProfile } from "../../support/profiles";

type Row = Record<string, unknown>;
type State = {users: Row[]; accounts: Row[]; sessions: Row[]; verifications: Row[]; events: Row[]};
async function control(ctx: ScenarioContext, json: Row) {
  const result = await ctx.rawRequest({path:"/__test/signup-policy", method:"POST", json});
  expect(result.status).toBe(200);
  return result;
}
async function read(ctx: ScenarioContext, profile: FixtureProfile) {
  const result = await ctx.rawRequest({path:`/__test/signup-policy/state?profile=${profile}`});
  expect(result.status).toBe(200);
  return result.body as State;
}
function hashEvidence(value: unknown) {
  if (typeof value !== "string") return value;
  expect(value).toMatch(/^[a-f0-9]{32}:[a-f0-9]{128}$/);
  const [salt, key] = value.split(":");
  return {token:value, salt:{token:salt,length:salt!.length}, derivedKey:{token:key,length:key!.length}, encoding:"hex-lower"};
}
function observed(state: State) {
  return {...state, accounts:state.accounts.map(row=>({...row,password:hashEvidence(row.password)})),
    events:state.events.map(event=>({...event,...(typeof event.hash==="string"?{hash:hashEvidence(event.hash)}:{})}))};
}
function rows(state: State) { return {users:state.users,accounts:state.accounts,sessions:state.sessions,verifications:state.verifications}; }
async function foreign(ctx: ScenarioContext) {
  const result = await ctx.actor("foreign","signup-standard").client.signUp.email({
    email:ctx.uniqueEmail("foreign-policy"),name:"Unrelated Principal",password:"foreign-password123",
  });
  expect(result.error).toBeNull();
  return {result,state:await ctx.readUserState({userId:result.data!.user.id})};
}

compatScenario("configured signup disablement rejects the registered route without callbacks or principal writes", async ctx=>{
  const other = await foreign(ctx);
  const observations: unknown[] = [];
  for (const profile of ["signup-disabled","signup-password-disabled"] as const) {
    const configured=await control(ctx,{operation:"mode",mode:"normal"});
    const before=await read(ctx,profile);
    const result=await ctx.actor(profile,profile).client.signUp.email({
      email:ctx.uniqueEmail(profile),name:"Disabled Registration",password:"password123",
    });
    expect(result.error).toMatchObject({status:400,code:"EMAIL_PASSWORD_SIGN_UP_DISABLED",message:"Email and password sign up is not enabled"});
    expect(result.data).toBeNull();
    const after=await read(ctx,profile);
    expect(rows(after)).toEqual(rows(before));
    expect(after.events).toEqual([]);
    observations.push({profile,configured,result,before:observed(before),after:observed(after)});
  }
  expect(await ctx.readUserState({userId:other.result.data!.user.id})).toEqual(other.state);
  return {foreign:other,observations};
},["POST /sign-up/email"]);

compatScenario("signup autoSignIn false returns a fresh synthetic duplicate after real hash and existing-user callbacks", async ctx=>{
  const profile="signup-no-auto", other=await foreign(ctx), owner=ctx.actor("owner",profile),email=ctx.uniqueEmail("no-auto-policy");
  const configured=await control(ctx,{operation:"mode",mode:"normal"});
  const signup=await owner.client.signUp.email({email,name:"Physical Principal",password:"original-password123"});
  expect(signup.error).toBeNull(); expect(signup.data?.token).toBeNull();
  const realId=signup.data!.user.id;
  const before=await read(ctx,profile);
  expect(before.sessions.filter(row=>row.userId===realId)).toEqual([]);
  const credential=before.accounts.find(row=>row.userId===realId)!;
  expect(await verifyPassword({hash:String(credential.password),password:"original-password123"})).toBe(true);
  const reset=await control(ctx,{operation:"mode",mode:"normal"});
  const duplicate=await owner.client.signUp.email({email:email.toUpperCase(),name:"Requested Synthetic Principal",password:"duplicate-password123",image:"https://images.example/requested.png"},
    {headers:{"x-test-policy-marker":"actual-duplicate-request"}});
  expect(duplicate.error).toBeNull(); expect(duplicate.data?.token).toBeNull();
  expect(duplicate.data?.user).toMatchObject({name:"Requested Synthetic Principal",email,emailVerified:false,image:"https://images.example/requested.png"});
  expect(duplicate.data?.user.id).not.toBe(realId);
  const after=await read(ctx,profile);
  expect(rows(after)).toEqual(rows(before));
  expect(after.users.some(row=>row.id===duplicate.data?.user.id)).toBe(false);
  expect(after.events.map(row=>row.stage)).toEqual(["hash-enter","hash-result","existing-user","existing-complete"]);
  expect(after.events[2]).toMatchObject({user:{id:realId,name:"Physical Principal",email},request:{method:"POST",path:"/sign-up/email",marker:"actual-duplicate-request",contentType:"application/json"}});
  const session=await owner.client.getSession(); expect(session.data).toBeNull();
  const wrong=await ctx.actor("wrong",profile).client.signIn.email({email,password:"duplicate-password123"});
  expect(wrong.error?.status).toBe(401);
  const signin=await ctx.actor("real",profile).client.signIn.email({email,password:"original-password123"});
  expect(signin.error).toBeNull(); expect(signin.data?.user.id).toBe(realId);
  const signed=await read(ctx,profile);
  expect(signed.users).toEqual(before.users); expect(signed.accounts).toEqual(before.accounts);
  expect(signed.sessions.filter(row=>row.userId===realId)).toHaveLength(1);
  expect(await ctx.readUserState({userId:other.result.data!.user.id})).toEqual(other.state);
  return {foreign:other,configured,signup,before:observed(before),reset,duplicate,after:observed(after),session,wrong,signin,signed:observed(signed)};
},["POST /sign-up/email","POST /sign-in/email"]);
