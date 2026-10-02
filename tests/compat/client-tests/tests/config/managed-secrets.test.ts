import {z} from "zod";
import {decodeBase32} from "../two-factor/totp-helper";
import {expect} from "bun:test";
import {createAuthClient} from "better-auth/client";
import {twoFactorClient} from "better-auth/client/plugins";
import {symmetricDecrypt, symmetricEncrypt} from "better-auth/crypto";
import {compatScenario, type ScenarioContext} from "../../support/scenario";
import {authProfilePath, type FixtureProfile} from "../../support/profiles";
import {storedVerification, verificationCount} from "../../support/verification";
const old="managed-old-reader-key-at-least-32-characters",current="compat-test-only-key-not-real-minimum-32chars",legacy="managed-legacy-reader-key-at-least-32-characters";
const keys={keys:new Map([[2,current],[0,old]]),currentVersion:2,legacySecret:legacy};
function client(ctx:ScenarioContext, profile:FixtureProfile, actor="owner") {
  const browser=ctx.actor(actor,profile);
  return {browser,client:createAuthClient({baseURL:`${ctx.baseURL}${authProfilePath(profile)}`,plugins:[twoFactorClient()],fetchOptions:{customFetchImpl:browser.fetch}})};
}
async function request(ctx:ScenarioContext, profile:FixtureProfile, endpoint:string, body:unknown) {
 return ctx.rawRequest({path:`${authProfilePath(profile)}/${endpoint}`,method:"POST",json:body});
}
async function delivery(ctx:ScenarioContext,email:string) {
 const response=await ctx.rawRequest({path:`/__test/managed-secrets/delivery?${new URLSearchParams({email})}`});expect(response.status).toBe(200);
 return (response.body as {otp:string}).otp;
}
async function encryptedRows(ctx:ScenarioContext,email:string) {
 const rows=await storedVerification(ctx,`sign-in-otp-${email}`);expect(rows).toHaveLength(1);
 const row=rows[0]!;const split=row.value.lastIndexOf(":");const ciphertext=row.value.slice(0,split);
 return {rows:rows.map(row=>({...row,value:{token:row.value}})),ciphertext,attempts:row.value.slice(split+1)};
}
compatScenario("managed rotation retains encrypted proofs and factors, retires readers and invalidates old signed cookies",async ctx=>{
 const results=[];
 for(const [write,read,version] of [["managed-old","managed-retained",0],["managed-bare","managed-legacy",null]] as const) {
  const email=ctx.uniqueEmail(write);
  const sent=await request(ctx,write,"email-otp/send-verification-otp",{email,type:"sign-in"});expect(sent.status).toBe(200);
  const otp=await delivery(ctx,email),before=await encryptedRows(ctx,email);
  if(version===null)expect(before.ciphertext).toMatch(/^[0-9a-f]+$/);else expect(before.ciphertext).toMatch(/^\$ba\$0\$[0-9a-f]+$/);
  expect(await symmetricDecrypt({key:keys,data:before.ciphertext})).toBe(otp);expect(before.attempts).toBe("0");
  const rejected=await request(ctx,"managed-retired","sign-in/email-otp",{email,otp});expect(rejected.status).toBe(500);
  expect(await verificationCount(ctx,`sign-in-otp-${email}`)).toBe(0);
  const resent=await request(ctx,write,"email-otp/send-verification-otp",{email,type:"sign-in"});expect(resent.status).toBe(200);
  const replacement=await delivery(ctx,email);
  const signedIn=await request(ctx,read,"sign-in/email-otp",{email,otp:replacement});expect(signedIn.status).toBe(200);
  const replay=await request(ctx,read,"sign-in/email-otp",{email,otp:replacement});expect(replay.status).toBe(400);expect(await verificationCount(ctx,`sign-in-otp-${email}`)).toBe(0);
  results.push({write,read,sent,before:before.rows,rejected,resent,signedIn,replay});
 }
 // Actual Source-encrypted imports exercise the installed envelope parser through
 // the public OTP admission owner, including malformed and authenticated controls.
 for(const [index,version,accepted] of [[0,"-0",true],[1,"\uFEFF0",true],[2,"0suffix",true],[3,"\u00850",false],[4,"9",false],[5,"x",false]] as const) {
  const email=ctx.uniqueEmail(`version-${index}`),otp="654321";
  const encrypted=await symmetricEncrypt({key:{keys:new Map([[0,old]]),currentVersion:0},data:otp});
  const value=encrypted.replace("$ba$0$",`$ba$${version}$`)+":0";
  const seeded=await ctx.rawRequest({path:"/__test/verification-state",method:"POST",json:{action:"seed",identifier:`sign-in-otp-${email}`,value,expiresAt:new Date(Date.now()+300_000).toISOString()}});expect(seeded.status).toBe(200);
  const before=await storedVerification(ctx,`sign-in-otp-${email}`);
  const outcome=await request(ctx,"managed-retained","sign-in/email-otp",{email,otp});expect(outcome.status).toBe(accepted?200:500);
  const after=await storedVerification(ctx,`sign-in-otp-${email}`);expect(after).toEqual([]);
  results.push({version,seeded,before:before.map(row=>({...row,value:{token:row.value}})),outcome,after:after.map(row=>({...row,value:{token:row.value}}))});
 }
 const account=client(ctx,"managed-old");const email=ctx.uniqueEmail("factor"),password="password123";
 const signup=await account.client.signUp.email({email,password,name:"Rotation owner"});expect(signup.error).toBeNull();
 const oldSession=await account.client.getSession();expect(oldSession.data?.user.id).toBe(signup.data!.user.id);
 const enabled=await account.client.twoFactor.enable({password});expect(enabled.error).toBeNull();const enabledValue=z.object({totpURI:z.string(),backupCodes:z.array(z.string())}).parse(enabled.data);expect(enabledValue.backupCodes).toEqual(["backup-one","backup-two"]);
 const oldURI=enabledValue.totpURI;
 // Same actual browser cookie sent to the rotated runtime must fail HMAC;
 // a fresh current-key sign-in gives a genuine pending factor challenge.
 const migrated={browser:account.browser,client:createAuthClient({baseURL:`${ctx.baseURL}${authProfilePath("managed-retained")}`,plugins:[twoFactorClient()],fetchOptions:{customFetchImpl:account.browser.fetch}})};
 const inherited=await migrated.client.getSession();expect(inherited.data).toBeNull();
 const currentLogin=await migrated.client.signIn.email({email,password});expect(currentLogin.data).toMatchObject({twoFactorRedirect:true});
 const backup=await migrated.client.twoFactor.verifyBackupCode({code:"backup-one"});expect(backup.error).toBeNull();
 const saved=await migrated.client.twoFactor.getTotpUri({password});expect(saved.error).toBeNull();expect(saved.data!.totpURI).toBe(oldURI);
 const factorResponse=await ctx.rawRequest({path:"/__test/two-factor-policy",method:"POST",json:{userId:signup.data!.user.id}});expect(factorResponse.status).toBe(200);
 const factor=factorResponse.body as Record<string,unknown>;
 expect(String(factor.secret)).toMatch(/^\$ba\$0\$/);expect(String(factor.backupCodes)).toMatch(/^\$ba\$2\$/);
 expect(await symmetricDecrypt({key:keys,data:String(factor.secret)})).toBe(new TextDecoder().decode(decodeBase32(new URL(oldURI).searchParams.get("secret")!)));
 expect(JSON.parse(String(await symmetricDecrypt({key:keys,data:String(factor.backupCodes)})))).toEqual(["backup-two"]);
 const retired={browser:migrated.browser,client:createAuthClient({baseURL:`${ctx.baseURL}${authProfilePath("managed-retired")}`,plugins:[twoFactorClient()],fetchOptions:{customFetchImpl:migrated.browser.fetch}})};const noSecret=await retired.client.twoFactor.getTotpUri({password});expect(noSecret.error?.status).toBe(500);
 const repeated=await migrated.client.twoFactor.verifyBackupCode({code:"backup-one"});expect(repeated.error?.code).toBe("INVALID_BACKUP_CODE");
 return {results,signup,oldSession,enabled:{...enabled,data:{...enabled.data,totpURI:{token:oldURI}}},inherited,currentLogin,backup,saved:{...saved,data:{...saved.data,totpURI:{token:saved.data!.totpURI}}},factor:{...factor,secret:{token:factor.secret},backupCodes:{token:factor.backupCodes}},noSecret,repeated,userState:await ctx.readUserState({userId:signup.data!.user.id})};
});
