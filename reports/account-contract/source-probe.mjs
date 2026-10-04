import assert from 'node:assert/strict';
import { Database } from 'bun:sqlite';
const repo=process.env.ACCOUNT_CONTRACT_REPO ?? process.cwd();
const root=repo+'/tests/compat/reference-server/node_modules/better-auth/dist';
const {betterAuth}=await import(root+'/index.mjs');
const {getMigrations}=await import(root+'/db/get-migration.mjs');
const {symmetricEncodeJWT,symmetricDecodeJWT}=await import(root+'/crypto/jwt.mjs');
const {getAccountCookie}=await import(root+'/cookies/session-store.mjs');
const vectors=await Bun.file(repo+'/tests/fixtures/oauth/account-cookie-vectors.json').json();
const decoded={};
for (const name of ['valid','noKid','wrongSalt','wrongSecret','expired','gcm','jws']) {
 decoded[name]=await symmetricDecodeJWT(vectors[name],vectors.secret,'better-auth-account');
 console.log(JSON.stringify({vector:name,decoded:decoded[name]}));
}
assert.equal(decoded.valid.userId,vectors.payload.userId);
assert.ok(decoded.valid.iat); assert.ok(decoded.valid.exp); assert.ok(decoded.valid.jti);
assert.deepEqual(JSON.parse(JSON.stringify(await getAccountCookie({context:{authCookies:{accountData:{name:'better-auth.account_data'}},secretConfig:vectors.secret},getCookie:()=>vectors.valid}))),decoded.valid);
const secret='source-account-contract-probe-secret-long-enough';
const database=new Database(':memory:');
const options={database,secret,baseURL:'http://localhost:3000',emailAndPassword:{enabled:true},account:{storeAccountCookie:true},socialProviders:{google:{clientId:'probe',clientSecret:'probe'}}};
await (await getMigrations(options)).runMigrations();
const auth=betterAuth(options); const ctx=await auth.$context;
const refreshes=[];
const provider=ctx.socialProviders.find(p=>p.id==='google');
provider.refreshAccessToken=async(token)=>{refreshes.push(token);assert.equal(token,'old-refresh');return {accessToken:'rotated-access',refreshToken:'rotated-refresh',accessTokenExpiresAt:new Date(Date.now()+1800000),refreshTokenExpiresAt:new Date(Date.now()+86400000)}};
const request=(path,cookie,body)=>auth.handler(new Request('http://localhost:3000/api/auth'+path,{method:'POST',headers:{'content-type':'application/json',origin:'http://localhost:3000',...(cookie?{cookie}:{})},body:JSON.stringify(body)}));
async function signup(email){const r=await request('/sign-up/email',null,{name:'Owner',email,password:'Password123!'});assert.equal(r.status,200);return {body:await r.json(),cookie:r.headers.getSetCookie().map(s=>s.split(';')[0]).join('; ')}}
for(const path of ['/refresh-token','/get-access-token']) {
 const owner=await signup(path.slice(1)+'@example.invalid');
 const foreign=await signup('foreign-'+path.slice(1)+'@example.invalid');
 const account=await ctx.internalAdapter.createAccount({userId:owner.body.user.id,providerId:'google',accountId:path,accessToken:'old-access',refreshToken:'old-refresh',accessTokenExpiresAt:new Date(Date.now()-10000),scope:'email,profile'});
 const cookie=await symmetricEncodeJWT(account,secret,'better-auth-account',300);
 const before=database.query('select * from account where id = ?').get(account.id);
 const callsBefore=refreshes.length;
 const deny=await request(path,foreign.cookie+'; better-auth.account_data='+cookie,{useAccountCookie:true});
 const denial=await deny.json();assert.equal(refreshes.length,callsBefore);assert.equal(deny.status,400);assert.equal(denial.code,'ACCOUNT_NOT_FOUND');assert.deepEqual(database.query('select * from account where id = ?').get(account.id),before);
 const accepted=await request(path,owner.cookie+'; better-auth.account_data='+cookie,{useAccountCookie:true});
 const output=await accepted.json();assert.equal(accepted.status,200);assert.equal(output.accessToken,'rotated-access');
 const after=database.query('select * from account where id = ?').get(account.id);assert.equal(after.refreshToken,'rotated-refresh');assert.equal(after.accessToken,'rotated-access');assert.equal(after.userId,owner.body.user.id);
 console.log(JSON.stringify({path,account,before,denied:{status:deny.status,body:denial},accepted:{status:accepted.status,body:output,cookies:accepted.headers.getSetCookie()},after,refreshes:[...refreshes]}));
}
database.close();
