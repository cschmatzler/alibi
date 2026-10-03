import {betterAuth} from 'better-auth';
import {APIError} from 'better-auth/api';
import {getMigrations} from 'better-auth/db/migration';
import {Database} from 'bun:sqlite';
import assert from 'node:assert/strict';
import {writeFileSync} from 'node:fs';
const secret='request-provider-fixture-secret-at-least-32';
const database=new Database('/tmp/close178-evidence/source.sqlite',{create:true});
const calls=[], http=[], callbacks=[]; let release; let arrived=0;
const barrier=new Promise(r=>release=r);
const server=Bun.serve({hostname:'127.0.0.1',port:0,async fetch(req){
 const url=new URL(req.url);
 if(url.pathname==='/oauth/token') {const form=Object.fromEntries(await req.formData());http.push({tokenForm:form});return Response.json({access_token:form.code,token_type:'Bearer',scope:'read_user'});}
 if(url.pathname==='/api/v4/user') {const code=req.headers.get('authorization').slice(7);const profile={id:code,email:`${code}@example.test`,name:code,state:'active',locked:false,email_verified:false};http.push({profile});return Response.json(profile);}
 return new Response('',{status:404});
}});
let factoryCalls=0; const factoryArgs=[];
const options={secret,database,baseURL:{allowedHosts:['*.example.test'],protocol:'https'},rateLimit:{enabled:false},
 socialProviders:{gitlab:async(...args)=>{factoryCalls++;factoryArgs.push(args.length);return {clientId:'fixture-client',clientSecret:'fixture-secret',issuer:server.url.origin}}},
 account:{accountLinking:{trustedProviders:async(req)=>{if(!req){calls.push('init');return ['init-only'];}calls.push(`${new URL(req.url).pathname}:${req.headers.get('x-trust')}`);
  if(req.headers.has('x-overlap')){if(++arrived===2)release();await barrier;}
  if(req.headers.get('x-trust')==='error')throw new Error('private-provider-policy-secret');
  if(req.headers.get('x-trust')==='api-error')throw new APIError('FORBIDDEN',{message:'private-provider-api-error'});
  return req.headers.get('x-trust')==='allow'?['gitlab','']:[];
 }}}};
await(await getMigrations(options)).runMigrations();
const auth=betterAuth(options);const ctx=await auth.$context;
assert.deepEqual(ctx.trustedProviders,['init-only']);assert.equal(factoryCalls,1);assert.deepEqual(factoryArgs,[0]);
const users={}; for(const code of ['deny','allow','parallel-deny','parallel-allow','actor','foreign'])users[code]=await ctx.internalAdapter.createUser({email:`${code}@example.test`,name:code,emailVerified:true});
function request(method,path,host,trust,body,cookie,overlap=false){const headers={'content-type':'application/json',origin:`https://${host}`,'x-trust':trust};if(cookie)headers.cookie=cookie;if(overlap)headers['x-overlap']='yes';return new Request(`https://${host}/api/auth${path}`,{method,headers,...method==='GET'?{}:{body:JSON.stringify(body)}});}
async function start(code,trust,cookie){const response=await auth.handler(request('POST',cookie?'/link-social':'/sign-in/social','a.example.test',trust,{provider:'gitlab',callbackURL:'https://a.example.test/done',errorCallbackURL:'https://a.example.test/failed',disableRedirect:true},cookie));const body=await response.json();assert.equal(response.status,200,JSON.stringify(body));const url=new URL(body.url);assert.equal(url.searchParams.get('scope'),'read_user');assert.equal(url.searchParams.get('redirect_uri'),'https://a.example.test/api/auth/callback/gitlab');return {state:url.searchParams.get('state'),cookie:response.headers.getSetCookie().map(v=>v.split(';')[0]).join('; '),body};}
async function callback(code,host,trust,flow,overlap=false){return auth.handler(request('GET',`/callback/gitlab?state=${flow.state}&code=${code}`,host,trust,undefined,flow.cookie,overlap));}
for(const [code,st,ct,allow]of[['deny','allow','deny',false],['allow','deny','allow',true]]){const flow=await start(code,st);const response=await callback(code,'a.example.test',ct,flow);assert.equal(response.status,302);assert.equal(response.headers.get('location'),allow?'https://a.example.test/done':'https://a.example.test/failed?error=account_not_linked');assert.equal(database.query('SELECT COUNT(*) n FROM account WHERE "accountId"=?').get(code).n,+allow);const replay=await callback(code,'a.example.test',ct,flow);assert(!replay.headers.get('location').endsWith('/done'));callbacks.push({case:code,start:flow.body,callbackLocation:response.headers.get('location'),cookies:response.headers.getSetCookie(),replay:replay.headers.get('location')});}
const df=await start('parallel-deny','allow'), af=await start('parallel-allow','deny');
const [denied,allowed]=await Promise.all([callback('parallel-deny','a.example.test','deny',df,true),callback('parallel-allow','b.example.test','allow',af,true)]);
assert.equal(denied.headers.get('location'),'https://a.example.test/failed?error=account_not_linked');assert.equal(allowed.headers.get('location'),'https://a.example.test/done');
const foreign=await ctx.internalAdapter.createAccount({userId:users.foreign.id,accountId:'actor',providerId:'gitlab',accessToken:'foreign-token',scope:'foreign-scope'});
const foreignBefore=database.query('SELECT id,userId,accountId,accessToken,scope FROM account WHERE id=?').get(foreign.id);
const session=await ctx.internalAdapter.createSession(users.actor.id);
const {signCookieValue}=await import('./node_modules/better-call/dist/crypto.mjs');
const cookie=`${ctx.authCookies.sessionToken.name}=${await signCookieValue(session.token,secret)}`;
const flow=await start('actor','allow',cookie);flow.cookie+=`; ${cookie}`;
const foreignResponse=await callback('actor','a.example.test','allow',flow);
assert.equal(foreignResponse.headers.get('location'),'https://a.example.test/failed?error=account_already_linked_to_different_user');
const unchanged=database.query('SELECT * FROM account WHERE id=?').get(foreign.id);assert.equal(unchanged.userId,users.foreign.id);assert.equal(unchanged.accessToken,'foreign-token');assert.equal(unchanged.scope,'foreign-scope');
callbacks.push({case:'foreign',start:flow.body,callbackLocation:foreignResponse.headers.get('location'),physicalBefore:foreignBefore,physicalAfter:database.query('SELECT id,userId,accountId,accessToken,scope FROM account WHERE id=?').get(foreign.id)});
let error;try{await auth.handler(request('POST','/sign-in/social','a.example.test','error',{provider:'gitlab'}));}catch(e){error=e.message;}
assert.equal(error,'private-provider-policy-secret');let apiError;try{await auth.handler(request('POST','/sign-in/social','a.example.test','api-error',{provider:'gitlab'}));}catch(e){apiError={status:e.statusCode,message:e.body.message};}assert.deepEqual(apiError,{status:403,message:'private-provider-api-error'});assert.deepEqual(ctx.trustedProviders,['init-only']);assert.equal(factoryCalls,1);
// Request-unavailable direct API keeps initialized linking trust; no request callback.
const before=calls.length;let directError;try{await auth.api.getSession({headers:new Headers()});}catch(e){directError=e.body.message;}assert(directError.startsWith('Dynamic baseURL could not be resolved'));assert.equal(calls.length,before);
const directCalls=[];const directAuth=betterAuth({secret,database,baseURL:'https://a.example.test',account:{accountLinking:{trustedProviders:async r=>{directCalls.push(r===undefined?'init':'request');return ['init-only'];}}}});await directAuth.$context;await directAuth.api.getSession({headers:new Headers()});assert.deepEqual(directCalls,['init']);
let initError;try{await betterAuth({secret,database,baseURL:'https://a.example.test',account:{accountLinking:{trustedProviders:async r=>{assert.equal(r,undefined);throw new Error('initial trust failure');}}}}).$context;}catch(e){initError=e.message;}assert.equal(initError,'initial trust failure');
const physical={users:database.query('SELECT COUNT(*) n FROM user').get().n,accounts:database.query('SELECT COUNT(*) n FROM account').get().n,sessions:database.query('SELECT COUNT(*) n FROM session').get().n};assert.deepEqual(physical,{users:6,accounts:3,sessions:3});
writeFileSync('/tmp/close178-evidence/source.json',JSON.stringify({callbacks,policyCalls:calls,providerHTTP:http,physical,factoryCalls,factoryArgs,initError,apiError,errorStage:'handler promise rejects before router; no response or cookies',directAPI:{staticCalls:directCalls,dynamicMissingSource:directError}},null,2));
server.stop(true);database.close();console.log('Published 1.7.6 request trust, callbacks, concurrency, foreign ownership, init factory, error and direct API receipts passed');
