import { expect } from "bun:test";
import { createHash } from "node:crypto";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { authProfilePath } from "../../support/profiles";
const secret="local-fixture-dedicated-oauth-proxy-secret-32",path=authProfilePath("oauth-proxy");
type Rows={users:Record<string,unknown>[];accounts:Record<string,unknown>[];sessions:Record<string,unknown>[];verification:Record<string,unknown>[]};
type Receipt={stage:string;query?:Record<string,string>;body?:Record<string,string>;authorization?:string};
type State={preview:Rows;production:Rows;receipts:Receipt[]};
async function state(ctx:ScenarioContext):Promise<State>{const r=await ctx.rawRequest({path:"/__test/oauth-proxy/state"});expect(r.status).toBe(200);return r.body as State;}
function observations(s:State){return {...s,receipts:s.receipts.map(r=>({...r,...(r.body?.code_verifier?{body:{...r.body,code_verifier:{token:r.body.code_verifier,length:r.body.code_verifier.length}}}:{})}))};}
async function response(r:Response){const text=await r.text();let body:unknown=text;if(text){try{body=JSON.parse(text);}catch{}}return {status:r.status,location:r.headers.get("location"),body};}
async function issue(ctx:ScenarioContext,actor:ReturnType<ScenarioContext["actor"]>,link=false){
 const body={provider:"gitlab",callbackURL:`${ctx.baseURL}/proxy-done?application=kept`,newUserCallbackURL:`${ctx.baseURL}/proxy-new`,errorCallbackURL:`${ctx.baseURL}/proxy-error`,disableRedirect:true,additionalData:{serverContext:{anonymousUserId:"forged-owner"},application:{kept:true}}};
 const started=link?await actor.client.linkSocial(body):await actor.client.signIn.social(body);expect(started.error).toBeNull();
 const authorization=new URL(started.data!.url!);expect(authorization.searchParams.get("redirect_uri")).toBe(`${ctx.baseURL.replace("localhost","127.0.0.1")}${path}/callback/gitlab`);
 const raw=authorization.searchParams.get("state")!;const packageBytes=await symmetricDecrypt({key:secret,data:raw});const pack=JSON.parse(packageBytes);expect(JSON.stringify(pack)).toBe(packageBytes);expect(pack.isOAuthProxy).toBe(true);
 const stateBytes=await symmetricDecrypt({key:secret,data:pack.stateCookie});const original=JSON.parse(stateBytes);expect(JSON.stringify(original)).toBe(stateBytes);expect(original.oauthState).toBe(pack.state);expect(original.serverContext).toBeUndefined();expect(original.application).toEqual({kept:true});
 const expiresAt=new Date(original.expiresAt).toISOString();expect(new Date(expiresAt).getTime()).toBe(original.expiresAt);
 const retained={...original,oauthState:{state:original.oauthState},codeVerifier:{token:original.codeVerifier},expiresAt};
 expect(JSON.stringify({...retained,oauthState:retained.oauthState.state,codeVerifier:retained.codeVerifier.token,expiresAt:new Date(retained.expiresAt).getTime()})).toBe(stateBytes);
 const issuedState={...pack,stateCookie:{token:pack.stateCookie,payload:retained}};
 expect(JSON.stringify({...issuedState,stateCookie:issuedState.stateCookie.token})).toBe(packageBytes);
 return {started,authorization,state:pack.state,verifier:original.codeVerifier,issuedState};
}
async function forward(ctx:ScenarioContext,actor:ReturnType<ScenarioContext["actor"]>,issued:Awaited<ReturnType<typeof issue>>){
 const approved=await response(await actor.fetch(issued.authorization,{redirect:"manual"}));expect(approved.status).toBe(302);
 const forwarded=await response(await actor.fetch(approved.location!,{redirect:"manual",credentials:"omit"}));expect(forwarded.status).toBe(302);
 const bridge=new URL(forwarded.location!);expect(bridge.origin).toBe(ctx.baseURL);expect(bridge.pathname).toBe(`${path}/callback/gitlab/oauth-proxy`);
 const token=bridge.searchParams.get("profile")!;const payload=JSON.parse(await symmetricDecrypt({key:secret,data:token}));expect(payload.state).toBe(issued.state);expect(payload.account.providerId).toBe("gitlab");expect(payload.userInfo.email).toBe("proxy-owner@fixture.test");
 const stored=await state(ctx),receipt=stored.receipts.find(r=>r.stage==="token")!;expect(receipt.body!.code_verifier).toBe(issued.verifier);expect(issued.verifier).toHaveLength(128);expect(createHash("sha256").update(issued.verifier).digest("base64url")).toBe(issued.authorization.searchParams.get("code_challenge")!);
 return {approved,forwarded,bridge,atom:{token,payload}};
}
const comparison={oauthProxyProfileSecret:secret};
compatScenario("OAuth proxy exchanges on production then consumes preview state for only the provider owner",async ctx=>{
 const owner=ctx.actor("proxy-owner","oauth-proxy"),foreign=ctx.actor("proxy-foreign","oauth-proxy");
 const seeded=await foreign.client.signUp.email({email:ctx.uniqueEmail("proxy-foreign"),name:"Foreign",password:"password123"});expect(seeded.error).toBeNull();
 const before=await state(ctx),issued=await issue(ctx,owner),saved=await state(ctx);expect(saved.preview.verification).toHaveLength(1);
 const forwarded=await forward(ctx,owner,issued),production=await state(ctx);expect(production.production).toEqual(before.production);expect(production.preview).toEqual(saved.preview);
 const completed=await response(await owner.fetch(forwarded.bridge,{redirect:"manual"}));expect(completed.status).toBe(302);expect(completed.location).toBe(`${ctx.baseURL}/proxy-new`);
 const current=await owner.client.getSession();expect(current.data!.user.email).toBe("proxy-owner@fixture.test");
 const after=await state(ctx);expect(after.preview.verification).toHaveLength(0);expect(after.preview.users).toHaveLength(2);expect(after.preview.accounts).toHaveLength(2);expect(after.preview.sessions).toHaveLength(2);
 const id=current.data!.user.id;expect(after.preview.accounts.find(r=>r.providerId==="gitlab")!.userId).toBe(id);expect(after.preview.sessions.find(r=>r.userId===id)!.token).toBe(current.data!.session.token);
 expect(after.preview.users.find(r=>r.id===seeded.data!.user.id)).toEqual(before.preview.users[0]);expect(after.preview.sessions.filter(r=>r.userId===seeded.data!.user.id)).toEqual(before.preview.sessions);
 const replay=await response(await owner.fetch(forwarded.bridge,{redirect:"manual"}));expect(new URL(replay.location!).searchParams.get("error")).toBe("state_mismatch");expect((await state(ctx)).preview).toEqual(after.preview);
 const codeReplay=await response(await owner.fetch(forwarded.approved.location!,{redirect:"manual",credentials:"omit"}));expect(new URL(codeReplay.location!).searchParams.get("error")).toBe("invalid_code");const final=await state(ctx);expect(final.preview).toEqual(after.preview);expect(final.production).toEqual(before.production);
 return {before:observations(before),started:issued.started,issuedState:issued.issuedState,issued:observations(saved),approved:forwarded.approved,forwarded:forwarded.forwarded,oauthProxyProfile:forwarded.atom,afterProduction:observations(production),completed,current,after:observations(after),replay,codeReplay,final:observations(final)};
},["social_sign_in","oauth_proxy"],undefined,comparison);
compatScenario("OAuth proxy checks origin provider authenticated age and state before writes and retains legacy completion",async ctx=>{
 const actor=ctx.actor("proxy-controls","oauth-proxy"),issued=await issue(ctx,actor),forwarded=await forward(ctx,actor,issued),before=await state(ctx);const controls=[];
 for(const mode of ["origin","provider","expired","future","unknown-state","bad-payload","bad-cipher"]){
  const url=new URL(forwarded.bridge),payload=structuredClone(forwarded.atom.payload);
  if(mode==="origin")url.searchParams.set("callbackURL","https://foreign.fixture.test/leak");if(mode==="provider")url.pathname=`${path}/callback/google/oauth-proxy`;
  if(mode==="expired")payload.timestamp=Date.now()-61000;if(mode==="future")payload.timestamp=Date.now()+11000;if(mode==="unknown-state")payload.state="unknown-state";
  const token=mode==="bad-cipher"?"wrong":await symmetricEncrypt({key:secret,data:JSON.stringify(mode==="bad-payload"?{}:payload)});url.searchParams.set("profile",token);
  const result=await response(await actor.fetch(url,{redirect:"manual"}));const expected=({provider:"provider_mismatch",expired:"payload_expired",future:"payload_expired","unknown-state":"state_mismatch","bad-payload":"invalid_payload","bad-cipher":"invalid_profile"} as Record<string,string>)[mode];
  if(mode==="origin"){expect(result.status).toBe(403);expect(result.location).toBeNull();}else{expect(result.status).toBe(302);expect(new URL(result.location!).searchParams.get("error")).toBe(expected!);}
  const after=await state(ctx);expect(after.preview).toEqual(before.preview);expect(after.production).toEqual(before.production);
  controls.push({mode,url:url.href,result,oauthProxyProfile:mode==="bad-cipher"?null:{token,payload:mode==="bad-payload"?{}:payload},after:observations(after)});
 }
 const legacy=new URL(forwarded.bridge);legacy.pathname=`${path}/oauth-proxy-callback`;
 const completed=await response(await actor.fetch(legacy,{redirect:"manual"}));expect(completed.status).toBe(302);expect(completed.location).toBe(`${ctx.baseURL}/proxy-new`);const current=await actor.client.getSession();expect(current.data!.user.email).toBe("proxy-owner@fixture.test");const final=await state(ctx);expect(final.preview.verification).toHaveLength(0);expect(final.preview.sessions).toHaveLength(1);
 return {started:issued.started,issuedState:issued.issuedState,approved:forwarded.approved,forwarded:forwarded.forwarded,oauthProxyProfile:forwarded.atom,before:observations(before),controls,legacyURL:legacy.href,completed,current,final:observations(final)};
},["social_sign_in","oauth_proxy","oauth_proxy_legacy"],undefined,comparison);
compatScenario("OAuth proxy linking follows the saved authenticated owner without creating any session",async ctx=>{
 const owner=ctx.actor("proxy-link-owner","oauth-proxy"),foreign=ctx.actor("proxy-link-foreign","oauth-proxy");
 const signed=await owner.client.signUp.email({email:"proxy-owner@fixture.test",name:"Existing Owner",password:"password123"}),other=await foreign.client.signUp.email({email:ctx.uniqueEmail("proxy-link-foreign"),name:"Foreign",password:"password123"});expect(signed.error).toBeNull();expect(other.error).toBeNull();
 const before=await state(ctx),issued=await issue(ctx,owner,true),saved=await state(ctx),forwarded=await forward(ctx,owner,issued);
 const completed=await response(await owner.fetch(forwarded.bridge,{redirect:"manual",credentials:"omit"}));expect(completed.status).toBe(302);expect(completed.location).toBe(`${ctx.baseURL}/proxy-done?application=kept`);
 const after=await state(ctx);expect(after.production).toEqual(before.production);expect(after.preview.users).toEqual(before.preview.users);expect(after.preview.sessions).toEqual(before.preview.sessions);expect(after.preview.accounts).toHaveLength(3);expect(after.preview.accounts.find(r=>r.providerId==="gitlab")!.userId).toBe(signed.data!.user.id);expect(after.preview.verification).toHaveLength(0);
 const current=await owner.client.getSession();expect(current.data!.session.token).toBe(signed.data!.token!);const foreignCurrent=await foreign.client.getSession();expect(foreignCurrent.data!.session.token).toBe(other.data!.token!);
 const replay=await response(await foreign.fetch(forwarded.bridge,{redirect:"manual"}));expect(new URL(replay.location!).searchParams.get("error")).toBe("state_mismatch");expect((await state(ctx)).preview).toEqual(after.preview);
 const denied=[];
 for(const mode of ["different-email","foreign-account"]){
  if(mode==="foreign-account"){const configured=await ctx.rawRequest({path:"/__test/oauth-proxy/profile",method:"POST",json:{id:777,email:other.data!.user.email,email_verified:true,name:"Proxy Owner",avatar_url:"https://assets.fixture.test/avatar.png",state:"active",locked:false}});expect(configured.status).toBe(200);}
  const attempt=await issue(ctx,foreign,true),pending=await state(ctx);const approval=await response(await foreign.fetch(attempt.authorization,{redirect:"manual"}));const transfer=await response(await foreign.fetch(approval.location!,{redirect:"manual",credentials:"omit"}));const bridge=new URL(transfer.location!);const token=bridge.searchParams.get("profile")!;const payload=JSON.parse(await symmetricDecrypt({key:secret,data:token}));expect(payload.state).toBe(attempt.state);
  const rejection=await response(await foreign.fetch(bridge,{redirect:"manual",credentials:"omit"}));expect(new URL(rejection.location!).searchParams.get("error")).toBe(mode==="different-email"?"email_does_not_match":"account_already_linked_to_different_user");
  const stored=await state(ctx);expect(stored.preview.users).toEqual(after.preview.users);expect(stored.preview.accounts).toEqual(after.preview.accounts);expect(stored.preview.sessions).toEqual(after.preview.sessions);expect(stored.preview.verification).toHaveLength(0);expect(stored.production).toEqual(before.production);
  denied.push({mode,started:attempt.started,issuedState:attempt.issuedState,pending:observations(pending),approval,transfer,oauthProxyProfile:{token,payload},rejection,after:observations(stored)});
 }

 return {signed,other,before:observations(before),started:issued.started,issuedState:issued.issuedState,saved:observations(saved),approved:forwarded.approved,forwarded:forwarded.forwarded,oauthProxyProfile:forwarded.atom,completed,after:observations(after),current,foreignCurrent,replay,denied};
},["link_social","oauth_proxy"],undefined,comparison);
