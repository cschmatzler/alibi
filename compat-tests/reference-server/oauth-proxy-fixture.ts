import { Database } from "bun:sqlite";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { oAuthProxy } from "better-auth/plugins";
import { getMigrations } from "better-auth/db/migration";
import { createHash } from "node:crypto";
export const OAUTH_PROXY_SECRET = "local-fixture-dedicated-oauth-proxy-secret-32";
export const OAUTH_PROXY_PATH = "/__test/profiles/oauth-proxy/api/auth";
/** Two genuine auth stores on different transport origins; no copied profile/state. */
export async function oauthProxyFixture(base: BetterAuthOptions) {
  const preview = String(base.baseURL), production = preview.replace("localhost", "127.0.0.1");
  const records: unknown[] = [], grants = new Map<string,{challenge:string;redirect:string;used:boolean}>();
  let count=0;
  let profile: Record<string,unknown> = {id:777,email:"proxy-owner@fixture.test",email_verified:true,name:"Proxy Owner",avatar_url:"https://assets.fixture.test/avatar.png",state:"active",locked:false};
  const instances = new Map<string,ReturnType<typeof betterAuth>>();
  for (const origin of [preview, production]) {
    const database = new Database(":memory:");
    const options: BetterAuthOptions = {...base, database, baseURL:origin, basePath:OAUTH_PROXY_PATH, trustedOrigins:[preview,production],
      plugins:[oAuthProxy({currentURL:origin,productionURL:production,secret:OAUTH_PROXY_SECRET})],
      emailAndPassword:{enabled:true}, socialProviders:{gitlab:{clientId:"proxy-fixture-client",clientSecret:"proxy-fixture-secret",issuer:`${preview}/__test/oauth-proxy/provider`,disableImplicitSignUp:false,disableSignUp:false}},
    };
    await (await getMigrations(options)).runMigrations();
    instances.set(origin,betterAuth(options));
  }
  async function state() {
    const output: Record<string,unknown> = {};
    for (const [label,origin] of [["preview",preview],["production",production]]) {
      const {adapter} = await instances.get(origin!)!.$context;
      const [users,accounts,sessions,verification] = await Promise.all(["user","account","session","verification"].map(model=>adapter.findMany<Record<string,unknown>>({model,sortBy:{field:"createdAt",direction:"asc"}})));
      output[label!] = {
        users:users!.map(r=>({id:r.id,name:r.name,email:r.email,emailVerified:r.emailVerified,image:r.image??null,createdAt:r.createdAt,updatedAt:r.updatedAt})),
        accounts:accounts!.map(r=>({id:r.id,userId:r.userId,accountId:r.accountId,providerId:r.providerId,accessToken:r.accessToken??null,refreshToken:r.refreshToken??null,idToken:r.idToken??null,scope:r.scope??null,accessTokenExpiresAt:r.accessTokenExpiresAt??null,refreshTokenExpiresAt:r.refreshTokenExpiresAt??null,createdAt:r.createdAt,updatedAt:r.updatedAt})),
        sessions:sessions!.map(r=>({id:r.id,userId:r.userId,token:r.token,expiresAt:r.expiresAt,createdAt:r.createdAt,updatedAt:r.updatedAt,ipAddress:r.ipAddress??null,userAgent:r.userAgent??null})),
        verification:verification!.map(r=>({id:r.id,expiresAt:r.expiresAt,createdAt:r.createdAt,updatedAt:r.updatedAt})),
      };
    }
    return Response.json({...output,receipts:records});
  }
  return {async reset() {
    for(const instance of instances.values()) { const {adapter}=await instance.$context; for(const model of ["session","account","verification","user"])await adapter.deleteMany({model,where:[]}); }
    grants.clear();records.length=0;count=0;
    profile={id:777,email:"proxy-owner@fixture.test",email_verified:true,name:"Proxy Owner",avatar_url:"https://assets.fixture.test/avatar.png",state:"active",locked:false};
  }, async handle(request:Request):Promise<Response|null> {
    const url=new URL(request.url);
    if(url.pathname.startsWith(`${OAUTH_PROXY_PATH}/`))return instances.get(url.origin)!.handler(request);
    if(url.pathname==="/__test/oauth-proxy/state")return state();
    if(url.pathname==="/__test/oauth-proxy/profile"&&request.method==="POST"){profile=await request.json();return Response.json({status:true});}
    if(url.pathname==="/__test/oauth-proxy/provider/oauth/authorize"){
      records.push({stage:"authorize",query:Object.fromEntries(url.searchParams)});
      const code=`proxy-fixture-code-${++count}`;
      grants.set(code,{challenge:url.searchParams.get("code_challenge")!,redirect:url.searchParams.get("redirect_uri")!,used:false});
      const callback=new URL(url.searchParams.get("redirect_uri")!);callback.searchParams.set("code",code);callback.searchParams.set("state",url.searchParams.get("state")!);
      return new Response(null,{status:302,headers:{location:callback.href}});
    }
    if(url.pathname==="/__test/oauth-proxy/provider/oauth/token"){
      const body=Object.fromEntries(new URLSearchParams(await request.text()));records.push({stage:"token",body});
      const grant=grants.get(body.code!);
      if(!grant||grant.used||grant.redirect!==body.redirect_uri||grant.challenge!==createHash("sha256").update(body.code_verifier!).digest("base64url"))return Response.json({error:"invalid_grant"},{status:400});
      grant.used=true;return Response.json({access_token:"proxy-fixture-access",refresh_token:"proxy-fixture-refresh",token_type:"Bearer",scope:"read_user issued",expires_in:3600});
    }
    if(url.pathname==="/__test/oauth-proxy/provider/api/v4/user"){
      records.push({stage:"userinfo",authorization:request.headers.get("authorization")});return Response.json(profile);
    }
    return null;
  }};
}
