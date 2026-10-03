import { betterAuth, type BetterAuthOptions } from "better-auth";
import { genericOAuth } from "better-auth/plugins";
export function genericTokenParamsFixture(base: BetterAuthOptions) {
  let control: Record<string,unknown>={}; const receipts: unknown[]=[];
  const transport=Bun.serve({port:0,async fetch(request) {
    if(new URL(request.url).pathname==="/token") {
      const raw=await request.text();receipts.push({path:"/token",authorization:request.headers.get("authorization"),contentType:request.headers.get("content-type"),body:[...new URLSearchParams(raw)],raw});
      return Response.json(control.tokenResponse??{access_token:"generic-access",refresh_token:"generic-refresh",token_type:"Bearer",expires_in:3600,scope:"profile"});
    }
    return Response.json(control.profile??{id:"generic-subject",email:"generic@example.invalid",name:"Generic Name",email_verified:true});
  }});
  function params(mode:string,refresh:boolean):Record<string,string> {
    if(mode.startsWith("refresh-")) return params(refresh?mode.slice(8):mode.slice(8).replace(/-secret$/, ""),refresh);
    const p:Record<string,string>=Object.assign(Object.create(null),{audience:"https://resource.example.invalid/a?x=1&y=two words",resource:"tenant :+&=/%é",client_id:"extra-client",grant_type:"extra-grant"});
    if(refresh) Object.assign(p,JSON.parse('{"refresh_token":"extra-refresh","scope":"rotated scope","__proto__":"blocked","constructor":"blocked","prototype":"blocked"}'));
    else Object.assign(p,{code:"extra-code",redirect_uri:"https://wrong.example.invalid",code_verifier:"extra-verifier"});
    if(["post","basic-secret","none-secret"].includes(mode)) p.client_secret="extra-secret";
    if(["manual","incomplete","conflict"].includes(mode)) {p.client_assertion="trusted-assertion";if(mode!=="incomplete")p.client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer";}
    return p;
  }
  const profiles=new Map<string,ReturnType<typeof betterAuth>>();
  for(const mode of ["post","basic","none","manual","default-none","default-post","basic-secret","none-secret","incomplete","conflict","refresh-basic-secret","refresh-none-secret"]){
    const path=`/__test/profiles/generic-token-${mode}/api/auth`;
    const configuredMode=mode.replace(/^refresh-/, "");
    profiles.set(path,betterAuth({...base,basePath:path,socialProviders:{},plugins:[genericOAuth({config:[{providerId:"generic",clientId:"client :+&",...(["post","basic","basic-secret","default-post"].includes(configuredMode)?{clientSecret:"secret :+&"}:{}),...(["manual","incomplete","default-none","default-post"].includes(configuredMode)?{}:{tokenEndpointAuth:{method:configuredMode==="post"?"client_secret_post":configuredMode.startsWith("basic")?"client_secret_basic":"none"} as const}),authorizationUrl:"https://generic.example.invalid/authorize",tokenUrl:`${transport.url}token`,userInfoUrl:`${transport.url}user`,scopes:["profile"],tokenUrlParams:params(mode,false),refreshTokenParams:params(mode,true)}]})]}));
  }
  return {profiles,reset(){control={};receipts.length=0;},async handle(request:Request){const p=new URL(request.url).pathname;if(p==="/__test/generic-token/control"&&request.method==="POST"){control=await request.json();return Response.json({status:true});}if(p==="/__test/generic-token/receipts")return Response.json(receipts);return null;}};
}
