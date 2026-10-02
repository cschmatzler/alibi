import {jwtVerify} from "jose";
import {betterAuth,type BetterAuthOptions} from "better-auth";

/** Actual published factory with only its fixed HTTP destinations redirected. */
export function lineProviderFixture(base:BetterAuthOptions){
 let control:Record<string,unknown>={};const receipts:unknown[]=[],mapperReceipts:unknown[]=[];
 const transport=Bun.serve({port:0,async fetch(request){
  const path=new URL(request.url).pathname,text=await request.text();
  receipts.push({path,method:request.method,authorization:request.headers.get("authorization"),contentType:request.headers.get("content-type"),body:["/token","/verify"].includes(path)?Object.fromEntries(new URLSearchParams(text)):text});
  if(path === "/token")return Response.json(control.tokenResponse ?? {...(control.idToken?{id_token:control.idToken}:{}),access_token:"fixture-line-access",refresh_token:"fixture-line-refresh",scope:"openid profile email",expires_in:3600},{status:typeof control.tokenStatus === "number"?control.tokenStatus:200});
  if(path === "/userinfo")return Response.json(control.profile ?? {sub:"fixture-line-subject",name:"Line User",email:"line@example.invalid",picture:"https://images.example.invalid/line.png"},{status:typeof control.userInfoStatus === "number"?control.userInfoStatus:200});
  if(path === "/verify") {
   const fields=Object.fromEntries(new URLSearchParams(text));
   if(typeof control.verifyStatus === "number" && control.verifyStatus !== 200)return Response.json({error:"remote verification unavailable"},{status:control.verifyStatus});
   try {
    const {payload}=await jwtVerify(fields.id_token!,new TextEncoder().encode("fixture-line-independent-hmac-key-32"),{algorithms:["HS256"],issuer:"https://access.line.me",audience:fields.client_id});
    if(fields.nonce && payload.nonce !== fields.nonce)throw new Error("Remote nonce mismatch");
    return Response.json(control.verifyResponse ?? payload);
   } catch {return Response.json({error:"invalid remote proof"},{status:400});}
  }
  return new Response("Unknown application-owned Line destination",{status:404});
 }});
 const previousFetch=globalThis.fetch.bind(globalThis);
 globalThis.fetch=(async(input,init)=>{const request=new Request(input,init),url=new URL(request.url);const route=url.origin === "https://api.line.me" && url.pathname === "/oauth2/v2.1/token"?"token":url.origin === "https://api.line.me" && url.pathname === "/oauth2/v2.1/userinfo"?"userinfo":url.origin === "https://api.line.me" && url.pathname === "/oauth2/v2.1/verify"?"verify":null;return route?previousFetch(new Request(`${transport.url}${route}`,request)):previousFetch(input,init);}) as typeof fetch;
 const profiles=new Map<string,ReturnType<typeof betterAuth>>();
 for(const mode of ["default","public","configured","disabled-scope","disabled-configured","mapped","implicit-disabled","signup-disabled","configured-endpoint","empty-clients","client-key","disabled-idtoken"] as const){
  const path=`/__test/profiles/social-line-${mode}/api/auth`;
  profiles.set(path,betterAuth({...base,basePath:path,plugins:[],socialProviders:{line:{clientId:mode === "empty-clients"?"":"fixture-social-client",...(mode !== "public"?{clientSecret:"fixture-social-secret"}:{}),...(["configured","disabled-configured"].includes(mode)?{scope:["configured-scope","openid","punctuation !~*'()"]}:{}),...(["disabled-scope","disabled-configured"].includes(mode)?{disableDefaultScope:true}:{}),...(mode === "configured-endpoint"?{authorizationEndpoint:"https://alternate-line.example.invalid/authorize?state=stale&state=duplicate&client_id=stale&retained=value",redirectURI:"https://client.example.invalid/line-return"}:{}),...(mode === "mapped"?{mapProfileToUser:(profile:Record<string,unknown>)=>{mapperReceipts.push(profile);return {id:"cannot-replace-raw-account",name:"Mapped Line User",email:"mapped-line@example.invalid",emailVerified:true,image:"https://images.example.invalid/mapped-line.png"};}}:{}),...(mode === "client-key"?{clientKey:"fixture-line-client-key"}:{}),disableIdTokenSignIn:mode === "disabled-idtoken",disableImplicitSignUp:mode === "implicit-disabled",disableSignUp:mode === "signup-disabled"}}}));
 }
 return {profiles,reset(){control={};receipts.length=0;mapperReceipts.length=0;},async handle(request:Request){const path=new URL(request.url).pathname;if(path === "/__test/line/control" && request.method === "POST"){control=await request.json();return Response.json({status:true});}if(path === "/__test/line/receipts")return Response.json(receipts);if(path === "/__test/line/mapper-receipts")return Response.json(mapperReceipts);return null;}};
}
