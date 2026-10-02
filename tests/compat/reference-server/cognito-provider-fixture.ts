import {betterAuth, type BetterAuthOptions} from "better-auth";

/** Published Cognito factory; only its fixed application-owned HTTP authorities are redirected. */
export function cognitoProviderFixture(base: BetterAuthOptions) {
  let control: Record<string, unknown> = {};
  const receipts: unknown[] = [];
  const mapperReceipts: unknown[] = [];
  const userInfoReceipts: unknown[] = [];
  const defaultKeys = JSON.parse(require("node:fs").readFileSync(new URL("../../fixtures/one-tap/jwks.json",import.meta.url),"utf8"));
  const transport = Bun.serve({port:0, async fetch(request) {
    const path = new URL(request.url).pathname;
    const body = request.method === "POST" ? Object.fromEntries(new URLSearchParams(await request.text())) : null;
    receipts.push({path,method:request.method,authorization:request.headers.get("authorization"),contentType:request.headers.get("content-type"),body});
    if(path === "/keys")return Response.json(control.keys ?? defaultKeys);
    if(path === "/token")return Response.json(control.tokenResponse ?? {access_token:"fixture-cognito-access",refresh_token:"fixture-cognito-refresh",token_type:"Bearer",expires_in:3600,...(control.idToken ? {id_token:control.idToken} : {})},{status:typeof control.tokenStatus === "number"?control.tokenStatus:200});
    if(path === "/userinfo")return Response.json(control.profile ?? {sub:"fixture-cognito-subject",name:"Cognito User",email:"cognito@example.invalid",email_verified:true,picture:"https://images.example.invalid/cognito.png"},{status:typeof control.userInfoStatus === "number"?control.userInfoStatus:200});
    return new Response("Unknown trusted Cognito destination",{status:404});
  }});
  const previousFetch=globalThis.fetch.bind(globalThis);
  globalThis.fetch=(async(input,init)=>{
    const request=new Request(input,init),url=new URL(request.url);
    const route=url.origin === "https://fixture-cognito.example.invalid" && ["/oauth2/token","/oauth2/userinfo"].includes(url.pathname) ? url.pathname.endsWith("token") ? "token" : "userinfo" : url.origin === "https://cognito-idp.fixture-region.amazonaws.com" && url.pathname === "/fixture-pool/.well-known/jwks.json" ? "keys" : null;
    if(route)return previousFetch(new Request(`${transport.url}${route}`,request));
    return previousFetch(input,init);
  }) as typeof fetch;
  const profiles=new Map<string,ReturnType<typeof betterAuth>>();
  for(const mode of ["default","configured","disabled-scope","disabled-configured","public","required","client-array","empty-clients","mapped","disabled-idtoken","implicit-disabled","signup-disabled","configured-endpoint","http-domain","encrypted","userinfo-override","query-overrides"] as const){
    const path=`/__test/profiles/social-cognito-${mode}/api/auth`;
    profiles.set(path,betterAuth({...base,basePath:path,plugins:[],...(mode === "encrypted" ? {account:{...base.account,encryptOAuthTokens:true}} : {}),socialProviders:{cognito:{
      clientId:mode === "empty-clients" ? [] : mode === "client-array" ? ["fixture-social-client","fixture-cognito-secondary"] : "fixture-social-client",
      ...(mode !== "public" && mode !== "required" ? {clientSecret:"fixture-social-secret"} : {}),
      domain:mode === "http-domain" ? "http://fixture-cognito.example.invalid" : "https://fixture-cognito.example.invalid",region:"fixture-region",userPoolId:"fixture-pool",
      requireClientSecret:mode === "required",
      ...(["configured","disabled-configured"].includes(mode) ? {scope:["configured-scope","openid","punctuation-!~*'()"],prompt:"login",identityProvider:"ConfiguredIdentity"} : {}),
      ...(mode === "disabled-scope" || mode === "disabled-configured" ? {disableDefaultScope:true} : {}),
      ...(mode === "query-overrides" ? {authorizationEndpoint:"https://alternate-cognito.example.invalid/authorize?response_type=stale&client_id=stale&state=stale&state=stale2&scope=stale&redirect_uri=stale&code_challenge=stale&code_challenge_method=stale&identity_provider=stale&custom=stale&retained=value"} : {}),
      ...(mode === "configured-endpoint" ? {authorizationEndpoint:"https://alternate-cognito.example.invalid/authorize?retained=value",redirectURI:"https://client.example.invalid/cognito-return"} : {}),
      ...(mode === "mapped" ? {mapProfileToUser:(profile:Record<string,unknown>)=>{mapperReceipts.push(profile);return {id:"cannot-replace-raw-subject",name:`Mapped ${profile.name ?? profile.given_name ?? profile.username ?? ""}`,email:"mapped-cognito@example.invalid",emailVerified:false,image:"https://images.example.invalid/mapped-cognito.png"};}} : {}),
      ...(mode === "userinfo-override" ? {getUserInfo:async()=>{const profile=control.profile as Record<string,unknown>;userInfoReceipts.push(profile);return {user:{id:"cannot-replace-raw-subject",name:"Application Cognito User",email:String(profile.email),emailVerified:true},data:profile};}} : {}),
      disableIdTokenSignIn:mode === "disabled-idtoken",disableImplicitSignUp:mode === "implicit-disabled",disableSignUp:mode === "signup-disabled",
    }}}));
  }
  return {profiles,reset(){control={};receipts.length=0;mapperReceipts.length=0;userInfoReceipts.length=0;},async handle(request:Request){
    const path=new URL(request.url).pathname;
    if(path === "/__test/cognito/control" && request.method === "POST"){control=await request.json();return Response.json({status:true});}
    if(path === "/__test/cognito/receipts")return Response.json(receipts);
    if(path === "/__test/cognito/mapper-receipts")return Response.json(mapperReceipts);
    if(path === "/__test/cognito/userinfo-profile-receipts")return Response.json(userInfoReceipts);
    return null;
  }};
}
