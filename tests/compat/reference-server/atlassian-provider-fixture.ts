import {betterAuth, type BetterAuthOptions} from "better-auth";

/** The unchanged published factory, redirecting only its fixed trusted HTTP destinations. */
export function atlassianProviderFixture(base: BetterAuthOptions) {
  let control: Record<string, unknown> = {};
  const receipts: unknown[] = [];
  const mapperReceipts: unknown[] = [];
  const transport = Bun.serve({port:0, async fetch(request) {
    const path = new URL(request.url).pathname;
    const body = request.method === "POST" ? Object.fromEntries(new URLSearchParams(await request.text())) : null;
    receipts.push({path,method:request.method,authorization:request.headers.get("authorization"),contentType:request.headers.get("content-type"),body});
    if (path === "/token") return Response.json(control.tokenResponse ?? {access_token:"fixture-atlassian-access",refresh_token:"fixture-atlassian-refresh",token_type:"Bearer",expires_in:3600,scope:"read:jira-user offline_access"},{status:Number(control.tokenStatus ?? 200)});
    if (path === "/me") return Response.json(control.profile ?? {account_id:"fixture-atlassian-subject",name:"Atlassian Name",email:"atlassian@example.invalid",picture:"https://images.example.invalid/atlassian.png"},{status:Number(control.profileStatus ?? 200)});
    return new Response("Unknown trusted Atlassian destination",{status:404});
  }});
  const previousFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = (async (input,init) => {
    const request = new Request(input,init);
    const url = new URL(request.url);
    if (url.href === "https://auth.atlassian.com/oauth/token" || url.href === "https://api.atlassian.com/me") return previousFetch(new Request(`${transport.url}${url.pathname.endsWith("token") ? "token" : "me"}`,request));
    return previousFetch(input,init);
  }) as typeof fetch;
  const profiles = new Map<string,ReturnType<typeof betterAuth>>();
  for (const mode of ["default","configured","disabled-scope","disabled-configured","mapped","implicit-disabled","signup-disabled","required","configured-endpoint"]) {
    const path = `/__test/profiles/social-atlassian-${mode}/api/auth`;
    profiles.set(path,betterAuth({...base,basePath:path,plugins:[],socialProviders:{atlassian:{
      clientId:"fixture-social-client",clientSecret:"fixture-social-secret",
      ...(["configured","disabled-configured"].includes(mode) ? {scope:["configured-scope","read:jira-user"],prompt:"consent" as const} : {}),
      ...(mode.startsWith("disabled-") ? {disableDefaultScope:true} : {}),
      ...(mode === "mapped" ? {mapProfileToUser:(profile:Record<string,unknown>)=>{mapperReceipts.push(profile);return {id:"cannot-replace-account-subject",name:`Mapped ${profile.name}`,email:"mapped-atlassian@example.invalid",emailVerified:true,image:"https://images.example.invalid/mapped-atlassian.png"};}} : {}),
      ...(mode === "implicit-disabled" ? {disableImplicitSignUp:true} : {}),
      ...(mode === "signup-disabled" ? {disableSignUp:true} : {}),
      ...(mode === "required" ? {requireEmailVerification:true} : {}),
      ...(mode === "configured-endpoint" ? {authorizationEndpoint:"https://configured.example.invalid/authorize",redirectURI:"https://configured.example.invalid/callback",responseMode:"form_post" as const} : {}),
    }}}));
  }
  return {profiles,reset(){control={};receipts.length=0;mapperReceipts.length=0;},async handle(request:Request){
    const path=new URL(request.url).pathname;
    if(path==="/__test/atlassian/control" && request.method==="POST"){control=await request.json();return Response.json({status:true});}
    if(path==="/__test/atlassian/receipts")return Response.json(receipts);
    if(path==="/__test/atlassian/mapper-receipts")return Response.json(mapperReceipts);
    return null;
  }};
}
