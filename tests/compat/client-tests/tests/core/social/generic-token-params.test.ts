import { expect } from "bun:test";
import { createHash } from "node:crypto";
import { authProfilePath } from "../../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../../support/scenario";

const resource = "tenant :+&=/%é";
async function state(ctx: ScenarioContext) {
  const result = await ctx.rawRequest({ path: "/__test/social-provider/state" });
  expect(result.status).toBe(200);
  return result.body as { users: Record<string,unknown>[]; accounts: Record<string,unknown>[]; sessions: Record<string,unknown>[] };
}
async function control(ctx: ScenarioContext, value: Record<string,unknown>) {
  expect((await ctx.rawRequest({path:"/__test/generic-token/control",method:"POST",json:value})).status).toBe(200);
}
type Receipt={path:string;authorization:string|null;contentType:string;body:[string,string][];raw:string};
async function receipts(ctx:ScenarioContext) {
  return (await ctx.rawRequest({path:"/__test/generic-token/receipts"})).body as Receipt[];
}
function form(row:Receipt) {
  const fields=Object.fromEntries(row.body);
  expect(row.body.length).toBe(Object.keys(fields).length);
  expect(row.contentType).toBe("application/x-www-form-urlencoded");
  expect(fields.resource).toBe(resource);
  expect(row.raw).toContain("resource=tenant+%3A%2B%26%3D%2F%25%C3%A9");
  expect(fields.audience).toBe("https://resource.example.invalid/a?x=1&y=two words");
  return fields;
}
function observed(rows:Receipt[]) {
  return rows.map(({raw:_,body,...row})=>({ ...row,body:Object.fromEntries(body.map(([key,value])=>[key,key==="code_verifier"?{token:value,length:value.length}:value])) }));
}
async function save(ctx:ScenarioContext,name:string,result:unknown) {
  if(process.env.GENERIC_TOKEN_EVIDENCE_DIR) await Bun.write(`${process.env.GENERIC_TOKEN_EVIDENCE_DIR}/${Bun.hash(ctx.baseURL+name)}.json`,JSON.stringify({name,baseURL:ctx.baseURL,result,rawReceipts:await receipts(ctx)},null,2));
  return result;
}
for(const mode of ["post","basic","none","manual","default-none","default-post"] as const) {
  const name=`generic token ${mode} configured forms preserve grant authority and persisted lifecycle`;
  compatScenario(name,async ctx=>{
    const fixture=`generic-token-${mode}` as const;
    const foreign=ctx.actor("foreign",fixture);
    expect((await foreign.client.signUp.email({email:ctx.uniqueEmail("foreign"),password:"Password123!",name:"Foreign"})).error).toBeNull();
    const before=await state(ctx);
    const profile={id:ctx.uniqueToken("generic-subject"),email:ctx.uniqueEmail("generic"),name:"Generic Name",email_verified:true};
    await control(ctx,{profile});
    const actor=ctx.actor("owner",fixture);
    const start=await actor.client.signIn.social({provider:"generic",callbackURL:"/dashboard"});
    expect(start.error).toBeNull();
    const url=new URL(start.data!.url!);
    const path=authProfilePath(fixture)+`/callback/generic?code=fixture-code&state=${encodeURIComponent(url.searchParams.get("state")!)}`;
    const callback=await actor.fetch(ctx.baseURL+path,{redirect:"manual"});
    expect(callback.status).toBe(302);expect(callback.headers.get("location")).toBe("/dashboard");
    const after=await state(ctx);
    for(const table of ["users","accounts","sessions"] as const) {expect(after[table].length).toBe(before[table].length+1);expect(after[table].find(row=>row.id===before[table][0]!.id)).toEqual(before[table][0]);}
    const account=after.accounts.find(row=>row.providerId==="generic")!;
    const owner=after.users.find(row=>row.id===account.userId)!;
    expect(owner).toMatchObject({email:profile.email,emailVerified:true,name:profile.name});
    expect(account).toMatchObject({accountId:profile.id,accessToken:"generic-access",refreshToken:"generic-refresh",scope:"profile"});
    const first=(await receipts(ctx))[0]!;const code=form(first);
    expect(code.grant_type).toBe("authorization_code");expect(code.code).toBe("fixture-code");expect(code.redirect_uri).toBe(ctx.baseURL+authProfilePath(fixture)+"/callback/generic");
    expect(code.code_verifier).toMatch(/^[A-Za-z0-9_-]{128}$/);
    expect(createHash("sha256").update(code.code_verifier!).digest("base64url")).toBe(url.searchParams.get("code_challenge")!);
    expect(code.client_id).toBe(mode==="basic"?"extra-client":"client :+&");
    expect(code.client_secret).toBe(["post","default-post"].includes(mode)?"secret :+&":undefined);
    const authorization=mode==="basic"?"Basic "+Buffer.from("client+%3A%2B%26:secret+%3A%2B%26").toString("base64"):null;
    expect(first.authorization).toBe(authorization);
    if(mode==="manual")expect(code.client_assertion).toBe("trusted-assertion");
    const replay=await actor.fetch(ctx.baseURL+path,{redirect:"manual"});expect(replay.status).toBe(302);expect(await state(ctx)).toEqual(after);expect(await receipts(ctx)).toHaveLength(1);
    const denied=await foreign.client.refreshToken({accountId:String(account.id)});expect(denied.error).toBeTruthy();expect(await state(ctx)).toEqual(after);expect(await receipts(ctx)).toHaveLength(1);
    await control(ctx,{profile,tokenResponse:{access_token:"rotated-access",refresh_token:"rotated-refresh",token_type:"Bearer",expires_in:1800,scope:"rotated scope"}});
    const refreshed=await actor.client.refreshToken({accountId:String(account.id)});expect(refreshed.error).toBeNull();
    const rotated=await state(ctx);expect(rotated.users).toEqual(after.users);expect(rotated.sessions).toEqual(after.sessions);expect(rotated.accounts.find(row=>row.id===before.accounts[0]!.id)).toEqual(before.accounts[0]);expect(rotated.accounts.find(row=>row.id===account.id)).toMatchObject({accessToken:"rotated-access",refreshToken:"rotated-refresh",scope:"profile"});
    const refresh=form((await receipts(ctx))[1]!);expect(refresh.grant_type).toBe("refresh_token");expect(refresh.refresh_token).toBe("generic-refresh");expect(refresh.scope).toBe("rotated scope");expect(refresh.client_id).toBe(code.client_id);expect(refresh.client_secret).toBe(code.client_secret);for(const key of ["__proto__","constructor","prototype"])expect(Object.hasOwn(refresh,key)).toBe(false);
    expect((await receipts(ctx))[1]!.authorization).toBe(authorization);
    // A foreign owner's explicit link cannot take over the existing provider subject.
    const linker=foreign;
    await control(ctx,{profile:{...profile,email:before.users[0]!.email}});
    const link=await linker.client.linkSocial({provider:"generic",callbackURL:"/linked"});expect(link.error).toBeNull();
    const linkUrl=new URL(link.data!.url!);const linkPath=authProfilePath(fixture)+`/callback/generic?code=fixture-code&state=${encodeURIComponent(linkUrl.searchParams.get("state")!)}`;
    const linkResponse=await linker.fetch(ctx.baseURL+linkPath,{redirect:"manual"});expect(new URL(linkResponse.headers.get("location")!,ctx.baseURL).searchParams.get("error")).toBe("account_already_linked_to_different_user");expect(await state(ctx)).toEqual(rotated);
    const linkedSubject=ctx.uniqueToken("linked-subject");
    await control(ctx,{profile:{...profile,id:linkedSubject,email:before.users[0]!.email}});
    const ownLink=await linker.client.linkSocial({provider:"generic",callbackURL:"/linked"});expect(ownLink.error).toBeNull();
    const ownLinkURL=new URL(ownLink.data!.url!);
    const ownCallback=await linker.fetch(ctx.baseURL+authProfilePath(fixture)+`/callback/generic?code=fixture-code&state=${encodeURIComponent(ownLinkURL.searchParams.get("state")!)}`,{redirect:"manual"});expect(ownCallback.headers.get("location")).toBe("/linked");
    const linked=await state(ctx);expect(linked.users).toEqual(rotated.users);expect(linked.sessions).toEqual(rotated.sessions);expect(linked.accounts).toHaveLength(rotated.accounts.length+1);
    for(const row of rotated.accounts)expect(linked.accounts.find(a=>a.id===row.id)).toEqual(row);
    expect(linked.accounts.find(row=>row.accountId===linkedSubject)).toMatchObject({userId:before.users[0]!.id,providerId:"generic",accessToken:"generic-access",refreshToken:"generic-refresh"});
    expect((await actor.client.signOut()).error).toBeNull();const logout=await state(ctx);expect(logout.users).toEqual(rotated.users);expect(logout.accounts).toEqual(linked.accounts);expect(logout.sessions).toEqual(before.sessions);
    const rows=await receipts(ctx);expect(rows).toHaveLength(4);
    return save(ctx,name,{start:ctx.snapshot(start),callback:{status:callback.status,location:callback.headers.get("location")},before,after,rotated,denied:ctx.snapshot(denied),refreshed:ctx.snapshot(refreshed),link:{status:linkResponse.status,location:linkResponse.headers.get("location")},linked,logout,receipts:observed(rows)});
  },["POST /sign-in/social","GET /callback/{}","POST /refresh-token","POST /link-social","POST /sign-out"]);
}
for(const mode of ["basic-secret","none-secret","incomplete","conflict","refresh-basic-secret","refresh-none-secret"] as const) {
 const name=`generic token ${mode} conflicting static authentication fails before outbound grant`;
 compatScenario(name,async ctx=>{
  const fixture=`generic-token-${mode}` as const;const actor=ctx.actor("owner",fixture);const before=await state(ctx);
  const start=await actor.client.signIn.social({provider:"generic",callbackURL:"/dashboard"});expect(start.error).toBeNull();const url=new URL(start.data!.url!);
  const callback=await actor.fetch(ctx.baseURL+authProfilePath(fixture)+`/callback/generic?code=fixture-code&state=${encodeURIComponent(url.searchParams.get("state")!)}`,{redirect:"manual"});
  expect(callback.status).toBe(302);
  if(mode.startsWith("refresh-")) {
    expect(callback.headers.get("location")).toBe("/dashboard");const created=await state(ctx);const account=created.accounts.find(row=>row.providerId==="generic")!;
    const response=await actor.client.refreshToken({accountId:String(account.id)});expect(response.error).toBeTruthy();expect(await state(ctx)).toEqual(created);expect(await receipts(ctx)).toHaveLength(1);
    return save(ctx,name,{before,created,after:await state(ctx),response:ctx.snapshot(response),receipts:observed(await receipts(ctx))});
  }
  expect(new URL(callback.headers.get("location")!,ctx.baseURL).searchParams.get("error")).toBe("invalid_code");expect(await state(ctx)).toEqual(before);expect(await receipts(ctx)).toEqual([]);
  return save(ctx,name,{before,after:await state(ctx),callback:{status:callback.status,location:callback.headers.get("location")},receipts:await receipts(ctx)});
 },["POST /sign-in/social","GET /callback/{}"]);
}
