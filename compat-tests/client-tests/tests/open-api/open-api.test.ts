import { expect } from "bun:test";
import { z } from "zod";
import { compatScenario } from "../../support/scenario";
import type { FixtureProfile } from "../../support/profiles";

const documentSchema=z.object({openapi:z.literal("3.1.1"),info:z.object({title:z.literal("Better Auth"),description:z.literal("API Reference for your Better Auth Instance"),version:z.literal("1.1.0")}),components:z.object({schemas:z.record(z.string(),z.unknown()),securitySchemes:z.record(z.string(),z.unknown())}),security:z.array(z.unknown()),servers:z.array(z.object({url:z.string()})),tags:z.array(z.unknown()),paths:z.record(z.string(),z.record(z.string(),z.unknown()))}).passthrough();
for (const profile of ["openapi-default","openapi-configured","openapi-jwt","openapi-username","openapi-custom-schema","openapi-plugins","openapi-plugins-teams","openapi-plugins-configured"] as const) {
 compatScenario(`OpenAPI ${profile} generates the complete configured document and reference frame`,async ctx=>{
  const actor=ctx.actor("docs",profile);
  const sdk=await actor.client.$fetch("/open-api/generate-schema",{method:"GET"});
  expect(sdk.error).toBeNull();
  const schema=documentSchema.parse(sdk.data);
  if(!profile.startsWith("openapi-plugins")) expect(Object.keys(schema.paths).sort()).toEqual([...(profile==="openapi-username" ? ["/sign-in/username","/is-username-available"] : []),...(profile==="openapi-configured" ? [] : ["/error"]),"/sign-in/social","/sign-up/email","/sign-in/email","/link-social","/account-info","/callback/{id}","/change-email","/change-password","/delete-user","/delete-user/callback","/get-access-token","/get-session","/list-accounts","/list-sessions","/ok","/refresh-token","/request-password-reset","/reset-password","/reset-password/{token}","/revoke-other-sessions","/revoke-session","/revoke-sessions","/send-verification-email","/sign-out","/unlink-account","/update-user","/verify-email","/verify-password"].sort());
  expect(schema.servers).toEqual([{url:`${ctx.baseURL}/__test/profiles/${profile}/api/auth`}]);
  expect(schema.paths["/get-session"]).toHaveProperty("get.operationId","getSession");
  expect(schema.paths["/get-session"]).toHaveProperty("post.operationId","getSessionPost");
  expect(schema.paths).not.toHaveProperty("/reference");
  expect(schema.paths).not.toHaveProperty("/open-api/generate-schema");
  if(!profile.startsWith("openapi-plugins")) expect(Object.keys(schema.components.schemas).sort()).toEqual(profile==="openapi-jwt" ? ["Account","Jwks","Session","User","Verification"] : ["Account","Session","User","Verification"]);
  expect(schema.components.schemas.User).toHaveProperty("properties.emailVerified",{type:"boolean",default:false,readOnly:true});
  if(profile.startsWith("openapi-plugins")) {
   expect(schema.paths).toHaveProperty("/admin/remove-user");
   expect(schema.paths).toHaveProperty("/organization/create");
   expect(schema.paths).toHaveProperty("/passkey/verify-registration");
   expect(schema.paths).toHaveProperty("/two-factor/enable");
   expect(schema.components.schemas).toHaveProperty("Apikey");
   expect(schema.components.schemas.Apikey).toHaveProperty("properties.rateLimitMax.default",profile==="openapi-plugins-configured" ? 43 : 10);
   expect(schema.components.schemas.Apikey).toHaveProperty("properties.rateLimitTimeWindow.default",profile==="openapi-plugins-configured" ? 7654321 : 86400000);
   expect(schema.components.schemas).toHaveProperty("Passkey");
   expect(schema.components.schemas.User).toHaveProperty("properties.banned",{type:"boolean",default:false,readOnly:true});
   if(profile==="openapi-plugins-teams") {
    expect(schema.paths).toHaveProperty("/organization/create-team");
    expect(schema.components.schemas).toHaveProperty("Team");
    expect(schema.components.schemas).toHaveProperty("OrganizationRole");
    expect(schema.components.schemas.Session).toHaveProperty("properties.activeTeamId");
   } else {
    expect(schema.components.schemas).not.toHaveProperty("Team");
    expect(schema.components.schemas).not.toHaveProperty("OrganizationRole");
    expect(schema.components.schemas.Session).not.toHaveProperty("properties.activeTeamId");
   }
  } else expect(schema.components.schemas.User).not.toHaveProperty("properties.banned");
  if(profile==="openapi-custom-schema") {
   expect(schema.components.schemas.User).toHaveProperty("properties.metadata",{type:"json",default:null,readOnly:true});
   const model=z.object({required:z.array(z.string())}).passthrough().parse(schema.components.schemas.User);
   expect(model.required).not.toContain("metadata");
   expect(schema.paths["/sign-up/email"]).not.toHaveProperty("post.requestBody.content.application/json.schema.properties.metadata");
   expect(schema.paths["/update-user"]).not.toHaveProperty("post.requestBody.content.application/json.schema.properties.metadata");
  }
  if(profile==="openapi-username") {
   expect(schema.components.schemas.User).toHaveProperty("properties.username",{type:"string"});
   expect(schema.paths["/sign-up/email"]).toHaveProperty("post.requestBody.content.application/json.schema.properties.username",{type:"string"});
   expect(schema.paths["/update-user"]).toHaveProperty("post.requestBody.content.application/json.schema.properties.displayUsername",{type:"string"});
  }
  expect(schema.components.schemas.Session).not.toHaveProperty("properties.active");
  const raw=await actor.fetch(`${ctx.baseURL}/api/auth/open-api/generate-schema`);
  expect(raw.status).toBe(200);
  expect(raw.headers.get("content-type")?.split(";")[0]).toBe("application/json");
  expect(await raw.json()).toEqual(schema);
  const path=profile==="openapi-configured" ? "/docs" : "/reference";
  const html=await actor.fetch(`${ctx.baseURL}/api/auth${path}`);
  expect(html.status).toBe(200);
  expect(html.headers.get("content-type")?.split(";")[0]).toBe("text/html");
  const page=await html.text();
  const embedded=/<script\s+id="api-reference"\s+type="application\/json">\s*([^]*?)\s*<\/script>/.exec(page);
  if(!embedded?.[1]) throw new Error("reference must include a complete schema JSON script");
  expect(JSON.parse(embedded[1])).toEqual(schema);
  expect(page.match(/nonce="fixture-reference-nonce"/g)?.length ?? 0).toBe(profile==="openapi-configured" ? 2 : 0);
  expect(page).toContain(`theme: "${profile==="openapi-configured" ? "moon" : "default"}"`);
  // Compare the entire HTML frame verbatim, with the complete embedded document
  // compared structurally above and in the returned observation.
  const frame=page.replace(embedded[1],"<document>");
  const wrongPath=await actor.fetch(`${ctx.baseURL}/api/auth${profile==="openapi-configured" ? "/reference" : "/docs"}`);
  expect(wrongPath.status).toBe(404);
  return ctx.snapshot({schema,frame,wrongPath:wrongPath.status});
 });
}
compatScenario("OpenAPI disabling the reference preserves the public schema endpoint",async ctx=>{
 const profile:FixtureProfile="openapi-disabled";
 const actor=ctx.actor("docs",profile);
 const schema=await actor.client.$fetch("/open-api/generate-schema",{method:"GET"});
 expect(schema.error).toBeNull();
 const document=documentSchema.parse(schema.data);
 const page=await actor.fetch(`${ctx.baseURL}/api/auth/reference`);
 expect(page.status).toBe(404);
 expect(await page.text()).toBe("");
 return ctx.snapshot({document,status:page.status});
});
