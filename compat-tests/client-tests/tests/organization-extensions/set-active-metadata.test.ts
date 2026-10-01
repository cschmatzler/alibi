import {expect} from "bun:test";
import {z} from "zod";
import {compatScenario,type ScenarioContext} from "../../support/scenario";

const stateSchema=z.object({
  organizations:z.array(z.object({id:z.string(),name:z.string(),slug:z.string(),memberId:z.string(),userId:z.string(),role:z.string(),logo:z.string().nullable(),metadata:z.string().nullable().optional()})),
  sessions:z.array(z.object({id:z.string(),token:z.string(),userId:z.string(),activeOrganizationId:z.string().nullable()})),
  orphanOrganizations:z.array(z.object({id:z.string(),name:z.string(),slug:z.string()})),
  receipts:z.array(z.object({operation:z.string(),userId:z.string(),email:z.string(),name:z.string()})),
});
async function state(ctx:ScenarioContext,email:string,metadata=true) {
  const response=await ctx.rawRequest({path:`/__test/organization-creation-state?email=${encodeURIComponent(email)}&includeMetadata=${metadata}&includeLogo=true`});
  expect(response.status).toBe(200);
  return stateSchema.parse(response.body);
}
async function signup(ctx:ScenarioContext) {
  const owner=ctx.actor("metadata-owner","org-creation-empty-role");
  const email=ctx.uniqueEmail("set-active-metadata");
  const response=await owner.client.signUp.email({name:"Metadata Owner",email,password:"password123"});
  expect(response.error).toBeNull();
  const result=z.object({token:z.string(),user:z.object({id:z.string()})}).parse(response.data);
  return {...owner,email,userId:result.user.id,token:result.token};
}
const responseSchema=z.object({id:z.string(),name:z.string(),slug:z.string(),logo:z.string().nullable(),metadata:z.string().nullable()});

compatScenario("organization set-active returns exact stored metadata text and changes only the current token selection", async ctx => {
  const owner=await signup(ctx);
  const metadata={"2":"second","1":"first",nested:{fixed:1e20,tiny:1e-19,array:[null,true,"literal"]},"$serde_json::private::RawValue":"application-key"};
  const slug=ctx.uniqueToken("record-metadata");
  const created=await owner.client.$fetch("/organization/create",{method:"POST",body:{name:"Record Metadata",slug,logo:"https://fixture.test/record.png",metadata}});
  expect(created.error).toBeNull();
  const firstId=z.object({id:z.string()}).parse(created.data).id;
  const other=ctx.actor("other-metadata-token","org-creation-empty-role");
  const signedIn=await other.client.signIn.email({email:owner.email,password:"password123"});
  expect(signedIn.error).toBeNull();
  const otherToken=z.object({token:z.string()}).parse(signedIn.data).token;
  const emptyCreated=await other.client.$fetch("/organization/create",{method:"POST",body:{name:"Empty Metadata",slug:ctx.uniqueToken("empty-metadata"),metadata:{}}});
  expect(emptyCreated.error).toBeNull();
  const secondId=z.object({id:z.string()}).parse(emptyCreated.data).id;
  const before=await state(ctx,owner.email);
  expect(before.organizations.find(row=>row.id===firstId)?.metadata).toBe(JSON.stringify(metadata));
  expect(before.organizations.find(row=>row.id===secondId)?.metadata).toBe("{}");
  expect(before.sessions.find(row=>row.token===owner.token)?.activeOrganizationId).toBe(firstId);
  expect(before.sessions.find(row=>row.token===otherToken)?.activeOrganizationId).toBe(secondId);
  const selectedEmpty=await owner.client.$fetch("/organization/set-active",{method:"POST",body:{organizationId:secondId}});
  expect(selectedEmpty.error).toBeNull();
  expect(responseSchema.parse(selectedEmpty.data)).toMatchObject({id:secondId,metadata:"{}"});
  expect(selectedEmpty.data).not.toHaveProperty("members");
  expect(selectedEmpty.data).not.toHaveProperty("invitations");
  const afterEmpty=await state(ctx,owner.email);
  expect(afterEmpty.organizations).toEqual(before.organizations);
  expect(afterEmpty.sessions.find(row=>row.token===owner.token)?.activeOrganizationId).toBe(secondId);
  expect(afterEmpty.sessions.find(row=>row.token===otherToken)).toEqual(before.sessions.find(row=>row.token===otherToken));
  const selectedRecord=await owner.client.$fetch("/organization/set-active",{method:"POST",body:{organizationSlug:slug}});
  expect(selectedRecord.error).toBeNull();
  expect(responseSchema.parse(selectedRecord.data)).toMatchObject({id:firstId,metadata:JSON.stringify(metadata)});
  const afterRecord=await state(ctx,owner.email);
  expect(afterRecord).toEqual(before);
  const changed={guard:"fresh-row",nested:[null,{fixed:1e20}],"1":"first"};
  const updated=await owner.client.$fetch("/organization/update",{method:"POST",body:{organizationId:firstId,data:{metadata:changed}}});
  expect(updated.error).toBeNull();
  expect(z.object({metadata:z.unknown()}).parse(updated.data).metadata).toEqual(changed);
  const selectedChanged=await owner.client.$fetch("/organization/set-active",{method:"POST",body:{organizationId:firstId}});
  expect(selectedChanged.error).toBeNull();
  expect(responseSchema.parse(selectedChanged.data)).toMatchObject({id:firstId,metadata:JSON.stringify(changed),logo:"https://fixture.test/record.png"});
  const afterChanged=await state(ctx,owner.email);
  expect(afterChanged.organizations.find(row=>row.id===firstId)).toEqual({...before.organizations.find(row=>row.id===firstId)!,metadata:JSON.stringify(changed)});
  expect(afterChanged.organizations.find(row=>row.id===secondId)).toEqual(before.organizations.find(row=>row.id===secondId));
  expect(afterChanged.sessions).toEqual(before.sessions);
  expect(afterChanged.receipts).toEqual(before.receipts);
  expect(afterChanged.orphanOrganizations).toEqual(before.orphanOrganizations);
  return {created:ctx.snapshot(created),emptyCreated:ctx.snapshot(emptyCreated),before,selectedEmpty:ctx.snapshot(selectedEmpty),afterEmpty,selectedRecord:ctx.snapshot(selectedRecord),afterRecord,updated:ctx.snapshot(updated),selectedChanged:ctx.snapshot(selectedChanged),afterChanged};
}, ["POST /organization/set-active", "POST /organization/update"]);

compatScenario("organization set-active emits null for absent metadata and retains real membership and session scope", async ctx => {
  const owner=await signup(ctx);
  const created=await owner.client.$fetch("/organization/create",{method:"POST",body:{name:"Absent Metadata",slug:ctx.uniqueToken("absent-metadata")}});
  expect(created.error).toBeNull();
  expect(created.data).not.toHaveProperty("metadata");
  const id=z.object({id:z.string()}).parse(created.data).id;
  // The nullable metadata storage migration is separate. This case owns its
  // public wire result and actual membership/session persistence, not SQL shape.
  const before=await state(ctx,owner.email,false);
  const selected=await owner.client.$fetch("/organization/set-active",{method:"POST",body:{organizationId:id}});
  expect(selected.error).toBeNull();
  expect(responseSchema.parse(selected.data)).toMatchObject({id,metadata:null});
  const after=await state(ctx,owner.email,false);
  expect(after).toEqual(before);
  expect(after.organizations[0]).toMatchObject({id,userId:owner.userId,role:"owner"});
  expect(after.sessions.find(row=>row.token===owner.token)?.activeOrganizationId).toBe(id);
  return {created:ctx.snapshot(created),before,selected:ctx.snapshot(selected),after};
}, ["POST /organization/set-active", "POST /organization/update"]);
