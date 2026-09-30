import {expect} from "bun:test";
import {createAuthClient} from "better-auth/client";
import {organizationClient} from "better-auth/client/plugins";
import {z} from "zod";
import {compatScenario} from "../../support/scenario";
import type {FixtureProfile} from "../../support/profiles";

const persisted=z.object({sessions:z.array(z.object({id:z.string(),token:z.string(),userId:z.string(),activeOrganizationId:z.string().nullable(),expiresAt:z.string()}))});
for(const profile of [undefined,"org-teams"] as const satisfies readonly (FixtureProfile|undefined)[]) {
 compatScenario(`organization metadata lookup ${profile??"default"} scopes selectors and clears only the denied session`,async ctx=>{
  function actor(name:string) {
   const source=ctx.actor(name,profile);
   return {...source,org:createAuthClient({baseURL:ctx.baseURL,plugins:[organizationClient()],fetchOptions:{customFetchImpl:source.fetch}})};
  }
  const owner=actor("metadata-owner"), outsider=actor("metadata-outsider"), otherSession=actor("metadata-outsider-other"), guest=actor("metadata-guest");
  const ownerSignup=await owner.client.signUp.email({email:ctx.uniqueEmail("metadata-owner"),password:"password123",name:"Metadata Owner"});
  const outsiderEmail=ctx.uniqueEmail("metadata-outsider");
  const outsiderSignup=await outsider.client.signUp.email({email:outsiderEmail,password:"password123",name:"Metadata Outsider"});
  expect(ownerSignup.error).toBeNull();expect(outsiderSignup.error).toBeNull();
  if(!ownerSignup.data||!outsiderSignup.data)throw new Error("real principals must be created");
  const noSelection=await owner.org.organization.getOrganization();
  expect(noSelection).toMatchObject({data:null,error:null});
  const guestDenied=await guest.org.organization.getOrganization({query:{organizationId:"missing"}});
  expect(guestDenied.error).toMatchObject({status:401});
  const first=await owner.org.organization.create({name:"Metadata Alpha",slug:ctx.uniqueToken("metadata-alpha"),metadata:{tier:"gold"}});
  const second=await owner.org.organization.create({name:"Metadata Beta",slug:ctx.uniqueToken("metadata-beta")});
  expect(first.error).toBeNull();expect(second.error).toBeNull();
  if(!first.data||!second.data)throw new Error("owned organizations must persist");
  const empty=await owner.org.organization.create({name:"Metadata Empty",slug:ctx.uniqueToken("metadata-empty"),metadata:{},keepCurrentActiveOrganization:true});
  expect(empty.error).toBeNull();if(!empty.data)throw new Error("explicit empty metadata must persist");
  expect(empty.data.metadata).toEqual({});
  const emptyMetadata=await owner.org.organization.getOrganization({query:{organizationId:empty.data.id}});
  expect(emptyMetadata.data?.metadata).toBe("{}");
  const active=await owner.org.organization.getOrganization();
  expect(active.data?.metadata).toBeNull();
  const byId=await owner.org.organization.getOrganization({query:{organizationId:first.data.id}});
  const bySlug=await owner.org.organization.getOrganization({query:{organizationId:first.data.id,organizationSlug:second.data.slug}});
  expect(active.data?.id).toBe(second.data.id);expect(byId.data?.id).toBe(first.data.id);expect(bySlug.data?.id).toBe(second.data.id);
  expect(byId.data?.metadata).toBe('{"tier":"gold"}');
  for(const result of [active,byId,bySlug]) {expect(result.error).toBeNull();expect(result.data).not.toHaveProperty("members");expect(result.data).not.toHaveProperty("invitations");expect(result.data).not.toHaveProperty("teams");}
  const emptySelectors=await owner.org.organization.getOrganization({query:{organizationSlug:""}});
  expect(emptySelectors.data?.id).toBe(second.data.id);
  const beforeMissing=persisted.parse(await ctx.readUserState({userId:ownerSignup.data.user.id}));
  const missingSlug=await owner.org.organization.getOrganization({query:{organizationId:first.data.id,organizationSlug:ctx.uniqueToken("metadata-absent-slug")}});
  expect(missingSlug.error).toMatchObject({status:400,code:"ORGANIZATION_NOT_FOUND"});
  const missing=await owner.org.organization.getOrganization({query:{organizationId:ctx.uniqueToken("metadata-absent")}});
  expect(missing.error).toMatchObject({status:400,code:"ORGANIZATION_NOT_FOUND"});
  const afterMissing=persisted.parse(await ctx.readUserState({userId:ownerSignup.data.user.id}));expect(afterMissing).toEqual(beforeMissing);
  const preserved=await owner.org.organization.getOrganization();expect(preserved.data?.id).toBe(second.data.id);
  const own=await outsider.org.organization.create({name:"Other Principal",slug:ctx.uniqueToken("metadata-other")});
  expect(own.error).toBeNull();if(!own.data)throw new Error("unrelated active organization must exist");
  const extraSignin=await otherSession.client.signIn.email({email:outsiderEmail,password:"password123"});expect(extraSignin.error).toBeNull();
  const selected=await otherSession.org.organization.setActive({organizationId:own.data.id});expect(selected.error).toBeNull();
  const current=await outsider.client.getSession(), other=await otherSession.client.getSession();
  expect(current.data?.session.token).toBeString();expect(other.data?.session.token).toBeString();expect(current.data?.session.token).not.toBe(other.data?.session.token);
  const before=persisted.parse(await ctx.readUserState({userId:outsiderSignup.data.user.id}));
  expect(before.sessions).toHaveLength(2);expect(before.sessions.every(session=>session.activeOrganizationId===own.data!.id)).toBe(true);
  const denied=await outsider.org.organization.getOrganization({query:{organizationSlug:first.data.slug}});
  expect(denied.error).toMatchObject({status:403,code:"USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION"});
  const after=persisted.parse(await ctx.readUserState({userId:outsiderSignup.data.user.id}));
  expect(after.sessions).toHaveLength(2);
  expect(after.sessions.find(session=>session.token===current.data?.session.token)?.activeOrganizationId).toBeNull();
  expect(after.sessions.find(session=>session.token===other.data?.session.token)).toEqual(before.sessions.find(session=>session.token===other.data?.session.token));
  const cleared=await outsider.org.organization.getOrganization();expect(cleared).toMatchObject({data:null,error:null});
  const unaffected=await otherSession.org.organization.getOrganization();expect(unaffected.data?.id).toBe(own.data.id);
  return ctx.snapshot({ownerSignup,outsiderSignup,noSelection,guestDenied,first,second,empty,emptyMetadata,active,byId,bySlug,emptySelectors,beforeMissing,missingSlug,missing,afterMissing,preserved,own,extraSignin,selected,current,other,before,denied,after,cleared,unaffected});
 },["GET /organization/get-organization"]);
}
