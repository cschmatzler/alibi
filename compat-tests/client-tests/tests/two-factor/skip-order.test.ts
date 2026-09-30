import { expect } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { twoFactorClient } from "better-auth/client/plugins";
import { z } from "zod";
import { compatScenario } from "../../support/scenario";
import { authProfilePath } from "../../support/profiles";

compatScenario("two-factor skip enrollment rejects a configured user update before factor persistence or session rotation",async ctx=>{
  const profile="two-factor-skip-user-hook";
  const client=createAuthClient({baseURL:`${ctx.baseURL}${authProfilePath(profile)}`,plugins:[twoFactorClient()],fetchOptions:{customFetchImpl:ctx.actor("owner",profile).fetch}});
  const signup=await client.signUp.email({email:ctx.uniqueEmail("skip-hook-owner"),name:"Hook Owner",password:"password123"});
  expect(signup.error).toBeNull(); if(!signup.data)throw new Error("owner required");
  const original=await client.getSession(); expect(original.data?.user.id).toBe(signup.data.user.id);
  const before=await ctx.readUserState({userId:signup.data.user.id});
  const wrong=await client.twoFactor.enable({password:"wrong-password"}); expect(wrong.error?.code).toBe("INVALID_PASSWORD");
  const rejected=await client.twoFactor.enable({password:"password123"});
  expect(rejected.error).toMatchObject({status:400,code:"USER_UPDATE_DENIED",message:"Configured user update denied"});
  const after=z.object({twoFactorExists:z.boolean(),sessions:z.array(z.object({token:z.string(),userId:z.string()}))}).parse(await ctx.readUserState({userId:signup.data.user.id}));
  expect(after.twoFactorExists).toBe(false); expect(after.sessions).toHaveLength(1);expect(after.sessions[0]).toMatchObject({token:original.data?.session.token,userId:signup.data.user.id});
  expect(await ctx.readUserState({userId:signup.data.user.id})).toEqual(before);
  const current=await client.getSession(); expect(current.data?.user.twoFactorEnabled).toBe(false);expect(current.data?.session.token).toBe(original.data?.session.token);
  const factor=await ctx.rawRequest({path:"/__test/two-factor-policy",method:"POST",json:{userId:signup.data.user.id}});expect(factor).toMatchObject({status:200,body:null});
  return ctx.snapshot({signup,original,before,wrong,rejected,after,current,factor});
});
