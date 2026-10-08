import { expect } from "bun:test";

import { apiKeyClient } from "@better-auth/api-key/client";
import { createAuthClient } from "better-auth/client";

import { compatScenario } from "../../../support/scenario";
import { signUpAndPromoteAdmin } from "../admin/helpers";
// In pinned 1.7.7 USER_BANNED belongs to deletion, not server verify;
// KEY_NOT_RECOVERABLE is exported but has no endpoint throw site.
compatScenario(
  "API-key banned owner retains server verification but cannot delete through its synthetic principal",
  async (ctx) => {
    const admin = await signUpAndPromoteAdmin(ctx, "admin");
    expect(admin.signup.error).toBeNull();
    const owner = ctx.actor("owner");
    const signup = await owner.client.signUp.email({
      email: ctx.uniqueEmail("banned-key-owner"),
      name: "Key owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    const keys = createAuthClient({
      baseURL: ctx.baseURL,
      plugins: [apiKeyClient()],
      fetchOptions: { customFetchImpl: owner.fetch },
    });
    const created = await keys.apiKey.create({ configId: "session", name: "Banned-owner key" });
    expect(created.error).toBeNull();
    const verify = async () => {
      const response = await ctx.rawRequest({
        path: "/__test/api-key/verify",
        method: "POST",
        json: { key: created.data!.key, configId: "session" },
      });
      expect(response.status).toBe(200);
      return response.body as any;
    };
    const before = await verify();
    expect(before.valid).toBe(true);
    const banned = await admin.adminClient.admin.banUser({
      userId: signup.data!.user.id,
      banReason: "Key test ban",
    });
    expect(banned.error).toBeNull();
    const whileBanned = await verify();
    expect(whileBanned.valid).toBe(true);
    const keyActor = ctx.actor("machine");
    const denied = await keyActor.fetch(ctx.baseURL + "/api/auth/api-key/delete", {
      method: "POST",
      headers: { "content-type": "application/json", "x-api-key": created.data!.key },
      body: JSON.stringify({ configId: "session", keyId: created.data!.id }),
    });
    const denial = {
      status: denied.status,
      body: await denied.json(),
      cookies: denied.headers.getSetCookie(),
    };
    expect(denial.status).toBe(401);
    expect(denial.body).toMatchObject({ code: "USER_BANNED" });
    expect(denial.cookies).toEqual([]);
    expect((await verify()).valid).toBe(true);
    const unbanned = await admin.adminClient.admin.unbanUser({ userId: signup.data!.user.id });
    expect(unbanned.error).toBeNull();
    const recovered = await verify();
    expect(recovered.valid).toBe(true);
    const removed = await admin.adminClient.admin.removeUser({ userId: signup.data!.user.id });
    expect(removed.error).toBeNull();
    const orphan = await keyActor.fetch(ctx.baseURL + "/api/auth/get-session", {
      headers: { "x-api-key": created.data!.key },
    });
    const orphaned = {
      status: orphan.status,
      body: await orphan.json(),
      cookies: orphan.headers.getSetCookie(),
    };
    expect(orphaned.status).toBe(401);
    expect(orphaned.body).toMatchObject({ code: "INVALID_REFERENCE_ID_FROM_API_KEY" });
    expect(orphaned.cookies).toEqual([]);
    return ctx.snapshot({
      signup,
      created,
      before,
      banned,
      whileBanned,
      denial,
      unbanned,
      recovered,
      removed,
      orphaned,
    });
  },
  ["POST /api-key/delete", "GET /get-session"],
);
