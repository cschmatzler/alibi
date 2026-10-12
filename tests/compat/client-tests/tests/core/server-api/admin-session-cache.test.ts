import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { cacheReceipt } from "../../../support/compact-cache-receipt";
import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import { readUserState } from "../../../support/verification";

function cookieHeader(raws: string[]) {
  const jar = new Map<string, string>();
  for (const raw of raws) {
    const cookie = Cookie.parse(raw)!;
    if (cookie.maxAge === 0) {
      jar.delete(cookie.key);
    } else {
      jar.set(cookie.key, cookie.value);
    }
  }
  return { cookie: [...jar].map(([name, value]) => name + "=" + value).join("; ") };
}
compatScenario(
  "admin cached impersonation and restoration publish the active identity on SDK and HTTP",
  async (ctx) => {
    const profile = "admin-server-cache";
    let adminCookie = "";
    const admin = await ctx.actor("cached-switch-admin", profile).client.signUp.email({
      email: ctx.uniqueEmail("cached-switch-admin"),
      name: "Cache Admin",
      password: "Password123!",
      fetchOptions: {
        onSuccess({ response }) {
          adminCookie = cookieHeader(response.headers.getSetCookie()).cookie;
        },
      },
    });
    expect(admin.error).toBeNull();
    const target = await ctx.actor("cached-switch-target").client.signUp.email({
      email: ctx.uniqueEmail("cached-switch-target"),
      name: "Cache Target",
      password: "Password123!",
    });
    expect(target.error).toBeNull();
    const foreign = await ctx.actor("cached-switch-foreign").client.signUp.email({
      email: ctx.uniqueEmail("cached-switch-foreign"),
      name: "Cache Foreign",
      password: "Password123!",
    });
    expect(foreign.error).toBeNull();
    const before = {
      admin: await readUserState(ctx, admin.data!.user.id),
      target: await readUserState(ctx, target.data!.user.id),
      foreign: await readUserState(ctx, foreign.data!.user.id),
    };
    async function invoke(
      mode: "SDK" | "HTTP",
      operation: "impersonateUser" | "stopImpersonating",
      headers: { cookie: string },
    ) {
      const path =
        mode === "SDK"
          ? "/__test/admin/server-api"
          : authProfilePath(profile) +
            (operation === "impersonateUser"
              ? "/admin/impersonate-user"
              : "/admin/stop-impersonating");
      const body = operation === "impersonateUser" ? { userId: target.data!.user.id } : {};
      const response = await ctx.actor("cached-switch-control").fetch(ctx.baseURL + path, {
        method: "POST",
        headers: { "content-type": "application/json", ...(mode === "HTTP" ? headers : {}) },
        body: JSON.stringify(mode === "SDK" ? { profile, operation, body, headers } : body),
      });
      const value = await response.json();
      expect(response.status).toBe(200);
      const raw = response.headers.getSetCookie();
      const live = raw.filter(
        (cookie) => cookie.startsWith("better-auth.session_data=") && !cookie.includes("Max-Age=0"),
      );
      expect(live.length).toBeGreaterThan(0);
      const publication = await cacheReceipt(
        new Headers({ "set-cookie": live[live.length - 1]! }),
        operation === "impersonateUser" ? 60 : 300,
      );
      expect(publication.compactSessionCache.decoded?.session.token).toBe(value.session.token);
      expect(publication.compactSessionCache.decoded?.user.id).toBe(value.user.id);
      return { status: response.status, body: value, publication, headers: cookieHeader(raw) };
    }
    const results = [];
    for (const mode of ["SDK", "HTTP"] as const) {
      const impersonated = await invoke(mode, "impersonateUser", { cookie: adminCookie });
      expect(impersonated.body.user.id).toBe(target.data!.user.id);
      expect(impersonated.publication.compactSessionCache.decoded?.session.impersonatedBy).toBe(
        admin.data!.user.id,
      );
      const current = await ctx.rawRequest({
        path: authProfilePath(profile) + "/get-session",
        headers: impersonated.headers,
      });
      expect((current.body as { user: { id: string } }).user.id).toBe(target.data!.user.id);
      const restored = await invoke(mode, "stopImpersonating", impersonated.headers);
      expect(restored.body.user.id).toBe(admin.data!.user.id);
      expect(restored.body.session.token).toBe(admin.data!.token!);
      expect(restored.publication.compactSessionCache.decoded?.user.role).toBe("admin");
      const original = await ctx.rawRequest({
        path: authProfilePath(profile) + "/get-session",
        headers: restored.headers,
      });
      expect((original.body as { user: { id: string }; session: { token: string } }).user.id).toBe(
        admin.data!.user.id,
      );
      expect((original.body as { session: { token: string } }).session.token).toBe(
        admin.data!.token!,
      );
      expect(await readUserState(ctx, target.data!.user.id)).toEqual(before.target);
      expect(await readUserState(ctx, admin.data!.user.id)).toEqual(before.admin);
      expect(await readUserState(ctx, foreign.data!.user.id)).toEqual(before.foreign);
      results.push({
        mode,
        impersonated: {
          status: impersonated.status,
          body: impersonated.body,
          publication: impersonated.publication,
        },
        current,
        restored: {
          status: restored.status,
          body: restored.body,
          publication: restored.publication,
        },
        original,
      });
    }
    return ctx.snapshot({ admin, target, foreign, before, results });
  },
);
