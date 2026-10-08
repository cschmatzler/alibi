import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
import { signUpAndPromoteAdmin } from "./helpers";
for (const mode of ["missing", "revoked", "other-admin"] as const) {
  compatScenario(
    `admin stop impersonation preserves live target session when restoration is ${mode}`,
    async (ctx) => {
      const admin = await signUpAndPromoteAdmin(ctx, "admin", "restoration-admin");
      const other = await signUpAndPromoteAdmin(ctx, "other-admin", "restoration-other");
      expect(admin.signup.error).toBeNull();
      expect(other.signup.error).toBeNull();
      const target = ctx.actor("target");
      const signup = await target.client.signUp.email({
        email: ctx.uniqueEmail("restoration-target"),
        password: "password123",
        name: "Target",
      });
      expect(signup.error).toBeNull();
      let issued: string[] = [];
      const impersonation = await admin.adminClient.admin.impersonateUser(
        { userId: signup.data!.user.id },
        {
          onSuccess({ response }) {
            issued = response.headers.getSetCookie();
          },
        },
      );
      expect(impersonation.error).toBeNull();
      const cookie = (headers: string[], name: string) => {
        const parsed = headers
          .map((raw) => Cookie.parse(raw)!)
          .filter((c) => c.key.endsWith(name))
          .at(-1);
        expect(parsed).toBeDefined();
        return `${parsed!.key}=${parsed!.value}`;
      };
      const principal = cookie(issued, "session_token") + "; " + cookie(issued, "dont_remember");
      const restoration = cookie(issued, "admin_session");
      let badCookie = principal;
      let otherImpersonation;
      let revoked;
      if (mode === "other-admin") {
        let otherIssued: string[] = [];
        otherImpersonation = await other.adminClient.admin.impersonateUser(
          { userId: signup.data!.user.id },
          {
            onSuccess({ response }) {
              otherIssued = response.headers.getSetCookie();
            },
          },
        );
        expect(otherImpersonation.error).toBeNull();
        badCookie += "; " + cookie(otherIssued, "admin_session");
      } else if (mode === "revoked") {
        revoked = await other.adminClient.admin.revokeUserSession({
          sessionToken: admin.signup.data!.token!,
        });
        expect(revoked.error).toBeNull();
        badCookie += "; " + restoration;
      }
      const admitted = await admin.client.getSession();
      expect(admitted.data!.user.id).toBe(signup.data!.user.id);
      const adminId = admin.signup.data!.user.id;
      const otherId = other.signup.data!.user.id;
      const targetId = signup.data!.user.id;
      const before = {
        admin: await ctx.readUserState({ userId: adminId }),
        other: await ctx.readUserState({ userId: otherId }),
        target: await ctx.readUserState({ userId: targetId }),
      };
      const denied = await admin.adminClient.admin.stopImpersonating(
        {},
        { headers: { cookie: badCookie } },
      );
      expect(denied.error).toMatchObject({ status: 500, message: "Failed to find admin session" });
      const after = {
        admin: await ctx.readUserState({ userId: adminId }),
        other: await ctx.readUserState({ userId: otherId }),
        target: await ctx.readUserState({ userId: targetId }),
      };
      expect(after).toEqual(before);
      const live = await admin.client.getSession();
      expect(live.data!.session.token).toBe(impersonation.data!.session.token);
      expect(live.data!.user.id).toBe(targetId);
      let recovered;
      if (mode !== "revoked") {
        recovered = await admin.adminClient.admin.stopImpersonating(
          {},
          { headers: { cookie: principal + "; " + restoration } },
        );
        expect(recovered.error).toBeNull();
        expect(recovered.data!.user.id).toBe(adminId);
        expect(recovered.data!.session.token).toBe(admin.signup.data!.token!);
      } else {
        expect((after.admin as any).sessions).toEqual([]);
        recovered = await ctx
          .actor("recovery")
          .client.signIn.email({ email: admin.email, password: "password123" });
        expect(recovered.error).toBeNull();
        expect(recovered.data!.user.id).toBe(adminId);
        expect(recovered.data!.token).not.toBe(admin.signup.data!.token!);
      }
      return ctx.snapshot({
        signup,
        impersonation,
        otherImpersonation,
        revoked,
        before,
        denied,
        after,
        live,
        recovered,
      });
    },
    ["POST /admin/stop-impersonating"],
  );
}
