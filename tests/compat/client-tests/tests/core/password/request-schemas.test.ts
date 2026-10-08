import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

const password = "password123";
const replacement = "replacement-password123";
const cases = [
  { label: "true", flag: true, accepted: true },
  { label: "false", flag: false, accepted: true },
  { label: "omitted", accepted: true },
  { label: "string-true", flag: "true", accepted: false },
  { label: "string-false", flag: "false", accepted: false },
  { label: "null", flag: null, accepted: false },
  { label: "numeric", flag: 1, accepted: false },
  { label: "empty-new", newPassword: "", accepted: false, code: "PASSWORD_TOO_SHORT" },
  { label: "empty-current", currentPassword: "", accepted: false, code: "INVALID_PASSWORD" },
] as const;
for (const input of cases) {
  compatScenario(
    `password mutation schema ${input.label} preserves transport and handler ordering`,
    async (ctx) => {
      const profile = "set-password-schema";
      const reset = await ctx.rawRequest({
        path: "/__test/set-password",
        method: "POST",
        json: { operation: "mode", mode: "normal", profile },
      });
      expect(reset.status).toBe(200);
      const owner = ctx.actor("schema-owner", profile);
      const sibling = ctx.actor("schema-sibling", profile);
      const foreign = ctx.actor("schema-foreign", profile);
      const email = ctx.uniqueEmail("schema-owner");
      const signup = await owner.client.signUp.email({ email, password, name: "Schema owner" });
      expect(signup.error).toBeNull();
      const userId = signup.data!.user.id;
      expect((await sibling.client.signIn.email({ email, password })).error).toBeNull();
      const other = await foreign.client.signUp.email({
        email: ctx.uniqueEmail("schema-foreign"),
        password,
        name: "Foreign owner",
      });
      expect(other.error).toBeNull();
      const foreignBefore = await ctx.readUserState({ userId: other.data!.user.id });
      expect(
        (
          await ctx.rawRequest({
            path: "/__test/set-password",
            method: "POST",
            json: { operation: "mode", mode: "schema-observe", profile },
          })
        ).status,
      ).toBe(200);
      const before: any = (await ctx.rawRequest({ path: "/__test/set-password/state" })).body;
      expect(before.sessions.filter((row: any) => row.userId === userId)).toHaveLength(2);
      const response = await owner.fetch(
        ctx.baseURL + authProfilePath(profile) + "/change-password",
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            newPassword: "newPassword" in input ? input.newPassword : replacement,
            currentPassword: "currentPassword" in input ? input.currentPassword : password,
            ...("flag" in input ? { revokeOtherSessions: input.flag } : {}),
          }),
        },
      );
      const result = {
        status: response.status,
        body: await response.json(),
        cookies: response.headers.getSetCookie(),
      };
      expect(result.status).toBe(input.accepted ? 200 : 400);
      if ("code" in input) expect((result.body as any).code).toBe(input.code);
      const after: any = (await ctx.rawRequest({ path: "/__test/set-password/state" })).body;
      const entered = input.accepted || input.label === "empty-current";
      for (const stage of ["hash-enter", "verify-enter"]) {
        expect(after.events.filter((event: any) => event.stage === stage)).toHaveLength(
          entered ? 1 : 0,
        );
      }
      if (!input.accepted) {
        expect(after.accounts).toEqual(before.accounts);
        expect(after.sessions).toEqual(before.sessions);
        expect(after.users).toEqual(before.users);
        expect(result.cookies).toEqual([]);
      } else {
        const credential = after.accounts.find(
          (row: any) => row.userId === userId && row.providerId === "credential",
        );
        expect(credential.password).not.toBe(
          before.accounts.find((row: any) => row.id === credential.id).password,
        );
        if (input.label === "true") {
          const sessions = after.sessions.filter((row: any) => row.userId === userId);
          expect(sessions).toHaveLength(1);
          expect(before.sessions.some((row: any) => row.id === sessions[0].id)).toBe(false);
          expect((await sibling.client.getSession()).data).toBeNull();
        } else expect(after.sessions).toEqual(before.sessions);
        const login = await ctx
          .actor("schema-fresh", profile)
          .client.signIn.email({ email, password: replacement });
        expect(login.error).toBeNull();
        expect(login.data?.user.id).toBe(userId);
      }
      expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(foreignBefore);
      return {
        result: ctx.snapshot({ status: result.status, body: result.body }),
        callbacks: after.events.map((event: any) => ({
          stage: event.stage,
          password: event.password,
        })),
        owner: ctx.snapshot(await ctx.readUserState({ userId })),
        foreign: ctx.snapshot(foreignBefore),
      };
    },
    ["POST /change-password"],
  );
}
for (const mode of ["absent", "invalid", "valid"] as const) {
  compatScenario(
    `password reset empty string ${mode} proof preserves token and length guard ordering`,
    async (ctx) => {
      const owner = ctx.actor("reset-owner");
      const email = ctx.uniqueEmail("reset-schema-owner");
      const signup = await owner.client.signUp.email({
        email,
        password,
        name: "Reset schema owner",
      });
      expect(signup.error).toBeNull();
      const userId = signup.data!.user.id;
      expect(
        (await owner.client.requestPasswordReset({ email, redirectTo: "/reset" })).error,
      ).toBeNull();
      const delivery: any = (
        await ctx.rawRequest({
          path: `/__test/reset-password-token?email=${encodeURIComponent(email)}`,
        })
      ).body;
      expect(delivery.token).toBeString();
      const identifier = `reset-password:${delivery.token}`;
      const proof = await ctx.readVerificationState({ identifier });
      expect(proof).toHaveLength(1);
      const before = await ctx.readUserState({ userId });
      const rejected = await ctx.rawRequest({
        path: "/api/auth/reset-password",
        method: "POST",
        json: {
          newPassword: "",
          ...(mode === "absent"
            ? {}
            : { token: mode === "valid" ? delivery.token : "invalid-reset-schema-proof" }),
        },
      });
      expect(rejected.status).toBe(400);
      expect((rejected.body as any).code).toBe(
        mode === "absent" ? "INVALID_TOKEN" : "PASSWORD_TOO_SHORT",
      );
      expect(await ctx.readVerificationState({ identifier })).toEqual(proof);
      expect(await ctx.readUserState({ userId })).toEqual(before);
      const recovery = await owner.client.resetPassword({
        token: delivery.token,
        newPassword: replacement,
      });
      expect(recovery.error).toBeNull();
      expect(await ctx.readVerificationState({ identifier })).toEqual([]);
      const signin = await ctx
        .actor("reset-fresh")
        .client.signIn.email({ email, password: replacement });
      expect(signin.error).toBeNull();
      expect(signin.data?.user.id).toBe(userId);
      return {
        rejected: ctx.snapshot(rejected),
        before: ctx.snapshot(before),
        recovery: ctx.snapshot(recovery),
        signin: ctx.snapshot(signin),
      };
    },
    ["POST /reset-password"],
  );
}
