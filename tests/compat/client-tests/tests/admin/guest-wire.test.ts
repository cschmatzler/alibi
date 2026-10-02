import { expect } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { adminClient } from "better-auth/client/plugins";
import { Cookie } from "tough-cookie";
import { compatScenario } from "../../support/scenario";

for (const mode of ["missing", "tampered", "revoked"] as const) {
  compatScenario(
    `admin ${mode} session rejects every valid guest operation without changing owned state`,
    async (ctx) => {
      const cookies = new Map<string, string>();
      const wires: {
        status: number;
        body: string;
        contentType: string | null;
      }[] = [];
      const client = (name: string) =>
        createAuthClient({
          baseURL: ctx.baseURL,
          plugins: [adminClient()],
          fetchOptions: {
            customFetchImpl: async (input, init) => {
              const response = await ctx.actor(name).fetch(input, init);
              const path = new URL(input instanceof Request ? input.url : input, ctx.baseURL)
                .pathname;
              if (path.startsWith("/api/auth/admin/")) {
                wires.push({
                  status: response.status,
                  body: await response.clone().text(),
                  contentType: response.headers.get("content-type"),
                });
              }
              for (const header of response.headers.getSetCookie()) {
                const cookie = Cookie.parse(header);
                if (cookie?.key.endsWith(".session_token") && cookie.value && cookie.maxAge !== 0)
                  cookies.set(name, cookie.cookieString());
              }
              return response;
            },
          },
        });
      const owner = client("owner"),
        target = client("target"),
        other = client("other"),
        retired = client("retired"),
        guest = client("guest");
      const password = "password123";
      const signup = async (actor: typeof owner, prefix: string) => {
        const result = await actor.signUp.email({
          email: ctx.uniqueEmail(prefix),
          password,
          name: prefix,
        });
        expect(result.error).toBeNull();
        if (!result.data) throw new Error("actual issued identity required");
        return result;
      };
      const ownerSignup = await signup(owner, `guest-wire-${mode}-owner`);
      await ctx.promoteAdmin({ email: ownerSignup.data!.user.email });
      // Run the successful transition before the long no-write rejection matrix.
      // The subsequent real login restores a live target token; every original
      // guest operation and complete state assertion remains below.
      const targetSignup = await signup(target, `guest-wire-${mode}-target`);
      const targetId = targetSignup.data!.user.id;
      const ban = await owner.admin.banUser({
        userId: targetId,
        banReason: "Authorized Ban",
      });
      expect(ban.error).toBeNull();
      const banned = {
        persisted: await ctx.readUserState({ userId: targetId }),
        user: await owner.admin.getUser({ query: { id: targetId } }),
      };
      expect(banned).toMatchObject({
        user: {
          data: { id: targetId, banned: true, banReason: "Authorized Ban" },
        },
        persisted: { sessions: [] },
      });
      const unban = await owner.admin.unbanUser({ userId: targetId });
      expect(unban.error).toBeNull();
      const unbanned = {
        persisted: await ctx.readUserState({ userId: targetId }),
        user: await owner.admin.getUser({ query: { id: targetId } }),
      };
      expect(unbanned).toMatchObject({
        user: { data: { id: targetId, banned: false, banReason: null } },
        persisted: { sessions: [] },
      });
      const targetSignin = await target.signIn.email({
        email: targetSignup.data!.user.email,
        password,
      });
      expect(targetSignin.error).toBeNull();
      expect(targetSignin.data!.token).not.toBe(targetSignup.data!.token);

      const otherSignup = await signup(other, `guest-wire-${mode}-other`);
      const retiredSignup = await signup(retired, `guest-wire-${mode}-retired`);
      const issued = cookies.get(mode === "revoked" ? "retired" : "owner");
      if (!issued) throw new Error("actual signed session cookie required");
      const signout = await retired.signOut();
      expect(signout.error).toBeNull();
      const signedCookie = Cookie.parse(issued);
      if (!signedCookie) throw new Error("issued cookie must parse");
      const decoded = decodeURIComponent(signedCookie.value);
      const separator = decoded.lastIndexOf(".");
      if (separator < 0) throw new Error("issued signature required");
      const signature = decoded.slice(separator + 1);
      const alteredSignature = (signature.startsWith("A") ? "B" : "A") + signature.slice(1);
      const tampered = `${signedCookie.key}=${encodeURIComponent(decoded.slice(0, separator + 1) + alteredSignature)}`;
      const headers =
        mode === "missing"
          ? undefined
          : {
              cookie: mode === "revoked" ? issued : tampered,
            };
      const ids = [ownerSignup, targetSignup, otherSignup, retiredSignup].map(
        (result) => result.data!.user.id,
      );
      const readAll = async () => {
        const persisted = [],
          users = [];
        // These are ordered state observations, not concurrent operations.
        for (const id of ids) {
          persisted.push(await ctx.readUserState({ userId: id }));
          users.push(await owner.admin.getUser({ query: { id } }));
        }
        return { persisted, users };
      };
      const before = await readAll();
      expect(before.users[0]).toMatchObject({
        data: { id: ids[0], role: "admin" },
      });
      expect(before.persisted[1]).toMatchObject({
        user: { id: ids[1] },
        sessions: [{ token: targetSignin.data!.token, userId: ids[1] }],
      });
      expect(before.persisted[3]).toMatchObject({ sessions: [] });
      const targetToken = targetSignin.data!.token,
        ownerToken = ownerSignup.data!.token;
      if (!targetToken || !ownerToken) throw new Error("actual issued tokens required");
      const createdEmail = ctx.uniqueEmail(`guest-wire-${mode}-forbidden-create`);
      const calls = [
        ["set-role", () => guest.admin.setRole({ userId: targetId, role: "admin" }, { headers })],
        ["get-user", () => guest.admin.getUser({ query: { id: targetId } }, { headers })],
        [
          "create-user",
          () =>
            guest.admin.createUser(
              { email: createdEmail, password, name: "Guest Creation" },
              { headers },
            ),
        ],
        [
          "update-user",
          () =>
            guest.admin.updateUser(
              { userId: targetId, data: { name: "Guest Mutation" } },
              { headers },
            ),
        ],
        ["list-users", () => guest.admin.listUsers({ query: { limit: 10 } }, { headers })],
        [
          "list-user-sessions",
          () => guest.admin.listUserSessions({ userId: targetId }, { headers }),
        ],
        [
          "ban-user",
          () => guest.admin.banUser({ userId: targetId, banReason: "Guest Ban" }, { headers }),
        ],
        ["unban-user", () => guest.admin.unbanUser({ userId: targetId }, { headers })],
        ["impersonate-user", () => guest.admin.impersonateUser({ userId: targetId }, { headers })],
        ["stop-impersonating", () => guest.admin.stopImpersonating({}, { headers })],
        [
          "revoke-user-session",
          () => guest.admin.revokeUserSession({ sessionToken: targetToken }, { headers }),
        ],
        [
          "revoke-user-sessions",
          () => guest.admin.revokeUserSessions({ userId: targetId }, { headers }),
        ],
        ["remove-user", () => guest.admin.removeUser({ userId: targetId }, { headers })],
        [
          "set-user-password",
          () =>
            guest.admin.setUserPassword(
              { userId: targetId, newPassword: "replacement123" },
              { headers },
            ),
        ],
        [
          "has-permission",
          () =>
            guest.admin.hasPermission(
              { permissions: { user: ["get"] }, userId: ids[0], role: "admin" },
              { headers },
            ),
        ],
      ] as const;
      const rejected = [];
      for (const [operation, call] of calls) {
        const count = wires.length;
        const result = await call();
        expect(result).toEqual({
          data: null,
          error: { status: 401, statusText: "Unauthorized" },
        });
        expect(wires).toHaveLength(count + 1);
        const wire = wires.at(-1)!;
        expect(wire).toEqual({
          status: 401,
          body: "",
          contentType: "application/json",
        });
        const state = await readAll();
        expect(state).toEqual(before);
        rejected.push({ operation, result: ctx.snapshot(result), wire, state });
      }
      const forbidden = await other.admin.banUser({
        userId: targetId,
        banReason: "Foreign Ban",
      });
      expect(forbidden.error).toMatchObject({
        status: 403,
        code: "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS",
      });
      expect(await readAll()).toEqual(before);
      const get = await owner.admin.getUser({ query: { id: targetId } });
      expect(get.error).toBeNull();
      expect(get.data?.id).toBe(targetId);
      const noCreatedUser = await owner.admin.listUsers({
        query: {
          searchField: "email",
          searchOperator: "contains",
          searchValue: createdEmail,
        },
      });
      expect(noCreatedUser.data?.users).toEqual([]);
      const current = await owner.getSession();
      expect(current.data?.user.id).toBe(ids[0]);
      expect(current.data?.session.token).toBe(ownerToken);
      return {
        ownerSignup: ctx.snapshot(ownerSignup),
        targetSignup: ctx.snapshot(targetSignup),
        targetSignin: ctx.snapshot(targetSignin),
        otherSignup: ctx.snapshot(otherSignup),
        retiredSignup: ctx.snapshot(retiredSignup),
        signout: ctx.snapshot(signout),
        before,
        rejected,
        forbidden: ctx.snapshot(forbidden),
        get: ctx.snapshot(get),
        noCreatedUser: ctx.snapshot(noCreatedUser),
        ban: ctx.snapshot(ban),
        banned,
        unban: ctx.snapshot(unban),
        unbanned,
        current: ctx.snapshot(current),
        after: await readAll(),
      };
    },
    [
      "GET /admin/get-user",
      "GET /admin/list-users",
      "POST /admin/ban-user",
      "POST /admin/create-user",
      "POST /admin/has-permission",
      "POST /admin/impersonate-user",
      "POST /admin/list-user-sessions",
      "POST /admin/remove-user",
      "POST /admin/revoke-user-session",
      "POST /admin/revoke-user-sessions",
      "POST /admin/set-role",
      "POST /admin/set-user-password",
      "POST /admin/stop-impersonating",
      "POST /admin/unban-user",
      "POST /admin/update-user",
    ],
  );
}
