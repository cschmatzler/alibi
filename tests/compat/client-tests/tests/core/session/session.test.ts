import { expect } from "bun:test";

import { z } from "zod";

import { compatScenario } from "../../../support/scenario";

compatScenario("list sessions and revoke a session through the SDK", async (ctx) => {
  const first = ctx.actor("first");
  const second = ctx.actor("second");
  const email = ctx.uniqueEmail("core-sessions");

  const signup = await first.client.signUp.email({
    email,
    password: "password123",
    name: "Sessions User",
  });
  const secondSignin = await second.client.signIn.email({
    email,
    password: "password123",
  });
  const sessions = await first.client.listSessions();
  const current = await first.client.getSession();
  const revoke = await first.client.revokeSession({
    token: current.data?.session?.token ?? "",
  });
  const firstAfter = await first.client.getSession();
  const secondAfter = await second.client.getSession();

  return {
    signup: ctx.snapshot(signup),
    secondSignin: ctx.snapshot(secondSignin),
    sessions: ctx.snapshot(sessions),
    current: ctx.snapshot(current),
    revoke: ctx.snapshot(revoke),
    firstAfter: ctx.snapshot(firstAfter),
    secondAfter: ctx.snapshot(secondAfter),
  };
});

compatScenario("revoke sessions logs out all active clients", async (ctx) => {
  const first = ctx.actor("first");
  const second = ctx.actor("second");
  const email = ctx.uniqueEmail("core-revoke-all");

  const signup = await first.client.signUp.email({
    email,
    password: "password123",
    name: "Revoke All User",
  });
  const secondSignin = await second.client.signIn.email({
    email,
    password: "password123",
  });
  const revoke = await first.client.revokeSessions();
  const firstAfter = await first.client.getSession();
  const secondAfter = await second.client.getSession();

  return {
    signup: ctx.snapshot(signup),
    secondSignin: ctx.snapshot(secondSignin),
    revoke: ctx.snapshot(revoke),
    firstAfter: ctx.snapshot(firstAfter),
    secondAfter: ctx.snapshot(secondAfter),
  };
});

compatScenario(
  "change password with revokeOtherSessions invalidates the other client",
  async (ctx) => {
    const primary = ctx.actor("primary");
    const secondary = ctx.actor("secondary");
    const email = ctx.uniqueEmail("core-change");

    const signup = await primary.client.signUp.email({
      email,
      password: "password123",
      name: "Change Password User",
    });
    const secondarySignin = await secondary.client.signIn.email({
      email,
      password: "password123",
    });
    const change = await primary.client.changePassword({
      currentPassword: "password123",
      newPassword: "newPassword123!",
      revokeOtherSessions: true,
    });
    const primaryAfter = await primary.client.getSession();
    const secondaryAfter = await secondary.client.getSession();

    return {
      signup: ctx.snapshot(signup),
      secondarySignin: ctx.snapshot(secondarySignin),
      change: ctx.snapshot(change),
      primaryAfter: ctx.snapshot(primaryAfter),
      secondaryAfter: ctx.snapshot(secondaryAfter),
    };
  },
);

compatScenario("revoke other sessions keeps the caller alive", async (ctx) => {
  const primary = ctx.actor("primary");
  const secondary = ctx.actor("secondary");
  const email = ctx.uniqueEmail("core-other-sessions");

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Revoke Other Sessions User",
  });
  const secondarySignin = await secondary.client.signIn.email({
    email,
    password: "password123",
  });
  const revoke = await primary.client.revokeOtherSessions();
  const primaryAfter = await primary.client.getSession();
  const secondaryAfter = await secondary.client.getSession();

  return {
    signup: ctx.snapshot(signup),
    secondarySignin: ctx.snapshot(secondarySignin),
    revoke: ctx.snapshot(revoke),
    primaryAfter: ctx.snapshot(primaryAfter),
    secondaryAfter: ctx.snapshot(secondaryAfter),
  };
});

const listModes = ["reject", "success", "coordinated"] as const;

for (const mode of listModes) {
  compatScenario(
    `list sessions ${mode === "coordinated" ? "coordinates ready callbacks before rejection and retains pending siblings" : mode === "reject" ? "rejects configured output while started callbacks continue" : "publishes ordered configured output without changing physical authority"}`,
    async (ctx) => {
      const rejection = mode !== "success";
      const profile = "additional-cached-fields";
      const owner = ctx.actor("list-owner", profile);
      const sibling = ctx.actor("list-sibling", profile);
      const slow = ctx.actor("list-slow", profile);
      const expired = ctx.actor("list-expired", profile);
      const foreign = ctx.actor("list-foreign", profile);
      const email = ctx.uniqueEmail("list-owner");
      expect(
        (await owner.client.signUp.email({ email, name: "List owner", password: "Password123!" }))
          .error,
      ).toBeNull();

      for (const actor of [sibling, slow, expired]) {
        expect(
          (await actor.client.signIn.email({ email, password: "Password123!" })).error,
        ).toBeNull();
      }

      expect(
        (
          await foreign.client.signUp.email({
            email: ctx.uniqueEmail("list-foreign"),
            name: "Foreign",
            password: "Password123!",
          })
        ).error,
      ).toBeNull();

      const initial = await owner.client.getSession();
      const token = z.string().parse(initial.data?.session.token);
      const siblingToken = z
        .string()
        .parse((await sibling.client.getSession()).data?.session.token);
      const slowToken = z.string().parse((await slow.client.getSession()).data?.session.token);
      const expiredToken = z
        .string()
        .parse((await expired.client.getSession()).data?.session.token);
      const foreignToken = z
        .string()
        .parse((await foreign.client.getSession()).data?.session.token);
      const expiresAt = new Date(Date.now() + 86_400_000 * 6).toISOString();

      // Operator setup writes real application columns, preserving genuine issued credentials.
      for (const [target, label] of [
        [
          siblingToken,
          mode === "coordinated"
            ? "collection-coordinated-reject"
            : rejection
              ? "collection-reject"
              : "listed-sibling",
        ],
        [slowToken, mode === "coordinated" ? "collection-coordinated-slow" : "collection-slow"],
      ]) {
        expect(
          (
            await ctx.rawRequest({
              path: "/__test/additional-fields/rewind-session?profile=cached",
              method: "POST",
              json: {
                token: target,
                label,
                expiresAt,
                ...(mode === "coordinated" && target === slowToken
                  ? { omitted: "collection-coordinated-slow" }
                  : {}),
              },
            })
          ).status,
        ).toBe(200);
      }

      expect(
        (
          await ctx.rawRequest({
            path: "/__test/additional-fields/rewind-session?profile=cached",
            method: "POST",
            json: {
              token: expiredToken,
              label: "throw",
              expiresAt: new Date(Date.now() - 86_400_000).toISOString(),
            },
          })
        ).status,
      ).toBe(200);

      if (mode === "reject") {
        expect(
          (
            await ctx.rawRequest({
              path: "/__test/additional-fields/rewind-session?profile=cached",
              method: "POST",
              json: { token, label: "collection-slower", expiresAt },
            })
          ).status,
        ).toBe(200);
      }

      if (mode === "coordinated") {
        expect(
          (
            await ctx.rawRequest({
              path: "/__test/additional-fields/rewind-session?profile=cached",
              method: "POST",
              json: { token, omitted: "collection-ready", expiresAt },
            })
          ).status,
        ).toBe(200);
      }

      const read = async () => {
        const result = await ctx.rawRequest({
          path: "/__test/additional-fields/state?profile=cached",
        });
        expect(result.status).toBe(200);

        const state = z
          .object({
            users: z.array(z.record(z.string(), z.unknown())),
            accounts: z.array(z.record(z.string(), z.unknown())),
            verifications: z.array(z.record(z.string(), z.unknown())),
            sessions: z.array(z.record(z.string(), z.unknown())),
            events: z.array(z.record(z.string(), z.unknown())),
          })
          .parse(result.body);
        return {
          physical: {
            users: state.users,
            accounts: state.accounts,
            verifications: state.verifications,
            sessions: state.sessions,
          },
          sessions: state.sessions,
          events: state.events.filter((event) => event.entity !== "account"),
        };
      };
      const before = await read();
      const result = await owner.client.listSessions();

      if (rejection) {
        expect(result.error?.status).toBe(500);
      }

      const pending = await read();
      expect(pending.physical).toEqual(before.physical);

      const callbacks = pending.events.slice(before.events.length);
      expect(
        callbacks.filter(
          (event) =>
            event.phase === "output" &&
            event.entity === "session" &&
            event.value ===
              (mode === "coordinated" ? "collection-coordinated-slow" : "collection-slow"),
        ),
      ).toHaveLength(1);

      if (mode === "reject") {
        expect(
          callbacks.filter(
            (event) => event.phase === "output" && event.value === "collection-slower",
          ),
        ).toHaveLength(1);
      }

      expect(
        callbacks.filter((event) => event.phase === "output" && event.value === "throw"),
      ).toEqual([]);

      if (rejection) {
        expect(result.error?.status).toBe(500);
        expect(callbacks.filter((event) => event.phase === "settled")).toEqual([]);
      } else {
        expect(result.error).toBeNull();

        const sessions = z.array(z.record(z.string(), z.unknown())).parse(result.data);
        const ownerRows = before.sessions.filter(
          (row) => row.userId === initial.data!.session.userId && row.token !== expiredToken,
        );
        expect(sessions.map((row) => row.token)).toEqual(ownerRows.map((row) => row.token));
        expect(sessions.map((row) => row.label)).toEqual(
          ownerRows.map((row) => ({ stored: row.label })),
        );

        for (const session of sessions) {
          expect(session.userId).toBe(initial.data!.session.userId);
          for (const field of ["hidden", "omitted", "private_column"]) {
            expect(session).not.toHaveProperty(field);
          }
        }

        expect(sessions.some((row) => row.token === foreignToken)).toBe(false);
      }

      if (mode === "coordinated") {
        const ready = callbacks.findIndex(
          (event) =>
            event.phase === "output" &&
            event.field === "omitted" &&
            event.value === "collection-ready",
        );
        const completed = callbacks.findIndex(
          (event) => event.phase === "completed" && event.path === "/list-sessions",
        );
        expect(ready).toBeGreaterThanOrEqual(0);
        expect(completed).toBeGreaterThan(ready);
        expect(
          (
            await ctx.rawRequest({
              path: "/__test/additional-fields/rewind-session?profile=cached",
              method: "POST",
              json: { token: slowToken, expiresAt, releaseCollection: true },
            })
          ).status,
        ).toBe(200);
      }

      if (mode !== "coordinated") {
        await new Promise((resolve) => setTimeout(resolve, 550));
      }

      const after = await read();
      expect(after.physical).toEqual(before.physical);
      expect(
        after.events.slice(before.events.length).filter((event) => event.phase === "settled"),
      ).toEqual(
        (mode === "reject"
          ? ["collection-slow", "collection-slower"]
          : [mode === "coordinated" ? "collection-coordinated-slow" : "collection-slow"]
        ).map((value) => ({
          phase: "settled",
          entity: "session",
          field: "label",
          value,
          requestScoped: false,
          requestPath: "/list-sessions",
        })),
      );

      // The authenticated foreign caller can list only its own physical session.
      const cached = await owner.client.getSession();
      expect(cached.error).toBeNull();
      expect(cached.data?.session.token).toBe(token);

      const foreignList = await foreign.client.listSessions();
      expect(foreignList.error).toBeNull();
      expect(foreignList.data?.map((session) => session.token)).toEqual([foreignToken]);

      return {
        initial: ctx.snapshot(initial),
        before: before.sessions,
        result: ctx.snapshot(result),
        pending: callbacks,
        after: after.events.slice(before.events.length),
        cached: ctx.snapshot(cached),
        foreignList: ctx.snapshot(foreignList),
        final: (await read()).sessions,
      };
    },
    ["GET /list-sessions", "GET /get-session"],
  );
}
