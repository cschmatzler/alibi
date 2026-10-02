import { expect } from "bun:test";
import { z } from "zod";
import { compatScenario } from "../../support/scenario";

const stateSchema = z.object({
  sessions: z.array(z.record(z.string(), z.unknown())),
  events: z.array(z.record(z.string(), z.unknown())),
});
compatScenario(
  "update-session publishes transformed current-token cache and preserves sibling and foreign physical sessions",
  async (ctx) => {
    const profile = "additional-cached-fields";
    const owner = ctx.actor("projection-owner", profile),
      sibling = ctx.actor("projection-sibling", profile),
      foreign = ctx.actor("projection-foreign", profile);
    const email = ctx.uniqueEmail("projection-owner");
    expect(
      (
        await owner.client.signUp.email({
          email,
          name: "Projection owner",
          password: "Password123!",
        })
      ).error,
    ).toBeNull();
    expect(
      (await owner.client.signIn.email({ email, password: "Password123!", rememberMe: false }))
        .error,
    ).toBeNull();
    expect(
      (await sibling.client.signIn.email({ email, password: "Password123!" })).error,
    ).toBeNull();
    expect(
      (
        await foreign.client.signUp.email({
          email: ctx.uniqueEmail("projection-foreign"),
          name: "Foreign",
          password: "Password123!",
        })
      ).error,
    ).toBeNull();
    const initial = await owner.client.getSession();
    expect(initial.error).toBeNull();
    const token = z.string().parse(initial.data?.session.token);
    const read = async () => {
      const result = await ctx.rawRequest({
        path: "/__test/additional-fields/state?profile=cached",
      });
      expect(result.status).toBe(200);
      const state = stateSchema.parse(result.body);
      state.events = state.events.filter((event) => event.entity !== "account");
      return state;
    };
    const before = await read();
    let updateCookies: string[] = [];
    const updated = await owner.client.$fetch("/update-session", {
      method: "POST",
      body: {
        label: "configured-update",
        hidden: "updated-private",
        token: "forged-token",
        userId: "forged-owner",
      },
      onResponse({ response }) {
        updateCookies = response.headers.getSetCookie();
      },
    });
    expect(updated.error).toBeNull();
    for (const name of ["session_token", "session_data", "dont_remember"]) {
      const cookie = updateCookies.find((value) => value.startsWith(`better-auth.${name}=`));
      expect(cookie).toBeDefined();
      expect(cookie!.toLowerCase()).not.toContain("max-age=");
    }
    expect(updated.data).toMatchObject({
      session: { token, label: { stored: "configured-update" } },
    });
    for (const field of ["hidden", "omitted", "private_column"])
      expect(
        z.object({ session: z.record(z.string(), z.unknown()) }).parse(updated.data).session,
      ).not.toHaveProperty(field);
    const after = await read();
    expect(after.sessions.find((row) => row.token === token)).toMatchObject({
      label: "configured-update",
      hidden: "updated-private",
      omitted: "drop",
    });
    expect(after.sessions.filter((row) => row.token !== token)).toEqual(
      before.sessions.filter((row) => row.token !== token),
    );
    expect(after.events.filter((event) => event.phase === "on-update")).toEqual([]);
    const cached = await owner.client.getSession();
    expect(cached.error).toBeNull();
    expect(cached.data?.session).toMatchObject({ token, label: { stored: "configured-update" } });
    const physical = await owner.client.getSession({ query: { disableCookieCache: true } });
    expect(physical.error).toBeNull();
    expect(physical.data?.session).toMatchObject({ token, label: { stored: "configured-update" } });
    const omitted = await owner.client.$fetch("/update-session", {
      method: "POST",
      body: { hidden: "private-second" },
    });
    expect(omitted.error).toBeNull();
    expect(omitted.data).toMatchObject({
      session: { token, label: { stored: "session-updated" } },
    });
    const final = await read();
    expect(final.events.filter((event) => event.phase === "on-update")).toEqual([
      { phase: "on-update", entity: "session", field: "label" },
    ]);
    expect(final.sessions.find((row) => row.token === token)).toMatchObject({
      label: "session-updated",
      hidden: "private-second",
    });
    expect(final.sessions.filter((row) => row.token !== token)).toEqual(
      before.sessions.filter((row) => row.token !== token),
    );
    const replacement = await owner.client.changePassword({
      currentPassword: "Password123!",
      newPassword: "Replacement184!",
      revokeOtherSessions: true,
    });
    expect(replacement.error).toBeNull();
    const replacementToken = z.string().parse(replacement.data?.token);
    expect(replacementToken).not.toBe(token);
    const replaced = await owner.client.getSession();
    expect(replaced.error).toBeNull();
    expect(replaced.data?.session).toMatchObject({
      token: replacementToken,
      label: { stored: "session-initial" },
    });
    const replacementState = await read();
    expect(replacementState.sessions.find((row) => row.token === replacementToken)).toMatchObject({
      label: "session-initial",
      hidden: "session-secret",
      omitted: "drop",
    });
    const ownerId = initial.data!.session.userId;
    expect(
      replacementState.sessions.filter((row) => row.userId === ownerId).map((row) => row.token),
    ).toEqual([replacementToken]);
    expect(replacementState.sessions.filter((row) => row.userId !== ownerId)).toEqual(
      before.sessions.filter((row) => row.userId !== ownerId),
    );
    expect(
      (await sibling.client.getSession({ query: { disableCookieCache: true } })).data,
    ).toBeNull();
    return {
      initial: ctx.snapshot(initial),
      before,
      updated: ctx.snapshot(updated),
      after,
      cached: ctx.snapshot(cached),
      physical: ctx.snapshot(physical),
      omitted: ctx.snapshot(omitted),
      final,
      replacement: ctx.snapshot(replacement),
      replaced: ctx.snapshot(replaced),
      replacementState,
    };
  },
  ["POST /update-session", "GET /get-session"],
);

compatScenario(
  "update-session rejects asynchronous validators before callbacks and binding while preserving raw numeric inputs",
  async (ctx) => {
    const actor = ctx.actor("async-session", "additional-async-validation-fields");
    expect(
      (
        await actor.client.signUp.email({
          email: ctx.uniqueEmail("async-session"),
          name: "Async session",
          password: "Password123!",
        })
      ).error,
    ).toBeNull();
    const read = async () => {
      const result = await ctx.rawRequest({
        path: "/__test/additional-fields/state?profile=async-validation",
      });
      expect(result.status).toBe(200);
      const state = stateSchema.parse(result.body);
      state.events = state.events.filter((event) => event.entity !== "account");
      return state;
    };
    const before = await read(),
      responses = [];
    for (const literal of ['"attempt"', "1e999", "-0"]) {
      const response = await actor.fetch(
        `${ctx.baseURL}/__test/profiles/additional-async-validation-fields/api/auth/update-session`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: `{"label":${literal}}`,
        },
      );
      expect(response.status).toBe(500);
      const body = await response.json();
      expect(body).toMatchObject({
        code: "ASYNC_VALIDATION_NOT_SUPPORTED",
        message: "Async validation is not supported",
      });
      responses.push({ status: response.status, body });
    }
    const after = await read();
    expect(after.sessions).toEqual(before.sessions);
    expect(after.events.filter((event) => event.phase === "after")).toEqual(
      before.events.filter((event) => event.phase === "after"),
    );
    expect(after.events.filter((event) => event.phase === "validation")).toEqual([
      {
        phase: "validation",
        entity: "session",
        field: "label",
        value: "attempt",
        negativeZero: false,
        infinite: false,
      },
      {
        phase: "validation",
        entity: "session",
        field: "label",
        value: null,
        negativeZero: false,
        infinite: true,
      },
      {
        phase: "validation",
        entity: "session",
        field: "label",
        value: 0,
        negativeZero: true,
        infinite: false,
      },
    ]);
    return { before, responses, after };
  },
  ["POST /update-session"],
);

for (const expiry of [false, true])
  for (const command of [
    "mutate",
    "cancel",
    "ordinary-error",
    "api-error",
    "after-error",
    "throw",
    "delete",
  ] as const)
    compatScenario(
      `session ${expiry ? "expiry renewal" : "configured update"} observes ${command} callback and physical commit boundary`,
      async (ctx) => {
        const actor = ctx.actor("hook-owner", "additional-cached-fields"),
          sibling = ctx.actor("hook-sibling", "additional-cached-fields"),
          foreign = ctx.actor("hook-foreign", "additional-cached-fields");
        const email = ctx.uniqueEmail("hook-owner");
        expect(
          (await actor.client.signUp.email({ email, name: "Hook owner", password: "Password123!" }))
            .error,
        ).toBeNull();
        expect(
          (await sibling.client.signIn.email({ email, password: "Password123!" })).error,
        ).toBeNull();
        expect(
          (
            await foreign.client.signUp.email({
              email: ctx.uniqueEmail("hook-foreign"),
              name: "Foreign",
              password: "Password123!",
            })
          ).error,
        ).toBeNull();
        const initial = await actor.client.getSession();
        const token = z.string().parse(initial.data?.session.token);
        const read = async () => {
          const result = await ctx.rawRequest({
            path: "/__test/additional-fields/state?profile=cached",
          });
          expect(result.status).toBe(200);
          const state = stateSchema.parse(result.body);
          state.events = state.events.filter((event) => event.entity !== "account");
          return state;
        };
        if (expiry) {
          // Operator setup bypasses auth callbacks only to make the persisted session due for renewal.
          const setup = await ctx.rawRequest({
            path: "/__test/additional-fields/rewind-session?profile=cached",
            method: "POST",
            json: {
              token,
              expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
              hidden: command,
            },
          });
          expect(setup.status).toBe(200);
        }
        const before = await read();
        const result = expiry
          ? await actor.client.getSession({ query: { disableCookieCache: true } })
          : await actor.client.$fetch("/update-session", {
              method: "POST",
              body: {
                hidden: command,
                label: command === "after-error" || command === "throw" ? command : "requested",
              },
            });
        const after = await read();
        expect(after.sessions.filter((row) => row.token !== token)).toEqual(
          before.sessions.filter((row) => row.token !== token),
        );
        const row = after.sessions.find((row) => row.token === token),
          prior = before.sessions.find((row) => row.token === token)!;
        if (command === "mutate") {
          expect(result.error).toBeNull();
          expect(result.data).toMatchObject({
            session: { token, label: { stored: "hook-updated" } },
          });
          expect(row).toMatchObject({ label: "hook-updated" });
        } else if (command === "cancel" || command === "delete") {
          expect(result.error).toMatchObject({ status: 401, code: "FAILED_TO_GET_SESSION" });
          if (command === "cancel") expect(row).toEqual(prior);
          else expect(row).toBeUndefined();
          expect((await actor.client.getSession()).data).toBeNull();
        } else {
          expect(result.error?.status).toBe(command === "api-error" ? 403 : 500);
          if (command === "api-error")
            expect(result.error).toMatchObject({
              code: "APP_DENIED",
              message: "Application denied",
            });
          if (command === "ordinary-error" || command === "api-error") expect(row).toEqual(prior);
          else expect(row).toMatchObject({ label: command });
        }
        const callbacks = after.events
          .slice(before.events.length)
          .filter((event) => event.phase === "before" || event.phase === "after");
        expect(callbacks[0]).toMatchObject({
          phase: "before",
          entity: "session",
          fields: expiry
            ? {}
            : {
                hidden: command,
                label: command === "after-error" || command === "throw" ? command : "requested",
              },
        });
        if (command === "mutate")
          expect(callbacks.find((event) => event.phase === "after")).toMatchObject({
            action: "update",
            record: { token, label: { stored: "hook-updated" }, hidden: "MUTATE" },
            persisted: { sessions: 2 },
          });
        if (
          command === "cancel" ||
          command === "ordinary-error" ||
          command === "api-error" ||
          command === "throw" ||
          command === "after-error"
        )
          expect(callbacks).toHaveLength(1);
        return {
          before,
          result: ctx.snapshot(result),
          after: { sessions: after.sessions, callbacks },
        };
      },
      ["POST /update-session", "GET /get-session"],
    );

compatScenario(
  "session replacement continues after collection rejection while launched callbacks retain deleted physical snapshots",
  async (ctx) => {
    const owner = ctx.actor("collection-owner", "additional-cached-fields"),
      rejecting = ctx.actor("collection-rejecting", "additional-cached-fields"),
      slow = ctx.actor("collection-slow", "additional-cached-fields");
    const email = ctx.uniqueEmail("collection-owner");
    expect(
      (
        await owner.client.signUp.email({
          email,
          name: "Collection owner",
          password: "Password123!",
        })
      ).error,
    ).toBeNull();
    expect(
      (await rejecting.client.signIn.email({ email, password: "Password123!" })).error,
    ).toBeNull();
    expect((await slow.client.signIn.email({ email, password: "Password123!" })).error).toBeNull();
    const rejectedToken = z
        .string()
        .parse((await rejecting.client.getSession()).data?.session.token),
      slowToken = z.string().parse((await slow.client.getSession()).data?.session.token);
    const expiresAt = new Date(Date.now() + 86_400_000 * 6).toISOString();
    for (const [token, label] of [
      [rejectedToken, "collection-reject"],
      [slowToken, "collection-slow"],
    ])
      expect(
        (
          await ctx.rawRequest({
            path: "/__test/additional-fields/rewind-session?profile=cached",
            method: "POST",
            json: { token, label, expiresAt },
          })
        ).status,
      ).toBe(200);
    const read = async () => {
      const result = await ctx.rawRequest({
        path: "/__test/additional-fields/state?profile=cached",
      });
      expect(result.status).toBe(200);
      const state = stateSchema.parse(result.body);
      state.events = state.events.filter((event) => event.entity !== "account");
      return state;
    };
    const before = await read();
    expect(before.sessions.find((row) => row.token === rejectedToken)?.label).toBe(
      "collection-reject",
    );
    expect(before.sessions.find((row) => row.token === slowToken)?.label).toBe("collection-slow");
    const result = await owner.client.changePassword({
      currentPassword: "Password123!",
      newPassword: "Replacement184!",
      revokeOtherSessions: true,
    });
    expect(result.error).toBeNull();
    const replacementToken = z.string().parse(result.data?.token);
    const pending = await read();
    expect(pending.sessions.map((row) => row.token)).toEqual([replacementToken]);
    expect(pending.events.filter((event) => event.phase === "settled")).toEqual([]);
    expect(
      pending.events.filter(
        (event) =>
          event.phase === "output" &&
          event.entity === "session" &&
          event.value === "collection-slow",
      ),
    ).toHaveLength(1);
    await new Promise((resolve) => setTimeout(resolve, 350));
    const final = await read();
    expect(final.events.filter((event) => event.phase === "settled")).toEqual([
      {
        phase: "settled",
        entity: "session",
        field: "label",
        value: "collection-slow",
        requestScoped: true,
      },
    ]);
    expect(final.sessions).toEqual(pending.sessions);
    // State reads are real HTTP observations; callback receipts remain independently comparable.
    return {
      sessions: before.sessions,
      result: ctx.snapshot(result),
      pending: pending.events.slice(before.events.length),
      final: final.events.slice(before.events.length),
    };
  },
  ["POST /change-password"],
);
