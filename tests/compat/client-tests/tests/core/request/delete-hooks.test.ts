import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { adminClient } from "better-auth/client/plugins";

import { compatScenario } from "../../../support/scenario";
for (const model of ["user", "session", "account"] as const)
  for (const mode of ["continue", "cancel", "data", "before-error", "after-error"] as const) {
    compatScenario(
      `${model} database delete hooks ${mode} preserve real callback snapshots and committed effects`,
      async (ctx) => {
        const owner = ctx.actor("owner", "delete-hooks");
        const email = ctx.uniqueEmail("delete-hooks");
        const signup = await owner.client.signUp.email({
          email,
          password: "password123",
          name: "Delete target",
        });
        expect(signup.error).toBeNull();
        const userId = signup.data!.user.id;
        if (model === "account")
          await ctx.seedOAuthAccount({
            email,
            providerId: "mock",
            accountId: ctx.uniqueToken("delete-provider"),
          });
        const project = (physical: any) => ({
          ...physical,
          user: physical.user && {
            id: physical.user.id,
            email: physical.user.email,
            emailVerified: physical.user.emailVerified,
          },
        });
        const before = project(await ctx.readUserState({ userId }));
        const rowId =
          model === "user"
            ? userId
            : model === "session"
              ? before.sessions[0].id
              : before.accounts.find((a: any) => a.providerId === "mock").id;
        const makeAdmin = (fetch: ReturnType<typeof ctx.actor>["fetch"]) =>
          createAuthClient({
            baseURL: ctx.baseURL,
            plugins: [adminClient()],
            fetchOptions: { customFetchImpl: fetch },
          });
        let administrator: ReturnType<typeof makeAdmin> | undefined;
        if (model === "user") {
          const admin = ctx.actor("admin", "delete-hooks");
          const adminEmail = ctx.uniqueEmail("hook-admin");
          expect(
            (
              await admin.client.signUp.email({
                email: adminEmail,
                password: "password123",
                name: "Delete admin",
              })
            ).error,
          ).toBeNull();
          await ctx.promoteAdmin({ email: adminEmail });
          administrator = createAuthClient({
            baseURL: ctx.baseURL,
            plugins: [adminClient()],
            fetchOptions: { customFetchImpl: admin.fetch },
          });
        }
        const arm = await ctx.rawRequest({
          path: "/__test/delete-hooks/control",
          method: "POST",
          json: { model, mode },
        });
        expect(arm.status).toBe(200);
        const deleted =
          model === "user"
            ? await administrator!.admin.removeUser({ userId })
            : model === "session"
              ? await owner.client.revokeSession({ token: signup.data!.token! })
              : await owner.client.unlinkAccount({ accountId: rowId });
        const after = project(await ctx.readUserState({ userId }));
        const callbacks = await ctx.rawRequest({ path: "/__test/delete-hooks/control" });
        const state = callbacks.body as any;
        const retained = mode === "cancel" || mode === "before-error";
        if (model === "user") expect(after.user !== null).toBe(retained);
        else if (model === "session")
          expect(after.sessions.some((s: any) => s.id === rowId)).toBe(retained);
        else expect(after.accounts.some((a: any) => a.id === rowId)).toBe(retained);
        expect(state.events).toEqual([
          { model, phase: "before", rowId },
          ...(retained ? [] : [{ model, phase: "after", rowId }]),
        ]);
        expect(state.receipts).toEqual(retained ? [] : [{ model, rowId }]);
        if (mode.endsWith("error")) expect(deleted.error).not.toBeNull();
        else expect(deleted.error).toBeNull();
        return ctx.snapshot({
          before,
          deleted,
          after,
          callbacks: {
            ...callbacks,
            body: {
              events: state.events.map((event: any) => ({ ...event, rowId: { id: event.rowId } })),
              receipts: state.receipts.map((receipt: any) => ({
                ...receipt,
                rowId: { id: receipt.rowId },
              })),
            },
          },
        });
      },
      ["POST /admin/remove-user", "POST /revoke-session", "POST /unlink-account"],
    );
  }
