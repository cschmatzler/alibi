/** Application adapter failures over the pinned, real SQL adapter. */
import type { Database } from "bun:sqlite";

import { createKyselyAdapter, kyselyAdapter } from "@better-auth/kysely-adapter";
import { betterAuth } from "better-auth";

export async function createSessionAdapterFailureFixture(
  base: Parameters<typeof betterAuth>[0],
  database: Database,
) {
  let mode = "";
  const events: string[] = [];
  const deletion = {
    held: "",
    reject: "",
    events: [] as { stage: string; token: string }[],
    heldGate: Promise.resolve(),
    rejectGate: Promise.resolve(),
    releaseHeld: () => {},
    releaseReject: () => {},
  };
  const actual = await createKyselyAdapter({ ...base, database });
  if (!actual.kysely) throw new Error("real Bun Kysely adapter required");
  const factory = kyselyAdapter(actual.kysely, { type: "sqlite" });
  function check(operation: string) {
    if (mode) events.push(operation);
    if (mode === operation) throw new Error("application-selected-session-adapter-failure");
  }
  const profiles = new Map(
    ["session-adapter-failure", "password-reset-no-sender"].map(
      (profile) =>
        [
          profile,
          betterAuth({
            ...base,
            basePath: `/__test/profiles/${profile}/api/auth`,
            ...(profile === "password-reset-no-sender"
              ? { emailAndPassword: { ...base.emailAndPassword, sendResetPassword: undefined } }
              : {}),
            plugins: [],
            database: (options) => {
              const adapter = factory(options);
              return {
                ...adapter,
                async findOne(args) {
                  if (args.model === "session") check("get_session");
                  if (
                    args.model === "user" &&
                    args.where.some((condition) => condition.field === "email")
                  )
                    check("get_user_by_email");
                  return adapter.findOne(args);
                },
                async findMany(args) {
                  if (args.model === "session") check("get_user_sessions");
                  return adapter.findMany(args);
                },
        async delete(args) {
          if (args.model === "session") check("delete_session");
          if (mode === "parallel" && args.model === "session") {
            const token = String(args.where.find((row) => row.field === "token")?.value);
            deletion.events.push({ stage: "started", token });
            if (token === deletion.held) await deletion.heldGate;
            if (token === deletion.reject) {
              await deletion.rejectGate;
              deletion.events.push({ stage: "rejected", token });
              throw new Error("Application sibling deletion rejected");
            }
            const result = await adapter.delete(args);
            deletion.events.push({ stage: "completed", token });
            return result;
          }
          return adapter.delete(args);
        },
                async deleteMany(args) {
                  if (args.model === "session") check("delete_user_sessions");
                  return adapter.deleteMany(args);
                },
              };
            },
          }),
        ] as const,
    ),
  );
  return {
    profiles,
    control(body: { mode?: string; operation?: string; heldToken?: string; rejectToken?: string }) {
      if (body.operation) {
        if (body.operation === "arm") {
          mode = "parallel";
          deletion.held = body.heldToken!;
          deletion.reject = body.rejectToken!;
          deletion.events.length = 0;
          deletion.heldGate = new Promise<void>((resolve) => {
            deletion.releaseHeld = resolve;
          });
          deletion.rejectGate = new Promise<void>((resolve) => {
            deletion.releaseReject = resolve;
          });
        }
        if (body.operation === "reject") deletion.releaseReject();
        if (body.operation === "release") deletion.releaseHeld();
        if (body.operation === "restore") {
          deletion.releaseHeld();
          deletion.releaseReject();
          mode = "";
        }
        return Response.json({ events: [...deletion.events] });
      }
      if (typeof body.mode === "string") {
        mode = body.mode;
        events.length = 0;
      }
      return Response.json({ mode, events: [...events] });
    },
  };
}
