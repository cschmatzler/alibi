/** Application adapter failures over the pinned, real SQL adapter. */
import type { Database } from "bun:sqlite";

import { createKyselyAdapter, kyselyAdapter } from "@better-auth/kysely-adapter";
import { betterAuth } from "better-auth";
import { deviceAuthorization } from "better-auth/plugins";

export async function createSessionAdapterFailureFixture(
  base: Parameters<typeof betterAuth>[0],
  database: Database,
) {
  let mode = "";
  const events: string[] = [];
  const deviceGate = {
    id: "",
    mode: "",
    count: 0,
    events: [] as unknown[],
    first: Promise.resolve(),
    second: Promise.resolve(),
    releaseFirst: () => {},
    releaseSecond: () => {},
  };
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
            plugins:
              profile === "session-adapter-failure"
                ? [deviceAuthorization({ interval: "0s" })]
                : [],
            database: (options) => {
              const adapter = factory(options);
              return {
                ...adapter,
                async findOne(args) {
                  if (args.model === "session") check("get_session");
                  if (
                    args.model === "user" &&
                    args.where.some((condition) => condition.field === "email")
                  ) {
                    check("get_user_by_email");
                  }
                  const row = await adapter.findOne(args);
                  if (
                    deviceGate.mode === "review" &&
                    args.model === "deviceCode" &&
                    args.where.some((condition) => condition.field === "userCode") &&
                    row?.id === deviceGate.id
                  ) {
                    const ordinal = ++deviceGate.count;
                    if (ordinal <= 2) {
                      deviceGate.events.push({
                        operation: "review",
                        ordinal,
                        id: row.id,
                        userId: row.userId ?? null,
                      });
                      await (ordinal === 1 ? deviceGate.first : deviceGate.second);
                    }
                  }
                  return row;
                },
                async findMany(args) {
                  if (args.model === "session") check("get_user_sessions");
                  return adapter.findMany(args);
                },
                async consumeOne(args) {
                  if (
                    deviceGate.mode === "consume" &&
                    args.model === "deviceCode" &&
                    args.where.some(
                      (condition) => condition.field === "id" && condition.value === deviceGate.id,
                    )
                  ) {
                    deviceGate.events.push({ operation: "consume", id: deviceGate.id });
                    await deviceGate.first;
                  }
                  return adapter.consumeOne(args);
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
    control(body: {
      mode?: string;
      operation?: string;
      heldToken?: string;
      rejectToken?: string;
      gate?: string;
      id?: string;
    }) {
      if (body.operation && (body.gate || deviceGate.mode)) {
        if (body.operation === "arm") {
          deviceGate.id = body.id!;
          deviceGate.mode = body.gate!;
          deviceGate.events.length = 0;
          deviceGate.count = 0;
          deviceGate.first = new Promise<void>((resolve) => {
            deviceGate.releaseFirst = resolve;
          });
          deviceGate.second = new Promise<void>((resolve) => {
            deviceGate.releaseSecond = resolve;
          });
        }
        if (body.operation === "release-first") deviceGate.releaseFirst();
        if (body.operation === "release-second") deviceGate.releaseSecond();
        if (body.operation === "restore") {
          deviceGate.releaseSecond();
          deviceGate.releaseFirst();
          deviceGate.mode = "";
        }
        return Response.json({ events: [...deviceGate.events] });
      }
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
