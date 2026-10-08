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
    events: [] as unknown[],
    first: Promise.resolve(),
    releaseFirst: () => {},
  };
  const actual = await createKyselyAdapter({ ...base, database });
  if (!actual.kysely) throw new Error("real Bun Kysely adapter required");
  const factory = kyselyAdapter(actual.kysely, { type: "sqlite" });
  function check(operation: string) {
    if (mode) events.push(operation);
    if (mode === operation) throw new Error("application-selected-session-adapter-failure");
  }
  const auth = betterAuth({
    ...base,
    basePath: "/__test/profiles/session-adapter-failure/api/auth",
    plugins: [deviceAuthorization({ interval: "0s" })],
    database: (options) => {
      const adapter = factory(options);
      return {
        ...adapter,
        async findOne(args) {
          if (args.model === "session") check("get_session");
          if (args.model === "user" && args.where.some((condition) => condition.field === "email"))
            check("get_user_by_email");
          return adapter.findOne(args);
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
          return adapter.delete(args);
        },
        async deleteMany(args) {
          if (args.model === "session") check("delete_user_sessions");
          return adapter.deleteMany(args);
        },
      };
    },
  });
  return {
    auth,
    control(body: { mode?: string; operation?: string; gate?: string; id?: string }) {
      if (body.operation) {
        if (body.operation === "arm") {
          deviceGate.id = body.id!;
          deviceGate.mode = body.gate!;
          deviceGate.events.length = 0;
          deviceGate.first = new Promise<void>((resolve) => {
            deviceGate.releaseFirst = resolve;
          });
        }
        if (body.operation === "release-first") deviceGate.releaseFirst();
        if (body.operation === "restore") {
          deviceGate.releaseFirst();
          deviceGate.mode = "";
        }
        return Response.json({ events: [...deviceGate.events] });
      }
      if (typeof body.mode === "string") {
        mode = body.mode;
        events.length = 0;
      }
      return Response.json({ mode, events: [...events] });
    },
  };
}
