import { type BetterAuthOptions, betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import { customSession, jwt, multiSession } from "better-auth/plugins";

export function createCustomSessionFixture(base: BetterAuthOptions) {
  let counter = 0;
  const calls = new Map<string, number>();
  const application = {
    mode: "idle",
    held: "",
    reject: "",
    entered: 0,
    events: [] as unknown[],
    gate: Promise.resolve(),
    all: Promise.resolve(),
    release: () => {},
    both: () => {},
  };
  async function projectWork(session: any, ctx: any) {
    if (ctx.path !== "/multi-session/list-device-sessions" || application.mode === "idle") return;
    const token = session.session.token;
    const userId = session.user.id;
    const request = {
      path: ctx.path,
      method: ctx.request?.method ?? null,
      marker: ctx.headers?.get("x-device-list-marker") ?? null,
    };
    application.events.push({ stage: "started", token, userId, request });
    if (++application.entered === 2) application.both();
    if (token === application.held) {
      await application.gate;
      if (application.mode !== "success") {
        // Read the actual callback context after aggregate HTTP rejection.
        const late = {
          path: ctx.path,
          method: ctx.request?.method ?? null,
          marker: ctx.headers?.get("x-device-list-marker") ?? null,
        };
        const name = `${late.marker}@${late.path}`;
        const updated = await ctx.context.internalAdapter.updateUser(userId, { name });
        application.events.push({
          stage: "updated",
          token,
          userId: updated.id,
          request: late,
          name: updated.name,
        });
      } else application.events.push({ stage: "completed", token, userId, request });
    } else if (token === application.reject) {
      await application.all;
      if (application.mode !== "success") {
        application.events.push({ stage: "rejected", token, userId, request });
        if (application.mode === "coded")
          throw new APIError("FORBIDDEN", {
            code: "DEVICE_LIST_REJECTED",
            message: "Application device projection rejected",
          });
        throw new Error("Private device projection failure");
      }
      application.events.push({ stage: "completed", token, userId, request });
    }
  }
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();

  for (const name of [
    "custom-session-gated",
    "custom-session-list-default",
    "custom-session-list-false",
    "custom-session",
    "custom-session-jwt",
    "custom-session-deferred",
    "custom-session-core-error",
  ]) {
    const path = `/__test/profiles/${name}/api/auth`;
    profiles.set(
      path,
      betterAuth({
        ...base,
        basePath: path,
        session: {
          ...base.session,
          deferSessionRefresh: name.endsWith("-deferred"),
          additionalFields: {
            label: {
              type: "string",
              defaultValue: "custom-public-label",
              ...(name.endsWith("-core-error")
                ? {
                    transform: {
                      async output() {
                        throw new Error("Configured session projection failed");
                      },
                    },
                  }
                : {}),
            },
            hidden: { type: "string", defaultValue: "custom-server-secret", returned: false },
          },
        },
        databaseHooks: {
          session: {
            create: {
              async before(session) {
                return {
                  data: { ...session, token: `custom${String(++counter).padStart(27, "0")}` },
                };
              },
            },
          },
        },
        plugins: [
          customSession(
            async (session, ctx) => {
              const count = (calls.get(name) ?? 0) + 1;
              calls.set(name, count);
              const mode = ctx.headers?.get("x-custom-session");

              if (mode === "error") {
                throw new APIError("FORBIDDEN", {
                  code: "CUSTOM_SESSION_DENIED",
                  message: "Application session denied",
                });
              }

              if (mode === "ordinary") {
                throw new Error("Application session failed");
              }

              if (mode === "null") {
                return null;
              }

              if (mode === "filtered") {
                return { userId: session.user.id, label: session.user.name };
              }

              if (name === "custom-session-gated") await projectWork(session, ctx);
              const stored = await ctx.context.internalAdapter.findUserById(session.user.id);

              if (!stored) {
                throw new Error("Authenticated user is missing");
              }

              return {
                ...session,
                application: {
                  userId: stored.id,
                  label: stored.name,
                  path: ctx.path,
                  ...(name.startsWith("custom-session-list-") ? { calls: count } : {}),
                },
              };
            },
            undefined,
            name === "custom-session-list-default"
              ? undefined
              : { shouldMutateListDeviceSessionsEndpoint: name !== "custom-session-list-false" },
          ),
          multiSession(),
          ...(name.endsWith("-jwt") || name.endsWith("-deferred") ? [jwt()] : []),
        ],
      }),
    );
  }

  return {
    profiles,
    control(body?: {
      operation?: string;
      mode?: string;
      heldToken?: string;
      rejectToken?: string;
    }) {
      if (body?.operation === "arm") {
        application.mode = body.mode!;
        application.held = body.heldToken!;
        application.reject = body.rejectToken!;
        application.entered = 0;
        application.events.length = 0;
        application.gate = new Promise<void>((resolve) => {
          application.release = resolve;
        });
        application.all = new Promise<void>((resolve) => {
          application.both = resolve;
        });
      }
      if (body?.operation === "release") application.release();
      if (body?.operation === "restore") {
        application.release();
        application.both();
        application.mode = "idle";
      }
      return { events: [...application.events] };
    },
    reset() {
      counter = 0;
      calls.clear();
    },
  };
}
