import { type BetterAuthPlugin } from "better-auth";
import { createAuthMiddleware } from "better-auth/api";

export const lifecycleEvents: unknown[] = [];

function returnedStatus(value: unknown): number {
  if (
    value &&
    typeof value === "object" &&
    "statusCode" in value &&
    typeof value.statusCode === "number"
  ) {
    return value.statusCode;
  }
  return 200;
}

export function lifecycleFixture(): BetterAuthPlugin {
  return {
    id: "lifecycle-fixture",
    hooks: {
      before: [
        {
          matcher: (ctx) => !!ctx.headers?.get("x-parity-lifecycle"),
          handler: createAuthMiddleware(async (ctx) => {
            lifecycleEvents.push({ stage: "before", path: ctx.path });
            if (ctx.headers?.get("x-parity-lifecycle") === "stop") {
              return ctx.json({ stopped: true });
            }
          }),
        },
      ],
      after: [
        {
          matcher: (ctx) => !!ctx.headers?.get("x-parity-lifecycle"),
          handler: createAuthMiddleware(async (ctx) => {
            lifecycleEvents.push({
              stage: "after",
              path: ctx.path,
              status: returnedStatus(ctx.context.returned),
            });
            ctx.setHeader("x-lifecycle-queued", "visible");
            ctx.setHeader("set-cookie", "lifecycle=value; HttpOnly; Path=/; SameSite=Lax");
            if (ctx.headers?.get("x-parity-lifecycle") === "reject") {
              throw ctx.error("FORBIDDEN", { message: "fixture after rejection" });
            }
          }),
        },
        {
          matcher: (ctx) => !!ctx.headers?.get("x-parity-lifecycle"),
          handler: createAuthMiddleware(async (ctx) => {
            const visible = ctx.context.responseHeaders?.get("x-lifecycle-queued") ?? null;
            lifecycleEvents.push({
              stage: "observe",
              path: ctx.path,
              header: visible,
              status: returnedStatus(ctx.context.returned),
              cookieCount: ctx.context.responseHeaders?.getSetCookie().length ?? 0,
            });
            ctx.setHeader("x-lifecycle-observed", visible ?? "missing");
          }),
        },
      ],
    },
  };
}
