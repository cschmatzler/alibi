/** Trusted controlled interface to the actual pinned server-only operation. */
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { createAuthMiddleware } from "better-auth/api";
import { hashPassword, verifyPassword } from "better-auth/crypto";
import { twoFactor } from "better-auth/plugins";
import type { Database } from "bun:sqlite";
export function createSetPasswordFixture(
  database: Database,
  options: BetterAuthOptions,
) {
  const events: Record<string, unknown>[] = [];
  let mode = "normal",
    waiters: (() => void)[] = [],
    ordinal = 0,
    firstHash: string | undefined,
    watchUserId = "";
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  for (const name of [
    "set-password-default",
    "set-password-policy",
    "set-password-cache",
  ]) {
    profiles.set(
      name,
      betterAuth({
        ...options,
        plugins: [twoFactor()],
        hooks: {
          before: createAuthMiddleware(async (ctx) => {
            const token = ctx.headers?.get("x-test-virtual-token");
            if (token) {
              const physical =
                await ctx.context.internalAdapter.findSession(token);
              if (physical) {
                ctx.context.session = physical;
                events.push({
                  stage: "virtual-session",
                  session: physical.session,
                  user: physical.user,
                });
              }
            }
          }),
        },
        basePath: `/__test/profiles/${name}/api/auth`,
        session: {
          ...options.session,
          ...(name === "set-password-cache"
            ? { cookieCache: { enabled: true, maxAge: 300 } }
            : {}),
        },
        emailAndPassword: {
          ...options.emailAndPassword,
          enabled: true,
          minPasswordLength: name === "set-password-policy" ? 10 : 8,
          maxPasswordLength: name === "set-password-policy" ? 20 : 128,
          password: {
            async hash(password) {
              const order = mode === "barrier" ? ordinal++ : undefined;
              events.push({
                stage: "hash-enter",
                password,
                ...(order !== undefined ? { order } : {}),
              });
              const hash = await hashPassword(password);
              if (mode === "barrier") {
                if (order === 0) firstHash = hash;
                await new Promise<void>((resolve) => {
                  waiters.push(resolve);
                  if (waiters.length === 2) {
                    const released = waiters;
                    waiters = [];
                    released.forEach((release) => release());
                  }
                });
                if (order === 1) {
                  const deadline = Date.now() + 3000;
                  while (
                    !database
                      .query(
                        "SELECT id FROM account WHERE userId=? AND password=?",
                      )
                      .get(watchUserId, firstHash!)
                  ) {
                    if (Date.now() > deadline)
                      throw new Error(
                        "Actual credential write did not complete",
                      );
                    await new Promise((resolve) => setTimeout(resolve, 5));
                  }
                }
              }
              events.push({
                stage: "hash-result",
                password,
                hash,
                ...(order !== undefined ? { order } : {}),
              });
              if (mode === "hash-error")
                throw new Error("Actual configured hash callback failed");
              return hash;
            },
            verify: verifyPassword,
          },
        },
      }),
    );
  }
  return {
    profiles,
    async handle(request: Request): Promise<Response | undefined> {
      const url = new URL(request.url);
      if (url.pathname === "/__test/set-password/state") {
        const instance = profiles.get("set-password-default")!,
          ctx = await instance.$context;
        const read = (model: "user" | "account" | "session") =>
          ctx.adapter.findMany<Record<string, unknown>>({
            model,
            sortBy: { field: "createdAt", direction: "asc" },
          });
        return Response.json({
          users: await read("user"),
          accounts: await read("account"),
          sessions: await read("session"),
          events,
        });
      }
      if (
        !["/__test/set-password", "/__test/server-api/set-password"].includes(
          url.pathname,
        ) ||
        request.method !== "POST"
      )
        return;
      const body = (await request.json()) as {
        operation?: string;
        profile?: string;
        newPassword?: string;
        mode?: string;
        accountId?: string;
        userId?: string;
        token?: string;
        expiresAt?: string;
      };
      const instance = profiles.get(body.profile ?? "set-password-default");
      if (!instance)
        return Response.json(
          { message: "unknown fixture profile" },
          { status: 400 },
        );
      const ctx = await instance.$context;
      if (body.operation === "mode") {
        mode = body.mode ?? "normal";
        events.length = 0;
        ordinal = 0;
        firstHash = undefined;
        watchUserId = body.userId ?? "";
        return Response.json({ status: true, mode });
      }
      if (body.operation === "misbind-credential") {
        await ctx.internalAdapter.updateAccount(body.accountId!, {
          accountId: body.userId!,
          password: null,
        });
        return Response.json({ status: true });
      }
      if (body.operation === "clear-password") {
        await ctx.internalAdapter.updateAccount(body.accountId!, {
          password: null,
        });
        return Response.json({ status: true });
      }
      if (body.operation === "revoke") {
        await ctx.internalAdapter.deleteSession(body.token!);
        return Response.json({ status: true });
      }
      if (body.operation === "expire") {
        await ctx.adapter.update({
          model: "session",
          where: [{ field: "token", value: body.token }],
          update: {
            expiresAt: new Date(body.expiresAt!),
            updatedAt: new Date(body.expiresAt!),
          },
        });
        return Response.json({ status: true });
      }
      if (body.operation === "set") {
        let trigger = false;
        try {
          if (mode === "create-error" || mode === "update-error") {
            database.run(
              `CREATE TEMP TRIGGER set_password_store_failure BEFORE ${mode === "create-error" ? "INSERT" : "UPDATE"} ON account WHEN NEW.providerId='credential' BEGIN SELECT RAISE(ABORT, 'Actual configured credential write failed'); END`,
            );
            trigger = true;
          }
          return await instance.api.setPassword({
            body: {
              newPassword: body.newPassword!,
              ...(body.userId ? { userId: body.userId } : {}),
            },
            headers: request.headers,
            asResponse: true,
          });
        } finally {
          if (trigger) database.run("DROP TRIGGER set_password_store_failure");
        }
      }
      return Response.json({ message: "unknown operation" }, { status: 400 });
    },
  };
}
