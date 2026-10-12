import type { Database } from "bun:sqlite";

import { type BetterAuthOptions, betterAuth } from "better-auth";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { admin, twoFactor, username } from "better-auth/plugins";
import { createAccessControl } from "better-auth/plugins/access";

/** Immutable application roles run through the actual pinned admin plugin. */
export function createAdminPermissionFixture(base: BetterAuthOptions, database: Database) {
  const access = createAccessControl({
    user: ["get", "create", "set-role", "update", "impersonate", "impersonate-admins"],
  });
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();

  for (const name of [
    "admin-impersonation-privileged",
    "admin-impersonation-ordinary",
    "admin-impersonation-legacy",
    "admin-impersonation-no-base",
    "admin-standard",
    "admin-server-cache",
    "admin-deny-all",
    "admin-exact-role",
    "admin-empty-role",
    "admin-role-manager",
    "admin-role-creator",
    "admin-duration-zero",
    "admin-duration-fractional",
    "admin-duration-negative",
    "admin-duration-invalid",
    "admin-duration-nan",
    "admin-duration-hook-error",
  ]) {
    const path = `/__test/profiles/${name}/api/auth`;
    profiles.set(
      path,
      betterAuth({
        ...base,
        ...(name === "admin-server-cache"
          ? {
              session: {
                ...base.session,
                cookieCache: { enabled: true, strategy: "compact", maxAge: 300 },
              },
            }
          : {}),
        hooks: {
          after: createAuthMiddleware(async (ctx) => {
            if (
              [
                "/admin/get-user",
                "/admin/set-role",
                "/admin/create-user",
                "/admin/has-permission",
                "/admin/update-user",
                "/admin/list-users",
                "/admin/list-user-sessions",
                "/admin/unban-user",
                "/admin/ban-user",
                "/admin/revoke-user-session",
                "/admin/revoke-user-sessions",
                "/admin/remove-user",
                "/admin/set-user-password",
                "/admin/impersonate-user",
                "/admin/stop-impersonating",
              ].includes(ctx.path) &&
              !ctx.request
            ) {
              ctx.context.responseHeaders ??= new Headers();
              if (ctx.context.session?.user.email) {
                ctx.context.responseHeaders.set(
                  "x-admin-principal",
                  ctx.context.session.user.email,
                );
              }
              ctx.context.responseHeaders.append(
                "set-cookie",
                "application_a=first; Path=/; HttpOnly",
              );
              ctx.context.responseHeaders.append(
                "set-cookie",
                "application_b=second; Path=/; HttpOnly",
              );
            }
          }),
        },
        ...(name === "admin-duration-hook-error"
          ? {
              databaseHooks: {
                ...base.databaseHooks,
                user: {
                  ...base.databaseHooks?.user,
                  update: {
                    ...base.databaseHooks?.user?.update,
                    before: async (user) => {
                      if ("banned" in user && user.banned === true) {
                        throw new APIError("FORBIDDEN", {
                          code: "APPLICATION_BAN_REFUSED",
                          message: "Invalid Date",
                        });
                      }
                    },
                  },
                },
                session: {
                  ...base.databaseHooks?.session,
                  create: {
                    ...base.databaseHooks?.session?.create,
                    before: async (session) => {
                      if ("impersonatedBy" in session && session.impersonatedBy) {
                        throw new APIError("INTERNAL_SERVER_ERROR", {
                          code: "APPLICATION_SESSION_REFUSED",
                          message: "Invalid Date",
                        });
                      }
                    },
                  },
                },
              },
            }
          : {}),
        basePath: path,
        plugins: [
          username(),
          twoFactor(),
          admin({
            ...(name === "admin-duration-zero"
              ? {
                  defaultBanReason: "",
                  defaultBanExpiresIn: 0,
                  impersonationSessionDuration: 0,
                }
              : {}),
            ...(name === "admin-duration-fractional"
              ? {
                  defaultBanReason: "configured reason",
                  defaultBanExpiresIn: 300.875,
                  impersonationSessionDuration: 120.75,
                }
              : {}),
            ...(name === "admin-duration-negative"
              ? {
                  defaultBanExpiresIn: -60.25,
                  impersonationSessionDuration: -10.5,
                }
              : {}),
            ...(name === "admin-duration-invalid"
              ? {
                  defaultBanExpiresIn: Infinity,
                  impersonationSessionDuration: Infinity,
                }
              : {}),
            ...(name === "admin-duration-nan"
              ? { defaultBanExpiresIn: NaN, impersonationSessionDuration: NaN }
              : {}),
            defaultRole: name.startsWith("admin-impersonation-")
              ? "operator"
              : name === "admin-role-manager"
                ? "manager"
                : name === "admin-role-creator"
                  ? "creator"
                  : name === "admin-exact-role"
                    ? "user, admin"
                    : name === "admin-empty-role"
                      ? ""
                      : "admin",
            ...(name.startsWith("admin-role-")
              ? {
                  roles: {
                    manager: access.newRole({
                      user: ["get", "create", "set-role", "update"],
                    }),
                    creator: access.newRole({ user: ["create"] }),
                    user: access.newRole({ user: ["get"] }),
                    "": access.newRole({ user: ["get"] }),
                  },
                }
              : {}),
            ...(name.startsWith("admin-impersonation-")
              ? {
                  roles: {
                    operator: access.newRole({
                      user:
                        name === "admin-impersonation-privileged"
                          ? ["set-role", "impersonate", "impersonate-admins"]
                          : name === "admin-impersonation-no-base"
                            ? ["set-role", "impersonate-admins"]
                            : ["set-role", "impersonate"],
                    }),
                    admin: access.newRole({ user: [] }),
                  },
                  ...(name === "admin-impersonation-legacy"
                    ? { allowImpersonatingAdmins: true }
                    : {}),
                }
              : {}),
            ...(name === "admin-deny-all" ? { roles: {} } : {}),
            ...(name === "admin-empty-role"
              ? { roles: { user: access.newRole({ user: ["get"] }) } }
              : {}),
          }),
        ],
      }),
    );
  }

  return {
    profiles,
    handle(request: Request) {
      const url = new URL(request.url);

      if (url.pathname === "/__test/admin/server-api" && request.method === "POST") {
        return (async () => {
          const input = (await request.json()) as {
            operation?:
              | "getUser"
              | "setRole"
              | "createUser"
              | "userHasPermission"
              | "adminUpdateUser"
              | "listUsers"
              | "listUserSessions"
              | "unbanUser"
              | "banUser"
              | "revokeUserSession"
              | "revokeUserSessions"
              | "removeUser"
              | "setUserPassword"
              | "impersonateUser"
              | "stopImpersonating";
            profile?: string;
            query?: unknown;
            body?: unknown;
            headers?: Record<string, string>;
          };
          const auth = profiles.get(
            `/__test/profiles/${input.profile ?? "admin-standard"}/api/auth`,
          )!;
          if (input.operation === "stopImpersonating") {
            return auth.api.stopImpersonating({
              ...(Object.hasOwn(input, "body") ? { body: input.body } : {}),
              ...(Object.hasOwn(input, "query") ? { query: input.query } : {}),
              ...(input.headers ? { headers: new Headers(input.headers) } : {}),
              asResponse: true,
            });
          }
          if (input.operation === "impersonateUser") {
            return auth.api.impersonateUser({
              body: input.body as { userId: string },
              ...(Object.hasOwn(input, "query") ? { query: input.query } : {}),
              ...(input.headers ? { headers: new Headers(input.headers) } : {}),
              asResponse: true,
            });
          }
          if (input.operation === "setUserPassword") {
            return auth.api.setUserPassword({
              body: input.body as { userId: string; newPassword: string },
              ...(Object.hasOwn(input, "query") ? { query: input.query } : {}),
              ...(input.headers ? { headers: new Headers(input.headers) } : {}),
              asResponse: true,
            });
          }
          if (input.operation === "removeUser") {
            return auth.api.removeUser({
              body: input.body as { userId: string },
              ...(Object.hasOwn(input, "query") ? { query: input.query } : {}),
              ...(input.headers ? { headers: new Headers(input.headers) } : {}),
              asResponse: true,
            });
          }
          if (input.operation === "revokeUserSessions") {
            return auth.api.revokeUserSessions({
              body: input.body as { userId: string },
              ...(Object.hasOwn(input, "query") ? { query: input.query } : {}),
              ...(input.headers ? { headers: new Headers(input.headers) } : {}),
              asResponse: true,
            });
          }
          if (input.operation === "revokeUserSession") {
            return auth.api.revokeUserSession({
              body: input.body as { sessionToken: string },
              ...(Object.hasOwn(input, "query") ? { query: input.query } : {}),
              ...(input.headers ? { headers: new Headers(input.headers) } : {}),
              asResponse: true,
            });
          }
          if (input.operation === "banUser") {
            return auth.api.banUser({
              body: input.body as { userId: string; banReason?: string; banExpiresIn?: number },
              ...(Object.hasOwn(input, "query") ? { query: input.query } : {}),
              ...(input.headers ? { headers: new Headers(input.headers) } : {}),
              asResponse: true,
            });
          }
          if (input.operation === "unbanUser") {
            return auth.api.unbanUser({
              body: input.body as { userId: string },
              ...(Object.hasOwn(input, "query") ? { query: input.query } : {}),
              ...(input.headers ? { headers: new Headers(input.headers) } : {}),
              asResponse: true,
            });
          }
          if (input.operation === "listUserSessions") {
            return auth.api.listUserSessions({
              body: input.body as { userId: string },
              ...(Object.hasOwn(input, "query") ? { query: input.query } : {}),
              ...(input.headers ? { headers: new Headers(input.headers) } : {}),
              asResponse: true,
            });
          }
          if (input.operation === "listUsers") {
            return auth.api.listUsers({
              query: input.query as { sortBy?: string },
              ...(Object.hasOwn(input, "body") ? { body: input.body } : {}),
              ...(input.headers ? { headers: new Headers(input.headers) } : {}),
              asResponse: true,
            });
          }
          if (input.operation === "adminUpdateUser") {
            return auth.api.adminUpdateUser({
              body: input.body as { userId: string; data: Record<string, unknown> },
              ...(Object.hasOwn(input, "query") ? { query: input.query } : {}),
              ...(input.headers ? { headers: new Headers(input.headers) } : {}),
              asResponse: true,
            });
          }
          if (input.operation === "userHasPermission") {
            return auth.api.userHasPermission({
              body: input.body as { role?: string; permissions: Record<string, string[]> },
              ...(Object.hasOwn(input, "query") ? { query: input.query } : {}),
              ...(input.headers ? { headers: new Headers(input.headers) } : {}),
              asResponse: true,
            });
          }
          if (input.operation === "createUser") {
            return auth.api.createUser({
              body: input.body as { email: string; name: string },
              ...(Object.hasOwn(input, "query") ? { query: input.query } : {}),
              ...(input.headers ? { headers: new Headers(input.headers) } : {}),
              asResponse: true,
            });
          }
          if (input.operation === "setRole") {
            return auth.api.setRole({
              body: input.body as { userId: string; role: string },
              ...(Object.hasOwn(input, "query") ? { query: input.query } : {}),
              ...(input.headers ? { headers: new Headers(input.headers) } : {}),
              asResponse: true,
            });
          }
          return auth.api.getUser({
            query: input.query as { id: string },
            ...(Object.hasOwn(input, "body") ? { body: input.body } : {}),
            ...(input.headers ? { headers: new Headers(input.headers) } : {}),
            asResponse: true,
          });
        })();
      }
      if (url.pathname === "/__test/admin-user-timestamps" && request.method === "POST") {
        return request
          .json()
          .then((body: { userId: string; createdAt: string; updatedAt: string }) => {
            if (
              ![body.createdAt, body.updatedAt].every(
                (value) => typeof value === "string" && Number.isFinite(new Date(value).getTime()),
              ) ||
              typeof body.userId !== "string"
            ) {
              return Response.json(
                { message: "valid stored timestamps required" },
                { status: 400 },
              );
            }

            const result = database
              .query("UPDATE user SET createdAt=?,updatedAt=? WHERE id=?")
              .run(body.createdAt, body.updatedAt, body.userId);

            if (result.changes !== 1) {
              return Response.json({ message: "user required" }, { status: 404 });
            }

            return Response.json(
              database
                .query("SELECT id AS userId,createdAt,updatedAt FROM user WHERE id=?")
                .get(body.userId),
            );
          });
      }

      if (url.pathname !== "/__test/admin-role-state" || request.method !== "GET") {
        return;
      }

      const email = url.searchParams.get("email");

      if (!email) {
        return Response.json({ message: "email required" }, { status: 400 });
      }

      const user = database
        .query(
          "SELECT id,email,name,role,banned,banReason,banExpires,createdAt,updatedAt FROM user WHERE email=?",
        )
        .get(email) as {
        id: string;
        email: string;
        name: string;
        role: string | null;
      } | null;
      return Response.json({
        user: user
          ? {
              ...user,
              banned:
                (user as typeof user & { banned: number | null }).banned === null
                  ? null
                  : Boolean((user as typeof user & { banned: number | null }).banned),
            }
          : null,
        accounts: user
          ? database
              .query(
                "SELECT id,userId,providerId,accountId FROM account WHERE userId=? ORDER BY providerId,createdAt",
              )
              .all(user.id)
          : [],
        sessions: user
          ? database
              .query(
                "SELECT id,userId,token,impersonatedBy,createdAt,expiresAt FROM session WHERE userId=? ORDER BY createdAt",
              )
              .all(user.id)
          : [],
      });
    },
  };
}
