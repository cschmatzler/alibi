import type { Database } from "bun:sqlite";
import { type BetterAuthOptions, betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
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
        ...(name === "admin-duration-hook-error"
          ? {
              databaseHooks: {
                ...base.databaseHooks,
                user: {
                  ...base.databaseHooks?.user,
                  update: {
                    ...base.databaseHooks?.user?.update,
                    before: async (user) => {
                      if ("banned" in user && user.banned === true)
                        throw new APIError("FORBIDDEN", {
                          code: "APPLICATION_BAN_REFUSED",
                          message: "Invalid Date",
                        });
                    },
                  },
                },
                session: {
                  ...base.databaseHooks?.session,
                  create: {
                    ...base.databaseHooks?.session?.create,
                    before: async (session) => {
                      if ("impersonatedBy" in session && session.impersonatedBy)
                        throw new APIError("INTERNAL_SERVER_ERROR", {
                          code: "APPLICATION_SESSION_REFUSED",
                          message: "Invalid Date",
                        });
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
            if (result.changes !== 1)
              return Response.json({ message: "user required" }, { status: 404 });
            return Response.json(
              database
                .query("SELECT id AS userId,createdAt,updatedAt FROM user WHERE id=?")
                .get(body.userId),
            );
          });
      }
      if (url.pathname !== "/__test/admin-role-state" || request.method !== "GET") return;
      const email = url.searchParams.get("email");
      if (!email) return Response.json({ message: "email required" }, { status: 400 });
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
