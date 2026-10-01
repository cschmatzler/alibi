import type { Database } from "bun:sqlite";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { admin, username, twoFactor } from "better-auth/plugins";
import { createAccessControl } from "better-auth/plugins/access";

/** Immutable application roles run through the actual pinned admin plugin. */
export function createAdminPermissionFixture(
  base: BetterAuthOptions,
  database: Database,
) {
  const access = createAccessControl({
    user: ["get", "create", "set-role", "update"],
  });
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  for (const name of [
    "admin-standard",
    "admin-deny-all",
    "admin-exact-role",
    "admin-empty-role",
    "admin-role-manager",
    "admin-role-creator",
  ]) {
    const path = `/__test/profiles/${name}/api/auth`;
    profiles.set(
      path,
      betterAuth({
        ...base,
        basePath: path,
        plugins: [
          username(),
          twoFactor(),
          admin({
            defaultRole:
              name === "admin-role-manager"
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
      if (
        url.pathname !== "/__test/admin-role-state" ||
        request.method !== "GET"
      )
        return;
      const email = url.searchParams.get("email");
      if (!email)
        return Response.json({ message: "email required" }, { status: 400 });
      const user = database
        .query("SELECT id,email,name,role FROM user WHERE email=?")
        .get(email) as {
        id: string;
        email: string;
        name: string;
        role: string | null;
      } | null;
      return Response.json({
        user,
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
                "SELECT id,userId,token,impersonatedBy FROM session WHERE userId=? ORDER BY createdAt",
              )
              .all(user.id)
          : [],
      });
    },
  };
}
