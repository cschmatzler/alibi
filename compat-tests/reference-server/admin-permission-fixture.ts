import { betterAuth, type BetterAuthOptions } from "better-auth";
import { admin, username, twoFactor } from "better-auth/plugins";
import { createAccessControl } from "better-auth/plugins/access";

/** Immutable application roles run through the actual pinned admin plugin. */
export function createAdminPermissionFixture(base: BetterAuthOptions) {
  const access = createAccessControl({ user: ["get"] });
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  for (const name of [
    "admin-standard",
    "admin-deny-all",
    "admin-exact-role",
    "admin-empty-role",
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
              name === "admin-exact-role"
                ? "user, admin"
                : name === "admin-empty-role"
                  ? ""
                  : "admin",
            ...(name === "admin-deny-all" ? { roles: {} } : {}),
            ...(name === "admin-empty-role"
              ? { roles: { user: access.newRole({ user: ["get"] }) } }
              : {}),
          }),
        ],
      }),
    );
  }
  return { profiles };
}
