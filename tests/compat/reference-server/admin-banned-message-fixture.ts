import { Database } from "bun:sqlite";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { APIError } from "better-auth/api";
import { admin, username, twoFactor } from "better-auth/plugins";

/** Stored, non-input, hidden application data reaches the real admin callback. */
export function createAdminBannedMessageFixture(
  base: BetterAuthOptions,
  database: Database,
) {
  if (
    !database
      .query("PRAGMA table_info(user)")
      .all()
      .some((column: any) => column.name === "metadata")
  ) {
    database.exec("ALTER TABLE user ADD COLUMN metadata JSON");
  }
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  const events: Record<string, unknown>[] = [];
  for (const name of ["admin-banned-message", "admin-banned-message-error"]) {
    const path = `/__test/profiles/${name}/api/auth`;
    profiles.set(
      path,
      betterAuth({
        ...base,
        basePath: path,
        user: {
          ...base.user,
          additionalFields: {
            ...base.user?.additionalFields,
            metadata: {
              type: "json",
              input: false,
              returned: false,
              defaultValue: { supportCode: "private-fixture-code" },
            },
          },
        },
        plugins: [
          username(),
          twoFactor(),
          admin({
            defaultRole: "admin",
            allowImpersonatingAdmins: true,
            bannedUserMessage: async (user) => {
              await Promise.resolve();
              events.push({
                profile: name,
                userId: user.id,
                email: user.email,
                name: user.name,
                role: user.role,
                banned: user.banned,
                banReason: user.banReason,
                banExpires: user.banExpires,
                metadata: user.metadata,
              });
              if (
                name === "admin-banned-message-error" &&
                user.banReason === "server application ban"
              )
                throw new APIError("INTERNAL_SERVER_ERROR", {
                  code: "APPLICATION_BAN_MESSAGE_UNAVAILABLE",
                  message: "configured message unavailable",
                });
              if (name === "admin-banned-message-error")
                throw new APIError("BAD_REQUEST", {
                  code: "APPLICATION_BAN_MESSAGE_REFUSED",
                  message: "configured message refused",
                });
              return `${(user.metadata as { supportCode: string }).supportCode}:${user.banReason}`;
            },
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
        url.pathname !== "/__test/admin-banned-message-events" ||
        request.method !== "GET"
      )
        return;
      const email = url.searchParams.get("email"),
        profile = url.searchParams.get("profile");
      const user = database
        .query("SELECT id,metadata FROM user WHERE email=?")
        .get(email) as { id: string; metadata: string } | null;
      return Response.json({
        user: user
          ? { userId: user.id, metadata: JSON.parse(user.metadata) }
          : null,
        events: events.filter(
          (event) =>
            event.email === email &&
            event.profile === profile &&
            event.userId === user?.id,
        ),
      });
    },
  };
}
