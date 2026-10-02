import { Database } from "bun:sqlite";
import { passkey } from "@better-auth/passkey";
import { betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import { username } from "better-auth/plugins";

/** Genuine application callbacks, immutable policies, and actual callback-time reads. */
export function passkeyAuthenticationFixture(
  database: Database,
  options: Parameters<typeof betterAuth>[0],
  baseURL: string,
) {
  const events: unknown[] = [];
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  for (const mode of [
    "accept",
    "forbidden",
    "public-error",
    "internal-error",
    "mutation",
    "deletion",
    "failed-deletion",
  ] as const) {
    const name = `passkey-auth-${mode}`;
    const path = `/__test/profiles/${name}/api/auth`;
    const instance = betterAuth({
      ...options,
      basePath: path,
      plugins: [
        passkey({
          rpID: "localhost",
          origin: baseURL,
          authentication: {
            afterVerification: async ({ ctx, verification, clientData }) => {
              if (!verification.verified)
                throw new Error("Actual successful verification required");
              const row = await ctx.context.adapter.findOne({
                model: "passkey",
                where: [
                  { field: "credentialID", value: verification.authenticationInfo.credentialID },
                ],
              });
              if (!row) throw new Error("Actual verified stored credential required");
              const sessions = database
                .query('SELECT COUNT(*) AS count FROM session WHERE "userId" = ?')
                .get((row as { userId: string }).userId);
              const challenges = database.query("SELECT COUNT(*) AS count FROM verification").get();
              events.push({
                profile: name,
                path: ctx.path,
                facts: verification.authenticationInfo,
                clientData,
                storedPasskey: row,
                sessions,
                challenges,
              });
              if (mode === "deletion" || mode === "failed-deletion") {
                if (mode === "failed-deletion")
                  database.run(
                    `CREATE TEMP TRIGGER reject_callback_delete BEFORE DELETE ON passkey BEGIN SELECT RAISE(ABORT, 'Application deletion failed'); END`,
                  );
                try {
                  await ctx.context.adapter.delete({
                    model: "passkey",
                    where: [{ field: "id", value: (row as { id: string }).id }],
                  });
                  const remaining = await ctx.context.adapter.findOne({
                    model: "passkey",
                    where: [{ field: "id", value: (row as { id: string }).id }],
                  });
                  if (remaining) throw new Error("Verified credential deletion required");
                } finally {
                  if (mode === "failed-deletion")
                    database.run("DROP TRIGGER reject_callback_delete");
                }
              }
              if (mode === "mutation") {
                const foreign = (await ctx.context.adapter.findOne({
                  model: "user",
                  where: [{ field: "name", value: "Foreign" }],
                })) as { id: string } | null;
                if (!foreign) throw new Error("Actual foreign application user required");
                await ctx.context.adapter.update({
                  model: "passkey",
                  where: [{ field: "id", value: (row as { id: string }).id }],
                  update: {
                    userId: foreign.id,
                    backedUp: true,
                    deviceType: "application-updated",
                    name: "Application updated",
                  },
                });
              }
              if (mode === "forbidden")
                throw new APIError("FORBIDDEN", {
                  code: "PASSKEY_APPLICATION_DENIED",
                  message: "Application denied this verified authentication",
                });
              if (mode === "public-error")
                throw new APIError("INTERNAL_SERVER_ERROR", {
                  code: "PASSKEY_APPLICATION_ERROR",
                  message: "Application authentication service failed",
                });
              if (mode === "internal-error") throw new Error("Private application failure");
            },
          },
        }),
        username(),
      ],
    });
    profiles.set(path, instance);
  }
  return {
    profiles,
    reset() {
      events.length = 0;
    },
    async handle(request: Request) {
      if (new URL(request.url).pathname === "/__test/passkey-authentication-events")
        return Response.json(events);
      return null;
    },
  };
}
