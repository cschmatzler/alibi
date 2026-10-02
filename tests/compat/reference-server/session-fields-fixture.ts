/** Concrete app session fields; every handler remains the pinned 1.7.6 runtime. */

import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { admin, openAPI, organization } from "better-auth/plugins";

export async function createSessionFieldsFixture(
  database: Database,
  shared: Parameters<typeof betterAuth>[0],
  origin: string,
) {
  const profiles = new Map<string, Pick<ReturnType<typeof betterAuth>, "handler">>();
  for (const name of ["session-fields", "session-fields-plugins", "session-fields-secondary"]) {
    const extra = {
      label: { type: "string", required: false, defaultValue: "initial" },
      hidden: { type: "string", required: false, returned: false, defaultValue: "server-secret" },
      serverOnly: { type: "string", required: false, input: false, defaultValue: "locked" },
      callback: { type: "string", required: false, defaultValue: () => "callback-created" },
      payload: { type: "json", required: false, defaultValue: { initial: true } },
      number: { type: "number", required: false },
      transformed: {
        type: "string",
        required: false,
        transform: {
          input: (value: unknown) => {
            if (value === undefined) return "generated-without-default";
            if (value === "stage:throw-at-binding") throw new Error("configured transform failed");
            if (value === "omit" || value === "stage:omit-at-binding") return undefined;
            return `stage:${typeof value === "string" ? value : ""}`;
          },
        },
      },
      validated: {
        type: "string",
        required: false,
        defaultValue: "",
        validator: {
          input: {
            "~standard": {
              version: 1,
              vendor: "session-fields-fixture",
              validate(value: unknown) {
                if (typeof value === "string" && value.trim()) return { value: value.trim() };
                if (typeof value === "number" && !Number.isFinite(value))
                  return { value: String(value) };
                if (Object.is(value, -0)) return { value: "-0" };
                return { issues: [{ message: "configured validation rejected the value" }] };
              },
            },
          },
        },
        transform: {
          input: (value: unknown) => `stored:${typeof value === "string" ? value : ""}`,
        },
      },
      ...(name.endsWith("plugins")
        ? {
            activeOrganizationId: {
              type: "string" as const,
              required: true,
              input: true,
              returned: false,
              defaultValue: "configured-default-org",
              transform: { input: (value: unknown) => `adapter:${value}` },
            },
            activeTeamId: { type: "string" as const, required: false },
            impersonatedBy: { type: "string" as const, required: false },
          }
        : {
            activeOrganizationId: {
              type: "string" as const,
              required: false,
              defaultValue: "declared-without-plugin",
            },
          }),
    } as const;
    const secondary = new Map<string, { value: string; expiresAt: number }>();
    const instance = betterAuth({
      ...shared,
      database,
      ...(name === "session-fields-secondary"
        ? {
            secondaryStorage: {
              async get(key: string) {
                const entry = secondary.get(key);
                return entry && entry.expiresAt > Date.now() ? entry.value : null;
              },
              async set(key: string, value: string, ttl: number) {
                secondary.set(key, { value, expiresAt: Date.now() + ttl * 1000 });
              },
              async delete(key: string) {
                secondary.delete(key);
              },
              async getAndDelete(key: string) {
                const entry = secondary.get(key);
                secondary.delete(key);
                return entry && entry.expiresAt > Date.now() ? entry.value : null;
              },
            },
          }
        : {}),
      baseURL: origin,
      basePath: `/__test/profiles/${name}/api/auth`,
      plugins: [
        ...(name.endsWith("plugins") ? [admin(), organization({ teams: { enabled: true } })] : []),
        openAPI(),
      ],
      session: { additionalFields: extra },
      databaseHooks: {
        session: {
          update: {
            async before(data, ctx) {
              if (data.label === "delete-before")
                database
                  .query("DELETE FROM session WHERE token=?")
                  .run(ctx?.context.session?.session.token ?? "");
              if (data.label === "cancel-before") return false;
              if (data.label === "restore-undefined")
                return { data: { ...data, transformed: "hook-current" } };
              if (data.transformed === "stage:hook-input")
                return { data: { ...data, transformed: "hook-current" } };
              if (data.label === "native-hook")
                return { data: { ...data, label: "model-override" } };
              return { data };
            },
          },
        },
      },
    });
    await (await getMigrations(instance.options)).runMigrations();
    profiles.set(name, instance);
  }
  return {
    profiles,
    state(email: string) {
      const user = database.query("SELECT id FROM user WHERE email=?").get(email) as {
        id: string;
      } | null;
      const rows = user
        ? (database
            .query("SELECT * FROM session WHERE userId=? ORDER BY createdAt")
            .all(user.id) as Record<string, unknown>[])
        : [];
      return rows.map((row) => ({
        id: row.id,
        token: row.token,
        userId: row.userId,
        updatedAt: new Date(row.updatedAt as string).toISOString(),
        label: row.label ?? null,
        hidden: row.hidden ?? null,
        serverOnly: row.serverOnly ?? null,
        transformed: row.transformed ?? null,
        validated: row.validated ?? null,
        callback: row.callback ?? null,
        number: row.number ?? null,
        payload: typeof row.payload === "string" ? JSON.parse(row.payload) : (row.payload ?? null),
        activeOrganizationId: row.activeOrganizationId ?? null,
        activeTeamId: row.activeTeamId ?? null,
        impersonatedBy: row.impersonatedBy ?? null,
      }));
    },
  };
}
