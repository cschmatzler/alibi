import type { Database } from "bun:sqlite";
import { apiKey } from "@better-auth/api-key";
import { passkey } from "@better-auth/passkey";
import { betterAuth } from "better-auth";
import { createAuthEndpoint } from "better-auth/api";
import {
  admin,
  deviceAuthorization,
  jwt,
  lastLoginMethod,
  multiSession,
  oneTap,
  openAPI,
  organization,
  phoneNumber,
  siwe,
  twoFactor,
  username,
} from "better-auth/plugins";
import { z } from "zod";

const documentationPlugin = () => ({
  id: "documentation",
  schema: {
    document: {
      fields: {
        label: { type: "string" as const, required: true },
        visibility: {
          type: ["private", "public"] as ("private" | "public")[],
          defaultValue: "private",
        },
        labels: { type: "string[]" as const },
        secret: { type: "string" as const, required: true, returned: false, input: false },
        dynamic: { type: "number" as const, defaultValue: () => 7 },
      },
    },
  },
  endpoints: {
    readDocument: createAuthEndpoint(
      "/documents/:id",
      {
        method: "GET",
        query: z.object({
          view: z.enum(["summary", "complete"]).describe("Projection").optional(),
        }),
        metadata: {
          openapi: { operationId: "document", description: "Read a document", tags: ["Documents"] },
        },
      },
      async (ctx) => ctx.json({ id: ctx.params.id }),
    ),
    updateDocument: createAuthEndpoint(
      "/documents/:id",
      {
        method: "POST",
        body: z
          .array(z.enum(["approved", "pending"]))
          .describe("Document labels")
          .nullable(),
        metadata: {
          openapi: {
            operationId: "document",
            description: "Update a document",
            tags: ["Documents"],
          },
        },
      },
      async (ctx) => ctx.json({ id: ctx.params.id, labels: ctx.body }),
    ),
    hiddenDocument: createAuthEndpoint(
      "/documentation-hidden",
      {
        method: "GET",
        metadata: { scope: "server" as const, openapi: { operationId: "hiddenDocument" } },
      },
      async (ctx) => ctx.json({ kind: "hidden" }),
    ),
    serverDocument: createAuthEndpoint(
      "/documentation-server-only",
      { method: "GET", metadata: { SERVER_ONLY: true } },
      async (ctx) => ctx.json({ kind: "server-only" }),
    ),
    disabledDocument: createAuthEndpoint(
      "/documentation-disabled",
      { method: "GET", metadata: { openapi: { operationId: "disabledDocument" } } },
      async (ctx) => ctx.json({ kind: "disabled" }),
    ),
  },
});
export const OPEN_API_PROFILES = [
  "openapi-minimal",
  "openapi-last-login",
  "openapi-last-login-database",
  "openapi-default",
  "openapi-configured",
  "openapi-disabled",
  "openapi-jwt",
  "openapi-username",
  "openapi-custom-schema",
  "openapi-plugins",
  "openapi-plugins-teams",
  "openapi-plugins-configured",
] as const;
export function openApiProfiles(port: number, database: Database) {
  // A real app-owned storage field: the custom schema profile documents this column.
  if (
    !database
      .query<{ name: string }, []>("PRAGMA table_info(user)")
      .all()
      .some((column) => column.name === "metadata")
  )
    database.exec("ALTER TABLE user ADD COLUMN metadata TEXT");
  for (const field of ["access", "aliases", "score", "anniversary"]) {
    if (
      !database
        .query<{ name: string }, []>("PRAGMA table_info(user)")
        .all()
        .some((column) => column.name === field)
    )
      database.exec(`ALTER TABLE user ADD COLUMN ${field} TEXT`);
  }
  database.exec(
    "CREATE TABLE IF NOT EXISTS document (id TEXT PRIMARY KEY, label TEXT NOT NULL, visibility TEXT, labels TEXT, secret TEXT, dynamic REAL)",
  );
  return new Map(
    OPEN_API_PROFILES.map((name) => {
      const options =
        name === "openapi-configured"
          ? { path: "/docs", theme: "moon" as const, nonce: "fixture-reference-nonce" }
          : name === "openapi-disabled"
            ? { disableDefaultReference: true }
            : {};
      const extra =
        name === "openapi-custom-schema"
          ? [documentationPlugin()]
          : name.startsWith("openapi-last-login")
            ? [lastLoginMethod({ storeInDatabase: name === "openapi-last-login-database" })]
            : name === "openapi-jwt"
              ? [jwt()]
              : name === "openapi-username"
                ? [username()]
                : name.startsWith("openapi-plugins")
                  ? [
                      oneTap({ clientId: "openapi-one-tap-client" }),
                      admin(),
                      organization({
                        teams: { enabled: name === "openapi-plugins-teams" },
                        dynamicAccessControl: { enabled: name === "openapi-plugins-teams" },
                      }),
                      twoFactor(),
                      apiKey(
                        name === "openapi-plugins-configured"
                          ? { rateLimit: { maxRequests: 43, timeWindow: 7654321 } }
                          : {},
                      ),
                      passkey(),
                      deviceAuthorization(),
                      jwt(),
                      multiSession(),
                      phoneNumber({
                        sendOTP: async () => {
                          throw new Error("Documentation profile has no phone delivery provider");
                        },
                      }),
                      siwe({
                        domain: "localhost",
                        getNonce: async () => "OpenApiDocumentationNonce",
                        verifyMessage: async () => false,
                      }),
                    ]
                  : [];
      const auth = betterAuth({
        baseURL: `http://localhost:${port}`,
        basePath: `/__test/profiles/${name}/api/auth`,
        secret: "fixture-open-api-only-secret-at-least-32-chars",
        database,
        ...(name === "openapi-minimal"
          ? {}
          : {
              emailAndPassword: { enabled: true },
              user: {
                ...(name === "openapi-custom-schema"
                  ? {
                      additionalFields: {
                        metadata: {
                          type: "json",
                          required: true,
                          input: false,
                          returned: false,
                          defaultValue: null,
                        },
                        access: {
                          type: ["reader", "editor"],
                          required: true,
                          defaultValue: "reader",
                        },
                        aliases: { type: "string[]", defaultValue: ["initial"] },
                        score: { type: "number[]" },
                        anniversary: { type: "date" },
                      },
                    }
                  : {}),
                changeEmail: { enabled: true },
                deleteUser: { enabled: true },
              },
            }),
        disabledPaths: [
          ...(name === "openapi-custom-schema" ? ["/documentation-disabled"] : []),
          ...(name === "openapi-configured" ? ["/error"] : []),
          ...(name === "openapi-jwt" ? ["/jwks", "/token"] : []),
        ],
        plugins: [...extra, openAPI(options)],
      });
      return [name, auth] as const;
    }),
  );
}
