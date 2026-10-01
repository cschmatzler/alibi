import type { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import { username } from "better-auth/plugins";
import { apiKey } from "@better-auth/api-key";

export function createApiKeyGenerationFixture(
  database: Database,
  options: Parameters<typeof betterAuth>[0],
) {
  const path = "/__test/profiles/api-key-generation/api/auth";
  const events: unknown[] = [];
  let mode = "normal",
    serial = 0;
  function configuration(configId: string, disableKeyHashing = false) {
    return {
      configId,
      disableKeyHashing,
      enableSessionForAPIKeys: configId === "generated",
      defaultPrefix: configId === "generated" ? "app_" : "raw_",
      defaultKeyLength: configId === "generated" ? 24 : 31,
      startingCharactersConfig: { charactersLength: 2 },
      rateLimit: { enabled: false },
      keyExpiration: { minExpiresIn: 0 },
      async customKeyGenerator(input: {
        length: number;
        prefix: string | undefined;
      }) {
        events.push({
          kind: "generator",
          ...input,
          prefix: input.prefix ?? null,
          mode,
        });
        if (mode === "generator-api")
          throw new APIError("FORBIDDEN", {
            code: "GENERATOR_DENIED",
            message: "Application generator denied",
          });
        if (mode === "generator-public-500")
          throw new APIError("INTERNAL_SERVER_ERROR", {
            code: "APPLICATION_GENERATION_DENIED",
            message: "Application generation denied",
          });
        if (mode === "generator-throw")
          throw new Error("Private generator failure");
        return mode === "unicode"
          ? "😀abcdefghijklmnop"
          : `${input.prefix ?? ""}generated-owned-secret-${String(++serial).padStart(6, "0")}`;
      },
      permissions: {
        async defaultPermissions(referenceId: string, ctx: any) {
          events.push({
            kind: "permissions",
            configurationId: configId,
            reference: { userId: referenceId },
            requestPresent: !!ctx.request,
            explicit: ctx.request ? (ctx.body.permissions ?? null) : null,
            mode,
          });
          if (mode === "permissions-api")
            throw new APIError("FORBIDDEN", {
              code: "PERMISSIONS_DENIED",
              message: "Application permissions denied",
            });
          if (mode === "permissions-throw")
            throw new Error("Private permissions failure");
          const owner = database
            .query("SELECT name FROM user WHERE id = ?")
            .get(referenceId) as { name: string };
          return Object.fromEntries([
            ["zeta", [owner.name === "Owner" ? "read" : "foreign"]],
            ["10", ["ten"]],
            ["2", ["two"]],
            ["alpha", [configId]],
            ["$serde_json::private::RawValue", ["literal"]],
          ]);
        },
      },
    };
  }
  const auth = betterAuth({
    ...options,
    basePath: path,
    plugins: [
      username(),
      apiKey([
        { configId: "default", rateLimit: { enabled: false } },
        configuration("generated"),
        configuration("plaintext", true),
        {
          configId: "static",
          defaultKeyLength: 0,
          customKeyGenerator: configuration("static").customKeyGenerator,
          rateLimit: { enabled: false },
          permissions: {
            defaultPermissions: Object.fromEntries([
              ["zeta", ["read"]],
              ["alpha", ["write"]],
            ]),
          },
        },
      ]),
    ],
  });
  return {
    path,
    auth,
    async control(request: Request): Promise<Response | null> {
      const url = new URL(request.url);
      if (url.pathname === "/__test/api-key-generation/events") {
        const result = events.splice(0);
        return Response.json(result);
      }
      if (
        url.pathname === "/__test/api-key-generation/mode" &&
        request.method === "POST"
      ) {
        const input = await request.json();
        mode = input.mode;
        if (input.reset) serial = 0;
        return Response.json({ mode });
      }
      if (url.pathname === "/__test/api-key-generation/state")
        return Response.json(
          database
            .query(
              'SELECT id, name, "referenceId", "configId", key, start, prefix, permissions, remaining, "requestCount", "expiresAt" FROM apikey ORDER BY name',
            )
            .all()
            .map((row: any) => ({
              ...row,
              expiresAt:
                row.expiresAt === null
                  ? null
                  : new Date(row.expiresAt).toISOString(),
            })),
        );
      if (
        url.pathname === "/__test/api-key-generation/expire" &&
        request.method === "POST"
      ) {
        const { keyId } = await request.json();
        database
          .query('UPDATE apikey SET "expiresAt" = ? WHERE id = ?')
          .run(new Date(0).toISOString(), keyId);
        return Response.json({ success: true });
      }
      if (
        url.pathname === "/__test/api-key-generation/cleanup" &&
        request.method === "POST"
      )
        return Response.json(await auth.api.deleteAllExpiredApiKeys());
      if (
        url.pathname === "/__test/api-key-generation/create" &&
        request.method === "POST"
      )
        return Response.json(
          await auth.api.createApiKey({ body: await request.json() }),
        );
      if (
        url.pathname === "/__test/api-key-generation/update" &&
        request.method === "POST"
      )
        return Response.json(
          await auth.api.updateApiKey({ body: await request.json() }),
        );
      if (
        url.pathname === "/__test/api-key-generation/verify" &&
        request.method === "POST"
      )
        return Response.json(
          await auth.api.verifyApiKey({ body: await request.json() }),
        );
      return null;
    },
  };
}
