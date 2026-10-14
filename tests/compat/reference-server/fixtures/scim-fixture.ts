import { Database } from "bun:sqlite";

import { scim } from "@better-auth/scim";
import { type BetterAuthOptions, betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
export async function scimFixture(base: BetterAuthOptions) {
  const options = {
    ...base,
    database: new Database(":memory:"),
    basePath: "/__test/profiles/scim/api/auth",
    plugins: [
      scim({
        connections: [],
        authentication: { verifyBearerToken: async () => null },
        managedConnections: {
          credentialHashSecret: "managed-scim-credential-hmac-secret-32-chars",
        },
      }),
    ],
  };
  await (await getMigrations(options)).runMigrations();
  const auth = betterAuth(options);
  return async (request: Request): Promise<Response | undefined> => {
    const path = new URL(request.url).pathname;
    if (path.startsWith("/__test/profiles/scim/api/auth/")) return auth.handler(request);
    if (path === "/__test/server-api/scim") {
      const query = new URL(request.url).searchParams;
      if (query.get("operation") === "reject-late-event") {
        options.database.exec(
          "CREATE TRIGGER reject_scim_late_event BEFORE INSERT ON scimManagedConnectionEvent WHEN NEW.actorId='rollback-operator' AND NEW.sequence=2 BEGIN SELECT RAISE(ABORT,'fixture rejected late event'); END",
        );
        return new Response(JSON.stringify({ installed: true }), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "managed-failure") {
        const input = (await request.json()) as any;
        input.body.expiresAt = new Date(input.body.expiresAt);
        try {
          await auth.api.createSCIMManagedConnection({ body: input.body });
          return new Response(JSON.stringify({ failed: false }), {
            headers: { "content-type": "application/json" },
          });
        } catch (error) {
          return new Response(
            JSON.stringify({
              failed: true,
              rejectedLateEvent: String(error).includes("fixture rejected late event"),
            }),
            { headers: { "content-type": "application/json" } },
          );
        }
      }
      if (query.get("operation") === "managed-storage") {
        const result = {
          connections: options.database.query("SELECT * FROM scimManagedConnection").all(),
          credentials: options.database.query("SELECT * FROM scimManagedCredential").all(),
          events: options.database
            .query("SELECT * FROM scimManagedConnectionEvent ORDER BY sequence")
            .all(),
        };
        return new Response(JSON.stringify(result), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "createSCIMManagedConnection") {
        const input = (await request.json()) as any;
        if (input.sdkDate) input.body.expiresAt = new Date(input.body.expiresAt);
        return auth.api.createSCIMManagedConnection({ body: input.body, asResponse: true });
      }

      if (query.get("operation") === "getSCIMSchemas") {
        return new Response(JSON.stringify(await auth.api.getSCIMSchemas()), {
          headers: { "content-type": "application/json" },
        });
      }
      if (query.get("operation") === "getSCIMSchema") {
        try {
          const value = await auth.api.getSCIMSchema({
            params: { schemaId: query.get("id") ?? "" },
          });
          return new Response(JSON.stringify(value), {
            headers: { "content-type": "application/json" },
          });
        } catch (error: any) {
          return new Response(JSON.stringify(error.body), {
            status: error.statusCode,
            headers: { "content-type": "application/json" },
          });
        }
      }
      if (query.get("operation") === "getSCIMResourceType") {
        try {
          const value = await auth.api.getSCIMResourceType({
            params: { resourceTypeId: query.get("id") ?? "" },
          });
          return new Response(JSON.stringify(value), {
            headers: { "content-type": "application/json" },
          });
        } catch (error: any) {
          return new Response(JSON.stringify(error.body), {
            status: error.statusCode,
            headers: { "content-type": "application/json" },
          });
        }
      }
      return new Response(
        JSON.stringify(
          new URL(request.url).searchParams.get("operation") === "getSCIMResourceTypes"
            ? await auth.api.getSCIMResourceTypes()
            : await auth.api.getSCIMServiceProviderConfig(),
        ),
        {
          headers: { "content-type": "application/json" },
        },
      );
    }
  };
}
