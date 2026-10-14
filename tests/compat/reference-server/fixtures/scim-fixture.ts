import { Database } from "bun:sqlite";

import { scim } from "@better-auth/scim";
import { type BetterAuthOptions, betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
export async function scimFixture(base: BetterAuthOptions) {
  const options = {
    ...base,
    database: new Database(":memory:"),
    basePath: "/__test/profiles/scim/api/auth",
    plugins: [scim({ connections: [], authentication: { verifyBearerToken: async () => null } })],
  };
  await (await getMigrations(options)).runMigrations();
  const auth = betterAuth(options);
  return async (request: Request): Promise<Response | undefined> => {
    const path = new URL(request.url).pathname;
    if (path.startsWith("/__test/profiles/scim/api/auth/")) return auth.handler(request);
    if (path === "/__test/server-api/scim") {
      const query = new URL(request.url).searchParams;
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
