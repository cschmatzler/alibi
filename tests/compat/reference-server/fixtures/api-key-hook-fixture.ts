import type { Database } from "bun:sqlite";

import { apiKey } from "@better-auth/api-key";
import { betterAuth } from "better-auth";
import { username } from "better-auth/plugins";

export function createApiKeyHookFixture(
  database: Database,
  options: Parameters<typeof betterAuth>[0],
) {
  const events: unknown[] = [];
  const path = "/__test/profiles/api-key-hooks/api/auth";
  const auth = betterAuth({
    ...options,
    basePath: path,
    plugins: [
      username(),
      apiKey([
        { configId: "default", rateLimit: { enabled: false } },
        { configId: "other", rateLimit: { enabled: false } },
        {
          configId: "hooks",
          enableSessionForAPIKeys: true,
          rateLimit: { enabled: false },
          customAPIKeyGetter(ctx) {
            const header = ctx.headers?.get("x-custom-api-key");
            const key = header?.startsWith("ApiKey ") ? header.slice(7) : null;

            // Observe actual authentication lookup; programmatic calls without key
            // credentials have no lookup side effect in this application.
            if ((header !== null && header !== undefined) || ctx.path === "/get-session") {
              events.push({
                kind: "getter",
                configurationId: "hooks",
                provided: !!key,
              });
            }

            return key;
          },
          async customAPIKeyValidator({ ctx, key }) {
            const policy = ctx.headers?.get("x-key-policy") ?? "allow";
            events.push({
              kind: "validator",
              configurationId: "hooks",
              policy,
              keyLength: key.length,
              prefix: key.startsWith("red_") ? "red_" : "other",
            });
            return policy !== "deny" && (policy !== "red-only" || key.startsWith("red_"));
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

      if (url.pathname === "/__test/api-key-hook/events") {
        const captured = [...events];
        events.length = 0;
        return Response.json(captured);
      }

      if (url.pathname === "/__test/api-key-hook/state") {
        const userId = url.searchParams.get("userId") ?? "";
        return Response.json({
          keys: database
            .query(
              'SELECT id, "referenceId", "configId", remaining, "requestCount", enabled FROM apikey ORDER BY name',
            )
            .all()
            .map((row) => ({
              ...(row as Record<string, unknown>),
              enabled: !!(row as Record<string, unknown>).enabled,
            })),
          sessions: database
            .query('SELECT COUNT(*) AS count FROM session WHERE "userId" = ?')
            .get(userId),
        });
      }

      if (url.pathname === "/__test/api-key-hook/create" && request.method === "POST") {
        return Response.json(await auth.api.createApiKey({ body: await request.json() }));
      }

      if (url.pathname === "/__test/api-key-hook/verify" && request.method === "POST") {
        // An actual request preserves the same caller headers for the predicate.
        const response = await auth.api.verifyApiKey({
          body: await request.json(),
          headers: request.headers,
          request,
        });
        return response instanceof Response ? response : Response.json(response);
      }

      if (url.pathname === "/__test/api-key-hook/update" && request.method === "POST") {
        return Response.json(await auth.api.updateApiKey({ body: await request.json() }));
      }

      return null;
    },
  };
}
