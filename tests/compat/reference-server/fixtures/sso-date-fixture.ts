import { sso } from "@better-auth/sso";
import { type BetterAuthOptions, betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { username } from "better-auth/plugins";

import { createDatabase } from "../sqlite.ts";
export async function ssoDateFixture(base: BetterAuthOptions) {
  const database = createDatabase(":memory:");
  const options = {
    ...base,
    database,
    plugins: [
      username(),
      sso({
        schema: {
          ssoProvider: {
            additionalFields: {
              anniversary: {
                type: "date" as const,
                required: true,
                fieldName: "application_anniversary",
              },
            },
          },
        },
      }),
    ],
  };
  await (await getMigrations(options)).runMigrations();
  let auth = betterAuth(options);
  return async (request: Request): Promise<Response | undefined> => {
    if (new URL(request.url).pathname !== "/__test/server-api/sso-dates") return;
    const input = (await request.json()) as any;
    if (input.action === "restart") {
      auth = betterAuth(options);
      return new Response(JSON.stringify({ restarted: true }), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "physical") {
      const rows = database.prepare("SELECT application_anniversary FROM ssoProvider").all();
      return new Response(JSON.stringify(rows), {
        headers: { "content-type": "application/json" },
      });
    }
    const args = {
      body: input.body,
      headers: new Headers(input.headers ?? {}),
      asResponse: true as const,
    };
    if (input.sdkDate) args.body.anniversary = new Date(args.body.anniversary);
    if (input.action === "signup") return auth.api.signUpEmail(args);
    if (input.action === "update") return auth.api.updateSSOProvider(args);
    if (input.action === "get") {
      return auth.api.getSSOProvider({
        query: { providerId: "date-provider" },
        headers: args.headers,
        asResponse: true,
      });
    }
    if (input.action === "list") {
      return auth.api.listSSOProviders({ headers: args.headers, asResponse: true });
    }
    return auth.api.registerSSOProvider(args);
  };
}
