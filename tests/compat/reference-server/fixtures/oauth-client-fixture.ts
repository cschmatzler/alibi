import { oauthProvider } from "@better-auth/oauth-provider";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { jwt, username } from "better-auth/plugins";
export async function oauthClientFixture(base: BetterAuthOptions) {
  const options = {
    baseURL: base.baseURL,
    basePath: base.basePath,
    secret: base.secret,
    database: base.database,
    emailAndPassword: { enabled: true },
    plugins: [username(), jwt(), oauthProvider({ loginPage: "/login", consentPage: "/consent" })],
  };
  await (await getMigrations(options)).runMigrations();
  const auth = betterAuth(options);
  return async (request: Request) => {
    const input = await request.json();
    if (input.action === "signup") {
      return auth.api.signUpEmail({ body: input.body, asResponse: true });
    }
    if (input.action === "row") {
      const context = await auth.$context;
      const row = (await context.adapter.findOne({
        model: "oauthClient",
        where: [{ field: "clientId", value: input.clientId }],
      })) as any;
      return new Response(
        JSON.stringify(
          row
            ? {
                clientId: row.clientId,
                userId: row.userId,
                clientName: row.name,
                redirectUris: row.redirectUris,
                client_secret: row.clientSecret ?? null,
              }
            : null,
        ),
        { headers: { "content-type": "application/json" } },
      );
    }
    if (input.action === "update") {
      return auth.api.updateOAuthClient({
        body: input.body,
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    if (input.action === "rotate") {
      return auth.api.rotateClientSecret({
        body: input.body,
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    if (input.action === "delete") {
      return auth.api.deleteOAuthClient({
        body: input.body,
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    if (input.action === "list") {
      return auth.api.getOAuthClients({
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    if (input.action === "public") {
      return auth.api.getOAuthClientPublic({
        query: input.query,
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    if (input.action === "get") {
      return auth.api.getOAuthClient({
        query: input.query,
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    return auth.api.createOAuthClient({
      body: input.body,
      ...(input.headers ? { headers: new Headers(input.headers) } : {}),
      asResponse: true,
    });
  };
}
