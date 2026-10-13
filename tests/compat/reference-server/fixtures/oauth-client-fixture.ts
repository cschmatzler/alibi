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
  const auths = {
    default: betterAuth(options),
    dynamic: betterAuth({
      ...options,
      plugins: [
        username(),
        jwt(),
        oauthProvider({
          loginPage: "/login",
          consentPage: "/consent",
          allowDynamicClientRegistration: true,
        }),
      ],
    }),
    public: betterAuth({
      ...options,
      plugins: [
        username(),
        jwt(),
        oauthProvider({
          loginPage: "/login",
          consentPage: "/consent",
          allowDynamicClientRegistration: true,
          allowUnauthenticatedClientRegistration: true,
        }),
      ],
    }),
  };
  return async (request: Request) => {
    const input = await request.json();
    const auth = auths[input.mode as keyof typeof auths] ?? auths.default;
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
                userId: row.userId ?? null,
                clientName: row.name,
                redirectUris: row.redirectUris,
                client_secret: row.clientSecret ?? null,
              }
            : null,
        ),
        { headers: { "content-type": "application/json" } },
      );
    }
    if (input.action === "admin-http") {
      const response = await auth.handler(
        new Request(
          `${base.baseURL}${base.basePath ?? "/api/auth"}/admin/oauth2/${input.operation === "update" ? "update-client" : "create-client"}`,
          {
            method: input.operation === "update" ? "PATCH" : "POST",
            headers: { ...input.headers, "content-type": "application/json" },
            body: JSON.stringify(input.body),
          },
        ),
      );
      return new Response(JSON.stringify({ status: response.status }), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "admin-update") {
      return auth.api.adminUpdateOAuthClient({
        body: input.body,
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    if (input.action === "admin-create") {
      return auth.api.adminCreateOAuthClient({
        body: input.body,
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    if (input.action === "register") {
      return auth.api.registerOAuthClient({
        body: input.body,
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
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
