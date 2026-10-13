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
    prelogin: betterAuth({
      ...options,
      plugins: [
        username(),
        jwt(),
        oauthProvider({
          loginPage: "/login",
          consentPage: "/consent",
          allowPublicClientPrelogin: true,
        }),
      ],
    }),
    expired: betterAuth({
      ...options,
      plugins: [
        username(),
        jwt(),
        oauthProvider({
          loginPage: "/login",
          consentPage: "/consent",
          allowPublicClientPrelogin: true,
          codeExpiresIn: -1,
        }),
      ],
    }),
    "resources-open": betterAuth({
      ...options,
      plugins: [
        username(),
        jwt(),
        oauthProvider({
          loginPage: "/login",
          consentPage: "/consent",
          enforcePerClientResources: false,
        }),
      ],
    }),
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
    if (input.action === "session") {
      return auth.api.getSession({ headers: new Headers(input.headers ?? {}), asResponse: true });
    }
    if (input.action === "grant-row") {
      const { createHash } = await import("node:crypto");
      const context = await auth.$context;
      const row = (await context.adapter.findOne({
        model: "verification",
        where: [
          {
            field: "identifier",
            value: createHash("sha256").update(input.token).digest("base64url"),
          },
        ],
      })) as any;
      return new Response(
        JSON.stringify(
          row
            ? { value: JSON.parse(row.value), createdAt: row.createdAt, expiresAt: row.expiresAt }
            : null,
        ),
        { headers: { "content-type": "application/json" } },
      );
    }
    if (input.action === "authorize") {
      const headers = new Headers(input.headers ?? {});
      return auth.api.oauth2Authorize({
        query: input.query,
        headers,
        asResponse: true,
        ...(input.attachRequest === false
          ? {}
          : {
              request: new Request(
                `${base.baseURL}${base.basePath ?? "/api/auth"}/oauth2/authorize`,
                { headers },
              ),
            }),
      });
    }
    if (input.action === "resource-update") {
      return auth.api.adminUpdateOAuthResource({
        params: input.params,
        body: input.body,
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    if (input.action === "resource-get") {
      return auth.api.adminGetOAuthResource({
        params: input.params,
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    if (input.action === "resource-list") {
      return auth.api.adminListOAuthResources({
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    if (input.action === "resource-create") {
      return auth.api.adminCreateOAuthResource({
        body: input.body,
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    if (input.action === "resource-row") {
      const context = await auth.$context;
      const row = await context.adapter.findOne({
        model: "oauthResource",
        where: [{ field: "identifier", value: input.identifier }],
      });
      return new Response(JSON.stringify(row), { headers: { "content-type": "application/json" } });
    }
    if (input.action === "resource-http") {
      const response = await auth.handler(
        new Request(
          `${base.baseURL}${base.basePath ?? "/api/auth"}/admin/oauth2/resources${["read", "update"].includes(input.operation) ? `/${encodeURIComponent(input.identifier)}` : ""}`,
          {
            method:
              input.operation === "update"
                ? "PATCH"
                : ["list", "read"].includes(input.operation)
                  ? "GET"
                  : "POST",
            headers: { ...input.headers, "content-type": "application/json" },
            ...(["list", "read"].includes(input.operation)
              ? {}
              : { body: JSON.stringify(input.body) }),
          },
        ),
      );
      return new Response(JSON.stringify({ status: response.status }), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "consent-delete") {
      return auth.api.deleteOAuthConsent({
        body: input.body,
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    if (input.action === "consent-update") {
      return auth.api.updateOAuthConsent({
        body: input.body,
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    if (input.action === "consent-get") {
      return auth.api.getOAuthConsent({
        query: input.query,
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    if (input.action === "consents") {
      return auth.api.getOAuthConsents({
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    if (input.action === "consent-row") {
      const context = await auth.$context;
      const rows = await context.adapter.findMany({
        model: "oauthConsent",
        where: [{ field: "clientId", value: input.clientId }],
      });
      return new Response(JSON.stringify(rows), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "consent") {
      try {
        return await auth.api.oauth2Consent({
          body: input.body,
          headers: new Headers(input.headers ?? {}),
          asResponse: true,
          ...(input.attachRequest === false
            ? {}
            : {
                request: new Request(
                  `${base.baseURL}${base.basePath ?? "/api/auth"}/oauth2/consent`,
                  { method: "POST", headers: input.headers },
                ),
              }),
        });
      } catch (error) {
        const failure = error as { statusCode?: number; body?: unknown };
        if (!failure.statusCode) {
          throw error;
        }
        return new Response(failure.body ? JSON.stringify(failure.body) : null, {
          status: failure.statusCode,
          headers: { "content-type": "application/json" },
        });
      }
    }
    if (input.action === "prelogin") {
      try {
        return await auth.api.getOAuthClientPublicPrelogin({ body: input.body, asResponse: true });
      } catch (error) {
        const failure = error as { statusCode?: number; body?: unknown };
        if (!failure.statusCode) {
          throw error;
        }
        return new Response(failure.body ? JSON.stringify(failure.body) : null, {
          status: failure.statusCode,
          headers: { "content-type": "application/json" },
        });
      }
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
