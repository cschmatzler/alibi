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
    selection: betterAuth({
      ...options,
      plugins: [
        username(),
        jwt(),
        oauthProvider({
          loginPage: "/login",
          consentPage: "/consent",
          selectAccount: { page: "/select", shouldRedirect: () => false },
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
    if (
      request.method === "GET" &&
      new URL(request.url).pathname === `${base.basePath ?? "/api/auth"}/jwks`
    ) {
      return auths.default.handler(request);
    }
    const input = await request.json();
    const auth = auths[input.mode as keyof typeof auths] ?? auths.default;
    if (input.action === "session-row") {
      const context = await auth.$context;
      const row = await context.adapter.findOne<{ id: string }>({
        model: "session",
        where: [{ field: "token", value: input.token }],
      });
      return new Response(JSON.stringify(row ? { id: row.id } : null), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "confirm-logical") {
      return (auth.api as any).oauth2EndSessionConfirmation({
        body: { action: "confirm" },
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    if (input.action === "logout-http") {
      const headers = new Headers(input.headers ?? {});
      headers.set("origin", base.baseURL!);
      headers.set("content-type", "application/x-www-form-urlencoded");
      return auth.handler(
        new Request(`${base.baseURL}${base.basePath ?? "/api/auth"}${input.path}`, {
          method: input.method,
          headers,
          ...(input.method === "POST" ? { body: new URLSearchParams(input.body) } : {}),
        }),
      );
    }
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
                id: row.id,
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
    if (input.action === "jwks") {
      return auth.api.getJwks({ asResponse: true });
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
    if (input.action === "expire-session") {
      const context = await auth.$context;
      const updated = await context.internalAdapter.updateSession(input.token, {
        expiresAt: new Date(Date.now() - 1000),
      });
      return new Response(
        JSON.stringify({ expired: Boolean(updated && updated.expiresAt.getTime() < Date.now()) }),
        { headers: { "content-type": "application/json" } },
      );
    }
    if (input.action === "revoke-concurrently") {
      const call = () =>
        auth.api.oauth2Revoke({
          body: input.body,
          headers: new Headers(input.headers ?? {}),
          asResponse: true,
          request: new Request(`${base.baseURL}${base.basePath ?? "/api/auth"}/oauth2/revoke`, {
            method: "POST",
            headers: { ...input.headers, "content-type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams(input.body),
          }),
        });
      const responses = await Promise.all([call(), call()]);
      return new Response(
        JSON.stringify(responses.map((response) => response.status).sort((a, b) => a - b)),
        { headers: { "content-type": "application/json" } },
      );
    }
    if (input.action === "revoke") {
      return auth.api.oauth2Revoke({
        body: input.body,
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
        request: new Request(`${base.baseURL}${base.basePath ?? "/api/auth"}/oauth2/revoke`, {
          method: "POST",
          headers: { ...input.headers, "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams(input.body),
        }),
      });
    }
    if (input.action === "introspect") {
      return auth.api.oauth2Introspect({
        body: input.body,
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
        request: new Request(`${base.baseURL}${base.basePath ?? "/api/auth"}/oauth2/introspect`, {
          method: "POST",
          headers: { ...input.headers, "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams(input.body),
        }),
      });
    }
    if (input.action === "userinfo") {
      return auth.api.oauth2UserInfo({
        body: input.body,
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
        ...(input.attachRequest === false
          ? {}
          : {
              request: new Request(
                `${base.baseURL}${base.basePath ?? "/api/auth"}/oauth2/userinfo`,
                {
                  method: input.method ?? "GET",
                  headers: {
                    ...input.headers,
                    ...(input.method === "POST"
                      ? { "content-type": "application/x-www-form-urlencoded" }
                      : {}),
                  },
                  ...(input.method === "POST"
                    ? { body: new URLSearchParams(input.body ?? {}) }
                    : {}),
                },
              ),
            }),
      });
    }
    if (input.action === "token") {
      return auth.api.oauth2Token({
        body: input.body,
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
        request: new Request(`${base.baseURL}${base.basePath ?? "/api/auth"}/oauth2/token`, {
          method: "POST",
          headers: {
            ...input.headers,
            "content-type": "application/x-www-form-urlencoded",
          },
          body: new URLSearchParams(input.body),
        }),
      });
    }
    if (input.action === "token-row") {
      const { createHash } = await import("node:crypto");
      const context = await auth.$context;
      const row = (await context.adapter.findOne({
        model: input.kind === "refresh" ? "oauthRefreshToken" : "oauthAccessToken",
        where: [
          { field: "token", value: createHash("sha256").update(input.token).digest("base64url") },
        ],
      })) as any;
      return new Response(
        JSON.stringify(
          row
            ? {
                id: row.id,
                clientId: row.clientId,
                userId: row.userId,
                sessionId: row.sessionId,
                scopes: row.scopes,
                createdAt: row.createdAt,
                expiresAt: row.expiresAt,
                authorizationCodeId: row.authorizationCodeId,
                token: row.token,
                refreshId: row.refreshId ?? null,
                authTime: row.authTime ?? null,
                resources: row.resources ?? null,
                revoked: row.revoked ?? null,
              }
            : null,
        ),
        { headers: { "content-type": "application/json" } },
      );
    }
    if (input.action === "end-session") {
      return auth.api.oauth2EndSession({
        query: input.query,
        body: input.body,
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
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
    if (input.action === "resource-unlink") {
      return auth.api.adminUnlinkClientResource({
        params: input.params,
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    if (input.action === "resource-link") {
      return auth.api.adminLinkClientResource({
        params: input.params,
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    if (input.action === "resource-links") {
      const context = await auth.$context;
      const rows = await context.adapter.findMany({
        model: "oauthClientResource",
        where: [{ field: "clientId", value: input.clientId }],
      });
      return new Response(JSON.stringify(rows), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "resource-delete") {
      const call = () =>
        auth.api.adminDeleteOAuthResource({
          params: input.params,
          headers: new Headers(input.headers ?? {}),
          asResponse: true,
        });
      if (input.foreignKeys === true) {
        const database = base.database as import("bun:sqlite").Database;
        const prior = database
          .query<{ foreign_keys: number }, []>("PRAGMA foreign_keys")
          .get()!.foreign_keys;
        database.exec("PRAGMA foreign_keys=ON");
        try {
          return await call();
        } finally {
          database.exec(`PRAGMA foreign_keys=${prior}`);
        }
      }
      return call();
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
          `${base.baseURL}${base.basePath ?? "/api/auth"}/admin/oauth2/resources${["read", "update", "delete", "link", "unlink"].includes(input.operation) ? `/${encodeURIComponent(input.identifier)}${["link", "unlink"].includes(input.operation) ? `/clients/${encodeURIComponent(input.clientId)}` : ""}` : ""}`,
          {
            method: ["delete", "unlink"].includes(input.operation)
              ? "DELETE"
              : input.operation === "update"
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
    if (input.action === "continue") {
      try {
        return await auth.api.oauth2Continue({
          body: input.body,
          headers: new Headers(input.headers ?? {}),
          asResponse: true,
          ...(input.attachRequest === false
            ? {}
            : {
                request: new Request(
                  `${base.baseURL}${base.basePath ?? "/api/auth"}/oauth2/continue`,
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
