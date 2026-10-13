import { sso } from "@better-auth/sso";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { username } from "better-auth/plugins";
export async function ssoFixture(base: BetterAuthOptions) {
  const options = {
    baseURL: base.baseURL,
    basePath: base.basePath,
    secret: base.secret,
    database: base.database,
    emailAndPassword: { enabled: true },
    plugins: [username(), sso()],
  };
  await (await getMigrations(options)).runMigrations();
  let auth = betterAuth(options);
  const handle = async (request: Request) => {
    const input = await request.json();
    if (input.action === "signup") {
      return auth.api.signUpEmail({ body: input.body, asResponse: true });
    }
    if (input.action === "delete-fault") {
      const database = base.database as any;
      database.exec(
        input.enabled
          ? `CREATE TRIGGER sso_delete_fault BEFORE DELETE ON "ssoProvider" BEGIN SELECT RAISE(ABORT, 'forced provider deletion failure'); END`
          : "DROP TRIGGER sso_delete_fault",
      );
      return new Response(JSON.stringify({ enabled: input.enabled }), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "create-account") {
      const context = await auth.$context;
      const row = await context.internalAdapter.createAccount(input.body);
      return new Response(
        JSON.stringify({
          id: row.id,
          userId: row.userId,
          providerId: row.providerId,
          accountId: row.accountId,
        }),
        { headers: { "content-type": "application/json" } },
      );
    }
    if (input.action === "account-row") {
      const context = await auth.$context;
      const row = await context.adapter.findOne({
        model: "account",
        where: [
          { field: "providerId", value: input.providerId },
          { field: "accountId", value: input.accountId },
        ],
      });
      return new Response(
        JSON.stringify(
          row
            ? {
                id: row.id,
                userId: row.userId,
                providerId: row.providerId,
                accountId: row.accountId,
              }
            : null,
        ),
        { headers: { "content-type": "application/json" } },
      );
    }
    if (input.action === "update") {
      return auth.api.updateSSOProvider({
        body: input.body,
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    if (input.action === "delete") {
      return auth.api.deleteSSOProvider({
        body: input.body,
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    if (input.action === "list") {
      return auth.api.listSSOProviders({
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    if (input.action === "get") {
      return auth.api.getSSOProvider({
        query: input.query,
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    if (input.action === "restart") {
      auth = betterAuth(options);
      return new Response(JSON.stringify({ restarted: true }), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "row") {
      const context = await auth.$context;
      const row = await context.adapter.findOne({
        model: "ssoProvider",
        where: [{ field: "providerId", value: input.providerId }],
      });
      return new Response(JSON.stringify(row), { headers: { "content-type": "application/json" } });
    }
    return auth.api.registerSSOProvider({
      body: input.body,
      headers: new Headers(input.headers ?? {}),
      asResponse: true,
    });
  };
  // Both hosts serialize an escaped ordinary server exception as an empty 500.
  // Intentional API errors are already rendered by asResponse above.
  return async (request: Request) => {
    try {
      return await handle(request);
    } catch {
      return new Response(null, { status: 500 });
    }
  };
}
