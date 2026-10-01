import { betterAuth, type BetterAuthOptions } from "better-auth";

/** Genuine built-in provider configuration with only deterministic local transport. */
export function socialProviderFixture(base: BetterAuthOptions) {
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  let profile: Record<string, unknown> = {};
  const receipts: unknown[] = [];
  const provider = Bun.serve({ port: 0, async fetch(request) {
    const path = new URL(request.url).pathname;
    const body = request.method === "POST" ? Object.fromEntries(new URLSearchParams(await request.text())) : null;
    receipts.push({ path, method: request.method, authorization: request.headers.get("authorization"), contentType: request.headers.get("content-type"), body });
    if (path === "/token") return Response.json({ access_token: "fixture-discord-access", token_type: "Bearer", scope: "identify email", expires_in: 3600 });
    if (path === "/userinfo") return Response.json(profile);
    return new Response("Unknown local provider endpoint", { status: 404 });
  }});
  const previousFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = (async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    if (url.origin === "https://discord.com" && url.pathname === "/api/oauth2/token") return previousFetch(new Request(`${provider.url}token`, request));
    if (url.origin === "https://discord.com" && decodeURIComponent(url.pathname) === "/api/users/@me") return previousFetch(new Request(`${provider.url}userinfo`, request));
    return previousFetch(input, init);
  }) as typeof fetch;
  for (const name of ["google", "github", "discord"] as const) {
    for (const mode of ["default", "configured", "disabled", "disabled-configured", "permissions", "bot", "zero", "fractional", "infinite", "prompt", "empty-prompt"]) {
      if (name !== "discord" && !["default", "configured", "disabled", "disabled-configured"].includes(mode)) continue;
      const path = `/__test/profiles/social-${name}-${mode}/api/auth`;
      const options = {
        clientId: "fixture-social-client", clientSecret: "fixture-social-secret",
        ...(mode === "configured" || mode === "disabled-configured" ? { scope: ["configured-scope"] } : {}),
        ...(mode.startsWith("disabled") ? { disableDefaultScope: true } : {}),
        ...(["permissions", "bot"].includes(mode) ? { permissions: 8 } : {}),
        ...(mode === "bot" ? { scope: ["bot"] } : {}),
        ...(mode === "zero" ? { permissions: 0 } : {}),
        ...(mode === "fractional" ? { permissions: 1.5 } : {}),
        ...(mode === "infinite" ? { permissions: Infinity } : {}),
        ...(mode === "prompt" ? { prompt: "consent" as const } : {}),
        ...(mode === "empty-prompt" ? { prompt: "" as "none" } : {}),
      };
      const authOptions: BetterAuthOptions = { ...base, basePath: path, plugins: [], socialProviders: { [name]: options } };
      profiles.set(path, betterAuth(authOptions));
    }
  }
  async function state() {
    const { adapter } = await profiles.get("/__test/profiles/social-discord-default/api/auth")!.$context;
    const [users, accounts, sessions] = await Promise.all([
      adapter.findMany<Record<string, unknown>>({ model: "user", sortBy: { field: "createdAt", direction: "asc" } }),
      adapter.findMany<Record<string, unknown>>({ model: "account", sortBy: { field: "createdAt", direction: "asc" } }),
      adapter.findMany<Record<string, unknown>>({ model: "session", sortBy: { field: "createdAt", direction: "asc" } }),
    ]);
    return Response.json({
      users: users.map(row => ({ id: row.id, name: row.name, email: row.email, emailVerified: row.emailVerified, image: row.image ?? null, createdAt: row.createdAt, updatedAt: row.updatedAt })),
      accounts: accounts.map(row => ({ id: row.id, userId: row.userId, accountId: row.accountId, providerId: row.providerId, accessToken: row.accessToken ?? null, refreshToken: row.refreshToken ?? null, idToken: row.idToken ?? null, scope: row.scope ?? null, accessTokenExpiresAt: row.accessTokenExpiresAt ?? null, refreshTokenExpiresAt: row.refreshTokenExpiresAt ?? null, createdAt: row.createdAt, updatedAt: row.updatedAt })),
      sessions: sessions.map(row => ({ id: row.id, userId: row.userId, token: row.token, expiresAt: row.expiresAt, createdAt: row.createdAt, updatedAt: row.updatedAt, ipAddress: row.ipAddress ?? null, userAgent: row.userAgent ?? null })),
      receipts,
    });
  }
  return { profiles, reset() { profile = {}; receipts.length = 0; }, async handle(request: Request) {
    const url = new URL(request.url);
    if (url.pathname === "/__test/social-provider/profile" && request.method === "POST") {
      profile = await request.json(); return Response.json({ status: true, profile });
    }
    if (url.pathname === "/__test/social-provider/state") return state();
    return null;
  }};
}
