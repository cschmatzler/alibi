import { Database } from "bun:sqlite";
import { createHash } from "node:crypto";

import { betterAuth, type BetterAuthOptions } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { bearer, oauthPopup, genericOAuth } from "better-auth/plugins";

export async function oauthPopupFixture(base: BetterAuthOptions) {
  const path = "/__test/profiles/oauth-popup/api/auth";
  const control = "/__test/oauth-popup";
  const database = new Database(":memory:");
  const options: BetterAuthOptions = {
    ...base,
    database,
    basePath: path,
    trustedOrigins: [
      String(base.baseURL),
      String(base.baseURL).replace("localhost", "127.0.0.1"),
      "http://app.fixture.test",
    ],
    plugins: [
      bearer(),
      oauthPopup(),
      genericOAuth({
        config: [
          {
            providerId: "local",
            clientId: "popup-client",
            clientSecret: "popup-secret",
            authorizationUrl: `${base.baseURL}${control}/provider/oauth/authorize`,
            tokenUrl: `${base.baseURL}${control}/provider/oauth/token`,
            userInfoUrl: `${base.baseURL}${control}/provider/api/v4/user`,
            scopes: ["read_user"],
            authentication: "post",
            mapProfileToUser: (profile) => ({
              name: profile.name,
              email: profile.email,
              emailVerified: profile.email_verified === true,
              image: typeof profile.avatar_url === "string" ? profile.avatar_url : undefined,
            }),
          },
        ],
      }),
    ],
    socialProviders: {
      gitlab: {
        clientId: "popup-client",
        clientSecret: "popup-secret",
        issuer: `${base.baseURL}${control}/provider`,
      },
    },
  };
  await (await getMigrations(options)).runMigrations();
  const auth = betterAuth(options);
  const grants = new Map<string, { challenge: string; redirect: string; used: boolean }>();
  const receipts: unknown[] = [];
  let count = 0;
  let hold = false;
  const { adapter } = await auth.$context;
  return {
    async handle(request: Request): Promise<Response | null> {
      const url = new URL(request.url);
      if (url.pathname.startsWith(`${path}/`)) {
        const response =
          request.method === "OPTIONS"
            ? new Response(null, { status: 204 })
            : await auth.handler(request);
        const origin = request.headers.get("origin");
        if (
          origin &&
          [
            String(base.baseURL),
            String(base.baseURL).replace("localhost", "127.0.0.1"),
            "http://app.fixture.test",
          ].includes(origin)
        ) {
          response.headers.set("access-control-allow-origin", origin);
          response.headers.set("access-control-allow-credentials", "true");
          response.headers.set(
            "access-control-allow-headers",
            "Content-Type, Authorization, X-Requested-With",
          );
          response.headers.set(
            "access-control-allow-methods",
            "GET, POST, PUT, DELETE, PATCH, OPTIONS",
          );
          response.headers.set("access-control-max-age", "86400");
        }
        return response;
      }
      if (url.pathname === `${control}/state`) {
        const rows: Record<string, unknown> = {};
        for (const model of ["user", "account", "session", "verification"]) {
          rows[model] = await adapter.findMany({ model });
        }
        return Response.json({ ...rows, receipts });
      }
      if (url.pathname === `${control}/reset`) {
        for (const model of ["session", "account", "verification", "user"]) {
          await adapter.deleteMany({ model, where: [] });
        }
        hold = false;
        grants.clear();
        receipts.length = 0;
        count = 0;
        return Response.json({ status: true });
      }
      if (url.pathname === `${control}/expire`) {
        for (const row of await adapter.findMany<{ id: string; value: string }>({
          model: "verification",
        })) {
          const value = JSON.parse(row.value);
          value.expiresAt = 0;
          await adapter.update({
            model: "verification",
            where: [{ field: "id", value: row.id }],
            update: { value: JSON.stringify(value), expiresAt: new Date(0) },
          });
        }
        return Response.json({ status: true });
      }
      if (url.pathname === `${control}/hold`) {
        hold = true;
        return Response.json({ status: true });
      }
      if (url.pathname === `${control}/provider/oauth/authorize`) {
        if (hold) {
          return new Response("<title>Provider awaiting approval</title>", {
            headers: { "content-type": "text/html" },
          });
        }
        receipts.push({ stage: "authorize", query: Object.fromEntries(url.searchParams) });
        const code = `popup-code-${++count}`;
        grants.set(code, {
          challenge: url.searchParams.get("code_challenge")!,
          redirect: url.searchParams.get("redirect_uri")!,
          used: false,
        });
        const callback = new URL(url.searchParams.get("redirect_uri")!);
        callback.searchParams.set("state", url.searchParams.get("state")!);
        callback.searchParams.set("code", code);
        return new Response(null, { status: 302, headers: { location: callback.href } });
      }
      if (url.pathname === `${control}/provider/oauth/token`) {
        const body = Object.fromEntries(new URLSearchParams(await request.text()));
        receipts.push({ stage: "token", body });
        const grant = grants.get(body.code!);
        if (
          !grant ||
          grant.used ||
          body.redirect_uri !== grant.redirect ||
          createHash("sha256").update(body.code_verifier!).digest("base64url") !== grant.challenge
        ) {
          return Response.json({ error: "invalid_grant" }, { status: 400 });
        }
        grant.used = true;
        return Response.json({
          access_token: "popup-access",
          refresh_token: "popup-refresh",
          token_type: "Bearer",
          scope: "read_user",
          expires_in: 3600,
        });
      }
      if (url.pathname === `${control}/provider/api/v4/user`) {
        receipts.push({ stage: "userinfo", authorization: request.headers.get("authorization") });
        return Response.json({
          id: 132,
          email: "popup-owner@fixture.test",
          email_verified: true,
          name: "Popup Owner",
          avatar_url: "https://assets.fixture.test/popup.png",
          state: "active",
          locked: false,
        });
      }
      return null;
    },
  };
}
