import type { Database } from "bun:sqlite";
import { appendFileSync } from "node:fs";

import { applyDefaultAccessTokenExpiry } from "@better-auth/core/oauth2";
import { type BetterAuthOptions, betterAuth } from "better-auth";

import inputs from "../../fixtures/provider-batch-profiles.json";

export const providerBatchModes = [
  "default",
  "claims-empty",
  "claims-custom",

  "expiry-positive",
  "expiry-zero",
  "expiry-negative",
  "custom-token",
  "custom-token-error",
  "configured",
  "disabled-configured",
  "mapped-async",
  "custom-async",
  "custom-error",
  "mapper-error",
  "refresh-callback",
  "override",
  "encrypted",
  "client-array",
  "empty-primary",
  "signup-disabled",
  "implicit-disabled",
  "required",
] as const;
const destinations: Record<string, { token: string[]; user?: string }> = {
  notion: {
    token: ["https://api.notion.com/v1/oauth/token"],
    user: "https://api.notion.com/v1/users/me",
  },
  paybin: { token: ["https://idp.paybin.io/oauth2/token"] },
  paypal: {
    token: ["https://api-m.sandbox.paypal.com/v1/oauth2/token"],
    user: "https://api-m.sandbox.paypal.com/v1/identity/oauth2/userinfo",
  },
  polar: {
    token: ["https://api.polar.sh/v1/oauth2/token"],
    user: "https://api.polar.sh/v1/oauth2/userinfo",
  },
  railway: {
    token: ["https://backboard.railway.com/oauth/token"],
    user: "https://backboard.railway.com/oauth/me",
  },
  reddit: {
    token: ["https://www.reddit.com/api/v1/access_token"],
    user: "https://oauth.reddit.com/api/v1/me",
  },
  roblox: {
    token: ["https://apis.roblox.com/oauth/v1/token"],
    user: "https://apis.roblox.com/oauth/v1/userinfo",
  },
  salesforce: {
    token: ["https://login.salesforce.com/services/oauth2/token"],
    user: "https://login.salesforce.com/services/oauth2/userinfo",
  },
  slack: {
    token: ["https://slack.com/api/openid.connect.token"],
    user: "https://slack.com/api/openid.connect.userInfo",
  },
  spotify: {
    token: ["https://accounts.spotify.com/api/token"],
    user: "https://api.spotify.com/v1/me",
  },
  tiktok: {
    token: ["https://open.tiktokapis.com/v2/oauth/token/"],
    user: "https://open.tiktokapis.com/v2/user/info/",
  },
  twitch: { token: ["https://id.twitch.tv/oauth2/token"] },
  twitter: { token: ["https://api.x.com/2/oauth2/token"], user: "https://api.x.com/2/users/me" },
  vercel: {
    token: ["https://api.vercel.com/login/oauth/token"],
    user: "https://api.vercel.com/login/oauth/userinfo",
  },
  vk: { token: ["https://id.vk.com/oauth2/auth"], user: "https://id.vk.com/oauth2/user_info" },
  wechat: {
    token: [
      "https://api.weixin.qq.com/sns/oauth2/access_token",
      "https://api.weixin.qq.com/sns/oauth2/refresh_token",
    ],
    user: "https://api.weixin.qq.com/sns/userinfo",
  },
  zoom: { token: ["https://zoom.us/oauth/token"], user: "https://api.zoom.us/v2/users/me" },
};

/** Inputs are provider responses; the published factories produce every assertion target. */
export function providerBatchFixture(base: BetterAuthOptions, database: Database) {
  let control: Record<string, unknown> = {};
  const receipts: unknown[] = [];
  const callbacks: unknown[] = [];
  const jwt = (profile: unknown) =>
    `e30.${Buffer.from(JSON.stringify(profile)).toString("base64url")}.fixture`;
  const transport = Bun.serve({
    port: 0,
    async fetch(request) {
      const url = new URL(request.url);
      const [provider, stage] = url.pathname.slice(1).split("/");
      const body =
        request.method === "POST"
          ? Object.fromEntries(new URLSearchParams(await request.text()))
          : null;
      const declaredHeaders: Record<string, string> = JSON.parse(
        request.headers.get("x-provider-batch-declared-headers") ?? "{}",
      );
      const receipt = {
        provider,
        stage,
        method: request.method,
        query: Object.fromEntries(url.searchParams),
        body,
        headers: Object.fromEntries(request.headers),
        declaredHeaders,
      };
      receipts.push(receipt);
      if (process.env.PROVIDER_BATCH_WIRE_LOG) {
        appendFileSync(process.env.PROVIDER_BATCH_WIRE_LOG, `${JSON.stringify(receipt)}\n`);
      }
      if (stage === "token" || stage === "refresh") {
        const response = Object.hasOwn(control, "tokenResponse")
          ? control.tokenResponse
          : {
              access_token: "batch-access",
              refresh_token: "batch-refresh",
              token_type: "Bearer",
              expires_in: 3600,
              scope: "identity email",
              openid: "batch-subject",
              ...(["paybin", "twitch"].includes(provider)
                ? {
                    id_token: jwt(
                      Object.hasOwn(control, "profile")
                        ? control.profile
                        : inputs[provider as keyof typeof inputs],
                    ),
                  }
                : {}),
            };
        return Response.json(response, { status: Number(control.tokenStatus ?? 200) });
      }
      if (stage === "email") {
        return Response.json(
          Object.hasOwn(control, "emailProfile")
            ? control.emailProfile
            : { data: { confirmed_email: "batch@example.invalid" } },
          { status: Number(control.emailStatus ?? 200) },
        );
      }
      return Response.json(
        Object.hasOwn(control, "profile")
          ? control.profile
          : inputs[provider as keyof typeof inputs],
        { status: Number(control.profileStatus ?? 200) },
      );
    },
  });
  const previousFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = (async (input, init) => {
    const active = typeof control.provider === "string" ? control.provider : undefined;
    if (!active || !destinations[active]) return previousFetch(input, init);
    const request = new Request(input, init);
    const url = new URL(request.url);
    const destination = destinations[active];
    const endpoint = `${url.origin}${url.pathname}`;
    let stage: string | undefined;
    if (destination.token.includes(endpoint)) {
      stage = endpoint.includes("refresh_token") ? "refresh" : "token";
    } else if (endpoint === destination.user) {
      stage =
        active === "twitter" && url.searchParams.get("user.fields") === "confirmed_email"
          ? "email"
          : "user";
    }
    if (!stage) return previousFetch(input, init);
    request.headers.set(
      "x-provider-batch-declared-headers",
      JSON.stringify(Object.fromEntries(request.headers)),
    );
    return previousFetch(new Request(`${transport.url}${active}/${stage}${url.search}`, request));
  }) as typeof fetch;
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  for (const provider of Object.keys(inputs)) {
    for (const mode of providerBatchModes) {
      if (mode.startsWith("claims-") && provider !== "twitch") continue;
      const path = `/__test/profiles/provider-batch-${provider}-${mode}/api/auth`;
      const providerOptions: Record<string, unknown> = {
        clientId:
          mode === "client-array"
            ? ["batch-client", "secondary-client"]
            : mode === "empty-primary"
              ? ["", "secondary-client"]
              : "batch-client",
        ...(provider === "tiktok" ? { clientKey: "batch-client" } : {}),
        clientSecret: "batch-secret",
        ...(mode === "claims-empty"
          ? { claims: [] }
          : mode === "claims-custom"
            ? { claims: ["custom", "custom", "email", "__proto__"] }
            : {}),
        ...(["configured", "disabled-configured"].includes(mode)
          ? {
              scope: ["configured", "shared", "configured"],
              disableDefaultScope: mode === "disabled-configured",
            }
          : {}),
        ...(mode === "override" ? { overrideUserInfoOnSignIn: true } : {}),
        ...(mode === "signup-disabled" ? { disableSignUp: true } : {}),
        ...(mode === "implicit-disabled" ? { disableImplicitSignUp: true } : {}),
        ...(mode === "required" ? { requireEmailVerification: true } : {}),
      };
      if (["mapped-async", "mapper-error"].includes(mode)) {
        providerOptions.mapProfileToUser = async (profile: unknown) => {
          callbacks.push({ kind: "mapper", provider, profile });
          await Promise.resolve();
          if (mode === "mapper-error") throw new Error("fixture mapper exception");
          return Object.hasOwn(control, "mapped")
            ? control.mapped
            : {
                id: "mapped-id-cannot-replace-subject",
                name: "Async Name",
                email: "mapped@example.invalid",
                emailVerified: true,
                image: null,
              };
        };
      }
      if (["custom-async", "custom-error"].includes(mode)) {
        providerOptions.getUserInfo = async (token: unknown) => {
          callbacks.push({ kind: "userinfo", provider, token });
          await Promise.resolve();
          if (mode === "custom-error") throw new Error("fixture userinfo exception");
          return {
            user: {
              id: "callback-id-cannot-replace-subject",
              name: "Callback Name",
              email: "callback@example.invalid",
              emailVerified: true,
              image: null,
            },
            data: Object.hasOwn(control, "profile")
              ? control.profile
              : provider === "notion"
                ? inputs.notion.bot.owner.user
                : inputs[provider as keyof typeof inputs],
          };
        };
      }
      if (mode === "refresh-callback") {
        providerOptions.refreshAccessToken = async (refreshToken: unknown) => {
          callbacks.push({ kind: "refresh", provider, refreshToken });
          await Promise.resolve();
          return {
            accessToken: "callback-access",
            refreshToken: "callback-refresh",
            accessTokenExpiresAt: new Date(Date.now() + 3600000),
            scopes: ["callback-scope"],
          };
        };
      }
      const settings: BetterAuthOptions = {
        ...base,
        basePath: path,
        // Public BetterAuthPlugin.init application policy: keep factory grant/refresh
        // handlers; these are not built-in factory getToken/expiry options.
        plugins:
          mode.startsWith("expiry-") || mode.startsWith("custom-token")
            ? [
                {
                  id: "provider-batch-grant-policy",
                  init(context) {
                    const configured = context.socialProviders.find(
                      (entry) => entry.id === provider,
                    )!;
                    const lifetime =
                      mode === "expiry-zero" ? 0 : mode === "expiry-negative" ? -60 : 17;
                    const grant = configured.validateAuthorizationCode.bind(configured);
                    configured.validateAuthorizationCode = async (data) => {
                      if (!mode.startsWith("custom-token")) {
                        return applyDefaultAccessTokenExpiry(await grant(data), lifetime);
                      }
                      await Promise.resolve();
                      callbacks.push({
                        kind: "custom-token",
                        provider,
                        code: data.code,
                        redirectURI: data.redirectURI,
                        codeVerifier: data.codeVerifier,
                      });
                      if (mode === "custom-token-error") {
                        throw new Error("custom token callback denied");
                      }
                      return applyDefaultAccessTokenExpiry(
                        {
                          accessToken: "custom-access",
                          refreshToken: "custom-refresh",
                          scopes: ["custom-scope"],
                        },
                        lifetime,
                      );
                    };
                    if (configured.refreshAccessToken) {
                      const refresh = configured.refreshAccessToken.bind(configured);
                      configured.refreshAccessToken = async (token, context) =>
                        applyDefaultAccessTokenExpiry(await refresh(token, context), lifetime);
                    }
                  },
                },
              ]
            : [],
        account: { ...base.account, encryptOAuthTokens: mode === "encrypted" },
        socialProviders: { [provider]: providerOptions } as BetterAuthOptions["socialProviders"],
      };
      profiles.set(path, betterAuth(settings));
    }
  }
  return {
    profiles,
    reset() {
      control = {};
      receipts.length = 0;
      callbacks.length = 0;
    },
    async handle(request: Request) {
      const path = new URL(request.url).pathname;
      if (path === "/__test/provider-batch/control" && request.method === "POST") {
        control = await request.json();
        return Response.json({ status: true });
      }
      if (path === "/__test/provider-batch/receipts") return Response.json(receipts);
      if (path === "/__test/provider-batch/callbacks") return Response.json(callbacks);
      if (path === "/__test/provider-batch/sql-state") {
        return Response.json(
          Object.fromEntries(
            ["user", "account", "session", "verification"].map((table) => [
              table,
              database.query(`SELECT * FROM "${table}" ORDER BY rowid`).all(),
            ]),
          ),
        );
      }
      return null;
    },
  };
}
