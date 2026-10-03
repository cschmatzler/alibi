import { betterAuth, type BetterAuthOptions } from "better-auth";
import { genericOAuth } from "better-auth/plugins";
export function genericTokenParamsFixture(base: BetterAuthOptions) {
  let control: Record<string, unknown> = {};
  const receipts: unknown[] = [];
  const transport = Bun.serve({
    port: 0,
    async fetch(request) {
      if (new URL(request.url).pathname === "/token") {
        const raw = await request.text();
        receipts.push({
          path: "/token",
          authorization: request.headers.get("authorization"),
          contentType: request.headers.get("content-type"),
          body: [...new URLSearchParams(raw)],
          raw,
        });
        return Response.json(
          control.tokenResponse ?? {
            access_token: "generic-access",
            refresh_token: "generic-refresh",
            token_type: "Bearer",
            expires_in: 3600,
            scope: "profile",
          },
        );
      }
      return Response.json(
        control.profile ?? {
          id: "generic-subject",
          email: "generic@example.invalid",
          name: "Generic Name",
          email_verified: true,
        },
      );
    },
  });
  function params(mode: string, refresh: boolean): Record<string, string> {
    if (mode.startsWith("refresh-")) {
      return params(refresh ? mode.slice(8) : mode.slice(8).replace(/-secret$/, ""), refresh);
    }
    const p: Record<string, string> = Object.assign(Object.create(null), {
      audience: "https://resource.example.invalid/a?x=1&y=two words",
      resource: "tenant :+&=/%é",
      client_id: "extra-client",
      grant_type: "extra-grant",
    });
    if (refresh) {
      Object.assign(
        p,
        JSON.parse(
          '{"refresh_token":"extra-refresh","scope":"rotated scope","__proto__":"blocked","constructor":"blocked","prototype":"blocked"}',
        ),
      );
    } else {
      Object.assign(p, {
        code: "extra-code",
        redirect_uri: "https://wrong.example.invalid",
        code_verifier: "extra-verifier",
      });
    }
    if (["post", "basic-secret", "none-secret"].includes(mode)) p.client_secret = "extra-secret";
    if (["manual", "incomplete", "conflict"].includes(mode)) {
      p.client_assertion = "trusted-assertion";
      if (mode !== "incomplete") {
        p.client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
      }
    }
    return p;
  }
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  for (const mode of [
    "post",
    "basic",
    "none",
    "manual",
    "default-none",
    "default-post",
    "basic-secret",
    "none-secret",
    "incomplete",
    "conflict",
    "refresh-basic-secret",
    "refresh-none-secret",
    "dynamic",
    "dynamic-none",
    "dynamic-error",
    "dynamic-custom",
  ]) {
    const path = `/__test/profiles/generic-token-${mode}/api/auth`;
    const configuredMode = mode.startsWith("dynamic") ? "post" : mode.replace(/^refresh-/, "");
    profiles.set(
      path,
      betterAuth<BetterAuthOptions>({
        ...base,
        basePath: path,
        socialProviders: {},
        plugins: [
          genericOAuth({
            config: [
              {
                providerId: "generic",
                clientId: "client :+&",
                ...(["post", "basic", "basic-secret", "default-post"].includes(configuredMode)
                  ? { clientSecret: "secret :+&" }
                  : {}),
                ...(["manual", "incomplete", "default-none", "default-post"].includes(
                  configuredMode,
                )
                  ? {}
                  : {
                      tokenEndpointAuth: {
                        method:
                          configuredMode === "post"
                            ? "client_secret_post"
                            : configuredMode.startsWith("basic")
                              ? "client_secret_basic"
                              : "none",
                      } as const,
                    }),
                authorizationUrl: "https://generic.example.invalid/authorize",
                tokenUrl: `${transport.url}token`,
                userInfoUrl: `${transport.url}user`,
                scopes: ["profile"],
                tokenUrlParams: params(mode, false),
                refreshTokenParams: mode.startsWith("dynamic")
                  ? async (ctx) => {
                      await Promise.resolve();
                      const tenant = ctx?.headers?.get("x-refresh-tenant");
                      const cookie =
                        ctx?.headers
                          ?.get("cookie")
                          ?.split(";")
                          .map((x) => x.trim())
                          .find((x) => x.startsWith("refresh_meta="))
                          ?.slice("refresh_meta=".length) ?? null;
                      receipts.push({
                        kind: "params",
                        tenant,
                        cookie,
                        method: ctx?.request?.method ?? null,
                        path: ctx?.request ? new URL(ctx.request.url).pathname : null,
                      });
                      if (mode === "dynamic-error") throw new Error("refresh policy rejected");
                      if (mode === "dynamic-none") return undefined;
                      if (!["allowed-one", "allowed-two"].includes(tenant ?? "")) {
                        throw new Error("tenant not allowed");
                      }
                      return {
                        resource: `tenant ${tenant} :+&=/%é`,
                        scope: `profile ${tenant}`,
                        client_id: "wrong-client",
                        client_secret: "wrong-secret",
                        grant_type: "wrong-grant",
                        refresh_token: "wrong-refresh",
                      };
                    }
                  : params(mode, true),
              },
            ],
          }),
          ...(mode === "dynamic-custom"
            ? [
                {
                  id: "application-refresh",
                  init(ctx: import("better-auth").AuthContext) {
                    const provider = ctx.socialProviders.find((p) => p.id === "generic")!;
                    provider.refreshAccessToken = async (refreshToken, context) => {
                      await Promise.resolve();
                      receipts.push({
                        kind: "custom",
                        refreshToken,
                        tenant: context?.headers?.get("x-refresh-tenant") ?? null,
                        cookie:
                          context?.headers
                            ?.get("cookie")
                            ?.split(";")
                            .map((x) => x.trim())
                            .find((x) => x.startsWith("refresh_meta="))
                            ?.slice("refresh_meta=".length) ?? null,
                        method: context?.request?.method ?? null,
                        path: context?.request ? new URL(context.request.url).pathname : null,
                      });
                      return {
                        accessToken: "custom-access",
                        refreshToken: "custom-refresh",
                        accessTokenExpiresAt: new Date(Date.now() + 3600000),
                        scopes: ["custom-scope"],
                      };
                    };
                  },
                },
              ]
            : []),
        ],
      }),
    );
  }
  return {
    profiles,
    reset() {
      control = {};
      receipts.length = 0;
    },
    async handle(request: Request) {
      const p = new URL(request.url).pathname;
      if (p === "/__test/generic-token/control" && request.method === "POST") {
        control = await request.json();
        return Response.json({ status: true });
      }
      if (p === "/__test/generic-token/receipts") return Response.json(receipts);
      return null;
    },
  };
}
