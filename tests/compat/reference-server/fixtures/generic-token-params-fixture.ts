import { createPrivateKeyJwtClientAssertionGetter } from "@better-auth/core/oauth2";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { genericOAuth } from "better-auth/plugins";

import assertionKeys from "../../fixtures/client-assertion-keys.json";
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
    "override",
    "local-verified",
    "implicit-disabled",
    "expiry-positive",
    "expiry-zero",
    "expiry-negative",
    "custom-token",
    "custom-token-error",

    "jwt-RS256",
    "jwt-RS384",
    "jwt-RS512",
    "jwt-PS256",
    "jwt-PS384",
    "jwt-PS512",
    "jwt-ES256",
    "jwt-ES384",
    "jwt-ES512",
    "jwt-EdDSA",
    "jwt-pem",
    "jwt-pem-ES256",
    "jwt-pem-ES384",
    "jwt-pem-ES512",
    "jwt-pem-EdDSA",
    "jwt-both",
    "jwt-empty-kid",
    "jwt-fractional",
    "jwt-nan",
    "jwt-infinity",
    "subject-key",
    "subject-error",
    "subject-invalid",
    "subject-default",

    "jwt-embedded",
    "jwt-expired",
    "jwt-bad-key",
    "jwt-padded",
    "jwt-missing-crt",
    "jwt-duplicate-ops",
    "jwt-invalid-ext",
    "jwt-secret",
    "jwt-manual",
    "jwt-getter-error",
  ]) {
    const path = `/__test/profiles/generic-token-${mode}/api/auth`;
    const configuredMode = mode.startsWith("dynamic") ? "post" : mode.replace(/^refresh-/, "");
    profiles.set(
      path,
      betterAuth<BetterAuthOptions>({
        ...base,
        basePath: path,
        socialProviders: {},
        ...(mode === "implicit-disabled"
          ? {
              account: {
                ...base.account,
                accountLinking: { ...base.account?.accountLinking, disableImplicitLinking: true },
              },
            }
          : {}),
        ...(mode === "local-verified"
          ? {
              account: {
                ...base.account,
                accountLinking: {
                  ...base.account?.accountLinking,
                  requireLocalEmailVerified: true,
                },
              },
            }
          : {}),
        plugins: [
          genericOAuth({
            config: [
              {
                providerId: "generic",
                overrideUserInfo: mode === "override",
                ...(mode.startsWith("subject-") && mode !== "subject-default"
                  ? {
                      mapProfileToUser: async () => ({ name: "Mapped Subject" }),
                      accountSubject: async ({ tokens, profile }: any) => {
                        await Promise.resolve();
                        receipts.push({ kind: "subject", tokens, profile });
                        if (mode === "subject-error") throw new Error("subject resolver denied");
                        return mode === "subject-invalid"
                          ? (control.subject as string | number)
                          : `${tokens.accessToken}:${profile.id}:${profile.raw_claim}`;
                      },
                    }
                  : {}),
                ...(mode.startsWith("expiry-") || mode.startsWith("custom-token")
                  ? {
                      accessTokenExpiresIn:
                        mode === "expiry-zero" ? 0 : mode === "expiry-negative" ? -60 : 17,
                    }
                  : {}),
                ...(mode.startsWith("custom-token")
                  ? {
                      getToken: async (data: {
                        code: string;
                        redirectURI: string;
                        codeVerifier?: string;
                      }) => {
                        await Promise.resolve();
                        receipts.push({
                          kind: "custom-token",
                          code: data.code,
                          redirectURI: data.redirectURI,
                          codeVerifier: data.codeVerifier,
                        });
                        if (mode === "custom-token-error") {
                          throw new Error("custom token callback denied");
                        }
                        return {
                          accessToken: "custom-access",
                          refreshToken: "custom-refresh",
                          scopes: ["custom-scope"],
                        };
                      },
                    }
                  : {}),

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
                ...(mode.startsWith("jwt-")
                  ? {
                      tokenEndpointAuth: {
                        method: "private_key_jwt",
                        getClientAssertion:
                          mode === "jwt-getter-error"
                            ? async () => {
                                throw new Error("assertion getter denied");
                              }
                            : createPrivateKeyJwtClientAssertionGetter({
                                ...(mode.startsWith("jwt-pem")
                                  ? {
                                      privateKeyPem:
                                        assertionKeys[
                                          (mode.slice(8) in assertionKeys
                                            ? mode.slice(8)
                                            : "RS256") as keyof typeof assertionKeys
                                        ].pem,
                                    }
                                  : {
                                      privateKeyJwk: {
                                        ...assertionKeys[
                                          (mode.slice(4) in assertionKeys
                                            ? mode.slice(4)
                                            : "RS256") as keyof typeof assertionKeys
                                        ].private,
                                        kid: "embedded-kid",
                                        ...(mode === "jwt-embedded" ? { alg: "RS256" } : {}),
                                        ...(mode === "jwt-bad-key" ? { kty: "EC" } : {}),
                                        ...(mode === "jwt-padded"
                                          ? { n: assertionKeys.RS256.private.n + "==" }
                                          : {}),
                                        ...(mode === "jwt-missing-crt"
                                          ? { dp: undefined, dq: undefined, qi: undefined }
                                          : {}),
                                        ...(mode === "jwt-duplicate-ops"
                                          ? { key_ops: ["sign", "sign"] }
                                          : {}),
                                        ...(mode === "jwt-invalid-ext"
                                          ? { ext: "true" as any }
                                          : {}),
                                      } as JsonWebKey & { kid: string },
                                    }),
                                ...(mode === "jwt-both"
                                  ? { privateKeyPem: "invalid PEM ignored" }
                                  : {}),
                                ...(mode === "jwt-embedded" || mode === "jwt-pem"
                                  ? {}
                                  : {
                                      algorithm: ((mode.startsWith("jwt-pem-")
                                        ? mode.slice(8)
                                        : mode.slice(4)) in assertionKeys
                                        ? mode.startsWith("jwt-pem-")
                                          ? mode.slice(8)
                                          : mode.slice(4)
                                        : "RS256") as "RS256",
                                    }),
                                ...(mode === "jwt-embedded"
                                  ? {}
                                  : { kid: mode === "jwt-empty-kid" ? "" : "configured-kid" }),
                                ...(mode === "jwt-expired"
                                  ? { expiresIn: -1 }
                                  : mode === "jwt-fractional"
                                    ? { expiresIn: 17.5 }
                                    : mode === "jwt-nan"
                                      ? { expiresIn: NaN }
                                      : mode === "jwt-infinity"
                                        ? { expiresIn: Infinity }
                                        : {}),
                              }),
                      } as const,
                    }
                  : {}),
                tokenUrlParams:
                  mode === "jwt-secret"
                    ? { client_secret: "forbidden-secret" }
                    : mode === "jwt-manual"
                      ? { client_assertion: "manual", client_assertion_type: "manual" }
                      : params(mode, false),
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
                  : mode === "jwt-secret"
                    ? { client_secret: "forbidden-secret" }
                    : mode === "jwt-manual"
                      ? { client_assertion: "manual", client_assertion_type: "manual" }
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
      if (p === "/__test/generic-token/assertion-options" && request.method === "POST") {
        const body = (await request.json()) as { mode: string };
        let accepted = true;
        try {
          createPrivateKeyJwtClientAssertionGetter({
            ...(body.mode === "missing-key"
              ? {}
              : {
                  privateKeyJwk: {
                    ...assertionKeys.RS256.private,
                    ...(body.mode === "jwk-alg" ? { alg: "HS256" } : {}),
                    ...(body.mode === "conflicting-alg" ? { alg: "RS384" } : {}),
                  },
                }),
            ...(body.mode === "unsupported-alg"
              ? { algorithm: "HS256" as "RS256" }
              : body.mode === "conflicting-alg"
                ? { algorithm: "RS256" as const }
                : {}),
          });
        } catch {
          accepted = false;
        }
        return Response.json({ accepted });
      }
      if (p === "/__test/generic-token/server-api" && request.method === "POST") {
        const body = (await request.json()) as {
          operation: string;
          userId?: string;
          accountId: string;
        };
        const instance = profiles.get("/__test/profiles/generic-token-none/api/auth")!;
        const selection = {
          accountId: body.accountId,
          ...(body.userId ? { userId: body.userId } : {}),
        };
        if (body.operation === "get-access-token") {
          return instance.api.getAccessToken({ body: selection, asResponse: true });
        }
        if (body.operation === "refresh-token") {
          return instance.api.refreshToken({ body: selection, asResponse: true });
        }
        return instance.api.accountInfo({ query: selection, asResponse: true });
      }
      if (p === "/__test/generic-token/orphan" && request.method === "POST") {
        const body = (await request.json()) as { accountId: string };
        const db = base.database as import("bun:sqlite").Database;
        const prior = db
          .query<{ foreign_keys: number }, []>("PRAGMA foreign_keys")
          .get()!.foreign_keys;
        db.exec("PRAGMA foreign_keys=OFF");
        try {
          db.query("UPDATE account SET userId='missing-owner' WHERE id=?").run(body.accountId);
        } finally {
          db.exec(`PRAGMA foreign_keys=${prior}`);
        }
        return Response.json({ status: true });
      }
      if (p === "/__test/generic-token/receipts") return Response.json(receipts);
      return null;
    },
  };
}
