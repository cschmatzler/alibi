import { createHash, createHmac } from "node:crypto";
import { readFile as readFixtureFile } from "node:fs/promises";

import {
  consumeClientAssertion,
  getOAuthProviderApi,
  oauthProvider,
  type OAuthOptions,
} from "@better-auth/oauth-provider";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { APIError, createAuthEndpoint } from "better-auth/api";
import { symmetricEncrypt, symmetricDecrypt } from "better-auth/crypto";
import { getMigrations } from "better-auth/db/migration";
import {
  verifyDpopProof,
  createDpopReplayStore,
  createInMemoryDpopReplayStore,
  isDpopProofError,
  isDpopBindingError,
  enforceDpopBinding,
  parseAccessTokenAuthorization,
  stripAccessTokenAuthorizationScheme,
  getConfirmationJkt,
  getDpopJktFromPayload,
  normalizeDpopHtu,
  deriveDpopAth,
  deriveDpopJkt,
} from "better-auth/oauth2";
import { jwt, username } from "better-auth/plugins";
import { APIError as EndpointAPIError, kAPIErrorHeaderSymbol } from "better-call";
import { SignJWT, importJWK, decodeProtectedHeader } from "jose";
import { z } from "zod";
export async function oauthClientFixture(base: BetterAuthOptions) {
  const registrationCalls: unknown[] = [];
  const validateInitialAccessToken: NonNullable<
    OAuthOptions["validateInitialAccessToken"]
  > = async ({ initialAccessToken, headers, clientMetadata }) => {
    registrationCalls.push({
      token: initialAccessToken,
      authorization: headers.get("authorization"),
      caller: headers.get("x-registration-caller"),
      clientMetadata,
    });
    await Promise.resolve();
    if (initialAccessToken === "forbidden") {
      throw new APIError("FORBIDDEN", { message: "Operator forbids registration" });
    }
    if (initialAccessToken === "ordinary-error") throw new Error("private validator failure");
    if (initialAccessToken === "api-error") {
      throw new APIError(
        "TOO_MANY_REQUESTS",
        {
          error: "slow_down",
          error_description: "Operator registration limit",
        },
        { "retry-after": "17", "x-registration-policy": "limited" },
      );
    }
    if (initialAccessToken === "api-empty") {
      throw new APIError("TEMPORARY_REDIRECT", undefined, {
        location: "https://operator.fixture.test/register",
        "content-type": "application/json",
      });
    }
    if (
      ["accepted", "reference"].includes(initialAccessToken) &&
      headers.get("x-registration-caller") === "fixture" &&
      clientMetadata.client_name === "Token client"
    ) {
      return initialAccessToken === "reference" ? { referenceId: "registration-reference" } : {};
    }
    return false;
  };
  const remoteKeys = JSON.parse(
    await readFixtureFile(
      new URL("../../../fixtures/oauth/client-assertion-keys.json", import.meta.url),
      "utf8",
    ),
  ).keys;
  const remoteDocument = (family: string, algorithm: string, kid: string) => ({
    keys: [
      { ...remoteKeys.find((key: any) => key.family === family).publicJwk, alg: algorithm, kid },
    ],
  });
  const remoteState = {
    responseMode: "valid",
    uri: "https://client.fixture.test/jwks",
    document: remoteDocument("RSA", "RS256", "first"),
    fetches: [] as unknown[],
  };
  const remoteFetch = async (url: any, init: any) => {
    remoteState.fetches.push({
      url: String(url),
      accept: new Headers(init.headers).get("accept"),
      redirect: init.redirect,
      aborted: init.signal.aborted,
    });
    const mode = remoteState.responseMode;
    if (mode === "exception") throw new Error("offline");
    const doc = remoteState.document;
    const pub = doc.keys[0];
    let body: any = JSON.stringify(doc);
    let status = 200;
    let headers: Record<string, string> = {
      "content-type": "application/jwk-set+json; charset=utf-8",
    };
    if (mode === "status") status = 503;
    if (mode === "redirect") status = 302;
    if (mode === "type") headers["content-type"] = "text/plain";
    if (mode === "no-type") {
      headers = {};
      body = new TextEncoder().encode(body);
    }
    if (mode === "length") headers["content-length"] = "65537";
    if (mode === "hex-length") headers["content-length"] = "0x10001";
    if (mode === "invalid-length") headers["content-length"] = "bogus";
    if (mode === "exact-body" || mode === "over-body") {
      body = body + " ".repeat((mode === "exact-body" ? 65536 : 65537) - body.length);
    }
    if (mode === "bad-json") body = "invalid json";
    if (mode === "empty-keys") body = JSON.stringify({ keys: [] });
    if (mode === "symmetric") body = JSON.stringify({ keys: [{ kty: "oct", k: "secret" }] });
    if (mode === "private-key") body = JSON.stringify({ keys: [{ ...pub, d: "secret" }] });
    if (mode === "bom") body = "\uFEFF" + body;
    if (mode === "nonfinite") {
      body = JSON.stringify({ ...doc, extra: "__nonfinite__" }).replace('"__nonfinite__"', "1e400");
    }
    if (mode === "bad-utf8") {
      const text = JSON.stringify({ ...doc, extra: "x" });
      body = Buffer.from(text);
      body[text.indexOf('"x"') + 1] = 255;
    }
    if (mode === "wrong-kid") body = JSON.stringify({ keys: [{ ...pub, kid: "other" }] });
    if (mode === "ambiguous") body = JSON.stringify({ keys: [pub, pub] });
    return new Response(body, { status, headers });
  };
  const remoteDiscovery = {
    id: "remote-registry",
    matches: (id: string) => id === "https://client.fixture.test/client.json",
    resolve: async (ctx: any, id: string, existing: any) => ({
      ...(existing ??
        (await ctx.context.adapter.create({
          model: "oauthClient",
          data: {
            clientId: id,
            clientDiscoveryId: "remote-registry",
            name: "Remote client",
            redirectUris: ["https://app.fixture.test/callback"],
            tokenEndpointAuthMethod: "private_key_jwt",
            jwksUri: remoteState.uri,
            scopes: ["email"],
            grantTypes: ["authorization_code"],
            responseTypes: ["code"],
            createdAt: new Date(),
            updatedAt: new Date(),
          },
        }))),
      jwksUri: remoteState.uri,
    }),
    get fetchClientMetadataResource() {
      return remoteState.responseMode === "no-transport" ? undefined : remoteFetch;
    },
  };
  const remoteProvider = oauthProvider({
    loginPage: "/login",
    consentPage: "/consent",
    extensions: [{ clientDiscovery: remoteDiscovery }],
  });
  const registryState = { mode: "live", events: [] as string[] };
  const registryDiscoveries = [
    {
      id: "registry-first",
      matches: (id: string) => {
        registryState.events.push("first:matches");
        return id.startsWith("registry-");
      },
      resolve: async () => {
        registryState.events.push("first:resolve");
        return null;
      },
    },
    {
      id: "registry-live",
      matches: (id: string) => {
        registryState.events.push("live:matches");
        return registryState.mode !== "mismatch" && id.startsWith("registry-");
      },
      resolve: async (ctx: any, id: string, existing: any) => {
        registryState.events.push(`live:resolve:${existing ? "existing" : "new"}`);
        if (registryState.mode === "reject") return null;
        if (existing) {
          if (registryState.mode === "refresh") {
            return ctx.context.adapter.update({
              model: "oauthClient",
              where: [{ field: "clientId", value: id }],
              update: { name: "Updated registry", updatedAt: new Date() },
            });
          }
          return existing;
        }
        return ctx.context.adapter.create({
          model: "oauthClient",
          data: {
            clientId: id,
            clientDiscoveryId: "registry-live",
            name: "Registry client",
            redirectUris: ["https://app.fixture.test/callback"],
            tokenEndpointAuthMethod: "none",
            scopes: ["email"],
            grantTypes: ["authorization_code"],
            responseTypes: ["code"],
            disabled: false,
            createdAt: new Date(),
            updatedAt: new Date(),
          },
        });
      },
    },
  ];
  const providerClientOptions = {
    loginPage: "/login",
    consentPage: "/consent",
    extensions: [{ clientDiscovery: registryDiscoveries }],
    cachedTrustedClients: new Set(["registry-client"]),
  };
  const providerClientHelper = {
    id: "provider-client-helper",
    endpoints: {
      providerResolveClient: createAuthEndpoint(
        "/fixture/provider-client",
        { method: "POST", body: z.object({ clientId: z.string(), discover: z.boolean() }) },
        async (ctx) => {
          const client = await getOAuthProviderApi(
            ctx,
            ctx.body.discover
              ? providerClientOptions
              : { ...providerClientOptions, extensions: [] },
          ).getClient(ctx.body.clientId);
          return ctx.json(
            client
              ? {
                  client_id: client.clientId,
                  client_name: client.name ?? null,
                  discovery_id: client.clientDiscoveryId ?? null,
                  user_id: client.userId ?? null,
                  client_secret: client.clientSecret ?? null,
                }
              : null,
          );
        },
      ),
    },
  };
  const authenticationExtensions = () => [
    {
      clientAuthentication: {
        application_assertion: {
          assertionTypes: ["urn:fixture:client-assertion", "urn:fixture:client-alias"],
          authenticate: async ({ assertion, clientId, expectedAudience }: any) => {
            const [payload, signature] = assertion.split(".");
            const expected = createHmac("sha256", "fixture-application-assertion-key")
              .update(payload)
              .digest("base64url");
            const value = JSON.parse(Buffer.from(payload, "base64url").toString());
            if (
              signature !== expected ||
              value.audience !== expectedAudience ||
              (value.suppliedClientId ?? undefined) !== clientId
            ) {
              throw new APIError("BAD_REQUEST", {
                error: "invalid_client",
                error_description: "application assertion rejected",
              });
            }
            return { clientId: value.clientId, confirmation: value.confirmation };
          },
        },
      },
    },
  ];
  const authenticationHelper = {
    id: "client-authentication-helper",
    endpoints: {
      authenticateClientFixture: createAuthEndpoint(
        "/fixture/authenticate-client",
        {
          method: "POST",
          body: z
            .object({
              requireCredentials: z.boolean().optional(),
              requestedScopes: z.array(z.string()).optional(),
              boundGrant: z.string().optional(),
            })
            .passthrough(),
        },
        async (ctx) => {
          const authenticated = await getOAuthProviderApi(
            ctx,
            {
              loginPage: "/login",
              consentPage: "/consent",
              ...(ctx.body.extensionAuth ? { extensions: authenticationExtensions() } : {}),
            },
            ctx.body.boundGrant,
          ).authenticateClient({
            requireCredentials: ctx.body.requireCredentials,
            scopes: ctx.body.requestedScopes,
          });
          return ctx.json({
            clientId: authenticated.clientId,
            method: authenticated.method ?? null,
            confirmation: authenticated.confirmation ?? null,
            client: {
              clientId: authenticated.client.clientId,
              clientName: authenticated.client.name ?? null,
              userId: authenticated.client.userId ?? null,
            },
          });
        },
      ),
    },
  };
  const assertionHelper = {
    id: "assertion-helper-fixture",
    endpoints: {
      consumeAssertionFixture: createAuthEndpoint(
        "/fixture/consume-assertion",
        {
          method: "POST",
          body: z.object({
            namespace: z.string(),
            payload: z.record(z.string(), z.unknown()),
            expectedAudience: z.string(),
          }),
        },
        async (ctx) => {
          await consumeClientAssertion(
            ctx,
            { loginPage: "/login", consentPage: "/consent" },
            ctx.body,
          );
          return ctx.json({ consumed: true });
        },
      ),
    },
  };
  const tokenStorage = {
    hash: async (token: string, kind: string) =>
      `app:${kind}:${createHash("sha256").update(token).digest("base64url")}`,
  };
  const tokenHashHelper = {
    id: "token-hash-helper",
    endpoints: {
      hashTokenFixture: createAuthEndpoint(
        "/fixture/hash-token",
        {
          method: "POST",
          body: z.object({ token: z.string(), kind: z.string(), custom: z.boolean() }),
        },
        async (ctx) =>
          ctx.json({
            hash: await getOAuthProviderApi(ctx, {
              loginPage: "/login",
              consentPage: "/consent",
              ...(ctx.body.custom ? { storeTokens: tokenStorage } : {}),
            }).hashToken(ctx.body.token, ctx.body.kind),
          }),
      ),
    },
  };
  const accessValidationHelper = {
    id: "access-validation-helper",
    endpoints: {
      validateAccessFixture: createAuthEndpoint(
        "/fixture/validate-access",
        {
          method: "POST",
          body: z.object({
            token: z.string(),
            clientId: z.string().optional(),
            requireActive: z.boolean(),
          }),
        },
        async (ctx) => {
          try {
            return ctx.json(
              await getOAuthProviderApi(ctx, { loginPage: "/login", consentPage: "/consent" })[
                ctx.body.requireActive ? "requireActiveAccessToken" : "validateAccessToken"
              ](ctx.body.token, ctx.body.clientId),
            );
          } catch (error) {
            if (error instanceof Error && error.name === "APIError") throw error;
            return ctx.json({ ordinary_error: true });
          }
        },
      ),
    },
  };
  const scopePolicy = (name: string) => ({
    email:
      name === "numeric"
        ? 1
        : name === "zero"
          ? 0
          : name === "date"
            ? new Date(0)
            : name === "relative"
              ? "45s"
              : "2h",
    ...(name === "relative" ? { profile: "90s" } : {}),
  });
  const expiryPolicy = {
    accessTokenExpiresIn: 120,
    m2mAccessTokenExpiresIn: 30,
    idTokenExpiresIn: 600,
    refreshTokenExpiresIn: 900,
  };
  const liveClaims = { value: "", calls: [] as any[] };
  const claimExtensions = (live = false) =>
    ["first", "second"].map((id) => {
      const tokenClaims = async ({
        ctx,
        user,
        client,
        scopes,
        grantType,
        referenceId,
        sessionId,
        metadata,
      }: any) => ({
        extension_owner: id,
        [`extension_${id}`]: {
          grant: grantType,
          scopes,
          userId: user?.id ?? null,
          clientId: client.clientId,
          referenceId: referenceId ?? null,
          sessionId: sessionId ?? null,
          metadata: metadata ?? null,
          caller: ctx.headers?.get("x-claims-caller") ?? null,
        },
        per_request: id,
        resource_wins: id,
        sub: "forged",
        iss: "https://forged.fixture.test",
        aud: "forged",
        email: "forged@example.test",
        scope: "forged",
        exp: 1,
        sid: "forged",
        constructor: "forged",
        nullable_claim: null,
      });
      return {
        claims: {
          accessToken: async (input: any) => {
            if (input.ctx.headers?.get("x-claims-error") === "access") {
              throw new APIError("BAD_REQUEST", {
                code: "CLAIM_REJECTED",
                message: "rejected access",
              });
            }
            if (live) {
              liveClaims.calls.push({
                extension: id,
                grant: input.grantType ?? null,
                sessionId: input.sessionId ?? null,
                userId: input.user?.id ?? null,
                clientId: input.client.clientId,
                referenceId: input.referenceId ?? null,
                scopes: input.scopes,
                resources: input.resources ?? null,
                metadata: input.metadata ?? null,
              });
            }
            return {
              ...(await tokenClaims(input)),
              ...(live
                ? {
                    live_value: liveClaims.value,
                    active: false,
                    azp: "forged",
                    client_id: "forged",
                    token_type: "forged",
                    iat: 1,
                    jti: "forged",
                    cnf: { jkt: "forged" },
                    auth_time: 1,
                    acr: "forged",
                    amr: ["forged"],
                  }
                : {}),
            };
          },
          idToken: async (input: any) => {
            if (input.ctx.headers?.get("x-claims-error") === "id") {
              throw new APIError("BAD_REQUEST", { code: "CLAIM_REJECTED", message: "rejected id" });
            }
            return tokenClaims(input);
          },
          userInfo: async ({ ctx, user, client, scopes, jwt, requestedClaims }: any) => ({
            extension_owner: id,
            [`extension_${id}`]: {
              scopes,
              userId: user.id,
              clientId: client?.clientId ?? null,
              requestedClaims,
              payloadSub: jwt.sub,
              caller: ctx.headers?.get("x-claims-caller") ?? null,
            },
            sub: "forged",
            name: "Forged name",
            email_verified: true,
            constructor: "forged",
            nullable_claim: null,
          }),
        },
      };
    });
  const issuanceHelper = {
    id: "issuance-helper",
    endpoints: {
      issueTokensFixture: createAuthEndpoint(
        "/fixture/issue-tokens",
        { method: "POST", body: z.record(z.string(), z.unknown()) },
        async (ctx: any) => {
          const api = getOAuthProviderApi(
            ctx,
            {
              loginPage: "/login",
              consentPage: "/consent",
              ...(ctx.body.expiryProfile ? expiryPolicy : {}),
              ...(ctx.body.claimsProfile ? { extensions: claimExtensions() } : {}),
              ...(ctx.body.disableJwtPlugin ? { disableJwtPlugin: true } : {}),
              ...(ctx.body.scopePolicy
                ? { scopeExpirations: scopePolicy(ctx.body.scopePolicy) }
                : {}),
              ...(ctx.body.dpop ? { dpop: ctx.body.dpop } : {}),
            },
            ctx.body.grantType,
          );
          const client = await api.getClient(ctx.body.clientId);
          const user = ctx.body.userId
            ? await ctx.context.internalAdapter.findUserById(ctx.body.userId)
            : undefined;
          const params = {
            ...ctx.body.params,
            ...(ctx.body.params.authTime ? { authTime: new Date(ctx.body.params.authTime) } : {}),
          };
          const refreshToken = ctx.body.originalRefreshToken
            ? await ctx.context.adapter.findOne({
                model: "oauthRefreshToken",
                where: [
                  {
                    field: "token",
                    value: await api.hashToken(ctx.body.originalRefreshToken, "refresh_token"),
                  },
                ],
              })
            : undefined;
          if (refreshToken && ctx.body.snapshotToken) refreshToken.token = ctx.body.snapshotToken;
          return api.issueTokens({
            ...params,
            client,
            user,
            ...(refreshToken ? { refreshToken } : {}),
          });
        },
      ),
    },
  };
  const memoryDpopReplay = createInMemoryDpopReplayStore();
  const dpopHelper = {
    id: "dpop-helper",
    endpoints: {
      dpopFixture: createAuthEndpoint(
        "/fixture/dpop",
        { method: "POST", body: z.record(z.string(), z.unknown()) },
        async (ctx: any) => {
          if (ctx.body.operation === "row") {
            const row = await ctx.context.adapter.findOne({
              model: "verification",
              where: [{ field: "identifier", value: `dpop-proof:${ctx.body.key}` }],
            });
            return ctx.json(row ? { value: row.value, expiresAt: row.expiresAt } : null);
          }
          let observed: any;
          const wrapped = {
            reserveVerificationValue: async (data: any) => {
              observed = data;
              return ctx.context.internalAdapter.reserveVerificationValue(data);
            },
          };
          const replayStore =
            ctx.body.replay === "memory"
              ? memoryDpopReplay
              : ctx.body.replay === "database"
                ? createDpopReplayStore(ctx.context.internalAdapter)
                : ctx.body.replay === "wrapped"
                  ? createDpopReplayStore(wrapped)
                  : undefined;
          try {
            if (ctx.body.operation === "payload-jkt") {
              return ctx.json({ jkt: getDpopJktFromPayload(ctx.body.payload) ?? null });
            }
            if (ctx.body.operation === "binding") {
              await enforceDpopBinding({ ...ctx.body, replayStore });
              return ctx.json({ accepted: true });
            }
            if (ctx.body.operation === "utilities") {
              return ctx.json({
                authorization: parseAccessTokenAuthorization(ctx.body.authorization) ?? null,
                stripped: stripAccessTokenAuthorizationScheme(ctx.body.token),
                confirmation: getConfirmationJkt(ctx.body.confirmation) ?? null,
                normalized: normalizeDpopHtu(ctx.body.url),
                ath: await deriveDpopAth(ctx.body.accessToken),
                jkt: await deriveDpopJkt(ctx.body.jwk),
              });
            }
            const proof = await verifyDpopProof({ ...ctx.body, replayStore });
            return ctx.json({ ...proof, ...(observed ? { reservation: observed } : {}) });
          } catch (error) {
            if (isDpopProofError(error) || isDpopBindingError(error)) {
              return ctx.json({ error: error.code, message: error.message });
            }
            return ctx.json({ ordinary_error: true });
          }
        },
      ),
    },
  };
  const options = {
    baseURL: base.baseURL,
    basePath: base.basePath,
    secret: base.secret,
    database: base.database,
    emailAndPassword: { enabled: true },
    plugins: [
      username(),
      jwt(),
      oauthProvider({ loginPage: "/login", consentPage: "/consent" }),
      providerClientHelper,
      authenticationHelper,
      tokenHashHelper,
      accessValidationHelper,
      issuanceHelper,
      dpopHelper,
    ],
  };
  await (await getMigrations(options)).runMigrations();
  let generatedClientIds = 0;
  let generatedSecrets = 0;
  let encryptedGeneratedSecrets = 0;
  let prefixedSecrets = 0;
  let encryptedPrefixedSecrets = 0;
  const customCipherKey = "application-client-secret-encryption-key-32-characters";
  const customCipher = {
    encrypt: async (secret: string) =>
      `custom:${await symmetricEncrypt({ key: customCipherKey, data: secret })}`,
    decrypt: async (stored: string) =>
      symmetricDecrypt({ key: customCipherKey, data: stored.slice("custom:".length) }),
  };
  const customCipherProfile = () => {
    let calls = 0;
    return betterAuth({
      ...options,
      plugins: [
        username(),
        oauthProvider({
          loginPage: "/login",
          consentPage: "/consent",
          disableJwtPlugin: true,
          prefix: { clientSecret: "client_prefix_" },
          storeClientSecret: customCipher,
          generateClientSecret: () => `operator-secret-${++calls}`,
        }),
      ],
    });
  };
  const customHash = (secret: string) =>
    `custom:${createHash("sha256").update(secret).digest("base64url")}`;
  const customSecretProfile = (verify: boolean) => {
    let calls = 0;
    return betterAuth({
      ...options,
      plugins: [
        username(),
        jwt(),
        oauthProvider({
          loginPage: "/login",
          consentPage: "/consent",
          generateClientSecret: () => `operator-secret-${++calls}`,
          ...(verify ? { prefix: { clientSecret: "client_prefix_" } } : {}),
          storeClientSecret: {
            hash: async (secret: string) => customHash(secret),
            ...(verify
              ? {
                  verify: async (secret: string, stored: string) =>
                    customHash(secret.endsWith("!") ? secret.slice(0, -1) : secret) === stored,
                }
              : {}),
          },
        }),
      ],
    });
  };
  const trustedProvider = oauthProvider({
    loginPage: "/login",
    consentPage: "/consent",
    generateClientId: () => "trusted-client",
    cachedTrustedClients: new Set(["trusted-client", "trusted-missing"]),
  });
  const trustedHelper = {
    id: "trusted-client-helper",
    endpoints: {
      trustedGetClient: createAuthEndpoint(
        "/fixture/trusted-client",
        { method: "POST", body: z.object({ fresh: z.boolean(), rename: z.boolean() }) },
        async (ctx) => {
          const client = await getOAuthProviderApi(
            ctx,
            ctx.body.fresh ? { ...trustedProvider.options } : trustedProvider.options,
          ).getClient("trusted-client");
          if (client && ctx.body.rename) client.name = "changed return value";
          return ctx.json(client ? { name: client.name } : null);
        },
      ),
    },
  };
  const trustedPlugins = [username(), jwt(), trustedProvider, trustedHelper];
  const extensionGrant = {
    grants: {
      "urn:fixture:extension": async ({ ctx, provider, grantType }: any) => {
        if (ctx.body.marker === "deny") {
          throw new APIError("BAD_REQUEST", {
            error: "invalid_grant",
            error_description: "extension rejected request",
          });
        }
        const scopes = (ctx.body.scope ?? "email").split(" ");
        const authenticated = await provider.authenticateClient({ scopes });
        return provider.issueTokens({
          client: authenticated.client,
          scopes,
          referenceId: "grant-reference",
          tokenResponse: {
            custom: ctx.body.marker,
            boundGrant: grantType,
            observedGrant: ctx.body.grant_type,
          },
        });
      },
    },
  };
  const auths = {
    "extension-grant": betterAuth({
      ...options,
      plugins: [
        username(),
        jwt(),
        oauthProvider({
          loginPage: "/login",
          consentPage: "/consent",
          grantTypes: [
            "authorization_code",
            "client_credentials",
            "refresh_token",
            "urn:fixture:orphan",
          ],
          extensions: [extensionGrant],
        }),
      ],
    }),
    trusted: betterAuth({ ...options, plugins: trustedPlugins }),
    "trusted-peer": betterAuth({ ...options, plugins: trustedPlugins }),
    "custom-encrypted-prefixed": customCipherProfile(),
    "custom-hash": customSecretProfile(false),
    "custom-prefixed-verify": customSecretProfile(true),
    "custom-token-hash": betterAuth({
      ...options,
      plugins: [
        username(),
        jwt(),
        oauthProvider({ loginPage: "/login", consentPage: "/consent", storeTokens: tokenStorage }),
        tokenHashHelper,
      ],
    }),
    "issuance-expiry": betterAuth({
      ...options,
      plugins: [
        username(),
        jwt(),
        oauthProvider({ loginPage: "/login", consentPage: "/consent", ...expiryPolicy }),
        issuanceHelper,
      ],
    }),
    ...Object.fromEntries(
      ["numeric", "zero", "relative", "date", "ceiling"].map((name) => [
        `scope-${name}`,
        betterAuth({
          ...options,
          plugins: [
            username(),
            jwt(),
            oauthProvider({
              loginPage: "/login",
              consentPage: "/consent",
              scopeExpirations: scopePolicy(name),
            }),
            issuanceHelper,
          ],
        }),
      ]),
    ),
    "resource-keyring": betterAuth({
      ...options,
      plugins: [
        username(),
        jwt({ jwks: { keyPairConfigs: [{ alg: "ES256", crv: "P-256" }] } }),
        oauthProvider({ loginPage: "/login", consentPage: "/consent" }),
        issuanceHelper,
      ],
    }),
    "extension-auth": betterAuth({
      ...options,
      plugins: [
        username(),
        jwt(),
        oauthProvider({
          loginPage: "/login",
          consentPage: "/consent",
          extensions: authenticationExtensions(),
        }),
        authenticationHelper,
      ],
    }),
    claims: betterAuth({
      ...options,
      plugins: [
        username(),
        jwt(),
        oauthProvider({
          loginPage: "/login",
          consentPage: "/consent",
          extensions: claimExtensions(),
        }),
        issuanceHelper,
      ],
    }),
    "claims-opaque": betterAuth({
      ...options,
      plugins: [
        username(),
        jwt(),
        oauthProvider({
          loginPage: "/login",
          consentPage: "/consent",
          disableJwtPlugin: true,
          extensions: claimExtensions(true),
        }),
        issuanceHelper,
      ],
    }),
    pairwise: betterAuth({
      ...options,
      advanced: {
        database: {
          generateId: ({ model }) => (model === "user" ? "pairwise-owner" : crypto.randomUUID()),
        },
      },
      plugins: [
        username(),
        jwt(),
        oauthProvider({
          loginPage: "/login",
          consentPage: "/consent",
          pairwiseSecret: "fixture-pairwise-secret-at-least-32-characters",
        }),
      ],
    }),
    default: betterAuth(options),
    interaction: betterAuth({
      ...options,
      rateLimit: { enabled: false },
      plugins: options.plugins.map((plugin) =>
        plugin.id === "jwt" ? jwt({ disableSettingJwtHeader: true }) : plugin,
      ),
    }),
    "remote-jwks": betterAuth({ ...options, plugins: [username(), jwt(), remoteProvider] }),
    "remote-jwks-peer": betterAuth({ ...options, plugins: [username(), jwt(), remoteProvider] }),
    "uri-host": betterAuth({ ...options, trustedOrigins: ["https://*"] }),
    discovered: betterAuth({
      ...options,
      plugins: [
        username(),
        jwt(),
        oauthProvider({
          loginPage: "/login",
          consentPage: "/consent",
          generateClientId: () => "registry-managed",
          extensions: [{ clientDiscovery: registryDiscoveries }],
        }),
      ],
    }),
    "assertion-helper": betterAuth({
      ...options,
      plugins: [
        username(),
        jwt(),
        oauthProvider({ loginPage: "/login", consentPage: "/consent" }),
        assertionHelper,
      ],
    }),
    "assertion-helper-peer": betterAuth({
      ...options,
      plugins: [
        username(),
        jwt(),
        oauthProvider({ loginPage: "/login", consentPage: "/consent" }),
        assertionHelper,
      ],
    }),
    "assertion-short": betterAuth({
      ...options,
      plugins: [
        username(),
        jwt(),
        oauthProvider({ loginPage: "/login", consentPage: "/consent", assertionMaxLifetime: 30 }),
      ],
    }),
    "assertion-zero": betterAuth({
      ...options,
      plugins: [
        username(),
        jwt(),
        oauthProvider({ loginPage: "/login", consentPage: "/consent", assertionMaxLifetime: 0 }),
      ],
    }),
    "assertion-negative": betterAuth({
      ...options,
      plugins: [
        username(),
        jwt(),
        oauthProvider({ loginPage: "/login", consentPage: "/consent", assertionMaxLifetime: -1 }),
      ],
    }),
    "assertion-nan": betterAuth({
      ...options,
      plugins: [
        username(),
        jwt(),
        oauthProvider({ loginPage: "/login", consentPage: "/consent", assertionMaxLifetime: NaN }),
      ],
    }),
    "assertion-infinite": betterAuth({
      ...options,
      plugins: [
        username(),
        jwt(),
        oauthProvider({
          loginPage: "/login",
          consentPage: "/consent",
          assertionMaxLifetime: Infinity,
        }),
      ],
    }),
    "assertion-negative-infinite": betterAuth({
      ...options,
      plugins: [
        username(),
        jwt(),
        oauthProvider({
          loginPage: "/login",
          consentPage: "/consent",
          assertionMaxLifetime: -Infinity,
        }),
      ],
    }),
    "basic-special": betterAuth({
      ...options,
      plugins: [
        username(),
        jwt(),
        oauthProvider({
          loginPage: "/login",
          consentPage: "/consent",
          generateClientId: () => "client +/é:fixed",
          generateClientSecret: () => "secret +/é:tail",
        }),
      ],
    }),
    "generated-id": betterAuth({
      ...options,
      plugins: [
        username(),
        jwt(),
        oauthProvider({
          loginPage: "/login",
          consentPage: "/consent",
          generateClientId: () => `operator-client-${++generatedClientIds}`,
        }),
      ],
    }),
    "empty-id": betterAuth({
      ...options,
      plugins: [
        username(),
        jwt(),
        oauthProvider({ loginPage: "/login", consentPage: "/consent", generateClientId: () => "" }),
      ],
    }),
    "prefixed-generator": betterAuth({
      ...options,
      plugins: [
        username(),
        jwt(),
        oauthProvider({
          loginPage: "/login",
          consentPage: "/consent",
          prefix: { clientSecret: "client_prefix_" },
          generateClientSecret: () => `operator-secret-${++prefixedSecrets}`,
        }),
      ],
    }),
    "encrypted-prefixed-generator": betterAuth({
      ...options,
      plugins: [
        username(),
        oauthProvider({
          loginPage: "/login",
          consentPage: "/consent",
          disableJwtPlugin: true,
          prefix: { clientSecret: "client_prefix_" },
          generateClientSecret: () => `operator-secret-${++encryptedPrefixedSecrets}`,
        }),
      ],
    }),
    "encrypted-generator": betterAuth({
      ...options,
      plugins: [
        username(),
        oauthProvider({
          loginPage: "/login",
          consentPage: "/consent",
          disableJwtPlugin: true,
          generateClientSecret: () => `operator-secret-${++encryptedGeneratedSecrets}`,
        }),
      ],
    }),
    generated: betterAuth({
      ...options,
      plugins: [
        username(),
        jwt(),
        oauthProvider({
          loginPage: "/login",
          consentPage: "/consent",
          generateClientSecret: () => `operator-secret-${++generatedSecrets}`,
        }),
      ],
    }),
    "empty-generator": betterAuth({
      ...options,
      plugins: [
        username(),
        jwt(),
        oauthProvider({
          loginPage: "/login",
          consentPage: "/consent",
          generateClientSecret: () => "",
        }),
      ],
    }),
    reuse: betterAuth({
      ...options,
      plugins: [
        username(),
        jwt(),
        oauthProvider({
          loginPage: "/login",
          consentPage: "/consent",
          refreshTokenReuseInterval: 60,
        }),
      ],
    }),
    machine: betterAuth({
      ...options,
      plugins: [
        username(),
        jwt(),
        oauthProvider({
          loginPage: "/login",
          consentPage: "/consent",
          scopes: ["api:read", "api:write"],
          clientPrivileges: ({ action, headers, user, session }) =>
            action !== "configure-client-credentials-scopes" ||
            (headers.get("x-machine-operator") === "grant" &&
              Boolean(user?.email.includes("machine-owner")) &&
              session?.userId === user?.id),
        }),
      ],
    }),
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
    ...Object.fromEntries(
      ["dynamic", "public", "token-dynamic", "token-public"].map((mode) => [
        mode,
        betterAuth({
          ...options,
          ...(mode.startsWith("token-") ? { rateLimit: { enabled: false } } : {}),
          plugins: [
            username(),
            jwt(),
            oauthProvider({
              loginPage: "/login",
              consentPage: "/consent",
              allowDynamicClientRegistration: true,
              allowUnauthenticatedClientRegistration: mode.endsWith("public"),
              ...(mode.startsWith("token-") ? { validateInitialAccessToken } : {}),
            }),
          ],
        }),
      ]),
    ),
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
    if (input.action === "registration-state") {
      const context = await auth.$context;
      const counts = Object.fromEntries(
        await Promise.all(
          ["user", "account", "session", "verification", "jwks", "oauthClient"].map(
            async (model) => [
              model,
              (await context.adapter.findMany({ model, limit: 10000 })).length,
            ],
          ),
        ),
      );
      return Response.json({ calls: registrationCalls, counts });
    }
    if (input.action === "claims-state") {
      if (typeof input.value === "string") liveClaims.value = input.value;
      return Response.json(liveClaims);
    }
    if (input.action === "backchannel-uri") {
      // Install a local RP on a persisted client. Public-host admission belongs
      // to registration coverage; notification still uses the real fetch.
      const context = await auth.$context;
      await context.adapter.update({
        model: "oauthClient",
        where: [{ field: "clientId", value: input.clientId }],
        update: { backchannelLogoutUri: input.uri, disabled: input.disabled ?? false },
      });
      return Response.json({ updated: true });
    }
    if (input.action === "authenticate-client") {
      const headers = new Headers(input.headers ?? {});
      headers.set("content-type", "application/json");
      return auth.api.authenticateClientFixture({
        body: input.body,
        headers,
        request: new Request(
          `${base.baseURL}${base.basePath ?? "/api/auth"}/fixture/authenticate-client`,
          { method: "POST", headers, body: JSON.stringify(input.body) },
        ),
        asResponse: true,
      });
    }
    if (input.action === "trusted-client") {
      return auth.api.trustedGetClient({
        body: { fresh: input.fresh ?? false, rename: input.rename ?? false },
        asResponse: true,
      });
    }
    if (input.action === "trusted-external-update" || input.action === "trusted-external-delete") {
      const ctx = await auth.$context;
      if (input.action === "trusted-external-update") {
        await ctx.adapter.update({
          model: "oauthClient",
          where: [{ field: "clientId", value: "trusted-client" }],
          update: { name: "External update" },
        });
      } else {
        await ctx.adapter.delete({
          model: "oauthClient",
          where: [{ field: "clientId", value: "trusted-client" }],
        });
      }
      return new Response(JSON.stringify({ updated: true }), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "provider-client") {
      return auth.api.providerResolveClient({
        body: { clientId: input.clientId, discover: input.discover },
        asResponse: true,
      });
    }
    if (input.action === "secret-cipher-validation") {
      try {
        oauthProvider({
          loginPage: "/login",
          consentPage: "/consent",
          storeClientSecret: customCipher,
        });
        return new Response(JSON.stringify({ valid: true }), {
          headers: { "content-type": "application/json" },
        });
      } catch (error) {
        return new Response(JSON.stringify({ valid: false, message: (error as Error).message }), {
          headers: { "content-type": "application/json" },
        });
      }
    }
    if (input.action === "secret-hash-validation") {
      try {
        oauthProvider({
          loginPage: "/login",
          consentPage: "/consent",
          disableJwtPlugin: true,
          storeClientSecret: { hash: async (secret: string) => customHash(secret) },
        });
        return new Response(JSON.stringify({ valid: true }), {
          headers: { "content-type": "application/json" },
        });
      } catch (error) {
        return new Response(JSON.stringify({ valid: false, message: (error as Error).message }), {
          headers: { "content-type": "application/json" },
        });
      }
    }
    if (input.action === "remote-jwks-document") {
      remoteState.document = remoteDocument(input.family, input.algorithm, input.kid);
      return new Response(JSON.stringify({ updated: true }), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "remote-jwks-response") {
      remoteState.responseMode = input.responseMode;
      remoteState.uri = input.uri;
      remoteState.fetches = [];
      return new Response(JSON.stringify({ updated: true }), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "remote-jwks-fetches") {
      return new Response(JSON.stringify(remoteState.fetches), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "discovery-validation") {
      try {
        oauthProvider({
          loginPage: "/login",
          consentPage: "/consent",
          extensions: [
            {
              clientDiscovery: input.ids.map((id: string) => ({
                id,
                matches: () => false,
                resolve: async () => null,
              })),
            },
          ],
        });
        return new Response(JSON.stringify({ valid: true }), {
          headers: { "content-type": "application/json" },
        });
      } catch (error) {
        return new Response(JSON.stringify({ valid: false, message: (error as Error).message }), {
          headers: { "content-type": "application/json" },
        });
      }
    }
    if (input.action === "discovery-state") {
      registryState.mode = input.state;
      registryState.events.length = 0;
      return new Response(JSON.stringify({ updated: true }), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "discovery-events") {
      return new Response(JSON.stringify(registryState.events), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "discovery-row") {
      const context = await auth.$context;
      const row = await context.adapter.findOne<any>({
        model: "oauthClient",
        where: [{ field: "clientId", value: input.clientId }],
      });
      return new Response(
        JSON.stringify(
          row
            ? {
                clientId: row.clientId,
                clientDiscoveryId: row.clientDiscoveryId ?? null,
                name: row.name,
              }
            : null,
        ),
        { headers: { "content-type": "application/json" } },
      );
    }
    if (input.action === "consume-assertion") {
      return (auth.api as any).consumeAssertionFixture({ body: input.params, asResponse: true });
    }
    if (input.action === "assertion-row") {
      const context = await auth.$context;
      const row = await context.adapter.findOne<{ id: string; expiresAt: Date }>({
        model: "oauthClientAssertion",
        where: [{ field: "id", value: input.id }],
      });
      return new Response(JSON.stringify(row ? { id: row.id, expiresAt: row.expiresAt } : null), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "signout" || input.action === "revoke-sessions") {
      const call = () =>
        input.action === "revoke-sessions"
          ? auth.api.revokeSessions({ headers: new Headers(input.headers ?? {}), asResponse: true })
          : auth.api.signOut({ headers: new Headers(input.headers ?? {}), asResponse: true });
      if (input.foreignKeys === true) {
        const database = base.database as import("better-sqlite3").Database;
        const prior = database
          .prepare<[], { foreign_keys: number }>("PRAGMA foreign_keys")
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
    if (input.action === "logout-http" || input.action === "protocol-http") {
      const headers = new Headers(input.headers ?? {});
      headers.set("origin", base.baseURL!);
      headers.set(
        "content-type",
        input.contentType ?? "application/x-www-form-urlencoded; charset=UTF-8",
      );
      const url = new URL(`${base.baseURL}${base.basePath ?? "/api/auth"}${input.path}`);
      for (const [name, value] of Object.entries(input.query ?? {})) {
        for (const item of Array.isArray(value) ? value : [value])
          url.searchParams.append(name, String(item));
      }
      return auth.handler(
        new Request(url, {
          method: input.method,
          headers,
          ...(input.method === "POST"
            ? {
                body:
                  typeof input.rawBody === "string"
                    ? input.rawBody
                    : input.contentType === "application/json"
                      ? JSON.stringify(input.body)
                      : new URLSearchParams(input.formEntries ?? input.body),
              }
            : {}),
        }),
      );
    }
    if (input.action === "signup" || input.action === "signin") {
      try {
        if (input.action === "signup") {
          return await auth.api.signUpEmail({ body: input.body, asResponse: true });
        }
        const output = await auth.api.signInEmail({
          body: input.body,
          asResponse: false,
          returnHeaders: true,
          returnStatus: true,
          headers: new Headers(input.headers ?? {}),
          ...(input.attachRequest
            ? {
                request: new Request(
                  `${base.baseURL}${base.basePath ?? "/api/auth"}/sign-in/email`,
                  { method: "POST", headers: input.headers },
                ),
              }
            : {}),
        });
        const headers = new Headers(output.headers);
        headers.set("content-type", "application/json");
        return new Response(JSON.stringify(output.response), {
          status: output.status ?? 200,
          headers,
        });
      } catch (error) {
        if (!(error instanceof EndpointAPIError)) {
          throw error;
        }
        const headers = new Headers(
          (error as EndpointAPIError & { [kAPIErrorHeaderSymbol]?: Headers })[
            kAPIErrorHeaderSymbol
          ] ?? error.headers,
        );
        headers.set("content-type", "application/json");
        return new Response(error.body ? JSON.stringify(error.body) : null, {
          status: error.statusCode,
          headers,
        });
      }
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
                referenceId: row.referenceId ?? null,
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
            value:
              input.protectedToken ?? createHash("sha256").update(input.token).digest("base64url"),
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
    if (input.action === "replace-refresh-replay") {
      const { createHash } = await import("node:crypto");
      const context = await auth.$context;
      const row = await context.adapter.update<any>({
        model: "oauthRefreshToken",
        where: [
          { field: "token", value: createHash("sha256").update(input.token).digest("base64url") },
        ],
        update: { rotationReplayResponse: input.ciphertext },
      });
      return new Response(JSON.stringify(row ? { id: row.id } : null), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "expire-refresh-replay") {
      const { createHash } = await import("node:crypto");
      const context = await auth.$context;
      const row = await context.adapter.update<any>({
        model: "oauthRefreshToken",
        where: [
          { field: "token", value: createHash("sha256").update(input.token).digest("base64url") },
        ],
        update: { rotationReplayExpiresAt: new Date(Date.now() - 1000) },
      });
      return new Response(
        JSON.stringify(
          row ? { id: row.id, rotationReplayExpiresAt: row.rotationReplayExpiresAt } : null,
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
            body: new URLSearchParams(input.formEntries ?? input.body),
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
          body: new URLSearchParams(input.formEntries ?? input.body),
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
          body: new URLSearchParams(input.formEntries ?? input.body),
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
    if (input.action === "extension-auth-validation") {
      try {
        const candidate = betterAuth({
          ...options,
          plugins: [
            jwt(),
            oauthProvider({
              loginPage: "/login",
              consentPage: "/consent",
              extensions: input.entries.map((entry: any) => ({
                clientAuthentication: {
                  [entry.method]: {
                    ...(entry.types === null ? {} : { assertionTypes: entry.types }),
                    authenticate: async () => ({ clientId: "unused" }),
                  },
                },
              })),
            }),
          ],
        });
        await candidate.$context;
        return Response.json({ valid: true });
      } catch (error) {
        return Response.json({ valid: false, message: (error as Error).message });
      }
    }
    if (input.action === "extension-validation") {
      try {
        await betterAuth({
          ...options,
          plugins: [
            username(),
            jwt(),
            oauthProvider({
              loginPage: "/login",
              consentPage: "/consent",
              extensions: input.keys.map((key: string) => ({
                grants: {
                  [key]: async () => {
                    throw new Error("unused setup handler");
                  },
                },
              })),
            }),
          ],
        }).$context;
        return Response.json({ valid: true }, { headers: { "content-type": "application/json" } });
      } catch (error) {
        return Response.json(
          { valid: false, message: (error as Error).message },
          { headers: { "content-type": "application/json" } },
        );
      }
    }
    if (input.action === "grant-metadata") {
      return auth.api.getOAuthServerConfig({ asResponse: true });
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
          body: new URLSearchParams(input.formEntries ?? input.body),
        }),
      });
    }
    if (input.action === "dpop-proof") {
      return (auth.api as any).dpopFixture({ body: input.body, asResponse: true });
    }
    if (input.action === "issue-tokens") {
      return (auth.api as any).issueTokensFixture({
        body: input.body,
        headers: input.headers ? new Headers(input.headers) : undefined,
        asResponse: true,
      });
    }
    if (input.action === "validate-access") {
      return (auth.api as any).validateAccessFixture({ body: input.body, asResponse: true });
    }
    if (input.action === "sign-access") {
      if (!input.omitKid) {
        return auth.api.signJWT({ body: { payload: input.body }, asResponse: true });
      }
      const generated = await auth.api.signJWT({ body: { payload: input.body } });
      const context = await auth.$context;
      const stored = await context.adapter.findOne<any>({
        model: "jwks",
        where: [{ field: "id", value: decodeProtectedHeader(generated.token).kid }],
      });
      const privateJwk = JSON.parse(
        await symmetricDecrypt({ key: context.secretConfig, data: JSON.parse(stored.privateKey) }),
      );
      const token = await new SignJWT(input.body)
        .setProtectedHeader({ alg: "EdDSA" })
        .sign(await importJWK(privateJwk, "EdDSA"));
      return new Response(JSON.stringify({ token }), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "hash-token") {
      return (auth.api as any).hashTokenFixture({
        body: { token: input.token, kind: input.kind, custom: input.mode === "custom-token-hash" },
        asResponse: true,
      });
    }
    if (input.action === "authority-counts") {
      const context = await auth.$context;
      const where = [{ field: "sessionId", value: input.sessionId }];
      const [access, refresh] = await Promise.all(
        ["oauthAccessToken", "oauthRefreshToken"].map((model) =>
          context.adapter.findMany({ model, where }),
        ),
      );
      return new Response(JSON.stringify({ access: access.length, refresh: refresh.length }), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "token-row") {
      const { createHash } = await import("node:crypto");
      const context = await auth.$context;
      const row = (await context.adapter.findOne({
        model: input.kind === "refresh" ? "oauthRefreshToken" : "oauthAccessToken",
        where: [
          {
            field: "token",
            value:
              input.protectedToken ?? createHash("sha256").update(input.token).digest("base64url"),
          },
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
                referenceId: row.referenceId ?? null,
                confirmation: row.confirmation ?? null,
                requestedUserInfoClaims: row.requestedUserInfoClaims ?? null,
                authTime: row.authTime ?? null,
                resources: row.resources ?? null,
                revoked: row.revoked ?? null,
                rotatedAt: row.rotatedAt ?? null,
                rotationReplayResponse: row.rotationReplayResponse ?? null,
                rotationReplayExpiresAt: row.rotationReplayExpiresAt ?? null,
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
        const database = base.database as import("better-sqlite3").Database;
        const prior = database
          .prepare<[], { foreign_keys: number }>("PRAGMA foreign_keys")
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
