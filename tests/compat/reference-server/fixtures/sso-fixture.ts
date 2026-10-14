import { Database } from "bun:sqlite";

import { sso } from "@better-auth/sso";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { APIError } from "better-auth/api";
import { getMigrations } from "better-auth/db/migration";
import { organization, username } from "better-auth/plugins";

import { ssoDnsFixture } from "./sso-dns-fixture";
import { ssoOidcFixture } from "./sso-oidc-fixture";
import { samlGrant, signedLogout } from "./sso-saml-grant";
export async function ssoFixture(base: BetterAuthOptions) {
  let providerLimit = 0;
  const limitEvents: any[] = [];
  const idp = ssoOidcFixture();
  const provisioningEvents: any[] = [];
  const roleEvents: any[] = [];
  const validationEvents: any[] = [];
  let validationDenyReturning = false;
  const options = {
    baseURL: base.baseURL,
    basePath: base.basePath,
    secret: base.secret,
    database: base.database,
    emailAndPassword: { enabled: true },
    trustedOrigins: [idp.base],
    plugins: [username(), sso()],
  };
  await (await getMigrations(options)).runMigrations();
  const dns = await ssoDnsFixture();
  const domainOptions = {
    ...options,
    account: { accountLinking: { requireLocalEmailVerified: false } },
    plugins: [username(), sso({ domainVerification: { enabled: true } })],
  };
  await (await getMigrations(domainOptions)).runMigrations();
  const sharedOptions = {
    ...options,
    plugins: [username(), sso({ redirectURI: "/sso/callback" })],
  };
  const sloOptions = {
    ...options,
    plugins: [username(), sso({ saml: { enableSingleLogout: true } })],
  };
  const signedSloOptions = {
    ...options,
    plugins: [
      username(),
      sso({ saml: { enableSingleLogout: true, wantLogoutResponseSigned: true } }),
    ],
  };
  const signedRequestSloOptions = {
    ...options,
    plugins: [
      username(),
      sso({ saml: { enableSingleLogout: true, wantLogoutRequestSigned: true } }),
    ],
  };
  const trustedClaimsOptions = {
    ...options,
    plugins: [username(), sso({ trustEmailVerified: true })],
  };
  const validationOptions = {
    ...options,
    user: {
      async validateUserInfo(data: any, context: any) {
        if (data.source.method !== "oauth" && !data.source.method.startsWith("sso-")) return;
        validationEvents.push(
          JSON.parse(
            JSON.stringify({
              source: data.source,
              name: data.user.name,
              email: data.user.email,
              requestPresent: Boolean(context.request),
              path: context.path,
            }),
          ),
        );
        if (
          !["sso-oidc", "sso-saml"].includes(data.source.method) ||
          !data.source.sso ||
          data.source.oauth
        ) {
          return { error: "wrong_sso_source", errorDescription: "SSO provenance required" };
        }
        if (data.source.action === "sign-in" && validationDenyReturning) {
          return { error: "sso_validation_denied", errorDescription: "SSO identity rejected" };
        }
        if (data.source.action === "create-user") data.user.name = "Policy SSO user";
      },
    },
  };
  const noSignupOptions = {
    ...options,
    plugins: [username(), sso({ disableImplicitSignUp: true })],
  };
  const configuredProviderDefinitions = [
    {
      providerId: "configured-oidc",
      domain: "oidc.company.test",
      oidcConfig: {
        issuer: idp.base,
        clientId: "enterprise-client",
        clientSecret: "stored-secret",
        pkce: true,
        authorizationEndpoint: `${idp.base}/authorize`,
        tokenEndpoint: `${idp.base}/token`,
        jwksEndpoint: `${idp.base}/jwks`,
        userInfoEndpoint: `${idp.base}/userinfo`,
        tokenEndpointAuthentication: "client_secret_basic" as const,
      },
    },
    {
      providerId: "configured-saml",
      domain: "saml.company.test",
      samlConfig: {
        issuer: "https://sp.example.test/entity",
        entryPoint: "https://idp.example.test/sso",
        cert: await Bun.file(
          new URL("../../fixtures/salesforce-transport/leaf.pem", import.meta.url),
        ).text(),
        idpMetadata: { entityID: "https://idp.example.test/entity" },
        wantAssertionsSigned: true,
      },
    },
  ];
  const configuredOptions = (changed = false) => ({
    ...options,
    plugins: [
      username(),
      sso({
        domainVerification: { enabled: true },
        defaultSSO: configuredProviderDefinitions.map((provider) =>
          changed ? { ...provider, domain: `changed.${provider.domain}` } : provider,
        ),
      }),
    ],
  });
  const keyEvents: any[] = [];
  let keyEnabled = true;
  const jwtOptions = async (key: boolean, mode = "pem") => ({
    ...options,
    plugins: [
      username(),
      sso({
        ...(mode === "precedence"
          ? {
              async resolvePrivateKey(context: any) {
                keyEvents.push({ ...context });
                return {};
              },
            }
          : {}),
        defaultSSO: [
          {
            providerId: "configured-jwt",
            domain: "jwt.company.test",
            oidcConfig: {
              issuer: idp.base,
              clientId: "enterprise-client",
              pkce: true,
              authorizationEndpoint: `${idp.base}/authorize`,
              tokenEndpoint: `${idp.base}/token-jwt`,
              jwksEndpoint: `${idp.base}/jwks`,
              userInfoEndpoint: `${idp.base}/userinfo`,
              tokenEndpointAuthentication: "private_key_jwt" as const,
              privateKeyId: "sso-key",
              privateKeyAlgorithm: "RS256",
            },
            ...(key
              ? {
                  privateKey:
                    mode === "jwk"
                      ? {
                          privateKeyJwk: await Bun.file(
                            new URL(
                              "../../fixtures/salesforce-transport/private.jwk.json",
                              import.meta.url,
                            ),
                          ).json(),
                          privateKeyPem: "unusable PEM must not be imported",
                        }
                      : {
                          privateKeyPem: await Bun.file(
                            new URL("../../fixtures/salesforce-transport/key.pem", import.meta.url),
                          ).text(),
                        },
                }
              : {}),
          },
        ],
      }),
    ],
  });
  const privateKeyPem = await Bun.file(
    new URL("../../fixtures/salesforce-transport/key.pem", import.meta.url),
  ).text();
  const resolverOptions = {
    ...options,
    plugins: [
      username(),
      sso({
        async resolvePrivateKey(context) {
          keyEvents.push({ ...context });
          return keyEnabled ? { privateKeyPem, kid: "resolved-kid", algorithm: "PS256" } : {};
        },
      }),
    ],
  };
  const provisioningOptions = (every: boolean) => ({
    ...options,
    plugins: [
      username(),
      sso({
        provisionUserOnEveryLogin: every,
        async provisionUser(data) {
          provisioningEvents.push({
            userId: data.user.id,
            email: data.user.email,
            name: data.user.name,
            userInfo: data.userInfo,
            providerId: data.provider.providerId,
            tokenPresent: data.token !== undefined,
            accessToken: data.token?.accessToken ?? null,
          });
        },
      }),
    ],
  });
  const organizationOptions = (mode: string) => ({
    ...options,
    ...(mode.startsWith("org-domain")
      ? {
          socialProviders: {
            gitlab: {
              clientId: "enterprise-client",
              clientSecret: "stored-secret",
              issuer: idp.base,
            },
          },
        }
      : {}),
    plugins: [
      username(),
      organization(),
      sso({
        domainVerification: { enabled: mode.startsWith("org-domain") },
        organizationProvisioning: {
          ...(["org-dynamic", "org-disabled", "org-invitation"].includes(mode)
            ? {
                async getRole(data: any) {
                  roleEvents.push({
                    userId: data.user.id,
                    email: data.user.email,
                    providerId: data.provider.providerId,
                    organizationId: data.provider.organizationId,
                    profile: data.userInfo,
                    tokenPresent: data.token !== undefined,
                  });
                  return "admin" as const;
                },
              }
            : {}),
          disabled: mode === "org-disabled" || mode === "org-domain-disabled",
          defaultRole: mode === "org-admin" ? ("admin" as const) : ("member" as const),
        },
      }),
    ],
  });
  await (await getMigrations(organizationOptions("org-default"))).runMigrations();
  let resolutionDecision: any = { action: "continue" };
  let resolutionDenySessions = false;
  let resolutionFailAfterUser = false;
  const resolutionEvents: any[] = [];
  const resolutionOptions = {
    ...options,
    databaseHooks: {
      session: {
        create: {
          before: async () => {
            if (resolutionDenySessions) {
              throw new APIError("FORBIDDEN", {
                code: "SESSION_POLICY_DENIED",
                message: "Session policy rejected",
              });
            }
          },
        },
      },
      user: {
        create: {
          after: async () => {
            if (resolutionFailAfterUser) {
              throw new Error("Committed application user hook failed");
            }
          },
        },
      },
    },
    plugins: [
      username(),
      sso({
        resolveUser: async (input, { database }) => {
          const identifier = `sso-resolver-write:${resolutionEvents.length + 1}`;
          await database.create({
            model: "verification",
            data: { identifier, value: input.providerId, expiresAt: new Date(Date.now() + 300000) },
          });
          resolutionEvents.push({ input, identifier });
          if (resolutionDecision.action === "throw") {
            throw new Error("Private application resolver detail");
          }
          return resolutionDecision;
        },
      }),
    ],
  };
  let mutationDenied = true;
  const mutationEvents: any[] = [];
  const mutationOptions = {
    ...options,
    plugins: [
      username(),
      sso({
        guardProviderMutation: async (mutation, { database }) => {
          const row = await database.findOne<any>({
            model: "ssoProvider",
            where: [
              { field: "id", value: mutation.provider.id },
              { field: "providerId", value: mutation.provider.providerId },
            ],
          });
          if (!row) {
            throw new Error("Locked provider missing");
          }
          const index = mutationEvents.length + 1;
          const identifier = `sso-guard-write:${mutation.action}:${index}`;
          await database.create({
            model: "verification",
            data: { identifier, value: row.domain, expiresAt: new Date(Date.now() + 300000) },
          });
          mutationEvents.push({ mutation, domain: row.domain, identifier });
          if (mutationDenied) {
            throw new Error("Application policy rejected with private detail");
          }
        },
      }),
    ],
  };
  const storageDatabase = new Database(":memory:");
  const storageOptions = {
    ...options,
    database: storageDatabase,
    plugins: [
      username(),
      sso({
        domainVerification: { enabled: true },
        schema: {
          ssoProvider: {
            modelName: "application_sso_provider",
            fields: {
              issuer: "application_issuer",
              domain: "application_domain",
              providerId: "application_provider",
              userId: "application_owner",
              organizationId: "application_org",
              oidcConfig: "application_oidc",
              samlConfig: "application_saml",
              domainVerified: "application_verified",
            },
          },
        },
      }),
    ],
  };
  await (await getMigrations(storageOptions)).runMigrations();
  const additionalDatabase = new Database(":memory:");
  const additionalOptions = {
    ...options,
    database: additionalDatabase,
    plugins: [
      username(),
      sso({
        schema: {
          ssoProvider: {
            additionalFields: {
              label: { type: "string" as const, required: true, fieldName: "application_label" },
              privateNote: { type: "string" as const, required: false, returned: false },
              managed: {
                type: "boolean" as const,
                required: false,
                input: false,
                defaultValue: false,
              },
              tier: { type: "number" as const, required: false, defaultValue: 2 },
              tags: { type: "string[]" as const, required: false },
              settings: { type: "json" as const, required: false },
            },
          },
        },
      }),
    ],
  };
  await (await getMigrations(additionalOptions)).runMigrations();
  const globalModes = [
    "idp-global-relative-true",
    "idp-global-relative-false",
    "idp-global-absolute-true",
    "idp-global-absolute-false",
    "idp-global-unsafe-true",
    "idp-global-unsafe-false",
  ];
  const algorithmModes = [
    "algorithm-strict",
    "algorithm-reject",
    "algorithm-override",
    "algorithm-empty",
  ];
  const signingAlgorithms = (mode: string) =>
    mode === "algorithm-strict"
      ? {
          allowedSignatureAlgorithms: ["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"],
          allowedDigestAlgorithms: ["sha256"],
        }
      : mode === "algorithm-reject"
        ? { onDeprecated: "reject" as const }
        : mode === "algorithm-override"
          ? {
              onDeprecated: "reject" as const,
              allowedSignatureAlgorithms: ["sha1"],
              allowedDigestAlgorithms: ["http://www.w3.org/2000/09/xmldsig#sha1"],
            }
          : { allowedSignatureAlgorithms: [], allowedDigestAlgorithms: [] };
  const encryptionModes = [
    "encrypted-deprecated-data-reject",
    "encrypted-deprecated-data-allow",
    "encrypted-deprecated-data-warn",
    "encrypted-deprecated-data-override",

    "encrypted-policy-key-denied",
    "encrypted-policy-data-denied",
    "encrypted-policy-key-allowed",
    "encrypted-policy-data-allowed",
    "encrypted-policy-key-empty",
    "encrypted-policy-data-empty",
    "encrypted-policy-outer-key-denied",
  ];
  const encryptionAlgorithms = (mode: string) =>
    mode.includes("deprecated-data-")
      ? mode.endsWith("override")
        ? {
            onDeprecated: "reject" as const,
            allowedDataEncryptionAlgorithms: ["http://www.w3.org/2001/04/xmlenc#tripledes-cbc"],
          }
        : {
            onDeprecated: (mode.endsWith("allow")
              ? "allow"
              : mode.endsWith("warn")
                ? "warn"
                : "reject") as "allow" | "warn" | "reject",
          }
      : mode.includes("policy-key-denied")
        ? { allowedKeyEncryptionAlgorithms: ["http://www.w3.org/2001/04/xmlenc#rsa-1_5"] }
        : mode.includes("policy-data-denied")
          ? { allowedDataEncryptionAlgorithms: ["http://www.w3.org/2009/xmlenc11#aes128-gcm"] }
          : mode.includes("policy-key-allowed")
            ? {
                allowedKeyEncryptionAlgorithms: ["http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"],
              }
            : mode.includes("policy-data-allowed")
              ? { allowedDataEncryptionAlgorithms: ["http://www.w3.org/2009/xmlenc11#aes256-gcm"] }
              : mode.includes("policy-data-empty")
                ? { allowedDataEncryptionAlgorithms: [] }
                : { allowedKeyEncryptionAlgorithms: [] };
  const instances = new Map([
    ["storage-schema", betterAuth(storageOptions)],
    ["additional-fields", betterAuth(additionalOptions)],
    ...encryptionModes.map(
      (mode) =>
        [
          mode,
          betterAuth({
            ...options,
            plugins: [username(), sso({ saml: { algorithms: encryptionAlgorithms(mode) } })],
          }),
        ] as const,
    ),
    ...algorithmModes.map(
      (mode) =>
        [
          mode,
          betterAuth({
            ...options,
            plugins: [username(), sso({ saml: { algorithms: signingAlgorithms(mode) } })],
          }),
        ] as const,
    ),
    ...globalModes.map(
      (mode) =>
        [
          mode,
          betterAuth({
            ...options,
            plugins: [
              username(),
              sso({
                saml: {
                  allowIdpInitiated: mode.endsWith("true"),
                  idpInitiatedCallbackUrl: mode.includes("relative")
                    ? "/global-complete"
                    : mode.includes("absolute")
                      ? `${new URL(base.baseURL as string).origin}/global-complete`
                      : "https://untrusted.example.test/hijack",
                },
              }),
            ],
          }),
        ] as const,
    ),
    [
      "idp-initiated",
      betterAuth({ ...options, plugins: [username(), sso({ saml: { allowIdpInitiated: true } })] }),
    ],
    [
      "provider-limits",
      betterAuth({
        ...options,
        plugins: [
          username(),
          sso({
            providersLimit: async (user) => {
              limitEvents.push({
                userId: user.id,
                email: user.email,
                name: user.name,
                emailVerified: user.emailVerified,
              });
              return providerLimit;
            },
          }),
        ],
      }),
    ],
    ["user-resolution", betterAuth(resolutionOptions)],
    ["mutation-guard", betterAuth(mutationOptions)],
    ["org-domain", betterAuth(organizationOptions("org-domain"))],
    ["org-domain-disabled", betterAuth(organizationOptions("org-domain-disabled"))],
    ["org-dynamic", betterAuth(organizationOptions("org-dynamic"))],
    ["org-invitation", betterAuth(organizationOptions("org-invitation"))],
    ["org-default", betterAuth(organizationOptions("org-default"))],
    ["org-admin", betterAuth(organizationOptions("org-admin"))],
    ["org-disabled", betterAuth(organizationOptions("org-disabled"))],

    ["provisioning", betterAuth(provisioningOptions(false))],
    ["provisioning-every", betterAuth(provisioningOptions(true))],
    ["key-resolver", betterAuth(resolverOptions)],
    ["configured-jwt", betterAuth(await jwtOptions(true))],
    ["configured-jwt-jwk", betterAuth(await jwtOptions(true, "jwk"))],
    ["configured-jwt-precedence", betterAuth(await jwtOptions(true, "precedence"))],
    ["configured-jwt-missing", betterAuth(await jwtOptions(false))],
    ["configured-changed", betterAuth(configuredOptions(true))],
    ["configured", betterAuth(configuredOptions())],
    ["default", betterAuth(options)],
    ["no-signup", betterAuth(noSignupOptions)],
    ["validation", betterAuth(validationOptions)],
    ["trusted-claims", betterAuth(trustedClaimsOptions)],
    ["domain", betterAuth(domainOptions)],
    ["shared", betterAuth(sharedOptions)],
    ["slo", betterAuth(sloOptions)],
    ["signed-slo", betterAuth(signedSloOptions)],
    ["signed-request-slo", betterAuth(signedRequestSloOptions)],
  ]);

  const handle = async (request: Request) => {
    const input = await request.json();
    if (input.action === "field-collision") {
      let error: string | null = null;
      try {
        sso({
          schema: {
            ssoProvider: {
              fields: input.mapped ? { domain: "application_domain" } : undefined,
              additionalFields: {
                [input.name]: { type: "string", required: false, fieldName: input.physical },
              },
            },
          },
        });
      } catch (caught) {
        error = (caught as Error).message;
      }
      return new Response(JSON.stringify({ accepted: error === null, error }), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "limit-policy") {
      providerLimit = input.limit;
      limitEvents.length = 0;
      return new Response(JSON.stringify({ configured: true }), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "limit-events") {
      return new Response(JSON.stringify(limitEvents), {
        headers: { "content-type": "application/json" },
      });
    }
    const mode = [
      "storage-schema",
      "additional-fields",
      ...encryptionModes,
      ...algorithmModes,
      ...globalModes,
      "idp-initiated",
      "provider-limits",
      "user-resolution",
      "mutation-guard",
      "org-default",
      "org-admin",
      "org-disabled",
      "org-dynamic",
      "org-invitation",
      "org-domain",
      "org-domain-disabled",
    ].includes(input.mode)
      ? input.mode
      : input.mode === "provisioning"
        ? "provisioning"
        : input.mode === "provisioning-every"
          ? "provisioning-every"
          : input.mode === "configured-jwt-jwk"
            ? "configured-jwt-jwk"
            : input.mode === "configured-jwt-precedence"
              ? "configured-jwt-precedence"
              : input.mode === "key-resolver"
                ? "key-resolver"
                : input.mode === "configured-jwt"
                  ? "configured-jwt"
                  : input.mode === "configured-jwt-missing"
                    ? "configured-jwt-missing"
                    : input.mode === "configured-changed"
                      ? "configured-changed"
                      : input.mode === "configured"
                        ? "configured"
                        : input.mode === "no-signup"
                          ? "no-signup"
                          : input.mode === "validation"
                            ? "validation"
                            : input.mode === "trusted-claims"
                              ? "trusted-claims"
                              : input.mode === "signed-request-slo"
                                ? "signed-request-slo"
                                : input.mode === "signed-slo"
                                  ? "signed-slo"
                                  : input.mode === "domain"
                                    ? "domain"
                                    : input.mode === "shared"
                                      ? "shared"
                                      : input.mode === "slo"
                                        ? "slo"
                                        : "default";
    const auth = instances.get(mode)!;
    if (input.action === "user-exists") {
      const context = await auth.$context;
      const user = await context.adapter.findOne({
        model: "user",
        where: [{ field: "email", value: input.email }],
      });
      return new Response(JSON.stringify(user !== null), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "storage-state") {
      const tables = storageDatabase
        .query("SELECT name FROM sqlite_master WHERE type='table'")
        .all() as any[];
      const customTableExists = tables.some((table) => table.name === "application_sso_provider");
      const defaultTableExists = tables.some((table) => table.name === "ssoProvider");
      const rows = customTableExists
        ? storageDatabase
            .query(
              "SELECT id,application_issuer AS issuer,application_domain AS domain,application_provider AS providerId,application_owner AS userId,application_org AS organizationId,application_oidc AS oidcConfig,application_saml AS samlConfig,application_verified AS domainVerified FROM application_sso_provider ORDER BY application_provider",
            )
            .all()
            .map((row: any) => ({
              ...row,
              domainVerified: row.domainVerified == null ? null : Boolean(row.domainVerified),
            }))
        : [];
      return new Response(JSON.stringify({ customTableExists, defaultTableExists, rows }), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "resolution-policy") {
      resolutionDecision = input.decision;
      resolutionDenySessions = Boolean(input.denySessions);
      resolutionFailAfterUser = Boolean(input.failAfterUser);
      if (input.clear) {
        resolutionEvents.length = 0;
      }
      return new Response(JSON.stringify({ configured: true }), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "resolution-events") {
      return new Response(JSON.stringify(resolutionEvents), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "mutation-policy") {
      mutationDenied = Boolean(input.denied);
      if (input.clear) {
        mutationEvents.length = 0;
      }
      return new Response(JSON.stringify({ configured: true }), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "mutation-events") {
      return new Response(JSON.stringify(mutationEvents), {
        headers: { "content-type": "application/json" },
      });
    }
    if (["org-create", "org-invite", "org-role"].includes(input.action)) {
      const operation =
        input.action === "org-create"
          ? "createOrganization"
          : input.action === "org-invite"
            ? "createInvitation"
            : "updateMemberRole";
      return (auth.api as any)[operation]({
        body: input.body,
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    if (input.action === "role-reset") {
      roleEvents.length = 0;
      return new Response(JSON.stringify({ configured: true }), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "role-events") {
      return new Response(JSON.stringify(roleEvents), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "member-row") {
      const context = await auth.$context;
      const row = await context.adapter.findOne<any>({
        model: "member",
        where: [
          { field: "organizationId", value: input.organizationId },
          { field: "userId", value: input.userId },
        ],
      });
      return new Response(
        JSON.stringify(
          row
            ? { id: row.id, userId: row.userId, organizationId: row.organizationId, role: row.role }
            : null,
        ),
        { headers: { "content-type": "application/json" } },
      );
    }
    if (input.action === "provisioning-reset") {
      provisioningEvents.length = 0;
      return new Response(JSON.stringify({ configured: true }), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "provisioning-events") {
      return new Response(JSON.stringify(provisioningEvents), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "key-reset") {
      keyEvents.length = 0;
      keyEnabled = true;
      return new Response(JSON.stringify({ configured: true }), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "key-enabled") {
      keyEnabled = input.enabled;
      return new Response(JSON.stringify({ configured: true }), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "key-events") {
      return new Response(JSON.stringify(keyEvents), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "validation-reset") {
      validationEvents.length = 0;
      validationDenyReturning = false;
      return new Response(JSON.stringify({ configured: true }), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "validation-deny") {
      validationDenyReturning = input.enabled;
      return new Response(JSON.stringify({ configured: true }), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "validation-events") {
      return new Response(JSON.stringify(validationEvents), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "dns-records") {
      dns.setRecords(input.records);
      return new Response(JSON.stringify({ configured: true }), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "dns-queries") {
      return new Response(JSON.stringify(dns.queries()), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "sign-saml-logout") {
      return new Response(
        JSON.stringify({ SAMLResponse: await signedLogout(input.xml, Boolean(input.wrongKey)) }),
        { headers: { "content-type": "application/json" } },
      );
    }
    if (input.action === "saml-grant") {
      return new Response(
        JSON.stringify(
          await samlGrant(
            input.authorization,
            input.email,
            Boolean(input.wrongKey),
            input.verified,
            Boolean(input.unsolicited),
            Boolean(input.unsupportedSignature),
          ),
        ),
        { headers: { "content-type": "application/json" } },
      );
    }
    if (input.action === "sign-out-http") {
      return auth.handler(
        new Request(`${options.baseURL}${options.basePath ?? "/api/auth"}/sign-out`, {
          method: "POST",
          headers: { ...input.headers, "content-type": "application/json" },
          body: "{}",
        }),
      );
    }
    if (input.action === "acs-http" || input.action === "slo-http") {
      const url = new URL(
        `${options.baseURL}${options.basePath ?? "/api/auth"}/sso/saml2/sp/${input.action === "slo-http" ? "slo" : "acs"}/${input.params.providerId}`,
      );
      const get = input.method === "GET";
      if (get) url.search = new URLSearchParams(input.query).toString();
      return auth.handler(
        new Request(
          url,
          get
            ? { method: "GET", headers: input.headers }
            : {
                method: "POST",
                headers: { ...input.headers, "content-type": "application/x-www-form-urlencoded" },
                body: new URLSearchParams(input.body),
              },
        ),
      );
    }
    if (input.action === "slo") {
      return auth.api.sloEndpoint({
        params: input.params,
        body: input.body,
        query: input.query,
        method: "POST",
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    if (input.action === "initiate-slo") {
      return auth.api.initiateSLO({
        params: input.params,
        body: input.body,
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    if (input.action === "acs") {
      return auth.api.acsEndpoint({
        params: input.params,
        body: input.body,
        query: input.query,
        method: input.method ?? "POST",
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    if (input.action === "sp-metadata") {
      return auth.api.spMetadata({
        query: input.query,
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    if (input.action === "sign-in") {
      return auth.api.signInSSO({
        body: input.body,
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    if (input.action === "verify-domain") {
      return auth.api.verifyDomain({
        body: input.body,
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    if (input.action === "request-domain") {
      return auth.api.requestDomainVerification({
        body: input.body,
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    if (input.action === "proof") {
      const context = await auth.$context;
      const proof = await context.internalAdapter.findVerificationValue(input.identifier);
      return new Response(
        JSON.stringify(
          proof
            ? {
                id: proof.id,
                identifier: proof.identifier,
                value: proof.value,
                expiresAt: proof.expiresAt,
              }
            : null,
        ),
        { headers: { "content-type": "application/json" } },
      );
    }
    if (input.action === "expire-proof") {
      const context = await auth.$context;
      await context.adapter.update({
        model: "verification",
        where: [{ field: "identifier", value: input.identifier }],
        update: { expiresAt: new Date(Date.now() - 1000) },
      });
      return new Response(JSON.stringify({ expired: true }), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "idp") {
      if (input.email) idp.setEmail(input.email);
      idp.setIdTokenCase(input.idTokenCase ?? "none");
      idp.setDiscoveryCase(input.discoveryCase ?? "valid");
      idp.setProfile(input.profile ?? null);
      return new Response(JSON.stringify({ base: idp.base }), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "idp-exchanges") {
      return new Response(JSON.stringify(idp.exchanges()), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "social-start") {
      return auth.api.signInSocial({ body: input.body, asResponse: true });
    }
    if (input.action === "social-callback-http") {
      return auth.handler(
        new Request(
          `${base.baseURL}${base.basePath ?? "/api/auth"}/callback/gitlab?${new URLSearchParams(input.query)}`,
          { headers: input.headers },
        ),
      );
    }
    if (input.action === "social-callback") {
      return auth.api.callbackOAuth({
        params: { id: "gitlab" },
        query: input.query,
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    if (input.action === "shared-callback") {
      return auth.api.callbackSSOShared({
        query: input.query,
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    if (input.action === "callback") {
      return auth.api.callbackSSO({
        params: input.params,
        query: input.query,
        headers: new Headers(input.headers ?? {}),
        asResponse: true,
      });
    }
    if (input.action === "sign-out-api") {
      return auth.api.signOut({ headers: new Headers(input.headers ?? {}), asResponse: true });
    }
    if (input.action === "session") {
      return auth.api.getSession({ headers: new Headers(input.headers ?? {}), asResponse: true });
    }
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
    if (
      input.action === "account-row" ||
      input.action === "saml-account-row" ||
      input.action === "id-token-account-row"
    ) {
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
                ...(input.action === "id-token-account-row" ? { idToken: row.idToken } : {}),
                ...(input.action === "saml-account-row"
                  ? { accessToken: row.accessToken, refreshToken: row.refreshToken }
                  : {}),
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
      instances.set(
        mode,
        betterAuth(
          mode === "additional-fields"
            ? additionalOptions
            : mode === "storage-schema"
              ? storageOptions
              : mode === "no-signup"
                ? noSignupOptions
                : mode === "validation"
                  ? validationOptions
                  : mode === "trusted-claims"
                    ? trustedClaimsOptions
                    : mode === "signed-request-slo"
                      ? signedRequestSloOptions
                      : mode === "signed-slo"
                        ? signedSloOptions
                        : mode === "domain"
                          ? domainOptions
                          : mode === "shared"
                            ? sharedOptions
                            : mode === "slo"
                              ? sloOptions
                              : options,
        ),
      );
      return new Response(JSON.stringify({ restarted: true }), {
        headers: { "content-type": "application/json" },
      });
    }
    if (input.action === "user-row") {
      const context = await auth.$context;
      const row = await context.adapter.findOne({
        model: "user",
        where: [{ field: "email", value: input.email }],
      });
      return new Response(JSON.stringify(row ? { id: row.id, email: row.email } : null), {
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
