import { sso } from "@better-auth/sso";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { username } from "better-auth/plugins";

import { ssoDnsFixture } from "./sso-dns-fixture";
import { ssoOidcFixture } from "./sso-oidc-fixture";
import { samlGrant, signedLogout } from "./sso-saml-grant";
export async function ssoFixture(base: BetterAuthOptions) {
  const idp = ssoOidcFixture();
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
  const instances = new Map([
    ["default", betterAuth(options)],
    ["trusted-claims", betterAuth(trustedClaimsOptions)],
    ["domain", betterAuth(domainOptions)],
    ["shared", betterAuth(sharedOptions)],
    ["slo", betterAuth(sloOptions)],
    ["signed-slo", betterAuth(signedSloOptions)],
    ["signed-request-slo", betterAuth(signedRequestSloOptions)],
  ]);

  const handle = async (request: Request) => {
    const input = await request.json();
    const mode =
      input.mode === "trusted-claims"
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
      return auth.handler(
        new Request(
          `${options.baseURL}${options.basePath ?? "/api/auth"}/sso/saml2/sp/${input.action === "slo-http" ? "slo" : "acs"}/${input.params.providerId}`,
          {
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
          mode === "trusted-claims"
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
