import { readFile as readFixtureFile } from "node:fs/promises";

import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
for (const protocol of ["saml", "oidc"]) {
  for (const mode of [
    "reject",
    "continue",
    "preserve",
    "update",
    "throw",
    "invalid",
    "missing-user",
    "ownership-conflict",
    "session-failure",
    "after-commit",
    ...(protocol === "oidc" ? ["missing-token", "invalid-token"] : []),
  ]) {
    compatScenario(
      `SSO ${protocol} user resolution ${mode} preserves transaction and account ownership`,
      async (ctx) => {
        const actor = ctx.actor();
        const control = (input: Record<string, unknown>) =>
          actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ mode: "user-resolution", ...input }),
            redirect: "manual",
          });
        const pairs = (response: Response) =>
          response.headers
            .getSetCookie()
            .filter((raw) => Boolean(Cookie.parse(raw)?.value))
            .map((raw) => raw.split(";")[0])
            .join("; ");
        expect(
          (
            await control({
              action: "resolution-policy",
              decision: { action: "continue" },
              clear: true,
            })
          ).status,
        ).toBe(200);
        const owner = await control({
          action: "signup",
          body: {
            email: ctx.uniqueEmail("resolver-owner"),
            name: "Resolver owner",
            password: "password123",
          },
        });
        expect(owner.status).toBe(200);
        const ownerUser = ((await owner.clone().json()) as any).user;
        const cookie = pairs(owner);
        const decision =
          mode === "reject"
            ? { action: "reject", code: "tenant_denied", message: "Enterprise tenant rejected" }
            : mode === "throw"
              ? { action: "throw" }
              : mode === "invalid"
                ? { action: "reject", code: " " }
                : ["continue", "session-failure", "after-commit"].includes(mode)
                  ? { action: "continue" }
                  : {
                      action: "link",
                      userId: mode === "missing-user" ? crypto.randomUUID() : ownerUser.id,
                      profile: mode === "update" ? "update" : "preserve",
                    };
        expect(
          (
            await control({
              action: "resolution-policy",
              clear: true,
              decision,
              denySessions: mode === "session-failure",
              failAfterUser: mode === "after-commit",
            })
          ).status,
        ).toBe(200);
        const providerId = `resolver-${protocol}-${mode}`;
        const idp = (await (await control({ action: "idp" })).json()) as any;
        const cert = await readFixtureFile(
          new URL("../../../../fixtures/salesforce-transport/leaf.pem", import.meta.url),
          "utf8",
        );
        const created = await control({
          headers: { cookie },
          body: {
            providerId,
            issuer: "https://sp.example.test/entity",
            domain: "company.test",
            ...(protocol === "saml"
              ? {
                  samlConfig: {
                    entryPoint: "https://idp.example.test/sso",
                    cert,
                    idpMetadata: { entityID: "https://idp.example.test/entity" },
                    wantAssertionsSigned: true,
                  },
                }
              : {
                  issuer: idp.base,
                  oidcConfig: {
                    clientId: "enterprise-client",
                    clientSecret: "stored-secret",
                    skipDiscovery: true,
                    pkce: true,
                    authorizationEndpoint: `${idp.base}/authorize`,
                    tokenEndpoint: `${idp.base}/token`,
                    jwksEndpoint: `${idp.base}/jwks`,
                    userInfoEndpoint: `${idp.base}/userinfo`,
                  },
                }),
          },
        });
        expect(created.status).toBe(200);
        expect(await (await control({ action: "resolution-events" })).json()).toEqual([]);
        const email = ctx.uniqueEmail("resolver-employee");
        const login = async () => {
          if (protocol === "oidc") {
            expect(
              (
                await control({
                  action: "idp",
                  idTokenCase:
                    mode === "missing-token"
                      ? "none"
                      : mode === "invalid-token"
                        ? "signature"
                        : "valid",
                  email,
                })
              ).status,
            ).toBe(200);
          }
          const started = await control({
            action: "sign-in",
            body: {
              providerId,
              callbackURL: `${ctx.baseURL}/complete`,
              errorCallbackURL: `${ctx.baseURL}/failed`,
            },
          });
          expect(started.status).toBe(200);
          const authorization = ((await started.json()) as any).url;
          if (protocol === "oidc") {
            const granted = await fetch(authorization, { redirect: "manual" });
            expect(granted.status).toBe(302);
            const query = Object.fromEntries(
              new URL(granted.headers.get("location")!).searchParams,
            );
            return control({
              action: "callback",
              params: { providerId },
              query,
              headers: { cookie: pairs(started) },
            });
          }
          const grant = (await (
            await control({ action: "saml-grant", authorization, email })
          ).json()) as any;
          return control({ action: "acs", params: { providerId }, body: grant });
        };
        let completed = await login();
        if (mode === "ownership-conflict") {
          expect(new URL(completed.headers.get("location")!).pathname).toBe("/complete");
          const firstCookie = pairs(completed);
          const foreign = await control({
            action: "signup",
            body: {
              email: ctx.uniqueEmail("foreign"),
              name: "Foreign target",
              password: "password123",
            },
          });
          expect(foreign.status).toBe(200);
          const foreignUser = ((await foreign.json()) as any).user;
          expect(
            (
              await control({
                action: "resolution-policy",
                decision: { action: "link", userId: foreignUser.id, profile: "preserve" },
              })
            ).status,
          ).toBe(200);
          completed = await login();
          const retained = (await (
            await control({ action: "session", headers: { cookie: firstCookie } })
          ).json()) as any;
          expect(retained.user.id).toBe(ownerUser.id);
        }
        expect(completed.status).toBe(302);
        const redirect = new URL(completed.headers.get("location")!);
        const success = ["continue", "preserve", "update", "after-commit"].includes(mode);
        const precondition = mode === "missing-token" || mode === "invalid-token";
        const ordinal = precondition ? 0 : mode === "ownership-conflict" ? 2 : 1;
        const account = (await (
          await control({
            action: protocol === "saml" ? "saml-account-row" : "account-row",
            providerId,
            accountId: protocol === "saml" ? email : "employee-subject",
          })
        ).json()) as any;
        const proof = (await (
          await control({ action: "proof", identifier: `sso-resolver-write:${ordinal || 1}` })
        ).json()) as any;
        if (success) {
          expect(redirect.pathname).toBe("/complete");
          expect(proof.value).toBe(providerId);
          const session = (await (
            await control({ action: "session", headers: { cookie: pairs(completed) } })
          ).json()) as any;
          expect(account.userId).toBe(session.user.id);
          expect(session.user.email).toBe(mode === "preserve" ? ownerUser.email : email);
          expect(session.user.name).toBe(mode === "preserve" ? ownerUser.name : "SSO employee");
          if (["continue", "after-commit"].includes(mode)) {
            expect(session.user.id).not.toBe(ownerUser.id);
          } else {
            expect(session.user.id).toBe(ownerUser.id);
          }
        } else {
          expect(redirect.pathname).toBe("/failed");
          const error = precondition
            ? "invalid_provider"
            : mode === "session-failure"
              ? "SESSION_POLICY_DENIED"
              : mode === "reject"
                ? "tenant_denied"
                : mode === "missing-user"
                  ? "user_not_found"
                  : mode === "ownership-conflict"
                    ? "account_ownership_conflict"
                    : "SSO_USER_RESOLUTION_FAILED";
          const description =
            mode === "session-failure"
              ? "Session policy rejected"
              : mode === "missing-token"
                ? "id_token_required_for_user_resolution"
                : mode === "invalid-token"
                  ? "token_not_verified"
                  : mode === "reject"
                    ? "Enterprise tenant rejected"
                    : mode === "missing-user"
                      ? "User not found"
                      : mode === "ownership-conflict"
                        ? "Account is already linked to another user"
                        : "Unable to resolve the SSO user";
          expect(Object.fromEntries(redirect.searchParams)).toEqual({
            error,
            error_description: description,
          });
          expect(proof).toBe(null);
          expect(await (await control({ action: "user-exists", email })).json()).toBe(false);
          if (mode === "ownership-conflict") {
            expect(account.userId).toBe(ownerUser.id);
          } else {
            expect(account).toBe(null);
          }
          expect(
            completed.headers
              .getSetCookie()
              .some(
                (raw) =>
                  raw.startsWith("better-auth.session_token=") && Boolean(Cookie.parse(raw)?.value),
              ),
          ).toBe(false);
        }
        const events = (await (await control({ action: "resolution-events" })).json()) as any[];
        expect(events).toHaveLength(ordinal);
        for (const event of events) {
          expect(event.input.protocol).toBe(protocol);
          expect(event.input.accountKey).toEqual({
            issuer: protocol === "saml" ? "https://idp.example.test/entity" : idp.base,
            accountId: protocol === "saml" ? email : "employee-subject",
          });
          expect(event.input.providerUser).toEqual({
            email,
            name: "SSO employee",
            emailVerified: false,
          });
          if (protocol === "saml") {
            expect(event.input.providerAttributes.email).toBe(email);
            expect(event.input.verifiedIdTokenClaims).toBeUndefined();
          } else {
            expect(event.input.providerClaims.email).toBe(email);
            expect(event.input.providerClaims.sub).toBe("employee-subject");
            expect(event.input.verifiedIdTokenClaims.iss).toBe(idp.base);
            expect(event.input.verifiedIdTokenClaims.sub).toBe("employee-subject");
            expect(event.input.verifiedIdTokenClaims.aud).toBe("enterprise-client");
            expect(event.input.providerAttributes).toBeUndefined();
          }
        }
        const retained = (await (
          await control({ action: "session", headers: { cookie } })
        ).json()) as any;
        expect(retained.user.id).toBe(ownerUser.id);
        expect(retained.user.email).toBe(mode === "update" ? email : ownerUser.email);
        return {
          success,
          error: Object.fromEntries(redirect.searchParams),
          calls: events.length,
          ownershipPreserved: true,
        };
      },
    );
  }
}
