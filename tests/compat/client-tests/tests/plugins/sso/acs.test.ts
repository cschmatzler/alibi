import { readFile as readFixtureFile } from "node:fs/promises";

import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
import { encryptSamlGrant } from "./encrypt-saml-grant";
for (const mode of [
  "unsupported-legacy-signature",
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
  "manual",
  "xml",
  "encrypted",
  "encrypted-key",
  "encrypted-response",
  "encrypted-outer-only",
  "encrypted-aes-128-gcm",
  "encrypted-aes-128-cbc",
  "encrypted-aes-256-cbc",
  "encrypted-tampered",
  "encrypted-missing-key",
  "encrypted-wrong-key",
  "encrypted-wrong-pass",
  "encrypted-missing-pass",
]) {
  const signatureDenied = mode === "unsupported-legacy-signature";
  const deprecated = mode.startsWith("encrypted-deprecated-");
  const deprecatedRejected = mode.endsWith("deprecated-data-reject");
  const policyDenied =
    deprecatedRejected ||
    (mode.includes("encrypted-policy-") && !mode.includes("allowed") && !mode.includes("outer"));
  const policyKey = mode.includes("policy-key");
  const outerPolicy = mode.includes("policy-outer");
  const xmlMetadata = mode === "xml";
  const encrypted = mode.startsWith("encrypted");
  const keyFailure = [
    "encrypted-missing-key",
    "encrypted-wrong-key",
    "encrypted-wrong-pass",
    "encrypted-missing-pass",
    "encrypted-tampered",
  ].includes(mode);
  const passwordKey = mode === "encrypted-key" || mode.endsWith("-pass");
  compatScenario(
    `SAML ${mode} ACS redeems signed requests, rejects wrong keys and prevents replay`,
    async (ctx) => {
      const actor = ctx.actor();
      const control = (input: Record<string, unknown>) =>
        actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            mode: mode.startsWith("encrypted-policy-") || deprecated ? mode : "default",
            ...input,
          }),
          redirect: "manual",
        });
      const pairs = (response: Response) =>
        response.headers
          .getSetCookie()
          .filter((raw) => Boolean(Cookie.parse(raw)?.value))
          .map((raw) => raw.split(";")[0])
          .join("; ");
      const owner = await control({
        action: "signup",
        body: {
          email: ctx.uniqueEmail("saml-acs-owner"),
          name: "Native owner",
          password: "password123",
        },
      });
      expect(owner.status).toBe(200);
      const cert = await readFixtureFile(
        new URL("../../../../fixtures/salesforce-transport/leaf.pem", import.meta.url),
        "utf8",
      );
      const providerId = signatureDenied
        ? "unsupported-legacy-signature-provider"
        : mode.startsWith("encrypted-policy-") || deprecated
          ? mode
          : mode === "encrypted-response" ||
              mode === "encrypted-outer-only" ||
              mode.startsWith("encrypted-aes-")
            ? `${mode}-acs-provider`
            : keyFailure
              ? `${mode}-acs-provider`
              : mode === "encrypted-key"
                ? "encrypted-key-acs-provider"
                : encrypted
                  ? "encrypted-acs-provider"
                  : xmlMetadata
                    ? "xml-acs-provider"
                    : "acs-provider";
      const certificate = cert
        .split("\n")
        .filter((line) => !line.startsWith("-----"))
        .join("")
        .trim();
      const metadata = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.example.test/entity"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAuthnRequestsSigned="false"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${certificate}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/from-xml"/></md:IDPSSODescriptor></md:EntityDescriptor>`;
      const created = await control({
        body: {
          providerId,
          issuer: "https://sp.example.test/entity",
          domain: "company.test",
          samlConfig: {
            entryPoint: xmlMetadata
              ? "https://unused.example.test/entrypoint"
              : "https://idp.example.test/sso",
            ...(xmlMetadata ? {} : { cert }),
            ...(encrypted
              ? {
                  spMetadata: {
                    isAssertionEncrypted: true,
                    ...(mode === "encrypted-missing-key"
                      ? {}
                      : {
                          encPrivateKey: await readFixtureFile(
                            new URL(
                              passwordKey
                                ? "../../../../fixtures/salesforce-transport/encrypted-key.pem"
                                : mode === "encrypted-wrong-key"
                                  ? "../../../../fixtures/passkey-attestation/ca-key.pem"
                                  : "../../../../fixtures/salesforce-transport/key.pem",
                              import.meta.url,
                            ),
                            "utf8",
                          ),
                        }),
                    ...(passwordKey && mode !== "encrypted-missing-pass"
                      ? {
                          encPrivateKeyPass:
                            mode === "encrypted-wrong-pass"
                              ? "incorrect-passphrase"
                              : "sso-test-passphrase",
                        }
                      : {}),
                  },
                }
              : {}),
            idpMetadata: xmlMetadata
              ? { entityID: "https://unused.example.test/entity", metadata }
              : {
                  entityID: "https://idp.example.test/entity",
                  ...(encrypted ? { isAssertionEncrypted: true } : {}),
                },
            wantAssertionsSigned: mode !== "encrypted-outer-only",
            callbackUrl: `${ctx.baseURL}/complete`,
          },
        },
        headers: { cookie: pairs(owner) },
      });
      expect(created.status).toBe(200);
      const observations = [];
      for (const [http, wrongKey] of [
        [false, false],
        [true, false],
        [false, true],
        [true, true],
      ]) {
        const email = ctx.uniqueEmail(wrongKey ? "wrong-key-user" : "saml-employee");
        const started = await control({
          action: "sign-in",
          body: {
            providerId,
            providerType: "saml",
            callbackURL: `${ctx.baseURL}/complete`,
            errorCallbackURL: `${ctx.baseURL}/failed`,
          },
        });
        expect(started.status).toBe(200);
        const authorizationURL = new URL(((await started.clone().json()) as any).url);
        expect(authorizationURL.origin).toBe("https://idp.example.test");
        expect(authorizationURL.pathname).toBe(xmlMetadata ? "/from-xml" : "/sso");
        const authorization = ((await started.json()) as any).url;
        let grant = (await (
          await control({
            action: "saml-grant",
            authorization,
            email,
            wrongKey,
            unsupportedSignature: signatureDenied,
          })
        ).json()) as any;
        if (encrypted) {
          grant = encryptSamlGrant(
            grant,
            cert,
            mode === "encrypted-outer-only",
            deprecated
              ? "des-ede3-cbc"
              : mode.startsWith("encrypted-aes-")
                ? mode.slice("encrypted-".length)
                : "aes-256-gcm",
          );
          if (mode === "encrypted-tampered") {
            const xml = Buffer.from(grant.SAMLResponse, "base64").toString();
            const values = [...xml.matchAll(/<xenc:CipherValue>([^<]+)<\/xenc:CipherValue>/g)];
            const content = values.at(-1)!;
            const bytes = Buffer.from(content[1]!, "base64");
            bytes[bytes.length - 1] = bytes[bytes.length - 1]! ^ 1;
            grant.SAMLResponse = Buffer.from(
              xml.replace(
                content[0],
                `<xenc:CipherValue>${bytes.toString("base64")}</xenc:CipherValue>`,
              ),
            ).toString("base64");
          }
          if (mode === "encrypted-response" || mode === "encrypted-outer-only" || outerPolicy) {
            const signed = await control({
              action: "sign-saml-logout",
              xml: Buffer.from(grant.SAMLResponse, "base64").toString(),
              wrongKey,
            });
            expect(signed.status).toBe(200);
            grant.SAMLResponse = ((await signed.json()) as any).SAMLResponse;
          }
        }
        const input = {
          action: http ? "acs-http" : "acs",
          params: { providerId },
          body: { SAMLResponse: grant.SAMLResponse, RelayState: grant.RelayState },
          headers: http ? { origin: "https://idp.example.test", cookie: pairs(owner) } : {},
        };
        const completed = await control(input);
        expect(completed.status, await completed.clone().text()).toBe(302);
        const location = new URL(completed.headers.get("location")!);
        expect(
          await (
            await control({ action: "proof", identifier: `auth-state:${grant.RelayState}` })
          ).json(),
        ).toBe(null);
        const request = await (
          await control({ action: "proof", identifier: `saml-authn-request:${grant.requestId}` })
        ).json();
        const used = (await (
          await control({ action: "proof", identifier: `saml-used-assertion:${grant.assertionId}` })
        ).json()) as any;
        const account = (await (
          await control({ action: "saml-account-row", providerId, accountId: email })
        ).json()) as any;
        if (wrongKey || keyFailure || policyDenied || signatureDenied) {
          expect(location.pathname).toBe("/failed");
          if (deprecatedRejected && !wrongKey) {
            expect(location.searchParams.get("error")).toBe("saml_deprecated_algorithm");
            expect(location.searchParams.get("error_description")).toBe(
              "SAML response uses deprecated data encryption algorithm: http://www.w3.org/2001/04/xmlenc#tripledes-cbc. Please configure your IdP to use AES-GCM.",
            );
          } else if (policyDenied && !wrongKey) {
            expect(location.searchParams.get("error")).toBe("saml_algorithm_not_allowed");
            expect(location.searchParams.get("error_description")).toBe(
              policyKey
                ? "SAML key encryption algorithm not in allow-list: http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
                : "SAML data encryption algorithm not in allow-list: http://www.w3.org/2009/xmlenc11#aes256-gcm",
            );
          } else {
            expect(location.searchParams.get("error")).toBe("saml_error");
            expect(location.searchParams.get("error_description")).toBe("Invalid SAML response");
          }
          expect(request).not.toBe(null);
          expect(used).toBe(null);
          expect(account).toBe(null);
          expect(
            completed.headers
              .getSetCookie()
              .some((cookie) => cookie.startsWith("better-auth.session_token=")),
          ).toBe(false);
          observations.push({ http, wrongKey, error: Object.fromEntries(location.searchParams) });
        } else {
          expect(location.toString()).toBe(`${ctx.baseURL}/complete`);
          const session = (await (
            await control({ action: "session", headers: { cookie: pairs(completed) } })
          ).json()) as any;
          expect(session.user.email).toBe(email);
          expect(session.user.name).toBe("SSO employee");
          expect(session.user.emailVerified).toBe(false);
          expect(account.userId).toBe(session.user.id);
          expect(account.accessToken).toBe("");
          expect(account.refreshToken).toBe("");
          expect(request).toBe(null);
          expect(used).not.toBe(null);
          const proof = JSON.parse(used.value);
          expect(proof.assertionId).toBe(grant.assertionId);
          expect(proof.issuer).toBe("https://idp.example.test/entity");
          expect(proof.providerId).toBe(providerId);
          const replay = await control(input);
          expect(replay.status).toBe(302);
          const rejected = new URL(replay.headers.get("location")!);
          expect(rejected.searchParams.get("error")).toBe("invalid_saml_response");
          expect(rejected.searchParams.get("error_description")).toBe(
            "Unknown or expired request ID",
          );
          observations.push({
            wrongKey,
            session,
            account,
            replay: Object.fromEntries(rejected.searchParams),
          });
        }
      }
      const rejected = await control({
        action: "sign-out-http",
        headers: { origin: "https://idp.example.test", cookie: pairs(owner) },
      });
      expect(rejected.status).toBe(403);
      const ownerSession = (await (
        await control({ action: "session", headers: { cookie: pairs(owner) } })
      ).json()) as any;
      expect(ownerSession.user.email).toBe(((await owner.clone().json()) as any).user.email);
      if (xmlMetadata) {
        const row = (await (await control({ action: "row", providerId })).json()) as any;
        const stored = JSON.parse(row.samlConfig);
        expect(stored.idpMetadata.entityID).toBe("https://unused.example.test/entity");
        expect(stored.entryPoint).toBe("https://unused.example.test/entrypoint");
        expect(stored.idpMetadata.metadata).toBe(metadata);
        for (const changed of [
          metadata.replace(
            "https://idp.example.test/entity",
            "https://other-idp.example.test/entity",
          ),
          metadata.replace(
            "https://idp.example.test/from-xml",
            "https://other-idp.example.test/sso",
          ),
        ]) {
          const rejected = await control({
            action: "update",
            headers: { cookie: pairs(owner) },
            body: { providerId, samlConfig: { idpMetadata: { metadata: changed } } },
          });
          expect(rejected.status).toBe(409);
          expect(await (await control({ action: "row", providerId })).json()).toEqual(row);
        }
      }
      return observations;
    },
  );
}
