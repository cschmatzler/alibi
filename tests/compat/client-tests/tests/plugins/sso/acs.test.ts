import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
import { encryptSamlGrant } from "./encrypt-saml-grant";
for (const mode of ["manual", "xml", "encrypted", "encrypted-key"]) {
  const xmlMetadata = mode === "xml";
  const encrypted = mode.startsWith("encrypted");
  compatScenario(
    `SAML ${mode} ACS redeems signed requests, rejects wrong keys and prevents replay`,
    async (ctx) => {
      const actor = ctx.actor();
      const control = (input: Record<string, unknown>) =>
        actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(input),
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
      const cert = await Bun.file(
        new URL("../../../../fixtures/salesforce-transport/leaf.pem", import.meta.url),
      ).text();
      const providerId =
        mode === "encrypted-key"
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
                    encPrivateKey: await Bun.file(
                      new URL(
                        mode === "encrypted-key"
                          ? "../../../../fixtures/salesforce-transport/encrypted-key.pem"
                          : "../../../../fixtures/salesforce-transport/key.pem",
                        import.meta.url,
                      ),
                    ).text(),
                    ...(mode === "encrypted-key"
                      ? { encPrivateKeyPass: "sso-test-passphrase" }
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
            wantAssertionsSigned: true,
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
          await control({ action: "saml-grant", authorization, email, wrongKey })
        ).json()) as any;
        if (encrypted) {
          grant = encryptSamlGrant(grant, cert);
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
        if (wrongKey) {
          expect(location.pathname).toBe("/failed");
          expect(location.searchParams.get("error")).toBe("saml_error");
          expect(location.searchParams.get("error_description")).toBe("Invalid SAML response");
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
