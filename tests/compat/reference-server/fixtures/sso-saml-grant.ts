import { randomUUID, sign as signBytes } from "node:crypto";
import { inflateRawSync } from "node:zlib";

import { XMLParser } from "fast-xml-parser";
import { SignedXml } from "xml-crypto";
export async function samlGrant(
  authorization: string,
  email: string,
  wrongKey: boolean,
  verified?: string[],
  unsolicited = false,
  unsupportedSignature = false,
) {
  const url = new URL(authorization);
  const request = new XMLParser({ ignoreAttributes: false, removeNSPrefix: true }).parse(
    inflateRawSync(Buffer.from(url.searchParams.get("SAMLRequest")!, "base64")).toString(),
  ).AuthnRequest;
  const requestId = request["@_ID"];
  const recipient = request["@_AssertionConsumerServiceURL"];
  const issuer = request.Issuer;
  const assertionId = `_${randomUUID()}`;
  const responseId = `_${randomUUID()}`;
  const now = Date.now();
  const instant = new Date(now).toISOString();
  const before = new Date(now - 60000).toISOString();
  const expires = new Date(now + 300000).toISOString();
  const esc = (value: string) =>
    value
      .replaceAll("&", "&amp;")
      .replaceAll('"', "&quot;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;");
  const verification =
    verified === undefined
      ? ""
      : `<saml:Attribute Name="verified-mailbox">${verified.map((value) => `<saml:AttributeValue>${esc(value)}</saml:AttributeValue>`).join("")}</saml:Attribute>`;
  let xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${responseId}" Version="2.0" IssueInstant="${instant}" Destination="${esc(recipient)}" InResponseTo="${esc(requestId)}"><saml:Issuer>https://idp.example.test/entity</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="${assertionId}" Version="2.0" IssueInstant="${instant}"><saml:Issuer>https://idp.example.test/entity</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${esc(email)}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="${esc(requestId)}" Recipient="${esc(recipient)}" NotOnOrAfter="${expires}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="${before}" NotOnOrAfter="${expires}"><saml:AudienceRestriction><saml:Audience>${esc(issuer)}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="${instant}" SessionIndex="session-index"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>${esc(email)}</saml:AttributeValue></saml:Attribute><saml:Attribute Name="displayName"><saml:AttributeValue>SSO employee</saml:AttributeValue></saml:Attribute>${verification}</saml:AttributeStatement></saml:Assertion></samlp:Response>`;
  if (unsolicited) xml = xml.replaceAll(` InResponseTo="${esc(requestId)}"`, "");
  const signer = await samlSigner(wrongKey, unsupportedSignature);
  signer.addReference({
    xpath: "//*[local-name()='Assertion']",
    transforms: [
      "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
      "http://www.w3.org/2001/10/xml-exc-c14n#",
    ],
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
  });
  signer.computeSignature(xml, {
    prefix: "ds",
    location: {
      reference: "//*[local-name()='Assertion']/*[local-name()='Issuer']",
      action: "after",
    },
  });
  return {
    SAMLResponse: Buffer.from(signer.getSignedXml()).toString("base64"),
    RelayState: url.searchParams.get("RelayState"),
    assertionId: assertionId,
    requestId: requestId,
  };
}

async function samlSigner(wrongKey: boolean, unsupportedSignature = false) {
  const privateKey = await Bun.file(
    new URL(
      wrongKey
        ? "../../../fixtures/one-tap/wrong-private-key.pem"
        : "../../fixtures/salesforce-transport/key.pem",
      import.meta.url,
    ),
  ).text();
  const cert = await Bun.file(
    new URL("../../fixtures/salesforce-transport/leaf.pem", import.meta.url),
  ).text();
  const signer = new SignedXml({
    privateKey,
    publicCert: cert,
    signatureAlgorithm: unsupportedSignature
      ? "http://www.w3.org/2001/04/xmldsig-more#rsa-md5"
      : "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
  });
  if (unsupportedSignature) {
    (signer.SignatureAlgorithms as any)["http://www.w3.org/2001/04/xmldsig-more#rsa-md5"] = class {
      getAlgorithmName() {
        return "http://www.w3.org/2001/04/xmldsig-more#rsa-md5";
      }
      getSignature(signedInfo: string, key: any) {
        return signBytes("RSA-MD5", Buffer.from(signedInfo), key).toString("base64");
      }
    };
  }
  return signer;
}

export async function signedLogout(xml: string, wrongKey: boolean) {
  const signer = await samlSigner(wrongKey);
  signer.addReference({
    xpath:
      "/*[local-name()='LogoutResponse' or local-name()='LogoutRequest' or local-name()='Response']",
    transforms: [
      "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
      "http://www.w3.org/2001/10/xml-exc-c14n#",
    ],
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
  });
  signer.computeSignature(xml, {
    prefix: "ds",
    location: { reference: "/*/*[local-name()='Issuer']", action: "after" },
  });
  return Buffer.from(signer.getSignedXml()).toString("base64");
}
