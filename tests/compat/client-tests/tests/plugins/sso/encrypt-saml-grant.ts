import {
  constants,
  createCipheriv,
  publicEncrypt,
  randomBytes,
  X509Certificate,
} from "node:crypto";
/** Standards-based IdP envelope; used against both live servers. */
export function encryptSamlGrant(
  grant: Record<string, any>,
  certificate: string,
  unsignedAssertion = false,
) {
  const xml = Buffer.from(grant.SAMLResponse, "base64").toString();
  const start = xml.indexOf("<saml:Assertion ");
  const end = xml.indexOf("</saml:Assertion>", start) + "</saml:Assertion>".length;
  if (start < 0 || end <= start) {
    throw new Error("Signed assertion missing");
  }
  let assertion = xml.slice(start, end);
  if (!assertion.split(">")[0]!.includes("xmlns:saml=")) {
    assertion = assertion.replace(
      "<saml:Assertion ",
      '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ',
    );
  }
  if (unsignedAssertion) {
    assertion = assertion.replace(/<ds:Signature\b[^>]*>[\s\S]*?<\/ds:Signature>/, "");
  }
  const secret = randomBytes(32);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", secret, iv);
  const ciphertext = Buffer.concat([
    iv,
    cipher.update(assertion, "utf8"),
    cipher.final(),
    cipher.getAuthTag(),
  ]);
  const wrapped = publicEncrypt(
    {
      key: new X509Certificate(certificate).publicKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha1",
    },
    secret,
  );
  const envelope = `<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/><xenc:CipherData><xenc:CipherValue>${wrapped.toString("base64")}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>${ciphertext.toString("base64")}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion>`;
  return {
    ...grant,
    SAMLResponse: Buffer.from(xml.slice(0, start) + envelope + xml.slice(end)).toString("base64"),
  };
}
