import { inflateRawSync } from "node:zlib";

import { XMLParser, XMLValidator } from "fast-xml-parser";
/** Decode a published logout request; preserve every protocol field except runtime ID/time aliases. */
export function samlLogoutProjection(encoded: string) {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) throw new Error("invalid SAML base64");
  const bytes = Buffer.from(encoded, "base64");
  if (bytes.toString("base64") !== encoded) throw new Error("noncanonical SAML base64");
  const xml = inflateRawSync(bytes, { maxOutputLength: 262144 }).toString("utf8");
  if (XMLValidator.validate(xml) !== true) throw new Error("invalid SAML XML");
  const parsed = new XMLParser({ ignoreAttributes: false, parseAttributeValue: false }).parse(xml);
  const root = parsed["samlp:LogoutRequest"];
  if (
    !root ||
    root["@_xmlns:samlp"] !== "urn:oasis:names:tc:SAML:2.0:protocol" ||
    root["@_xmlns:saml"] !== "urn:oasis:names:tc:SAML:2.0:assertion"
  ) {
    throw new Error("not a SAML logout request");
  }
  const id = root["@_ID"];
  const issuedAt = root["@_IssueInstant"];
  if (
    typeof id !== "string" ||
    !/^_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id) ||
    typeof issuedAt !== "string" ||
    !Number.isFinite(Date.parse(issuedAt))
  ) {
    throw new Error("invalid SAML request identity or clock");
  }
  const document = { ...root };
  delete document["@_ID"];
  delete document["@_IssueInstant"];
  return { id, issuedAt, document };
}
