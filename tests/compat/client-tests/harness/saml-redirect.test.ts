import { deflateRawSync } from "node:zlib";

import { expect, test } from "vitest";

import { compareValues } from "../support/compare";
const context = {
  leftBaseURL: "http://localhost:3100",
  rightBaseURL: "http://localhost:3200",
  leftStartedAt: 0,
  rightStartedAt: 0,
};
const published = (
  id: string,
  destination = "https://idp.example.test/logout",
  index = "session-index",
) => ({
  location: `https://idp.example.test/logout?SAMLRequest=${encodeURIComponent(deflateRawSync(Buffer.from(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${id}" Version="2.0" IssueInstant="2026-10-13T23:00:00.000Z" Destination="${destination}"><saml:Issuer>https://sp.example.test/entity</saml:Issuer><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">employee@example.test</saml:NameID><samlp:SessionIndex>${index}</samlp:SessionIndex></samlp:LogoutRequest>`)).toString("base64"))}`,
});
test("SAML redirect comparison keeps destination/session binding while aliasing generated IDs", () => {
  const left = published("_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
  expect(compareValues(left, published("_bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"), context)).toEqual(
    [],
  );
  expect(
    compareValues(
      left,
      published("_bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "https://attacker.example/logout"),
      context,
    ),
  ).not.toEqual([]);
  expect(
    compareValues(
      left,
      published("_bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", undefined, "another-session"),
      context,
    ),
  ).not.toEqual([]);
  expect(
    compareValues(
      left,
      { location: "https://idp.example.test/logout?SAMLRequest=invalid" },
      context,
    ),
  ).not.toEqual([]);
});
