import { createHmac } from "node:crypto";

import { safeJSONParse } from "@better-auth/core/utils/json";
/** Original-byte envelopes measured with the published 1.7.6 decoder. */
import { getCookieCache } from "better-auth/cookies";
const secret = "compat-test-only-key-not-real-minimum-32chars";
const expiresAt = 4070908800000;
const payload = {
  session: {
    id: "exotic-session",
    token: "00010000000000000000000000000001",
    userId: "exotic-owner",
    createdAt: "2026-10-01T00:00:00.000Z",
    updatedAt: "2026-10-01T00:00:00.000Z",
    expiresAt: "2099-01-01T00:00:00.000Z",
    label: "cache-public-label",
  },
  user: {
    id: "exotic-owner",
    email: "EXOTIC@EXAMPLE.TEST",
    name: "Signed Exotic Owner",
    emailVerified: false,
    createdAt: "2026-10-01T00:00:00.000Z",
    updatedAt: "2026-10-01T00:00:00.000Z",
  },
  updatedAt: 1790812800000,
  version: "1",
};
type Case = {
  name: string;
  edit?: (p: any) => void;
  bytes?: (b: Buffer) => Buffer;
  outer?: number;
  originalSignature?: boolean;
  token?: (s: string) => string;
};
const cases: Case[] = [
  { name: "canonical" },
  { name: "expanded-year", edit: (p) => (p.session.expiresAt = "+010000-01-01T00:00:00.000Z") },
  {
    name: "revived-year-rollover",
    edit: (p) => (p.session.expiresAt = "9999-12-31T24:00:00.000Z"),
  },
  { name: "legacy-date", edit: (p) => (p.session.expiresAt = "Jan 1 2099 GMT") },
  { name: "invalid-date", edit: (p) => (p.session.expiresAt = "2099-13-01T00:00:00.000Z") },
  { name: "day-overflow", edit: (p) => (p.session.expiresAt = "2099-02-31T00:00:00.000Z") },
  { name: "midnight-overflow", edit: (p) => (p.session.expiresAt = "2099-01-01T24:00:00.000Z") },
  {
    name: "fraction-truncation",
    edit: (p) => (p.session.expiresAt = "2099-01-01T00:00:00.123456789Z"),
  },
  {
    name: "original-date-signature",
    edit: (p) => (p.session.expiresAt = "2099-02-31T00:00:00.000Z"),
    originalSignature: true,
  },
  { name: "date-name", edit: (p) => (p.user.name = "2026-10-01T00:00:00.000Z") },
  { name: "date-version", edit: (p) => (p.version = "2026-10-01T00:00:00.000Z") },
  { name: "version-mismatch", edit: (p) => (p.version = "2") },
  { name: "empty-version", edit: (p) => (p.version = "") },
  { name: "outer-expired", outer: 1 },
  { name: "session-expired", edit: (p) => (p.session.expiresAt = "2020-01-01T00:00:00.000Z") },
  { name: "wrong-token", edit: (p) => (p.session.token = "different-signed-token") },
  ...[null, true, 12, [], ["owner", null, 2], {}, { toString: "bad" }].map((value, i) => ({
    name: `user-id-coercion-${i}`,
    edit: (p: any) => (p.session.userId = value),
  })),
  { name: "date-user-id", edit: (p) => (p.session.userId = "2026-10-01T00:00:00.000Z") },
  {
    name: "date-array-user-id",
    edit: (p) => (p.session.userId = ["2026-10-01T00:00:00.000Z", null, 2]),
  },
  { name: "date-rollover-user-id", edit: (p) => (p.session.userId = "9999-12-31T24:00:00.000Z") },
  {
    name: "expanded-year-user-id",
    edit: (p) => (p.session.userId = "+010000-01-01T00:00:00.000Z"),
  },
  { name: "legacy-user-id", edit: (p) => (p.session.userId = "Jan 1 2099 GMT") },
  {
    name: "prototype-plain-user-id",
    edit: (p) => (p.session.userId = JSON.parse('{"__proto__":{"sentinel":"plain"}}')),
  },
  {
    name: "prototype-primitive-user-id",
    edit: (p) => (p.session.userId = JSON.parse('{"__proto__":12}')),
  },
  {
    name: "prototype-null-user-id",
    edit: (p) => (p.session.userId = JSON.parse('{"__proto__":null}')),
  },
  {
    name: "prototype-noncallable-user-id",
    edit: (p) => (p.session.userId = JSON.parse('{"__proto__":{"toString":"not-callable"}}')),
  },
  { name: "missing-user-id", edit: (p) => delete p.session.userId },
  { name: "unicode", edit: (p) => (p.user.name = "\ufffd 💡 Straße Ελληνικά") },
  { name: "bom", bytes: (b) => Buffer.concat([Buffer.from([239, 187, 191]), b]) },
  { name: "malformed-utf8", edit: (p) => (p.user.name = "\ufffd") },
  {
    name: "prototype-key",
    edit: (p) =>
      (p.user.extra = JSON.parse(
        '{"__proto__":{"sentinel":"retained-before-revival"},"visible":true}',
      )),
  },
  { name: "padding-tail", token: (s) => s + "=ignored-after-padding" },
  {
    name: "base64-nonzero-residual-bits",
    token: (s) => {
      const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
      // This original envelope ends with two unused bits. Change one unused
      // bit while retaining every decoded byte and the original signed JSON.
      if (s.length % 4 !== 3) throw new Error("Unexpected original envelope length");
      return s.slice(0, -1) + alphabet[alphabet.indexOf(s.at(-1)!) ^ 1];
    },
  },
  { name: "base64-residual-bits", token: (s) => s + "A" },
  {
    name: "tampered",
    bytes: (b) => Buffer.from(b.toString().replace("Signed Exotic Owner", "Unsigned Evil Owner")),
  },
];
// TextDecoder replaces an isolated invalid byte with U+FFFD. Sign the resulting
// revived JSON first, then retain the genuinely malformed original envelope.
cases.find((c) => c.name === "malformed-utf8")!.bytes = (b) => {
  const marker = Buffer.from("\ufffd");
  const offset = b.indexOf(marker);
  return Buffer.concat([
    b.subarray(0, offset),
    Buffer.from([255]),
    b.subarray(offset + marker.length),
  ]);
};
const observations = [];
for (const c of cases) {
  const original = structuredClone(payload);
  c.edit?.(original);
  const expiry = c.outer ?? expiresAt;
  const signed = c.originalSignature ? original : safeJSONParse(JSON.stringify(original));
  const signature = createHmac("sha256", secret)
    .update(JSON.stringify({ ...signed, expiresAt: expiry }))
    .digest("base64url");
  const envelope = { session: original, expiresAt: expiry, signature };
  let bytes = Buffer.from(JSON.stringify(envelope));
  if (c.bytes) bytes = c.bytes(bytes);
  let token = bytes.toString("base64url");
  if (c.token) token = c.token(token);
  const header = "better-auth.session_data=" + token;
  const calls: unknown[] = [];
  const decoded = await getCookieCache(new Headers({ cookie: header }), {
    secret,
    isSecure: false,
    strategy: "compact",
    version: (session, user) => {
      calls.push({ session, user });
      return "1";
    },
  });
  observations.push({
    name: c.name,
    token,
    originalBytesHex: Buffer.from(token, "base64url").toString("hex"),
    envelope,
    header,
    decoded,
    versionCalls: calls,
  });
}
// These values are accepted by JavaScript's runtime but have no equivalent
// Rust UTF-8 String or prototype-bearing object. Preserve them as original
// JSON text, not fabricated native Undefined/Date/prototype model variants.
const javascriptOnlyObservations = [];
for (const [name, representation, edit] of [
  ["lone-high-surrogate", "ill-formed UTF-16 string", (p: any) => (p.user.name = "\ud800")],
  ["lone-low-surrogate", "ill-formed UTF-16 string", (p: any) => (p.user.name = "\udfff")],
  [
    "prototype-array-user-id",
    "inherited Array.prototype.toString on an ordinary object",
    (p: any) => (p.session.userId = JSON.parse('{"__proto__":["alpha","beta"]}')),
  ],
] as const) {
  const original = structuredClone(payload);
  edit(original);
  const signature = createHmac("sha256", secret)
    .update(JSON.stringify({ ...safeJSONParse(JSON.stringify(original)), expiresAt }))
    .digest("base64url");
  const envelopeJSON = JSON.stringify({ session: original, expiresAt, signature });
  const token = Buffer.from(envelopeJSON).toString("base64url");
  const header = "better-auth.session_data=" + token;
  const decoded = await getCookieCache(new Headers({ cookie: header }), {
    secret,
    isSecure: false,
  });
  if (!decoded) throw new Error(`Source no longer accepts ${name}`);
  javascriptOnlyObservations.push({
    name,
    representation,
    token,
    originalBytesHex: Buffer.from(envelopeJSON).toString("hex"),
    envelopeJSON,
    header,
    decodedJSON: JSON.stringify(decoded),
  });
}

await Bun.write(
  new URL("../../../fixtures/session/compact-exotic-inputs.json", import.meta.url),
  JSON.stringify({ upstreamVersion: "1.7.6", observations, javascriptOnlyObservations }, null, 2) +
    "\n",
);
console.log(
  observations.map((c) => ({
    name: c.name,
    accepted: c.decoded !== null,
    versionCalls: c.versionCalls.length,
  })),
);
