// Fixture-signed ID tokens. The public half of the key is served as the
// one-tap fixture JWKS, so OAuth providers that verify ID tokens share it.
import { sign } from "node:crypto";

import { CompactSign, importPKCS8 } from "jose";

export const issuedAt = Math.floor(Date.now() / 1000);

const privatePem = await Bun.file(
  new URL("../../../fixtures/one-tap/private-key.pem", import.meta.url),
).text();

const privateKey = await importPKCS8(privatePem, "RS256");

const wrongKey = await importPKCS8(
  await Bun.file(
    new URL("../../../fixtures/one-tap/wrong-private-key.pem", import.meta.url),
  ).text(),
  "RS256",
);

export async function credential(
  claims: Record<string, unknown>,
  header: Record<string, unknown> = {},
  wrong = false,
  raw?: string,
) {
  const payload = {
    iss: "https://accounts.google.com",
    aud: "one-tap-plugin-client",
    iat: issuedAt,
    exp: issuedAt + 3600,
    ...claims,
  };
  return new CompactSign(new TextEncoder().encode(raw ?? JSON.stringify(payload)))
    .setProtectedHeader({ alg: "RS256", kid: "one-tap-local-rs256", ...header })
    .sign(wrong ? wrongKey : privateKey, { crit: { unknown: true } });
}

export function signedRawToken(
  claims: Record<string, unknown>,
  header: Record<string, unknown>,
  algorithm = "RSA-SHA256",
) {
  const encoded = [
    header,
    {
      iss: "https://accounts.google.com",
      aud: "one-tap-plugin-client",
      iat: issuedAt,
      exp: issuedAt + 3600,
      ...claims,
    },
  ]
    .map((value) => Buffer.from(JSON.stringify(value)).toString("base64url"))
    .join(".");
  return encoded + "." + sign(algorithm, Buffer.from(encoded), privatePem).toString("base64url");
}
