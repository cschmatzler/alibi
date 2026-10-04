import { hkdfSync } from "node:crypto";

// Independent byte-level reproduction of the published 1.7.7 key derivation.
export function oauthPurposeSecret(
  secret: string,
  purpose:
    | "oauth-state-cookie"
    | "oauth-proxy-state"
    | "oauth-proxy-package"
    | "oauth-proxy-profile",
): string {
  return Buffer.from(
    hkdfSync("sha256", secret, "better-auth:oauth-encryption:v1", `better-auth:${purpose}:v1`, 32),
  ).toString("hex");
}
