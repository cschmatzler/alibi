import { createDecipheriv, createHash, createHmac, hkdfSync, timingSafeEqual } from "node:crypto";

import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";

import type { RequestWindow } from "./trace";

export type ManagedAccountCookieProfile = {
  readonly credentialVersion: number;
  readonly secret: string;
  readonly credentialSecret?: string;
  /** Renewal changes the JWE key while retaining an independently observed row. */
  readonly renewal?: boolean;
  readonly accessToken: string;
  readonly refreshToken: string;
};
const record = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);
function equal(a: unknown, b: unknown): boolean {
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((child, index) => equal(child, b[index]));
  }
  if (record(a) && record(b)) {
    return (
      Object.keys(a).length === Object.keys(b).length &&
      Object.keys(a).every((key) => Object.hasOwn(b, key) && equal(a[key], b[key]))
    );
  }
  return Object.is(a, b);
}

/** Bind the two snapshots to the actual callback issuance and subsequent physical read. */
export function managedAccountCookieReceipt(
  value: {
    token: unknown;
    authPath: unknown;
    payload: Record<string, unknown>;
    account: Record<string, unknown>;
  },
  windows: readonly (RequestWindow | undefined)[] | undefined,
  profile: ManagedAccountCookieProfile | undefined,
): boolean {
  const issued = windows?.find((window) => {
    try {
      return (
        window?.issuedAccountCookie !== undefined &&
        decodeURIComponent(window.issuedAccountCookie) === value.token
      );
    } catch {
      return false;
    }
  });
  if (!issued) return false;
  const read = windows?.find((window) => {
    const control = window?.controlObservation;
    return (
      window &&
      window.startedAt >= issued.finishedAt &&
      control?.kind === "managed-secrets" &&
      record(control.body) &&
      control.digest === createHash("sha256").update(JSON.stringify(control.body)).digest("hex") &&
      Array.isArray(control.body.accounts) &&
      control.body.accounts.some((account) => equal(account, value.account))
    );
  });
  if (!read) return false;
  const instant = (value: unknown) =>
    typeof value === "string" &&
    /^\d{4}-\d\d-\d\dT/.test(value) &&
    Number.isFinite(Date.parse(value))
      ? Date.parse(value)
      : NaN;
  const snapshot = instant(value.payload.updatedAt);
  const physical = instant(value.account.updatedAt);
  const created = instant(value.payload.createdAt);
  const writeWindow = profile?.renewal
    ? windows?.find((earlier) => {
        if (!earlier?.issuedAccountCookie || earlier.finishedAt > issued.startedAt) return false;
        return windows?.some((observer) => {
          const control = observer?.controlObservation;
          return (
            observer &&
            observer.startedAt >= earlier.finishedAt &&
            observer.finishedAt <= issued.startedAt &&
            control?.kind === "managed-secrets" &&
            record(control.body) &&
            control.digest ===
              createHash("sha256").update(JSON.stringify(control.body)).digest("hex") &&
            Array.isArray(control.body.accounts) &&
            control.body.accounts.some((account) => equal(account, value.account)) &&
            physical >= earlier.startedAt &&
            physical <= observer.finishedAt
          );
        });
      })
    : issued;
  return (
    !!writeWindow &&
    Number.isFinite(snapshot) &&
    Number.isFinite(physical) &&
    Number.isFinite(created) &&
    created <= snapshot &&
    snapshot <= physical &&
    snapshot <= issued.finishedAt &&
    physical >= writeWindow.startedAt &&
    physical <= read.finishedAt
  );
}

/** Authenticate the actual issued JWE, encrypted token plaintext and unchanged physical account relationship. */
export function authenticatedManagedAccountCookie(
  value: unknown,
  profiles: Readonly<Record<string, ManagedAccountCookieProfile>> | undefined,
): value is Record<string, unknown> & {
  token: string;
  authPath: string;
  payload: Record<string, unknown>;
  account: Record<string, unknown>;
} {
  if (
    !record(value) ||
    typeof value.authPath !== "string" ||
    typeof value.token !== "string" ||
    !record(value.header) ||
    !record(value.payload) ||
    !record(value.account)
  ) {
    return false;
  }
  const profile = profiles?.[value.authPath];
  if (!profile) return false;
  const parts = value.token.split(".");
  if (parts.length !== 5 || parts[1] !== "") return false;
  try {
    const header = JSON.parse(Buffer.from(parts[0]!, "base64url").toString());
    const key = Buffer.from(
      hkdfSync(
        "sha256",
        profile.secret,
        "better-auth-account",
        "BetterAuth.js Generated Encryption Key",
        64,
      ),
    );
    const kid = createHash("sha256")
      .update(JSON.stringify({ k: key.toString("base64url"), kty: "oct" }))
      .digest("base64url");
    if (
      header.alg !== "dir" ||
      header.enc !== "A256CBC-HS512" ||
      header.kid !== kid ||
      !equal(header, value.header)
    ) {
      return false;
    }
    const iv = Buffer.from(parts[2]!, "base64url");
    const ciphertext = Buffer.from(parts[3]!, "base64url");
    const tag = Buffer.from(parts[4]!, "base64url");
    const al = Buffer.alloc(8);
    al.writeBigUInt64BE(BigInt(Buffer.byteLength(parts[0]!) * 8));
    const expected = createHmac("sha512", key.subarray(0, 32))
      .update(parts[0]!)
      .update(iv)
      .update(ciphertext)
      .update(al)
      .digest()
      .subarray(0, 32);
    if (tag.length !== expected.length || !timingSafeEqual(tag, expected)) return false;
    const decoder = createDecipheriv("aes-256-cbc", key.subarray(32), iv);
    const payload = JSON.parse(
      Buffer.concat([decoder.update(ciphertext), decoder.final()]).toString(),
    );
    if (!equal(payload, value.payload)) return false;
    // The account is the real physical row independently observed after this
    // OAuth issuance. Random ciphertext is admitted only for its exact fields.
    // Source issues the pre-update account snapshot while its adapter advances
    // updatedAt; every ownership and credential field must still match exactly.
    for (const field of Object.keys(value.account).filter((field) => field !== "updatedAt")) {
      const row = value.account[field];
      const claim = payload[field];
      if (equal(row, claim)) continue;
      if (
        ["createdAt", "accessTokenExpiresAt", "refreshTokenExpiresAt"].includes(field) &&
        typeof row === "string" &&
        typeof claim === "string" &&
        Number.isFinite(Date.parse(row)) &&
        Date.parse(row) === Date.parse(claim)
      ) {
        continue;
      }
      return false;
    }
    for (const field of ["accessToken", "refreshToken"] as const) {
      const data = payload[field];
      if (typeof data !== "string") return false;
      const prefix = `$ba$${profile.credentialVersion}$`;
      if (!data.startsWith(prefix) || !/^[0-9a-f]+$/.test(data.slice(prefix.length))) return false;
      const bytes = Buffer.from(data.slice(prefix.length), "hex");
      if (bytes.length < 40) return false;
      const plain = xchacha20poly1305(
        createHash("sha256")
          .update(profile.credentialSecret ?? profile.secret)
          .digest(),
        bytes.subarray(0, 24),
      ).decrypt(bytes.subarray(24));
      if (new TextDecoder("utf-8", { fatal: true }).decode(plain) !== profile[field]) return false;
    }
    return true;
  } catch {
    return false;
  }
}
