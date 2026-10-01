export function decodeBase32(secret: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const normalized = secret.toUpperCase().replace(/=+$/g, "");
  let bits = 0;
  let value = 0;
  const output: number[] = [];

  for (const char of normalized) {
    const idx = alphabet.indexOf(char);
    if (idx === -1) {
      continue;
    }
    value = (value << 5) | idx;
    bits += 5;
    while (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return new Uint8Array(output);
}

export async function generateCurrentTotp(totpURI: string) {
  const url = new URL(totpURI);
  const secret = url.searchParams.get("secret");
  if (!secret) {
    throw new Error("TOTP URI is missing the secret");
  }

  const digits = Number(url.searchParams.get("digits") ?? "6");
  const period = Number(url.searchParams.get("period") ?? "30");
  return hotpAtCounter(decodeBase32(secret), digits, Math.floor(Date.now() / 1000 / period));
}

export async function hotpAtCounter(secret: Uint8Array<ArrayBuffer>, digits: number, counter: number) {
  const counterBytes = new Uint8Array(8);
  const view = new DataView(counterBytes.buffer);
  view.setUint32(4, counter);

  const key = await crypto.subtle.importKey(
    "raw",
    secret,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const digest = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, counterBytes),
  );
  const offset = digest[digest.length - 1]! & 0x0f;
  const binary = ((digest[offset]! & 0x7f) << 24)
    | (digest[offset + 1]! << 16)
    | (digest[offset + 2]! << 8)
    | digest[offset + 3]!;

  return String(binary % 10 ** digits).padStart(digits, "0");
}

export function redactTwoFactorPayload<T>(value: T): T {
  if (!value || typeof value !== "object") {
    return value;
  }

  const clone = structuredClone(value as object) as Record<string, unknown>;
  if (
    clone.data &&
    typeof clone.data === "object" &&
    !Array.isArray(clone.data)
  ) {
    const data = clone.data as Record<string, unknown>;
    if (typeof data.totpURI === "string") {
      data.totpURI = "<totpURI>";
    }
    if (Array.isArray(data.backupCodes)) {
      data.backupCodes = data.backupCodes.map(() => "<backup-code>");
    }
  }
  return clone as T;
}

