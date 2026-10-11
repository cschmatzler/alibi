import { expect } from "bun:test";

const dispatchSecret = "compat-test-only-key-not-real-minimum-32chars";

export async function cacheReceipt(headers: Headers) {
  const { createHmac } = await import("node:crypto");
  const { getCookieCache } = await import("better-auth/cookies");
  const rawCookies = headers
    .getSetCookie()
    .filter((raw) => raw.startsWith("better-auth.session_data="));
  expect(rawCookies).toHaveLength(1);

  const token = decodeURIComponent(
    rawCookies[0]!.split(";")[0]!.slice("better-auth.session_data=".length),
  );
  const envelope = JSON.parse(Buffer.from(token, "base64url").toString());
  const observedAt = Date.now();
  expect(envelope.signature).toBe(
    createHmac("sha256", dispatchSecret)
      .update(JSON.stringify({ ...envelope.session, expiresAt: envelope.expiresAt }))
      .digest("base64url"),
  );

  const decoded = await getCookieCache(new Headers({ cookie: rawCookies[0]!.split(";")[0]! }), {
    secret: dispatchSecret,
    strategy: "compact",
    isSecure: false,
  });
  expect(decoded).not.toBeNull();

  return {
    compactSessionCache: {
      token,
      envelope,
      decoded,
      observedAt,
      effectiveMaxAgeSeconds: 300,
      rawCookies,
    },
  };
}
