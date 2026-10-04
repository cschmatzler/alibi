import type { Database } from "bun:sqlite";

import { type BetterAuthOptions, betterAuth } from "better-auth";

/** Actual configured producers; every header comes from installed auth routes. */
export function physicalCookieProfiles(base: BetterAuthOptions, database: Database) {
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  for (const mode of [
    "serializer-valid",
    "serializer-host",
    "serializer-age-boundary",
    "serializer-age-limit",
    "serializer-expiry-limit",
    "cross-localhost",
    "cross-ipv6",
    "cross-inferred",
    "cross-proxy",
    "default",
    "attributes",
    "secure",
    "none",
    "short",
    "legacy",
    "legacy-alias",
    "secure-prefix",
    "https-default",
    "https-disabled",
    "secure-custom",
    "secure-alias",
    "dynamic-https",
    "dynamic-http",
    "dynamic-auto",
  ] as const) {
    const path = `/__test/profiles/physical-cookie-${mode}/api/auth`;
    const attributes =
      mode === "attributes"
        ? { httpOnly: false, sameSite: "strict" as const, path, domain: "localhost" }
        : mode === "secure"
          ? { secure: true }
          : mode === "none"
            ? { sameSite: "none" as const, secure: false }
            : {};
    profiles.set(
      path,
      betterAuth({
        ...base,
        ...(mode.startsWith("cross-")
          ? {
              baseURL:
                mode === "cross-proxy"
                  ? {
                      allowedHosts: ["cookie177.test:*", "auth.cookie177.test:*"],
                      protocol: "https" as const,
                    }
                  : mode === "cross-ipv6"
                    ? "https://[::1]:4377"
                    : mode === "cross-localhost"
                      ? "https://localhost:4377"
                      : "https://cookie177.test",
            }
          : {}),
        basePath: path,
        ...(mode.startsWith("https-") ? { baseURL: "https://localhost" } : {}),
        ...(mode.startsWith("dynamic-")
          ? {
              baseURL: {
                allowedHosts: ["localhost:*", "127.0.0.1:*"],
                protocol:
                  mode === "dynamic-https"
                    ? ("https" as const)
                    : mode === "dynamic-http"
                      ? ("http" as const)
                      : ("auto" as const),
              },
            }
          : {}),
        trustedOrigins: [
          ...((base.trustedOrigins as string[] | undefined) ?? []),
          String(base.baseURL),
          "https://localhost",
          "https://cookie177.test:*",
          "https://auth.cookie177.test:*",
        ],
        plugins: [],
        session: {
          ...base.session,
          expiresIn:
            mode === "serializer-age-boundary"
              ? 34560000
              : mode === "serializer-age-limit"
                ? 34560001
                : mode === "short"
                  ? 60
                  : 604800,
          cookieCache: { enabled: false },
        },
        advanced: {
          ...base.advanced,
          ...(mode.startsWith("cross-")
            ? {
                crossSubDomainCookies: { enabled: true },
                trustedProxyHeaders: true,
              }
            : {}),
          ...(mode.startsWith("cross-") || mode === "https-default" || mode.startsWith("dynamic-")
            ? {}
            : {
                useSecureCookies:
                  mode === "secure-prefix" || mode === "secure-custom" || mode === "secure-alias",
              }),
          defaultCookieAttributes: attributes,
          ...(mode.startsWith("serializer-")
            ? {
                useSecureCookies: false,
                defaultCookieAttributes: {
                  path,
                  domain: "localhost",
                  httpOnly: false,
                  sameSite: "strict",
                  expires: new Date("2027-01-01T00:00:00Z"),
                  partitioned: false,
                },
                cookies: {
                  session_token: {
                    ...(mode === "serializer-host" ? { name: "__Host-policy" } : {}),
                    attributes: {
                      secure: true,
                      partitioned: true,
                      httpOnly: true,
                      ...(mode === "serializer-expiry-limit"
                        ? { expires: new Date(Date.now() + 401 * 86400000) }
                        : {}),
                    },
                  },
                  dont_remember: { attributes: { maxAge: 121.9 } },
                },
              }
            : {}),
          ...(mode === "secure-alias"
            ? {
                cookies: { session_token: { name: "alias.session_token" } },
              }
            : {}),
          ...(mode === "secure-custom"
            ? {
                cookiePrefix: "policy",
                defaultCookieAttributes: {
                  secure: false,
                  path: "/discarded",
                  sameSite: "strict",
                  httpOnly: false,
                },
                cookies: {
                  session_token: {
                    name: "configured_session",
                    attributes: { path, httpOnly: true, sameSite: "lax", secure: false },
                  },
                  dont_remember: { attributes: { path, sameSite: "lax", httpOnly: true } },
                },
              }
            : {}),
          ...(mode === "attributes"
            ? {
                cookies: {
                  session_token: { name: "physical_session" },
                  dont_remember: { name: "physical_preference", attributes: { maxAge: 121 } },
                },
              }
            : mode === "legacy" || mode === "legacy-alias"
              ? {
                  cookies: {
                    session_token: { name: mode === "legacy" ? "customsession" : "some.alias" },
                  },
                }
              : {}),
        },
      }),
    );
  }
  return {
    profiles,
    control(request: Request): Response | null {
      const url = new URL(request.url);

      if (url.pathname !== "/__test/physical-cookie/storage") {
        return null;
      }

      const id =
        url.searchParams.get("userId") ??
        (url.searchParams.get("email")
          ? (
              database
                .query("SELECT id FROM user WHERE email=?")
                .get(url.searchParams.get("email")) as { id: string } | null
            )?.id
          : undefined);

      if (!id) {
        return Response.json({ user: [], accounts: [], sessions: [] });
      }

      // All declared core columns, physically read with an independently scoped bind.
      return Response.json({
        user: database
          .query(
            "SELECT id,name,email,emailVerified,image,createdAt,updatedAt FROM user WHERE id=?",
          )
          .all(id),
        accounts: database
          .query("SELECT * FROM account WHERE userId=? ORDER BY providerId,accountId,id")
          .all(id),
        sessions: database
          .query(
            "SELECT id,expiresAt,token,createdAt,updatedAt,ipAddress,userAgent,userId FROM session WHERE userId=? ORDER BY createdAt,id",
          )
          .all(id),
      });
    },
  };
}
