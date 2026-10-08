import type { Database } from "bun:sqlite";

import { betterAuth } from "better-auth";
import { twoFactor } from "better-auth/plugins";

export function createTwoFactorOtpFixture(
  base: Parameters<typeof betterAuth>[0],
  database: Database,
) {
  const deliveries = new Map<string, { userId: string; otp: string }>();
  const receipts = new Map<string, Array<{ phase: string; input: string }>>();
  const record = (profile: string, phase: string, input: string) => {
    const values = receipts.get(profile) ?? [];
    values.push({ phase, input });
    receipts.set(profile, values);
  };
  const reverse = (value: string) => value.split("").reverse().join("");
  const numeric: Record<string, { digits: number; period?: number; allowedAttempts?: number }> = {
    "two-factor-otp-nan": { digits: NaN, period: NaN, allowedAttempts: NaN },
    "two-factor-otp-half": { digits: 0.5, period: 0.5, allowedAttempts: Infinity },
    "two-factor-otp-large": { digits: 32769.5, period: 1e8, allowedAttempts: Infinity },
    "two-factor-otp-infinite-digits": { digits: Infinity },
    "two-factor-otp-infinite-expiry": { digits: 6, period: Infinity },
    "two-factor-otp-negative-expiry": { digits: 6, period: -1 },
  };
  const names = [
    "two-factor-otp-missing-options",
    "two-factor-otp-missing-sender",
    "two-factor-otp-plain",
    "two-factor-otp-hashed",
    "two-factor-otp-encrypted",
    "two-factor-otp-custom-hash",
    "two-factor-otp-custom-cipher",
    "two-factor-otp-zero",
    "two-factor-otp-negative",
    "two-factor-otp-nan",
    "two-factor-otp-half",
    "two-factor-otp-large",
    "two-factor-otp-infinite-digits",
    "two-factor-otp-infinite-expiry",
    "two-factor-otp-negative-expiry",
  ] as const;
  const profiles = new Map(
    names.map((name) => {
      const storage = name.endsWith("custom-hash")
        ? {
            hash: async (input: string) => {
              record(name, "hash", input);
              return "hash-" + reverse(input);
            },
          }
        : name.endsWith("custom-cipher")
          ? {
              encrypt: async (input: string) => {
                record(name, "encrypt", input);
                return "cipher-" + reverse(input);
              },
              decrypt: async (input: string) => {
                record(name, "decrypt", input);
                return reverse(input.slice(7));
              },
            }
          : name.endsWith("hashed")
            ? "hashed"
            : name.endsWith("encrypted")
              ? "encrypted"
              : "plain";
      const settings =
        numeric[name] ??
        (name.endsWith("zero")
          ? { digits: 0 }
          : name.endsWith("negative")
            ? { digits: -1 }
            : name.endsWith("plain")
              ? {}
              : name.endsWith("encrypted")
                ? { digits: 8, period: 0, allowedAttempts: 0 }
                : name.endsWith("hashed")
                  ? { digits: 3.5, period: 0.5, allowedAttempts: 2.5 }
                  : { digits: 3, period: 1, allowedAttempts: 2 });
      return [
        name,
        betterAuth({
          ...base,
          appName: "Fixture Auth",
          basePath: `/__test/profiles/${name}/api/auth`,
          plugins: [
            twoFactor({
              totpOptions: { disable: name.endsWith("hashed") },
              ...(name === "two-factor-otp-missing-options"
                ? {}
                : {
                    otpOptions:
                      name === "two-factor-otp-missing-sender"
                        ? {}
                        : {
                            ...settings,
                            storeOTP: storage,
                            sendOTP: async ({ user, otp }) => {
                              if (user.email) {
                                deliveries.set(user.email, { userId: user.id, otp });
                              }
                              record(name, "send", otp);
                            },
                          },
                  }),
            }),
          ],
        }),
      ] as const;
    }),
  );
  const handler = async (request: Request, url: URL): Promise<Response | undefined> => {
    for (const [name, auth] of profiles) {
      if (url.pathname.startsWith(`/__test/profiles/${name}/api/auth/`)) {
        return auth.handler(request);
      }
    }

    if (url.pathname !== "/__test/two-factor-otp-config" || request.method !== "POST") {
      return;
    }

    const body = (await request.json()) as {
      profile: string;
      email: string;
      identifier?: string;
      counter?: string;
      expire?: boolean;
    };
    const delivery = deliveries.get(body.email);
    const row = body.identifier
      ? database
          .query(
            "SELECT id,identifier,value,expiresAt FROM verification WHERE identifier=? ORDER BY createdAt DESC",
          )
          .get(body.identifier)
      : delivery
        ? database
            .query(
              "SELECT id,identifier,value,expiresAt FROM verification WHERE identifier LIKE ? OR identifier IN(SELECT '2fa-otp-'||identifier FROM verification WHERE value=? AND identifier LIKE '2fa-%') ORDER BY createdAt DESC",
            )
            .get(`2fa-otp-${delivery.userId}!%`, delivery.userId)
        : null;

    if (row && typeof body.counter === "string") {
      const current = row as { identifier: string; value: string };
      database
        .query("UPDATE verification SET value=? WHERE identifier=?")
        .run(`${current.value.split(":")[0]}:${body.counter}`, current.identifier);
    }

    if (row && body.expire === true) {
      database
        .query("UPDATE verification SET expiresAt=? WHERE identifier=?")
        .run(new Date(Date.now() - 1000).toISOString(), (row as { identifier: string }).identifier);
    }

    const current = row
      ? database
          .query(
            "SELECT id,identifier,value,expiresAt FROM verification WHERE identifier=? ORDER BY createdAt DESC",
          )
          .get((row as { identifier: string }).identifier)
      : null;
    const identifier = body.identifier ?? (row as { identifier: string } | null)?.identifier;
    const generations = identifier
      ? (
          database
            .query("SELECT COUNT(*) AS total FROM verification WHERE identifier=?")
            .get(identifier) as { total: number }
        ).total
      : 0;
    return Response.json({
      delivery: delivery ?? null,
      row: current,
      generations,
      receipts: receipts.get(body.profile) ?? [],
    });
  };
  return Object.assign(handler, {
    reset() {
      deliveries.clear();
      receipts.clear();
    },
  });
}
