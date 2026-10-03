import type { Database } from "bun:sqlite";

import { betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import { twoFactor } from "better-auth/plugins";

export function createTwoFactorPolicyFixture(
  base: Parameters<typeof betterAuth>[0],
  database: Database,
) {
  const deliveries = new Map<string, { otp: string }>();
  const backupReceipts = new Map<string, Array<{ phase: string; input: string }>>();
  const recordBackup = (profile: string, phase: string, input: string) => {
    const rows = backupReceipts.get(profile) ?? [];
    rows.push({ phase, input });
    backupReceipts.set(profile, rows);
  };
  const numericBackup: Record<
    string,
    { amount: number; length: number; storeBackupCodes: "plain" }
  > = {
    "two-factor-backup-nan-count": { amount: NaN, length: Infinity, storeBackupCodes: "plain" },
    "two-factor-backup-negative-infinite-count": {
      amount: -Infinity,
      length: 0,
      storeBackupCodes: "plain",
    },
    "two-factor-backup-nan-length": { amount: 1.5, length: NaN, storeBackupCodes: "plain" },
    "two-factor-backup-half-length": { amount: 1, length: 0.5, storeBackupCodes: "plain" },
    "two-factor-backup-large-length": { amount: 1, length: 32769.5, storeBackupCodes: "plain" },
    "two-factor-backup-large-count": { amount: 1024.5, length: 12, storeBackupCodes: "plain" },
    "two-factor-backup-infinite-count": { amount: Infinity, length: 0, storeBackupCodes: "plain" },
  };
  const backupOptions = (name: string) =>
    numericBackup[name] ??
    (name === "two-factor-backup-plain"
      ? { amount: 2.5, length: 3.5, storeBackupCodes: "plain" as const }
      : name === "two-factor-backup-zero"
        ? { amount: 0, length: 0, storeBackupCodes: "plain" as const }
        : name === "two-factor-backup-negative"
          ? { amount: -1, length: -2, storeBackupCodes: "plain" as const }
          : name === "two-factor-backup-encrypted"
            ? { amount: 3, length: 6, storeBackupCodes: "encrypted" as const }
            : name === "two-factor-backup-invalid-length"
              ? { amount: 2, length: 0, storeBackupCodes: "plain" as const }
              : name === "two-factor-backup-custom"
                ? {
                    customBackupCodesGenerate: () => {
                      recordBackup(name, "generate", "");
                      const count = backupReceipts
                        .get(name)!
                        .filter((row) => row.phase === "generate").length;
                      return [`same-${count}`, `same-${count}`, `other-${count}`];
                    },
                    storeBackupCodes: {
                      encrypt: async (input: string) => {
                        recordBackup(name, "encrypt", input);
                        return "backup-" + input;
                      },
                      decrypt: async (input: string) => {
                        recordBackup(name, "decrypt", input);
                        return input.slice(7);
                      },
                    },
                  }
                : {});
  const profiles = new Map(
    [
      "two-factor-lockout-fractional",
      "two-factor-lockout-zero",
      "two-factor-lockout-disabled",
      "two-factor-skip-verification",
      "two-factor-skip-user-hook",
      "two-factor-skip-session-cancel",
      "two-factor-skip-session-forbidden",
      "two-factor-pending-session-cancel",
      "two-factor-pending-session-forbidden",
      "two-factor-passwordless",
      "two-factor-passwordless-child-required",
      "two-factor-passwordless-child-optional",
      "two-factor-backup-plain",
      "two-factor-backup-zero",
      "two-factor-backup-negative",
      "two-factor-backup-encrypted",
      "two-factor-backup-invalid-length",
      "two-factor-backup-custom",
      "two-factor-backup-nan-count",
      "two-factor-backup-negative-infinite-count",
      "two-factor-backup-nan-length",
      "two-factor-backup-half-length",
      "two-factor-backup-large-length",
      "two-factor-backup-large-count",
      "two-factor-backup-infinite-count",
      "two-factor-trust-fractional",
      "two-factor-trust-zero-challenge",
      "two-factor-trust-negative-challenge",
      "two-factor-trust-zero",
      "two-factor-trust-negative",
      "two-factor-trust-cleanup-disabled",
    ].map(
      (name) =>
        [
          name,
          betterAuth({
            ...base,
            appName: "Fixture Auth",
            basePath: `/__test/profiles/${name}/api/auth`,
            ...(name === "two-factor-trust-cleanup-disabled"
              ? { verification: { ...base.verification, disableCleanup: true } }
              : {}),
            ...(name === "two-factor-skip-user-hook"
              ? {
                  databaseHooks: {
                    ...base.databaseHooks,
                    user: {
                      ...base.databaseHooks?.user,
                      update: {
                        ...base.databaseHooks?.user?.update,
                        before: async (data) => {
                          if (data.twoFactorEnabled === true) {
                            throw new APIError("BAD_REQUEST", {
                              message: "Configured user update denied",
                              code: "USER_UPDATE_DENIED",
                            });
                          }
                        },
                      },
                    },
                  },
                }
              : {}),
            ...(name.includes("-session-")
              ? {
                  databaseHooks: {
                    ...base.databaseHooks,
                    session: {
                      ...base.databaseHooks?.session,
                      create: {
                        ...base.databaseHooks?.session?.create,
                        before: async (_data, context) => {
                          if (
                            name.startsWith("two-factor-pending-")
                              ? context?.path.startsWith("/two-factor/verify-")
                              : context?.path.endsWith("/two-factor/enable")
                          ) {
                            if (name.endsWith("-cancel")) {
                              return false;
                            }
                            throw new APIError("FORBIDDEN", {
                              message: "session creation cancelled by database hook",
                            });
                          }
                        },
                      },
                    },
                  },
                }
              : {}),
            plugins: [
              twoFactor({
                twoFactorCookieMaxAge:
                  name === "two-factor-trust-zero-challenge"
                    ? 0
                    : name === "two-factor-trust-negative-challenge"
                      ? -0.25
                      : name.startsWith("two-factor-trust-")
                        ? 600.75
                        : undefined,
                trustDeviceMaxAge:
                  name === "two-factor-trust-zero"
                    ? 0
                    : name === "two-factor-trust-negative"
                      ? -0.25
                      : name.startsWith("two-factor-trust-")
                        ? 1200.875
                        : undefined,
                allowPasswordless:
                  name === "two-factor-passwordless" ||
                  name === "two-factor-passwordless-child-required",
                totpOptions: {
                  allowPasswordless:
                    name === "two-factor-passwordless-child-required"
                      ? false
                      : name === "two-factor-passwordless-child-optional"
                        ? true
                        : undefined,
                },
                backupCodeOptions: {
                  ...backupOptions(name),
                  allowPasswordless:
                    name === "two-factor-passwordless-child-required"
                      ? false
                      : name === "two-factor-passwordless-child-optional"
                        ? true
                        : undefined,
                },
                skipVerificationOnEnable:
                  name.startsWith("two-factor-skip-") ||
                  name.startsWith("two-factor-pending-") ||
                  name.startsWith("two-factor-backup-") ||
                  name.startsWith("two-factor-trust-"),
                accountLockout:
                  name === "two-factor-lockout-fractional"
                    ? { maxFailedAttempts: 2.5, durationSeconds: 600.25 }
                    : name === "two-factor-lockout-zero"
                      ? { maxFailedAttempts: 0, durationSeconds: 0 }
                      : name === "two-factor-lockout-disabled"
                        ? { enabled: false }
                        : {},
                otpOptions: {
                  sendOTP: async ({ user, otp }) => {
                    if (user.email) {
                      deliveries.set(user.email, { otp });
                    }
                  },
                },
              }),
            ],
          }),
        ] as const,
    ),
  );
  const handle = async function handle(request: Request, url: URL): Promise<Response | undefined> {
    for (const [name, auth] of profiles) {
      if (url.pathname.startsWith(`/__test/profiles/${name}/api/auth/`)) {
        return auth.handler(request);
      }
    }

    if (url.pathname !== "/__test/two-factor-policy" || request.method !== "POST") {
      return;
    }

    const body = (await request.json()) as {
      userId?: unknown;
      count?: unknown;
      verified?: unknown;
      expireLock?: unknown;
      deliveryEmail?: unknown;
      credentialState?: unknown;
      emptyCredentialPassword?: unknown;
      pendingState?: unknown;
      pendingKey?: unknown;
      importFactor?: unknown;
      backupProfile?: unknown;
      viewBackupCodes?: unknown;
      trustIdentifier?: unknown;
    };

    if (typeof body.deliveryEmail === "string") {
      return Response.json(deliveries.get(body.deliveryEmail) ?? null);
    }

    if (typeof body.userId !== "string") {
      return Response.json({ message: "userId required" }, { status: 400 });
    }

    if (typeof body.backupProfile === "string" && body.viewBackupCodes === true) {
      const selected = profiles.get(body.backupProfile);

      if (!selected) {
        return Response.json({ message: "unknown backup profile" }, { status: 400 });
      }

      const result = await selected.api.viewBackupCodes({
        body: { userId: body.userId },
      });
      return Response.json({
        ...result,
        receipts: backupReceipts.get(body.backupProfile) ?? [],
      });
    }

    if (body.pendingState === true) {
      const key =
        typeof body.pendingKey === "string"
          ? body.pendingKey
          : (
              database
                .query(
                  "SELECT identifier FROM verification WHERE value=? AND identifier LIKE '2fa-%'",
                )
                .get(body.userId) as { identifier: string } | null
            )?.identifier;
      const record = (identifier: string) =>
        database.query("SELECT value FROM verification WHERE identifier=?").get(identifier) as {
          value: string;
        } | null;
      return Response.json({
        key: key ?? null,
        challenge: key ? Boolean(record(key)) : false,
        attempts: key ? (record(`2fa-attempts-${key}`)?.value ?? null) : null,
        otpExists: key ? Boolean(record(`2fa-otp-${key}`)) : false,
        trustCount: (
          database
            .query(
              "SELECT count(*) AS n FROM verification WHERE value=? AND identifier LIKE 'trust-device-%'",
            )
            .get(body.userId) as { n: number }
        ).n,
      });
    }

    if (typeof body.trustIdentifier === "string") {
      database
        .query("UPDATE verification SET value=? WHERE identifier=?")
        .run(body.userId, body.trustIdentifier);
      return Response.json({ status: true });
    }

    if (body.emptyCredentialPassword === true) {
      database
        .query("UPDATE account SET password='' WHERE userId=? AND providerId='credential'")
        .run(body.userId);
    }

    if (body.credentialState === true) {
      return Response.json(
        database
          .query(
            "SELECT userId,providerId,password FROM account WHERE userId=? ORDER BY providerId",
          )
          .all(body.userId)
          .map((row) => {
            const account = row as { userId: string; providerId: string; password: string | null };
            return {
              userId: account.userId,
              providerId: account.providerId,
              hasPassword: Boolean(account.password),
            };
          }),
      );
    }

    if (body.importFactor && typeof body.importFactor === "object") {
      const factor = body.importFactor as { secret?: unknown; backupCodes?: unknown };
      if (typeof factor.secret !== "string" || typeof factor.backupCodes !== "string") {
        return Response.json({ message: "invalid factor import" }, { status: 400 });
      }
      database
        .query("UPDATE twoFactor SET secret=?,backupCodes=? WHERE userId=?")
        .run(factor.secret, factor.backupCodes, body.userId);
    }

    if (Object.hasOwn(body, "count")) {
      database
        .query("UPDATE twoFactor SET failedVerificationCount=? WHERE userId=?")
        .run(body.count as number | null, body.userId);
    }

    if (typeof body.verified === "boolean") {
      database
        .query("UPDATE twoFactor SET verified=? WHERE userId=?")
        .run(body.verified ? 1 : 0, body.userId);
    }

    if (body.expireLock === true) {
      database
        .query("UPDATE twoFactor SET lockedUntil=? WHERE userId=?")
        .run(new Date(Date.now() - 1000).toISOString(), body.userId);
    }

    const row = database
      .query(
        "SELECT id,userId,secret,backupCodes,verified,failedVerificationCount,lockedUntil FROM twoFactor WHERE userId=?",
      )
      .get(body.userId) as Record<string, unknown> | null;

    if (row && row.verified !== null) {
      row.verified = Boolean(row.verified);
    }

    return Response.json(row);
  };
  return Object.assign(handle, { reset: () => backupReceipts.clear() });
}
