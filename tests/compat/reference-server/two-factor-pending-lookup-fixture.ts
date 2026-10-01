/** Application-owned SQL observations; the pinned factor and adapter execute unchanged. */
import { betterAuth } from "better-auth";
import { twoFactor } from "better-auth/plugins";
import { createKyselyAdapter } from "@better-auth/kysely-adapter";
import type { Database } from "bun:sqlite";

function phase(sql: string) {
  const query = sql.toLowerCase();
  if (query.startsWith("select") && query.includes('from "verification"'))
    return query.includes('"identifier"') && query.includes('"identifier" =')
      ? "lookup"
      : query.includes('"expiresat" <')
        ? "cleanup-read"
        : undefined;
  if (
    query.startsWith("delete") &&
    query.includes('from "verification"') &&
    query.includes('"expiresat" <')
  )
    return "cleanup-delete";
  if (query.startsWith("select") && query.includes('from "user"'))
    return "user";
}
export async function createTwoFactorPendingLookupFixture(
  base: Parameters<typeof betterAuth>[0],
  database: Database,
) {
  let armed = false;
  const receipts: string[] = [];
  const deliveries = new Map<string, { otp: string }>();
  const actual = await createKyselyAdapter({ ...base, database });
  if (!actual.kysely) throw new Error("real Bun Kysely adapter required");
  const pending = new WeakMap<object, string>();
  const observed = actual.kysely.withPlugin({
    transformQuery(args) {
      if (armed) {
        const name = phase(
          actual.kysely!.getExecutor().compileQuery(args.node, args.queryId)
            .sql,
        );
        if (name) pending.set(args.queryId, name);
      }
      return args.node;
    },
    async transformResult(args) {
      const name = pending.get(args.queryId);
      if (name && armed) {
        receipts.push(name);
        if (name === "user") armed = false;
      }
      return args.result;
    },
  });
  const profiles = new Map(
    [
      "two-factor-pending-lookup",
      "two-factor-pending-lookup-disabled",
      "two-factor-pending-lookup-zero",
      "two-factor-pending-lookup-zero-disabled",
    ].map(
      (name) =>
        [
          name,
          betterAuth({
            ...base,
            database: { db: observed, type: "sqlite", transaction: true },
            basePath: `/__test/profiles/${name}/api/auth`,
            verification: {
              ...base.verification,
              disableCleanup: name.endsWith("-disabled"),
            },
            plugins: [
              twoFactor({
                skipVerificationOnEnable: true,
                twoFactorCookieMaxAge: name.includes("-zero") ? 0 : 600,
                backupCodeOptions: { storeBackupCodes: "plain" },
                otpOptions: {
                  sendOTP: async ({ user, otp }) => {
                    if (user.email) deliveries.set(user.email, { otp });
                  },
                },
              }),
            ],
          }),
        ] as const,
    ),
  );
  function snapshot() {
    return {
      verifications: database
        .query(
          "SELECT id,identifier,value,expiresAt,createdAt,updatedAt FROM verification ORDER BY CASE WHEN identifier LIKE '2fa-attempts-%' THEN 0 WHEN identifier LIKE '2fa-otp-%' THEN 1 WHEN identifier LIKE '2fa-%' THEN 2 ELSE 3 END,createdAt,id",
        )
        .all()
        .map((row) => {
          const value = row as Record<string, unknown>;
          return {
            ...value,
            expiresAt: new Date(value.expiresAt as string).toISOString(),
            createdAt: new Date(value.createdAt as string).toISOString(),
            updatedAt: new Date(value.updatedAt as string).toISOString(),
          };
        }),
      factors: database
        .query(
          "SELECT t.id,t.userId,t.secret,t.backupCodes,t.verified,t.failedVerificationCount,t.lockedUntil FROM twoFactor t JOIN user u ON u.id=t.userId ORDER BY u.email,t.id",
        )
        .all()
        .map((row) => {
          const value = row as Record<string, unknown>;
          return {
            ...value,
            verified: value.verified === null ? null : Boolean(value.verified),
          };
        }),
    };
  }
  return {
    profiles,
    async control(body: Record<string, unknown>) {
      armed = false;
      const profile = profiles.get(String(body.profile));
      if (!profile)
        return Response.json({ message: "unknown profile" }, { status: 400 });
      const context = await profile.$context;
      if (body.action === "clear") {
        receipts.length = 0;
        return Response.json({ cleared: true });
      }
      if (body.action === "arm") {
        receipts.length = 0;
        armed = true;
        return Response.json({ armed: true });
      }
      if (body.action === "delivery")
        return Response.json(deliveries.get(String(body.email)) ?? null);
      if (body.action === "snapshot")
        return Response.json({ receipts: [...receipts], snapshot: snapshot() });
      if (body.action === "seed") {
        const row = await context.internalAdapter.createVerificationValue({
          identifier: String(body.identifier),
          value: String(body.value),
          expiresAt: new Date(String(body.expiresAt)),
        });
        if (body.createdAt)
          database
            .query("UPDATE verification SET createdAt=? WHERE id=?")
            .run(String(body.createdAt), row.id);
      }
      if (body.action === "patch") {
        if (body.expiresAt)
          database
            .query("UPDATE verification SET expiresAt=? WHERE identifier=?")
            .run(String(body.expiresAt), String(body.identifier));
        if (body.value)
          database
            .query("UPDATE verification SET value=? WHERE identifier=?")
            .run(String(body.value), String(body.identifier));
      }
      if (body.action === "user")
        await context.adapter.update({
          model: "user",
          where: [{ field: "id", value: String(body.userId) }],
          update: { name: String(body.name) },
        });
      return Response.json({ changed: true });
    },
  };
}
