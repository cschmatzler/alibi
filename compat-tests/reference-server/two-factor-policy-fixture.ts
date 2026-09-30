import type { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { twoFactor } from "better-auth/plugins";
import { APIError } from "better-auth/api";

export function createTwoFactorPolicyFixture(base: Parameters<typeof betterAuth>[0], database: Database) {
  const deliveries = new Map<string, { otp: string }>();
  const profiles = new Map(["two-factor-lockout-fractional", "two-factor-lockout-zero", "two-factor-lockout-disabled", "two-factor-skip-verification", "two-factor-skip-user-hook", "two-factor-skip-session-cancel", "two-factor-skip-session-forbidden"].map(name => [name, betterAuth({
    ...base, appName: "Fixture Auth", basePath: `/__test/profiles/${name}/api/auth`,
    ...(name === "two-factor-skip-user-hook" ? {databaseHooks:{...base.databaseHooks,user:{...base.databaseHooks?.user,update:{...base.databaseHooks?.user?.update,before:async data=>{if(data.twoFactorEnabled===true)throw new APIError("BAD_REQUEST",{message:"Configured user update denied",code:"USER_UPDATE_DENIED"});}}}}} : {}),
    ...(name.startsWith("two-factor-skip-session-") ? {databaseHooks:{...base.databaseHooks,session:{...base.databaseHooks?.session,create:{...base.databaseHooks?.session?.create,before:async (_data,context)=>{
      if(context?.path.endsWith("/two-factor/enable")) {
        if(name === "two-factor-skip-session-cancel") return false;
        throw new APIError("FORBIDDEN",{message:"session creation cancelled by database hook"});
      }
    }}}}} : {}),
    plugins: [twoFactor({
      skipVerificationOnEnable: name.startsWith("two-factor-skip-"),
      accountLockout: name === "two-factor-lockout-fractional" ? { maxFailedAttempts: 2.5, durationSeconds: 600.25 }
        : name === "two-factor-lockout-zero" ? { maxFailedAttempts: 0, durationSeconds: 0 }
        : name === "two-factor-lockout-disabled" ? { enabled: false } : {},
      otpOptions: { sendOTP: async ({ user, otp }) => { if (user.email) deliveries.set(user.email, { otp }); } },
    })],
  })] as const));
  return async function handle(request: Request, url: URL): Promise<Response | undefined> {
    for (const [name, auth] of profiles) {
      if (url.pathname.startsWith(`/__test/profiles/${name}/api/auth/`)) return auth.handler(request);
    }
    if (url.pathname !== "/__test/two-factor-policy" || request.method !== "POST") return;
    const body = await request.json() as { userId?: unknown; count?: unknown; verified?: unknown; expireLock?: unknown; deliveryEmail?: unknown };
    if (typeof body.deliveryEmail === "string") return Response.json(deliveries.get(body.deliveryEmail) ?? null);
    if (typeof body.userId !== "string") return Response.json({ message: "userId required" }, { status: 400 });
    if (Object.hasOwn(body, "count")) database.query('UPDATE twoFactor SET failedVerificationCount=? WHERE userId=?').run(body.count as number | null, body.userId);
    if (typeof body.verified === "boolean") database.query('UPDATE twoFactor SET verified=? WHERE userId=?').run(body.verified ? 1 : 0, body.userId);
    if (body.expireLock === true) database.query('UPDATE twoFactor SET lockedUntil=? WHERE userId=?').run(new Date(Date.now() - 1000).toISOString(), body.userId);
    const row = database.query('SELECT id,userId,secret,backupCodes,verified,failedVerificationCount,lockedUntil FROM twoFactor WHERE userId=?').get(body.userId) as Record<string, unknown> | null;
    if (row && row.verified !== null) row.verified = Boolean(row.verified);
    return Response.json(row);
  };
}
