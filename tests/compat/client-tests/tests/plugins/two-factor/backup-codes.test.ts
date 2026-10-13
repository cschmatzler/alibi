import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { twoFactorClient } from "better-auth/client/plugins";
import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
import { generateCurrentTotp } from "../../../support/totp";

function twoFactorActor(
  ctx: Parameters<Parameters<typeof compatScenario>[1]>[0],
  name = "primary",
) {
  const actor = ctx.actor(name);
  return createAuthClient({
    baseURL: ctx.baseURL,
    plugins: [twoFactorClient()],
    fetchOptions: {
      customFetchImpl: actor.fetch,
    },
  });
}

function redactBackupCodePayload<T>(value: T): T {
  if (!value || typeof value !== "object") {
    return value;
  }

  const clone = structuredClone(value as object) as Record<string, unknown>;

  if (clone.data && typeof clone.data === "object" && !Array.isArray(clone.data)) {
    const data = clone.data as Record<string, unknown>;
    if (Array.isArray(data.backupCodes)) {
      data.backupCodes = data.backupCodes.map(() => "<backup-code>");
    }
    if (typeof data.totpURI === "string") {
      data.totpURI = "<totpURI>";
    }
  }

  return clone as T;
}

function redactRawBackupCodeResponse<T>(value: T): T {
  if (!value || typeof value !== "object") {
    return value;
  }

  const clone = structuredClone(value as object) as Record<string, unknown>;

  if (clone.body && typeof clone.body === "object" && !Array.isArray(clone.body)) {
    const body = clone.body as Record<string, unknown>;
    if (Array.isArray(body.backupCodes)) {
      body.backupCodes = body.backupCodes.map(() => "<backup-code>");
    }
  }

  return clone as T;
}

compatScenario(
  "two-factor generate-backup-codes replaces the backup code set for enabled users",
  async (ctx) => {
    const client = twoFactorActor(ctx);
    const email = ctx.uniqueEmail("two-factor-generate");
    const password = "password123";

    await client.signUp.email({
      email,
      password,
      name: "Two Factor Generate",
    });

    const enable = await client.twoFactor.enable({ password });
    const setupCode = await generateCurrentTotp(enrollmentUri(enable.data));
    await client.twoFactor.verifyTotp({ code: setupCode });

    const generateBackupCodes = await client.twoFactor.generateBackupCodes({ password });

    return {
      generateBackupCodes: ctx.snapshot(redactBackupCodePayload(generateBackupCodes)),
    };
  },
);

compatScenario(
  "two-factor verify-backup-code signs the user in and consumes the used code",
  async (ctx) => {
    const client = twoFactorActor(ctx);
    const email = ctx.uniqueEmail("two-factor-verify");
    const password = "password123";

    const created = await client.signUp.email({
      email,
      password,
      name: "Two Factor Verify",
    });

    const enable = await client.twoFactor.enable({ password });
    const setupCode = await generateCurrentTotp(enrollmentUri(enable.data));
    await client.twoFactor.verifyTotp({ code: setupCode });

    const generated = await client.twoFactor.generateBackupCodes({ password });
    const backupCode = generated.data!.backupCodes[0]!;

    await client.signOut();

    let pendingCookie = "";
    const signIn = await client.signIn.email({
      email,
      password,
      fetchOptions: {
        onSuccess({ response }) {
          pendingCookie = response.headers
            .getSetCookie()
            .filter((raw) => Boolean(Cookie.parse(raw)?.value))
            .map((cookie) => cookie.split(";")[0])
            .join("; ");
        },
      },
    });
    async function serverVerify(body: unknown, cookie = pendingCookie) {
      const response = await ctx
        .actor("primary")
        .fetch(`${ctx.baseURL}/__test/server-api/two-factor-verify-backup`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ body, headers: { cookie } }),
        });
      const value = (await response.json()) as any;
      return response.ok
        ? { data: value, error: null }
        : { data: null, error: { ...value, status: response.status } };
    }
    const before = await ctx.readUserState({ userId: created.data!.user.id });
    const invalidInputs = [];
    for (const body of [
      {},
      { code: 42 },
      { code: "unused", disableSession: null },
      { code: "unused", trustDevice: 42 },
    ]) {
      const denied = await serverVerify(body);
      expect(denied.error).toMatchObject({ status: 400, code: "VALIDATION_ERROR" });
      invalidInputs.push(ctx.snapshot(denied));
    }
    const guest = await serverVerify({ code: backupCode }, "");
    expect(guest.error).toMatchObject({ status: 401, code: "INVALID_TWO_FACTOR_COOKIE" });
    expect(await ctx.readUserState({ userId: created.data!.user.id })).toEqual(before);
    const unpublished = await serverVerify({
      code: generated.data!.backupCodes[1]!,
      disableSession: true,
      trustDevice: true,
    });
    expect(unpublished.error).toBeNull();
    expect(unpublished.data).not.toHaveProperty("token");
    expect(unpublished.data.user.id).toBe(created.data!.user.id);
    expect(await ctx.readUserState({ userId: created.data!.user.id })).toEqual(before);
    expect((await client.getSession()).data).toBeNull();
    const retired = await serverVerify({ code: backupCode });
    expect(retired.error).toMatchObject({ status: 401, code: "INVALID_TWO_FACTOR_COOKIE" });
    await client.signIn.email({
      email,
      password,
      fetchOptions: {
        onSuccess({ response }) {
          pendingCookie = response.headers
            .getSetCookie()
            .filter((raw) => Boolean(Cookie.parse(raw)?.value))
            .map((cookie) => cookie.split(";")[0])
            .join("; ");
        },
      },
    });
    const verifyBackupCode = await serverVerify({ code: backupCode, userId: "untrusted-selector" });
    expect(verifyBackupCode.error).toBeNull();
    const session = await client.getSession();

    await client.signOut();
    await client.signIn.email({
      email,
      password,
      fetchOptions: {
        onSuccess({ response }) {
          pendingCookie = response.headers
            .getSetCookie()
            .filter((raw) => Boolean(Cookie.parse(raw)?.value))
            .map((cookie) => cookie.split(";")[0])
            .join("; ");
        },
      },
    });
    const reusedBackupCode = await serverVerify({ code: backupCode });
    expect(reusedBackupCode.error).toMatchObject({ status: 401, code: "INVALID_BACKUP_CODE" });

    return {
      signIn: ctx.snapshot(signIn),
      invalidInputs,
      guest: ctx.snapshot(guest),
      unpublished: ctx.snapshot(unpublished),
      retired: ctx.snapshot(retired),
      verifyBackupCode: ctx.snapshot(verifyBackupCode),
      session: ctx.snapshot(session),
      reusedBackupCode: ctx.snapshot(reusedBackupCode),
    };
  },
);

compatScenario(
  "two-factor server-only backup code retrieval returns parsed arrays",
  async (ctx) => {
    const client = twoFactorActor(ctx);
    const email = ctx.uniqueEmail("two-factor-view");
    const password = "password123";

    const signup = await client.signUp.email({
      email,
      password,
      name: "Two Factor View",
    });

    const enable = await client.twoFactor.enable({ password });
    const setupCode = await generateCurrentTotp(enrollmentUri(enable.data));
    await client.twoFactor.verifyTotp({ code: setupCode });
    const generated = await client.twoFactor.generateBackupCodes({ password });

    const viewBackupCodes = await ctx.rawRequest({
      path: `/__test/view-backup-codes?userId=${encodeURIComponent(signup.data!.user.id)}`,
    });

    return {
      generated: ctx.snapshot(redactBackupCodePayload(generated)),
      viewBackupCodes: ctx.snapshot(redactRawBackupCodeResponse(viewBackupCodes)),
    };
  },
);

compatScenario(
  "two-factor view-backup-codes stays unexposed as a public HTTP route",
  async (ctx) => {
    const client = twoFactorActor(ctx);
    const email = ctx.uniqueEmail("two-factor-no-route");
    const password = "password123";

    const signup = await client.signUp.email({
      email,
      password,
      name: "Two Factor No Route",
    });

    const enable = await client.twoFactor.enable({ password });
    const setupCode = await generateCurrentTotp(enrollmentUri(enable.data));
    await client.twoFactor.verifyTotp({ code: setupCode });

    const publicRoute = await ctx.rawRequest({
      path: "/api/auth/two-factor/view-backup-codes",
      method: "POST",
      json: {
        userId: signup.data!.user.id,
      },
    });

    return {
      publicRoute: ctx.snapshot(publicRoute),
    };
  },
  [],
  30_000,
  { oracle: { unroutedRequests: "asserts view-backup-codes is not exposed over HTTP" } },
);

function enrollmentUri(value: unknown): string {
  if (
    value &&
    typeof value === "object" &&
    "totpURI" in value &&
    typeof value.totpURI === "string"
  ) {
    return value.totpURI;
  }
  throw new Error("TOTP enrollment must return a URI");
}
