import { createAuthClient } from "better-auth/client";
import { twoFactorClient } from "better-auth/client/plugins";

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

    await client.signUp.email({
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

    const signIn = await client.signIn.email({
      email,
      password,
    });
    const verifyBackupCode = await client.twoFactor.verifyBackupCode({ code: backupCode });
    const session = await client.getSession();

    await client.signOut();
    await client.signIn.email({
      email,
      password,
    });
    const reusedBackupCode = await client.twoFactor.verifyBackupCode({ code: backupCode });

    return {
      signIn: ctx.snapshot(signIn),
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
