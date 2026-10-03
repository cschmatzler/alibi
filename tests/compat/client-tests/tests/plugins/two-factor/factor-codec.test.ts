import { Database } from "bun:sqlite";
import { expect } from "bun:test";

import { betterAuth } from "better-auth";
import { createAuthClient } from "better-auth/client";
import { twoFactorClient } from "better-auth/client/plugins";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { getMigrations } from "better-auth/db/migration";
import { twoFactor } from "better-auth/plugins";
import { z } from "zod";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import { generateCurrentTotp } from "../../../support/totp";

const secret = ["compat", "test", "only", "key", "not", "real", "minimum", "32chars"].join("-");

const factorSchema = z.object({
  id: z.string(),
  userId: z.string(),
  secret: z.string(),
  backupCodes: z.string(),
});

const enrollmentSchema = z.object({ totpURI: z.string(), backupCodes: z.array(z.string()) });

// These ciphertexts come from a real published auth endpoint and SQLite row,
// rather than a fixture that implements or supplies the encryption under test.
async function publishedFactor(email: string) {
  const database = new Database(":memory:");
  try {
    const origin = "http://localhost:42117";
    const options = {
      database,
      baseURL: origin,
      secret,
      appName: "Fixture Auth",
      emailAndPassword: { enabled: true },
      rateLimit: { enabled: false },
      plugins: [twoFactor({ skipVerificationOnEnable: true })],
    };
    await (await getMigrations(options)).runMigrations();
    const auth = betterAuth(options);
    const cookies = new Map<string, string>();
    const request = async (path: string, body: unknown) => {
      const response = await auth.handler(
        new Request(`${origin}/api/auth${path}`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            origin,
            cookie: [...cookies].map(([key, value]) => `${key}=${value}`).join("; "),
          },
          body: JSON.stringify(body),
        }),
      );

      for (const header of response.headers.getSetCookie()) {
        const pair = header.split(";")[0]!;
        const index = pair.indexOf("=");
        cookies.set(pair.slice(0, index), pair.slice(index + 1));
      }

      expect(response.status).toBe(200);

      return response.json();
    };
    const created = z.object({ user: z.object({ id: z.string() }) }).parse(
      await request("/sign-up/email", {
        email,
        password: "password123",
        name: "Published Owner",
      }),
    );
    const enrollment = enrollmentSchema.parse(
      await request("/two-factor/enable", { password: "password123" }),
    );
    const row = factorSchema.parse(
      database
        .query("SELECT id,userId,secret,backupCodes FROM twoFactor WHERE userId=?")
        .get(created.user.id),
    );
    return { row, enrollment };
  } finally {
    database.close();
  }
}

compatScenario(
  "two-factor actual persisted factors decrypt with pinned crypto and imported pinned factors complete public TOTP and backup flows",
  async (ctx) => {
    const profile = "two-factor-skip-verification";
    const client = (name: string) =>
      createAuthClient({
        baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
        plugins: [twoFactorClient()],
        fetchOptions: { customFetchImpl: ctx.actor(name, profile).fetch },
      });
    const owner = client("owner");
    const email = ctx.uniqueEmail("factor-codec");
    const password = "password123";
    const signup = await owner.signUp.email({ email, password, name: "Codec Owner" });
    expect(signup.error).toBeNull();

    if (!signup.data) {
      throw new Error("owner required");
    }

    const userId = signup.data.user.id;
    const enabled = await owner.twoFactor.enable({ password });
    expect(enabled.error).toBeNull();

    const enrollment = enrollmentSchema.parse(enabled.data);
    const read = async (importFactor?: { secret: string; backupCodes: string }) => {
      const response = await ctx.rawRequest({
        path: "/__test/two-factor-policy",
        method: "POST",
        json: { userId, ...(importFactor ? { importFactor } : {}) },
      });
      expect(response.status).toBe(200);
      return factorSchema.parse(response.body);
    };
    const initial = await read();
    expect(initial.userId).toBe(userId);

    const plaintext = await symmetricDecrypt({ key: secret, data: initial.secret });
    expect(plaintext).toHaveLength(32);
    expect(initial.secret).toMatch(/^[0-9a-f]+$/);
    expect(initial.backupCodes).toMatch(/^[0-9a-f]+$/);
    expect(JSON.parse(await symmetricDecrypt({ key: secret, data: initial.backupCodes }))).toEqual(
      enrollment.backupCodes,
    );

    const uri = await owner.twoFactor.getTotpUri({ password });
    expect(uri.error).toBeNull();
    expect(z.object({ totpURI: z.string() }).parse(uri.data).totpURI).toBe(enrollment.totpURI);

    const regenerated = await owner.twoFactor.generateBackupCodes({ password });
    expect(regenerated.error).toBeNull();

    const replacement = z
      .object({ backupCodes: z.array(z.string()) })
      .parse(regenerated.data).backupCodes;
    const regeneratedRow = await read();
    expect(regeneratedRow.id).toBe(initial.id);
    expect(regeneratedRow.secret).toBe(initial.secret);
    expect(
      JSON.parse(await symmetricDecrypt({ key: secret, data: regeneratedRow.backupCodes })),
    ).toEqual(replacement);

    const imported = await publishedFactor(email);
    const importedRow = await read({
      secret: imported.row.secret,
      backupCodes: imported.row.backupCodes,
    });
    expect(importedRow).toEqual({
      ...regeneratedRow,
      secret: imported.row.secret,
      backupCodes: imported.row.backupCodes,
    });

    const foreign = client("foreign");
    const other = await foreign.signUp.email({
      email: ctx.uniqueEmail("factor-foreign"),
      password,
      name: "Other Owner",
    });
    expect(other.error).toBeNull();

    if (!other.data) {
      throw new Error("other owner required");
    }

    const otherEnabled = await foreign.twoFactor.enable({ password });
    expect(otherEnabled.error).toBeNull();

    const otherBefore = await ctx.readUserState({ userId: other.data.user.id });
    const wrongOwner = await foreign.twoFactor.verifyBackupCode({
      code: imported.enrollment.backupCodes[0]!,
    });
    expect(wrongOwner.error?.code).toBe("INVALID_BACKUP_CODE");
    expect(await read()).toEqual(importedRow);
    expect(await ctx.readUserState({ userId: other.data.user.id })).toEqual(otherBefore);

    const totp = await owner.twoFactor.verifyTotp({
      code: await generateCurrentTotp(imported.enrollment.totpURI),
    });
    expect(totp.error).toBeNull();
    expect(totp.data?.user.id).toBe(userId);

    const backup = await owner.twoFactor.verifyBackupCode({
      code: imported.enrollment.backupCodes[0]!,
    });
    expect(backup.error).toBeNull();
    expect(backup.data?.user.id).toBe(userId);

    const consumed = await read();
    expect(consumed.id).toBe(initial.id);
    expect(consumed.secret).toBe(imported.row.secret);
    expect(JSON.parse(await symmetricDecrypt({ key: secret, data: consumed.backupCodes }))).toEqual(
      imported.enrollment.backupCodes.slice(1),
    );

    const replay = await owner.twoFactor.verifyBackupCode({
      code: imported.enrollment.backupCodes[0]!,
    });
    expect(replay.error?.code).toBe("INVALID_BACKUP_CODE");
    expect(await read()).toEqual(consumed);
    expect((await owner.getSession()).data?.session.token).toBe(backup.data?.token);

    return ctx.snapshot({
      signup,
      wrongOwner,
      totp,
      backup,
      replay,
      storage: {
        initialCodes: enrollment.backupCodes.length,
        regeneratedCodes: replacement.length,
        importedCodes: imported.enrollment.backupCodes.length,
        remainingCodes: imported.enrollment.backupCodes.length - 1,
      },
    });
  },
  [
    "POST /two-factor/enable",
    "POST /two-factor/get-totp-uri",
    "POST /two-factor/generate-backup-codes",
    "POST /two-factor/verify-totp",
    "POST /two-factor/verify-backup-code",
  ],
);

compatScenario(
  "two-factor installed mixed JSON preserves valid proofs and incompatible shapes restore pending attempts",
  async (ctx) => {
    const profile = "two-factor-skip-verification";
    const makeClient = (actor: string) =>
      createAuthClient({
        baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
        plugins: [twoFactorClient()],
        fetchOptions: { customFetchImpl: ctx.actor(actor, profile).fetch },
      });
    const owner = makeClient("owner");
    const foreign = makeClient("foreign");
    const password = "password123";
    const email = ctx.uniqueEmail("installed-json");
    const signup = await owner.signUp.email({ email, password, name: "Installed Owner" });
    expect(signup.error).toBeNull();
    const userId = signup.data!.user.id;
    expect((await owner.twoFactor.enable({ password })).error).toBeNull();
    const other = await foreign.signUp.email({
      email: ctx.uniqueEmail("foreign-json"),
      password,
      name: "Foreign",
    });
    expect(other.error).toBeNull();
    expect((await foreign.twoFactor.enable({ password })).error).toBeNull();
    const foreignBefore = await ctx.readUserState({ userId: other.data!.user.id });
    const published = await publishedFactor(email);
    const code = published.enrollment.backupCodes[0]!;
    const remaining = published.enrollment.backupCodes[1]!;
    const read = async (json?: string) => {
      const imported =
        json === undefined
          ? {}
          : {
              importFactor: {
                secret: published.row.secret,
                backupCodes: await symmetricEncrypt({ key: secret, data: json }),
              },
            };
      const response = await ctx.rawRequest({
        path: "/__test/two-factor-policy",
        method: "POST",
        json: { userId, ...imported },
      });
      expect(response.status).toBe(200);
      return factorSchema.passthrough().parse(response.body);
    };
    const original = await read();
    await owner.signOut();
    expect((await owner.signIn.email({ email, password })).data).toMatchObject({
      twoFactorRedirect: true,
    });
    const pending = async (key?: string) => {
      const response = await ctx.rawRequest({
        path: "/__test/two-factor-policy",
        method: "POST",
        json: { userId, pendingState: true, ...(key ? { pendingKey: key } : {}) },
      });
      expect(response.status).toBe(200);
      return z
        .object({
          key: z.string(),
          challenge: z.boolean(),
          attempts: z.string().nullable(),
          trustCount: z.number(),
        })
        .parse(response.body);
    };
    const start = await pending();
    const before = await ctx.readUserState({ userId });
    const errors = [];
    // Decryption succeeds. Truthy non-arrays fail inside Source's verification
    // try/catch, so both the challenge and the attempt budget must survive.
    for (const json of ['{"code":"present"}', "true", "42", '"present"']) {
      const installed = await read(json);
      const response = await ctx
        .actor("owner", profile)
        .fetch(`${authProfilePath(profile)}/two-factor/verify-backup-code`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ code, trustDevice: true }),
        });
      const result = { status: response.status, body: await response.text() };
      expect(result.status).toBe(500);
      expect(result.body).toBe("");
      expect(await pending()).toEqual(start);
      expect(await read()).toEqual(installed);
      expect(await ctx.readUserState({ userId })).toEqual(before);
      errors.push(result);
    }
    // A parse failure is an invalid proof, rather than a runtime shape error.
    const malformed = await read("[");
    const invalid = await owner.twoFactor.verifyBackupCode({ code });
    expect(invalid.error?.code).toBe("INVALID_BACKUP_CODE");
    expect((await pending()).attempts).toBe("1");
    expect(await read()).toEqual({ ...malformed, failedVerificationCount: 1 });
    const mixed = [code, 7, null, false, { keep: ["雪", true] }, code, remaining];
    const installed = await read(JSON.stringify(mixed));
    expect(installed.id).toBe(original.id);
    expect(installed.userId).toBe(userId);
    const wrongOwner = await foreign.twoFactor.verifyBackupCode({ code });
    expect(wrongOwner.error?.code).toBe("INVALID_BACKUP_CODE");
    expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(foreignBefore);
    const completed = await owner.twoFactor.verifyBackupCode({ code });
    expect(completed.error).toBeNull();
    expect(completed.data?.user.id).toBe(userId);
    const consumed = await read();
    expect(consumed.id).toBe(original.id);
    expect(consumed.secret).toBe(published.row.secret);
    expect(consumed.failedVerificationCount).toBe(0);
    const decoded = JSON.parse(await symmetricDecrypt({ key: secret, data: consumed.backupCodes }));
    expect(decoded).toEqual([7, null, false, { keep: ["雪", true] }, remaining]);
    const retired = await pending(start.key);
    expect(retired.challenge).toBe(false);
    expect(retired.attempts).toBeNull();
    const replay = await owner.twoFactor.verifyBackupCode({ code });
    expect(replay.error?.code).toBe("INVALID_BACKUP_CODE");
    expect(await read()).toEqual(consumed);
    expect((await owner.getSession()).data?.session.token).toBe(completed.data?.token);
    expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(foreignBefore);
    return ctx.snapshot({
      errors,
      invalid,
      wrongOwner,
      completed,
      replay,
      retired: { ...retired, identifier: { token: retired.key }, key: undefined },
      remaining: decoded.length,
    });
  },
  ["POST /two-factor/verify-backup-code"],
);
