import { Database } from "bun:sqlite";
import { expect } from "bun:test";
import { createHmac } from "node:crypto";

import { betterAuth } from "better-auth";
import { createAuthClient } from "better-auth/client";
import { twoFactorClient } from "better-auth/client/plugins";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { getMigrations } from "better-auth/db/migration";
import { twoFactor } from "better-auth/plugins";
import { Cookie } from "tough-cookie";
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
    const read = async (json?: string, targetUserId = userId) => {
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
        json: { userId: targetUserId, ...imported },
      });
      expect(response.status).toBe(200);
      return factorSchema.passthrough().parse(response.body);
    };
    const original = await read();
    const foreignFactor = await read(undefined, other.data!.user.id);
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
    const mixed = [
      code,
      7,
      null,
      false,
      { keep: ["雪", true] },
      code,
      remaining,
      "2025-01-02T03:04:05Z",
    ];
    const installed = await read(JSON.stringify(mixed));
    expect(installed.id).toBe(original.id);
    expect(installed.userId).toBe(userId);
    const wrongOwner = await foreign.twoFactor.verifyBackupCode({ code });
    expect(wrongOwner.error?.code).toBe("INVALID_BACKUP_CODE");
    expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(foreignBefore);
    expect(await read(undefined, other.data!.user.id)).toEqual(foreignFactor);
    const numericProof = await owner.twoFactor.verifyBackupCode({ code: "7" });
    expect(numericProof.error?.code).toBe("INVALID_BACKUP_CODE");
    expect((await pending()).attempts).toBe("2");
    expect(await read()).toEqual({ ...installed, failedVerificationCount: 2 });
    const dateProof = await owner.twoFactor.verifyBackupCode({ code: "2025-01-02T03:04:05Z" });
    expect(dateProof.error?.code).toBe("INVALID_BACKUP_CODE");
    expect((await pending()).attempts).toBe("3");
    expect(await read()).toEqual({ ...installed, failedVerificationCount: 3 });
    const completed = await owner.twoFactor.verifyBackupCode({ code });
    expect(completed.error).toBeNull();
    expect(completed.data?.user.id).toBe(userId);
    const consumed = await read();
    expect(consumed.id).toBe(original.id);
    expect(consumed.secret).toBe(published.row.secret);
    expect(consumed).toEqual({
      ...installed,
      backupCodes: consumed.backupCodes,
      failedVerificationCount: 0,
    });
    const decoded = JSON.parse(await symmetricDecrypt({ key: secret, data: consumed.backupCodes }));
    expect(decoded).toEqual([
      7,
      null,
      false,
      { keep: ["雪", true] },
      remaining,
      "2025-01-02T03:04:05.000Z",
    ]);
    const retired = await pending(start.key);
    expect(retired.challenge).toBe(false);
    expect(retired.attempts).toBeNull();
    const replay = await owner.twoFactor.verifyBackupCode({ code });
    expect(replay.error?.code).toBe("INVALID_BACKUP_CODE");
    expect(await read()).toEqual(consumed);
    expect((await owner.getSession()).data?.session.token).toBe(completed.data?.token);
    expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(foreignBefore);
    expect(await read(undefined, other.data!.user.id)).toEqual(foreignFactor);
    return ctx.snapshot({
      errors,
      numericProof,
      dateProof,
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

compatScenario("two-factor remaining heterogeneous view and serializer contracts", async (ctx) => {
  const profile = "two-factor-skip-verification";
  const owner = createAuthClient({
    baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
    plugins: [twoFactorClient()],
    fetchOptions: { customFetchImpl: ctx.actor("owner", profile).fetch },
  });
  const password = "password123";
  const email = ctx.uniqueEmail("remaining-json");
  const signup = await owner.signUp.email({ email, password, name: "Remaining Owner" });
  expect(signup.error).toBeNull();
  const userId = signup.data!.user.id;
  expect((await owner.twoFactor.enable({ password })).error).toBeNull();
  const published = await publishedFactor(email);
  const code = published.enrollment.backupCodes[0]!;
  const install = async (json: string) => {
    const response = await ctx.rawRequest({
      path: "/__test/two-factor-policy",
      method: "POST",
      json: {
        userId,
        importFactor: {
          secret: published.row.secret,
          backupCodes: await symmetricEncrypt({ key: secret, data: json }),
        },
      },
    });
    expect(response.status).toBe(200);
    return factorSchema.passthrough().parse(response.body);
  };
  const view = async () =>
    ctx.rawRequest({ path: `/__test/view-backup-codes?userId=${userId}`, method: "GET" });
  const observations = [];
  for (const [json, expected] of [
    [
      '{"nested":["2025-02-30T00:00:00Z",1e400],"__proto__":{"keep":true}}',
      { nested: ["2025-03-02T00:00:00.000Z", null], __proto__: { keep: true } },
    ],
    ["true", true],
    ["42", 42],
    ['"present"', "present"],
    ["1e400", null],
    ["[]", []],
  ] as const) {
    const installed = await install(json);
    const result = await view();
    expect(result.status).toBe(200);
    // Object literal __proto__ is a setter; use parsed expected JSON for that own key.
    const expectedValue = json.startsWith("{")
      ? JSON.parse('{"nested":["2025-03-02T00:00:00.000Z",null],"__proto__":{"keep":true}}')
      : expected;
    expect(result.body).toEqual({ status: true, backupCodes: expectedValue });
    expect(
      (
        await ctx.rawRequest({
          path: "/__test/two-factor-policy",
          method: "POST",
          json: { userId },
        })
      ).body,
    ).toEqual(installed);
    observations.push(result);
  }
  for (const json of ["[", "null", "false", "0", "-0", '""']) {
    await install(json);
    const result = await view();
    expect(result.status).toBe(500);
    expect(result.body).toEqual({ message: "Invalid backup code" });
    observations.push(result);
  }
  const dates = ["2025-02-30T00:00:00Z", "9999-12-31T24:00:00Z", "2025-01-02T03:04:05.123456Z"];
  const invalidDates = [
    "+275760-09-13T00:00:00.000Z",
    "2025-02-32T00:00:00Z",
    "2025-01-02T03:04:60Z",
  ];
  const json = `[${JSON.stringify(code)},${dates.map((x) => JSON.stringify(x)).join(",")},1e400,-1e400,9007199254740993,${invalidDates.map((x) => JSON.stringify(x)).join(",")}]`;
  await install(json);
  for (const date of dates) {
    const denied = await owner.twoFactor.verifyBackupCode({ code: date });
    expect(denied.error?.code).toBe("INVALID_BACKUP_CODE");
  }
  const completed = await owner.twoFactor.verifyBackupCode({ code });
  expect(completed.error).toBeNull();
  const after = await ctx.rawRequest({
    path: "/__test/two-factor-policy",
    method: "POST",
    json: { userId },
  });
  const row = factorSchema.parse(after.body);
  const plaintext = await symmetricDecrypt({ key: secret, data: row.backupCodes });
  expect(plaintext).toBe(
    JSON.stringify([
      "2025-03-02T00:00:00.000Z",
      "+010000-01-01T00:00:00.000Z",
      "2025-01-02T03:04:05.123Z",
      null,
      null,
      9007199254740992,
      ...invalidDates,
    ]),
  );
  // Expanded-year strings are outside the actual reviver grammar and remain string proofs.
  const expanded = await owner.twoFactor.verifyBackupCode({ code: invalidDates[0]! });
  expect(expanded.error).toBeNull();
  return ctx.snapshot({ observations, completed, expanded, plaintext });
});

for (const profile of [
  "two-factor-pending-session-cancel",
  "two-factor-pending-session-forbidden",
  "two-factor-pending-session-ordinary",
] as const) {
  compatScenario(
    `two-factor remaining corruption before ${profile} preserves error stage and retirement`,
    async (ctx) => {
      const client = (actor: string) =>
        createAuthClient({
          baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
          plugins: [twoFactorClient()],
          fetchOptions: { customFetchImpl: ctx.actor(actor, profile).fetch },
        });
      const owner = client("owner");
      const foreign = client("foreign");
      const password = "password123";
      const email = ctx.uniqueEmail("combined-corruption");
      const signup = await owner.signUp.email({ email, password, name: "Combined Owner" });
      expect(signup.error).toBeNull();
      const userId = signup.data!.user.id;
      expect((await owner.twoFactor.enable({ password })).error).toBeNull();
      const other = await foreign.signUp.email({
        email: ctx.uniqueEmail("foreign"),
        password,
        name: "Foreign",
      });
      expect(other.error).toBeNull();
      const foreignBefore = await ctx.readUserState({ userId: other.data!.user.id });
      const published = await publishedFactor(email);
      const code = published.enrollment.backupCodes[0]!;
      const policy = async (body: Record<string, unknown> = {}) => {
        const result = await ctx.rawRequest({
          path: "/__test/two-factor-policy",
          method: "POST",
          json: { userId, ...body },
        });
        expect(result.status).toBe(200);
        return result.body;
      };
      const install = async (json: string) =>
        factorSchema.passthrough().parse(
          await policy({
            importFactor: {
              secret: published.row.secret,
              backupCodes: await symmetricEncrypt({ key: secret, data: json }),
            },
          }),
        );
      await owner.signOut();
      expect((await owner.signIn.email({ email, password })).data).toMatchObject({
        twoFactorRedirect: true,
      });
      const before = z
        .object({
          key: z.string(),
          challenge: z.boolean(),
          attempts: z.string().nullable(),
          trustCount: z.number(),
        })
        .passthrough()
        .parse(await policy({ pendingState: true }));
      const shape = await install("1e400");
      const failed = await ctx
        .actor("owner", profile)
        .fetch(`${authProfilePath(profile)}/two-factor/verify-backup-code`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ code, trustDevice: true }),
        });
      expect(failed.status).toBe(500);
      expect(await failed.text()).toBe("");
      expect(await policy({ pendingState: true })).toEqual(before);
      expect(await policy()).toEqual(shape);
      const mixed = await install(JSON.stringify([code, { keep: true }, code]));
      const result = await ctx
        .actor("owner", profile)
        .fetch(`${authProfilePath(profile)}/two-factor/verify-backup-code`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ code, trustDevice: true }),
        });
      const text = await result.text();
      expect(result.headers.getSetCookie()).toEqual([]);
      if (profile.endsWith("ordinary")) {
        expect(result.status).toBe(500);
        expect(text).toBe("");
      } else if (profile.endsWith("cancel")) {
        expect(result.status).toBe(500);
        expect(JSON.parse(text)).toEqual({
          message: "failed to create session",
          code: "FAILED_TO_CREATE_SESSION",
        });
      } else {
        expect(result.status).toBe(403);
        expect(JSON.parse(text)).toEqual({
          message: "session creation cancelled by database hook",
        });
      }
      const after = z
        .object({ challenge: z.boolean(), attempts: z.string().nullable(), trustCount: z.number() })
        .passthrough()
        .parse(await policy({ pendingState: true, pendingKey: before.key }));
      expect(after).toMatchObject({ challenge: false, attempts: null, trustCount: 0 });
      const stored = factorSchema.passthrough().parse(await policy());
      expect(stored).toEqual({ ...mixed, backupCodes: stored.backupCodes });
      expect(JSON.parse(await symmetricDecrypt({ key: secret, data: stored.backupCodes }))).toEqual(
        [{ keep: true }],
      );
      const state = z
        .object({ sessions: z.array(z.unknown()) })
        .passthrough()
        .parse(await ctx.readUserState({ userId }));
      expect(state.sessions).toEqual([]);
      const replay = await owner.twoFactor.verifyBackupCode({ code });
      expect(replay.error?.code).toBe("INVALID_TWO_FACTOR_COOKIE");
      expect(await policy()).toEqual(stored);
      expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(foreignBefore);
      return ctx.snapshot({
        status: result.status,
        body: text ? JSON.parse(text) : null,
        after: { ...after, key: { token: before.key } },
        state,
        replay,
      });
    },
  );
}

const signedRaw = (payload: string) =>
  `${payload}.${createHmac("sha256", secret).update(payload).digest("base64")}`;
const bitAlias = (raw: string) => {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const i = raw.length - 2;
  const next = alphabet[alphabet.indexOf(raw[i]!) + 1]!;
  const result = raw.slice(0, i) + next + raw.slice(i + 1);
  expect(Buffer.from(result.slice(result.lastIndexOf(".") + 1), "base64")).toEqual(
    Buffer.from(raw.slice(raw.lastIndexOf(".") + 1), "base64"),
  );
  return result;
};

const wireCases = [
  {
    name: "uri",
    key: "2fa-雪-é.uri",
    pref: "雪-é",
    wire: (x: string) =>
      encodeURIComponent(x)
        .replace(/%[0-9A-F]{2}/g, (x) => x.toLowerCase())
        .replace(/\./g, "%2e"),
  },
  {
    name: "base64",
    key: "2fa-bits",
    pref: "yes",
    wire: (x: string) => encodeURIComponent(bitAlias(x)),
  },
  { name: "malformed-uri", key: "2fa-%E9", pref: "%E9", wire: (x: string) => x },
  {
    name: "quoted",
    key: "2fa-quoted",
    pref: "temporary",
    wire: (x: string) => `"${encodeURIComponent(x)}"`,
  },
  {
    name: "key-whitespace",
    key: "2fa-key-whitespace",
    pref: "yes",
    wire: (x: string) => encodeURIComponent(x),
  },
] as const;
for (const c of wireCases) {
  compatScenario(
    `two-factor remaining pending preference and disable cookie wire aliases ${c.name}`,
    async (ctx) => {
      const profile = "two-factor-pending-lookup";
      const history: Cookie[] = [];
      const owner = createAuthClient({
        baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
        plugins: [twoFactorClient()],
        fetchOptions: {
          customFetchImpl: ctx.actor("owner", profile).fetch,
          onResponse: ({ response }) => {
            for (const raw of response.headers.getSetCookie()) {
              const cookie = Cookie.parse(raw);
              if (cookie) history.push(cookie);
            }
          },
        },
      });
      const password = "password123";
      const email = ctx.uniqueEmail("wire-alias");
      const signup = await owner.signUp.email({ email, password, name: "Wire Owner" });
      expect(signup.error).toBeNull();
      const userId = signup.data!.user.id;
      const enabled = await owner.twoFactor.enable({ password });
      expect(enabled.error).toBeNull();
      const codes = enrollmentSchema.parse(enabled.data).backupCodes;
      const other = createAuthClient({
        baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
        plugins: [twoFactorClient()],
        fetchOptions: { customFetchImpl: ctx.actor("foreign", profile).fetch },
      });
      const foreign = await other.signUp.email({
        email: ctx.uniqueEmail("foreign-wire"),
        password,
        name: "Foreign",
      });
      expect(foreign.error).toBeNull();
      const foreignBefore = await ctx.readUserState({ userId: foreign.data!.user.id });
      const control = async (body: Record<string, unknown>) => {
        const r = await ctx.rawRequest({
          path: "/__test/two-factor-pending-lookup",
          method: "POST",
          json: { profile, ...body },
        });
        expect(r.status).toBe(200);
        return r.body;
      };
      const rows = async (identifier: string) => await ctx.readVerificationState({ identifier });
      await owner.signOut();

      const observations = [];
      const index = 0;
      {
        for (const [identifier, value] of [
          [c.key, userId],
          [`2fa-attempts-${c.key}`, "0"],
        ]) {
          await control({
            action: "seed",
            identifier,
            value,
            expiresAt: "2030-01-01T00:00:00.000Z",
          });
        }
        const pair = (suffix: string, payload: string) =>
          `better-auth.${suffix}${c.name === "key-whitespace" ? " \t" : ""}=${c.wire(signedRaw(payload))}`;
        const cookie = `${pair("two_factor", c.key)}; ${pair("dont_remember", c.pref)}${c.name === "key-whitespace" ? "; better-auth.two_factor=invalid; better-auth.dont_remember=invalid" : ""}`;
        const before = await rows(c.key);
        const attempts = await rows(`2fa-attempts-${c.key}`);
        // Valid HMAC bytes without required padding must fail before attempt consumption.
        const bad = await owner.twoFactor.verifyBackupCode(
          { code: codes[index]! },
          {
            headers: {
              cookie: `better-auth.two_factor=${encodeURIComponent(signedRaw(c.key).slice(0, -1))}`,
            },
          },
        );
        expect(bad.error?.code).toBe("INVALID_TWO_FACTOR_COOKIE");
        expect(await rows(c.key)).toEqual(before);
        expect(await rows(`2fa-attempts-${c.key}`)).toEqual(attempts);
        let malformedPreference: unknown = null;
        if (c.name === "uri") {
          const key = "2fa-malformed-preference";
          for (const [identifier, value] of [
            [key, userId],
            [`2fa-attempts-${key}`, "0"],
          ]) {
            await control({
              action: "seed",
              identifier,
              value,
              expiresAt: "2030-01-01T00:00:00.000Z",
            });
          }
          const offset = history.length;
          malformedPreference = await owner.twoFactor.verifyBackupCode(
            { code: codes[1]! },
            {
              headers: {
                cookie: `better-auth.two_factor=${encodeURIComponent(signedRaw(key))}; better-auth.dont_remember=${encodeURIComponent(signedRaw("temporary").slice(0, -1))}`,
              },
            },
          );
          expect((malformedPreference as { error: unknown }).error).toBeNull();
          expect(await rows(key)).toEqual([]);
          expect(await rows(`2fa-attempts-${key}`)).toEqual([]);
          expect(
            history.slice(offset).findLast((x) => x.key === "better-auth.session_token")?.maxAge,
          ).toBe(604800);
          expect(
            history.slice(offset).filter((x) => x.key === "better-auth.dont_remember"),
          ).toEqual([]);
          await owner.signOut();
        }
        const start = history.length;
        const result = await owner.twoFactor.verifyBackupCode(
          { code: codes[index]!, trustDevice: true },
          { headers: { cookie } },
        );
        expect(result.error).toBeNull();
        expect(result.data?.user.id).toBe(userId);
        expect(await rows(c.key)).toEqual([]);
        expect(await rows(`2fa-attempts-${c.key}`)).toEqual([]);
        const issued = history.slice(start);
        expect(issued.findLast((x) => x.key === "better-auth.two_factor")).toMatchObject({
          value: "",
          maxAge: 0,
        });
        expect(issued.findLast((x) => x.key === "better-auth.dont_remember")).toMatchObject({
          value: "",
          maxAge: 0,
        });
        const session = issued.findLast((x) => x.key === "better-auth.session_token");
        expect(session?.maxAge).toBeNull();
        const trust = issued.findLast((x) => x.key === "better-auth.trust_device");
        expect(trust).toBeDefined();
        const trustPayload = decodeURIComponent(trust!.value).split(".").slice(0, -1).join(".");
        const trustIdentifier = trustPayload.split("!")[1]!;
        expect(await rows(trustIdentifier)).not.toEqual([]);
        // Disable reads its trust proof independently of the inner trust-token check.
        // Give that route a Unicode/malformed-URI payload and the issued row identity.
        const disablePayload = `${c.pref}!${trustIdentifier}`;
        let sessionPair = `${session!.key}=${session!.value}`;
        const invalidDisable = await owner.twoFactor.disable(
          { password: "wrong" },
          {
            headers: {
              cookie: `${sessionPair}; ${pair("trust_device", disablePayload)}${c.name === "key-whitespace" ? "; better-auth.trust_device=invalid" : ""}`,
            },
          },
        );
        expect(invalidDisable.error?.code).toBe("INVALID_PASSWORD");
        expect(await rows(trustIdentifier)).not.toEqual([]);
        let malformedDisable: unknown = null;
        if (c.name === "uri") {
          const offset = history.length;
          malformedDisable = await owner.twoFactor.disable(
            { password },
            {
              headers: {
                cookie: `${sessionPair}; better-auth.trust_device=${encodeURIComponent(signedRaw(disablePayload).slice(0, -1))}`,
              },
            },
          );
          expect((malformedDisable as { error: unknown }).error).toBeNull();
          expect(await rows(trustIdentifier)).not.toEqual([]);
          expect(history.slice(offset).filter((x) => x.key === "better-auth.trust_device")).toEqual(
            [],
          );
          expect((await owner.twoFactor.enable({ password })).error).toBeNull();
          const current = history.findLast(
            (x) => x.key === "better-auth.session_token" && x.value,
          )!;
          sessionPair = `${current.key}=${current.value}`;
        }
        const clearedStart = history.length;
        const disabled = await owner.twoFactor.disable(
          { password },
          {
            headers: {
              cookie: `${sessionPair}; ${pair("trust_device", disablePayload)}${c.name === "key-whitespace" ? "; better-auth.trust_device=invalid" : ""}`,
            },
          },
        );
        expect(disabled.error).toBeNull();
        expect(await rows(trustIdentifier)).toEqual([]);
        expect(
          history.slice(clearedStart).findLast((x) => x.key === "better-auth.trust_device"),
        ).toMatchObject({ value: "", maxAge: 0 });
        expect(await ctx.readUserState({ userId: foreign.data!.user.id })).toEqual(foreignBefore);
        observations.push({
          bad,
          result,
          malformedPreference,
          invalidDisable,
          malformedDisable,
          disabled,
        });
        await owner.signOut();
      }
      return ctx.snapshot({ observations });
    },
  );
}

for (const phase of ["decrypt", "encrypt"] as const) {
  for (const mode of ["ordinary", "explicit"] as const) {
    compatScenario(
      `two-factor remaining custom cipher ${phase} ${mode} error with installed corruption`,
      async (ctx) => {
        const profile = "two-factor-backup-custom";
        let challengeCookie = "";
        const owner = createAuthClient({
          baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
          plugins: [twoFactorClient()],
          fetchOptions: {
            customFetchImpl: ctx.actor("owner", profile).fetch,
            onResponse: ({ response }) => {
              for (const raw of response.headers.getSetCookie()) {
                const cookie = Cookie.parse(raw);
                if (cookie?.key === "better-auth.two_factor" && cookie.value) {
                  challengeCookie = cookie.value;
                }
              }
            },
          },
        });
        const password = "password123";
        const email = ctx.uniqueEmail("cipher-corruption");
        const signup = await owner.signUp.email({ email, password, name: "Cipher Owner" });
        expect(signup.error).toBeNull();
        const userId = signup.data!.user.id;
        const enabled = await owner.twoFactor.enable({ password });
        expect(enabled.error).toBeNull();
        const code = enrollmentSchema.parse(enabled.data).backupCodes[0]!;
        const policy = async (body: Record<string, unknown> = {}) => {
          const result = await ctx.rawRequest({
            path: "/__test/two-factor-policy",
            method: "POST",
            json: { userId, ...body },
          });
          expect(result.status).toBe(200);
          return result.body;
        };
        const original = factorSchema.passthrough().parse(await policy());
        await owner.signOut();
        expect((await owner.signIn.email({ email, password })).data).toMatchObject({
          twoFactorRedirect: true,
        });
        const before = z
          .object({ key: z.string(), attempts: z.string().nullable(), challenge: z.boolean() })
          .passthrough()
          .parse(await policy({ pendingState: true }));
        const json = JSON.stringify([code, { reject: mode }, code]);
        const installed = factorSchema.passthrough().parse(
          await policy({
            importFactor: {
              secret: original.secret,
              backupCodes: phase === "decrypt" ? `backup-throw-decrypt-${mode}` : `backup-${json}`,
            },
          }),
        );
        const stateBefore = await ctx.readUserState({ userId });
        const response = await ctx
          .actor("owner", profile)
          .fetch(`${authProfilePath(profile)}/two-factor/verify-backup-code`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ code, trustDevice: true }),
          });
        const text = await response.text();
        expect(response.headers.getSetCookie()).toEqual([]);
        expect(response.status).toBe(mode === "ordinary" ? 500 : 403);
        if (mode === "ordinary") expect(text).toBe("");
        else {
          expect(JSON.parse(text)).toEqual({
            message: "session creation cancelled by database hook",
            code: "BACKUP_CALLBACK_DENIED",
          });
        }
        expect(await policy()).toEqual(installed);
        expect(await ctx.readUserState({ userId })).toEqual(stateBefore);
        const after = z
          .object({ key: z.string(), attempts: z.string().nullable(), challenge: z.boolean() })
          .passthrough()
          .parse(await policy({ pendingState: true }));
        expect(after).toEqual({ ...before, attempts: phase === "decrypt" ? "0" : null });
        // Restore only the application's installed storage; the actual pending
        // attempt/challenge owner decides whether the same proof can complete.
        await policy({
          importFactor: {
            secret: original.secret,
            backupCodes: `backup-${JSON.stringify([code, code, { keep: true }])}`,
          },
        });
        let completionKey = before.key;
        if (phase === "encrypt") {
          const deniedRetry = await owner.twoFactor.verifyBackupCode({ code });
          expect(deniedRetry.error?.code).toBe("INVALID_TWO_FACTOR_COOKIE");
          expect(await policy({ pendingState: true, pendingKey: before.key })).toEqual(after);
          expect((await owner.signIn.email({ email, password })).data).toMatchObject({
            twoFactorRedirect: true,
          });
          const raw = decodeURIComponent(challengeCookie);
          completionKey = raw.slice(0, raw.lastIndexOf("."));
          expect(completionKey).not.toBe(before.key);
        }
        const completed = await owner.twoFactor.verifyBackupCode({ code, trustDevice: true });
        expect(completed.error).toBeNull();
        expect(completed.data?.user.id).toBe(userId);
        const retired = z
          .object({ challenge: z.boolean(), attempts: z.string().nullable() })
          .passthrough()
          .parse(await policy({ pendingState: true, pendingKey: completionKey }));
        expect(retired).toMatchObject({ challenge: false, attempts: null });
        const consumed = factorSchema.passthrough().parse(await policy());
        expect(consumed.id).toBe(original.id);
        expect(consumed.secret).toBe(original.secret);
        expect(consumed.backupCodes).toBe('backup-[{"keep":true}]');
        const replay = await owner.twoFactor.verifyBackupCode({ code });
        expect(replay.error?.code).toBe("INVALID_BACKUP_CODE");
        expect(await policy()).toEqual(consumed);
        return ctx.snapshot({
          status: response.status,
          body: text ? JSON.parse(text) : null,
          after: { ...after, key: { token: before.key } },
          completed,
          replay,
        });
      },
    );
  }
}
