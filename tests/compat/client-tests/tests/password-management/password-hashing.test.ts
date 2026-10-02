import { beforeAll, expect } from "bun:test";
import { z } from "zod";
import { RUST_BASE_URL, requireHealthy, TS_BASE_URL } from "../../support/config";
import { compatScenario } from "../../support/scenario";

const password = "Ａuth-é-🔒";
const normalizedPassword = "Auth-e\u0301-🔒";
const replacementPassword = "replacement-pässword🔐123";
const hashFormat = /^[a-f0-9]{32}:[a-f0-9]{128}$/;
const sourceHashes = new Map<string, { imported: string; replacement: string }>();
const credential = z.object({ userId: z.string(), accountId: z.string(), hash: z.string() });

async function passwordControl(baseURL: string, body: unknown) {
  const response = await fetch(`${baseURL}/__test/password`, {
    method: "POST",
    headers: { "content-type": "application/json", connection: "close" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) throw new Error(`Password fixture operation failed: ${response.status}`);
  return response.json();
}

// Each generated hash is shared unchanged by the two runs of its scenario.
// The source runtime produces it with its actual configured password hasher.
beforeAll(async () => {
  await Promise.all([requireHealthy(TS_BASE_URL, "TS"), requireHealthy(RUST_BASE_URL, "Rust")]);
  for (const [source, baseURL] of [
    ["TypeScript", TS_BASE_URL],
    ["Rust", RUST_BASE_URL],
  ] as const) {
    const parseHash = (value: unknown) =>
      z.object({ hash: z.string().regex(hashFormat) }).parse(value).hash;
    const imported = parseHash(await passwordControl(baseURL, { operation: "hash", password }));
    const independentlySalted = parseHash(
      await passwordControl(baseURL, { operation: "hash", password }),
    );
    expect(independentlySalted).not.toBe(imported);
    const replacement = parseHash(
      await passwordControl(baseURL, {
        operation: "hash",
        password: replacementPassword,
      }),
    );
    sourceHashes.set(source, { imported, replacement });
  }
});

for (const source of ["TypeScript", "Rust"] as const) {
  compatScenario(
    `official client signs in with imported ${source} scrypt credentials`,
    async (ctx) => {
      const hashes = sourceHashes.get(source);
      if (!hashes) throw new Error(`Missing ${source} password hashes`);
      const owner = ctx.actor("owner");
      const email = ctx.uniqueEmail(`imported-${source.toLowerCase()}`);
      const otherEmail = ctx.uniqueEmail("other-owner");
      const signup = await owner.client.signUp.email({
        email,
        name: "Imported Credential Owner",
        password: "initial-password123",
      });
      const otherSignup = await ctx.actor("other-owner").client.signUp.email({
        email: otherEmail,
        name: "Other Credential Owner",
        password: "other-password123",
      });
      expect(signup.error).toBeNull();
      expect(otherSignup.error).toBeNull();
      const ownerId = signup.data?.user.id;
      if (!ownerId) throw new Error("Sign-up did not return the credential owner");
      await owner.client.signOut();

      const imported = await ctx.rawRequest({
        path: "/__test/password",
        method: "POST",
        json: { operation: "import", email, hash: hashes.imported },
      });
      expect(imported.status).toBe(200);
      const persisted = credential.parse(imported.body);
      expect(persisted.userId).toBe(ownerId);
      expect(persisted.hash).toBe(hashes.imported);

      const previousPassword = await ctx.actor("old-password").client.signIn.email({
        email,
        password: "initial-password123",
      });
      const wrongPassword = await ctx.actor("wrong-password").client.signIn.email({
        email,
        password: "Auth-e-🔒",
      });
      const wrongOwner = await ctx.actor("wrong-owner").client.signIn.email({
        email: otherEmail,
        password: normalizedPassword,
      });
      for (const rejected of [previousPassword, wrongPassword, wrongOwner]) {
        expect(rejected.data).toBeNull();
        expect(rejected.error?.status).toBe(401);
      }

      const signin = await ctx.actor("normalized-password").client.signIn.email({
        email,
        password: normalizedPassword,
      });
      const originalSpelling = await ctx
        .actor("original-password")
        .client.signIn.email({ email, password });
      expect(signin.error).toBeNull();
      expect(originalSpelling.error).toBeNull();
      expect(signin.data?.user.id).toBe(ownerId);
      expect(originalSpelling.data?.user.id).toBe(ownerId);
      expect(signin.data?.token).toBeTruthy();
      expect(originalSpelling.data?.token).not.toBe(signin.data?.token);
      const session = await ctx.actor("normalized-password").client.getSession();
      expect(session.data?.session.userId).toBe(ownerId);
      expect(session.data?.session.token).toBe(signin.data?.token);

      const afterSignin = await ctx.rawRequest({
        path: "/__test/password",
        method: "POST",
        json: { operation: "credential", email },
      });
      expect(afterSignin.status).toBe(200);
      expect(credential.parse(afterSignin.body)).toEqual(persisted);

      const replacement = await ctx.rawRequest({
        path: "/__test/password",
        method: "POST",
        json: { operation: "import", email, hash: hashes.replacement },
      });
      expect(replacement.status).toBe(200);
      expect(credential.parse(replacement.body)).toEqual({
        ...persisted,
        hash: hashes.replacement,
      });
      const replacedPassword = await ctx
        .actor("replaced-password")
        .client.signIn.email({ email, password });
      expect(replacedPassword.data).toBeNull();
      expect(replacedPassword.error?.status).toBe(401);
      const replacementSignin = await ctx.actor("replacement").client.signIn.email({
        email,
        password: replacementPassword,
      });
      expect(replacementSignin.error).toBeNull();
      expect(replacementSignin.data?.user.id).toBe(ownerId);
      const verification = await ctx.rawRequest({
        path: "/__test/password",
        method: "POST",
        json: { operation: "verify", password: replacementPassword, hash: hashes.replacement },
      });
      expect(verification).toEqual({ status: 200, location: null, body: { valid: true } });

      return {
        signup: ctx.snapshot(signup),
        otherSignup: ctx.snapshot(otherSignup),
        imported,
        previousPassword: ctx.snapshot(previousPassword),
        wrongPassword: ctx.snapshot(wrongPassword),
        wrongOwner: ctx.snapshot(wrongOwner),
        signin: ctx.snapshot(signin),
        originalSpelling: ctx.snapshot(originalSpelling),
        session: ctx.snapshot(session),
        afterSignin,
        replacement,
        replacedPassword: ctx.snapshot(replacedPassword),
        replacementSignin: ctx.snapshot(replacementSignin),
        verification,
      };
    },
    ["POST /sign-up/email", "POST /sign-in/email"],
  );
}

compatScenario("official client password limits count UTF-16 code units", async (ctx) => {
  const observations: unknown[] = [];
  for (const [label, value, accepted] of [
    ["four-accented-characters", "éééé", false],
    ["three-astral-characters", "🔒🔒🔒", false],
    ["four-astral-characters", "🔒🔒🔒🔒", true],
    ["over-maximum-astral-characters", "🔒".repeat(65), false],
  ] as const) {
    const result = await ctx.actor(label).client.signUp.email({
      email: ctx.uniqueEmail(label),
      name: "UTF-16 Password User",
      password: value,
    });
    if (accepted) {
      expect(result.error).toBeNull();
      expect(result.data?.token).toBeTruthy();
    } else {
      expect(result.data).toBeNull();
      expect(result.error?.status).toBe(400);
    }
    observations.push({ label, result: ctx.snapshot(result) });
  }
  return observations;
});
