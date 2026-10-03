import { expect } from "bun:test";
import { mkdir } from "node:fs/promises";

import { passkeyClient } from "@better-auth/passkey/client";
import { createAuthClient } from "better-auth/client";
import { z } from "zod";

import { compatScenario, type ScenarioContext } from "../../../support/scenario";
import {
  CertificateDevice,
  type AttestationFormat,
  type CeremonyMode,
  publicKey,
  replacementPublicKey,
} from "./certificate-device";

const path = "/__test/profiles/passkey-acceptance/api/auth";
const formats: AttestationFormat[] = [
  "packed",
  "fido-u2f",
  "android-key",
  "apple",
  "tpm",
  "android-safetynet",
];
function client(ctx: ScenarioContext, actor: string) {
  return createAuthClient({
    baseURL: ctx.baseURL + path,
    plugins: [passkeyClient()],
    fetchOptions: { customFetchImpl: ctx.actor(actor).fetch },
  });
}
async function state(ctx: ScenarioContext, id: string) {
  const result = await ctx.rawRequest({ path: "/__test/passkey-state?userId=" + id });
  expect(result.status).toBe(200);
  return z
    .object({
      passkeys: z.array(
        z.object({ userId: z.string(), counter: z.number(), name: z.string().nullable() }),
      ),
      sessions: z.object({ count: z.number() }),
      challenges: z.object({ count: z.number() }),
    })
    .parse(result.body);
}
async function physical(ctx: ScenarioContext, id: string) {
  return { passkey: await state(ctx, id), user: await ctx.readUserState({ userId: id }) };
}
async function retain(ctx: ScenarioContext, label: string, value: unknown) {
  if (process.env.COMPAT_OBSERVATIONS_DIR) {
    await mkdir(process.env.COMPAT_OBSERVATIONS_DIR, { recursive: true });
    await Bun.write(
      `${process.env.COMPAT_OBSERVATIONS_DIR}/raw-${new URL(ctx.baseURL).port}-${label}.json`,
      JSON.stringify(value, null, 2),
    );
  }
}

for (const format of formats) {
  compatScenario(
    `passkey certificate ${format} verifies genuine authority, UV-absent enrollment, denial, retry, replay and current-row counters`,
    async (ctx) => {
      const owner = client(ctx, "owner");
      const foreign = client(ctx, "foreign");
      const signup = await owner.signUp.email({
        email: ctx.uniqueEmail("certificate-owner"),
        name: "Certificate owner",
        password: "password123",
      });
      let foreignCookies: string[] = [];
      const other = await foreign.signUp.email(
        {
          email: ctx.uniqueEmail("certificate-foreign"),
          name: "Foreign owner",
          password: "password123",
        },
        {
          onSuccess({ response }) {
            foreignCookies = response.headers.getSetCookie();
          },
        },
      );
      expect(signup.error).toBeNull();
      expect(other.error).toBeNull();
      const id = signup.data!.user.id;
      const foreignId = other.data!.user.id;
      const foreignBefore = await physical(ctx, foreignId);
      const modes: CeremonyMode[] = [
        "wrong-rp",
        "wrong-origin",
        "wrong-root",
        "signature",
        ...(format === "fido-u2f" ? ["nonzero-aaguid" as const] : []),
        ...(format === "apple" ||
        format === "android-key" ||
        format === "tpm" ||
        format === "android-safetynet"
          ? ["wrong-nonce" as const]
          : []),
        ...(format === "android-safetynet" ? ["cts" as const, "future" as const] : []),
      ];
      const denied = [];
      for (const mode of modes) {
        const before = await physical(ctx, id);
        const options = await owner.$fetch("/passkey/generate-register-options", { method: "GET" });
        expect(options.error).toBeNull();
        const device = new CertificateDevice(`certificate-${format}-${mode}`);
        const proof = device.register(options.data, ctx.baseURL, format, mode);
        const attempt = await owner.$fetch("/passkey/verify-registration", {
          method: "POST",
          body: { response: proof, createSession: true },
        });
        expect(attempt.error).not.toBeNull();
        expect((attempt.error as any).code).toBe("FAILED_TO_VERIFY_REGISTRATION");
        expect(await physical(ctx, id)).toEqual(before);
        const replay = await owner.$fetch("/passkey/verify-registration", {
          method: "POST",
          body: { response: proof, createSession: true },
        });
        expect((replay.error as any).code).toBe("CHALLENGE_NOT_FOUND");
        await retain(ctx, `${format}-${mode}`, {
          options,
          proof,
          attempt,
          replay,
          before,
          after: await physical(ctx, id),
        });
        denied.push({
          mode,
          attempt: ctx.snapshot(attempt),
          replay: ctx.snapshot(replay),
          physical: await physical(ctx, id),
        });
      }
      let challengeCookie = "";
      const options = await owner.$fetch("/passkey/generate-register-options", {
        method: "GET",
        onSuccess({ response }) {
          challengeCookie = response.headers
            .getSetCookie()
            .find((value) => value.startsWith("better-auth.ceremony-proof="))!
            .split(";")[0]!;
        },
      });
      expect(options.error).toBeNull();
      expect(challengeCookie).toStartWith("better-auth.ceremony-proof=");
      const device = new CertificateDevice(`certificate-${format}-accepted`);
      const proof = device.register(
        options.data,
        ctx.baseURL,
        format,
        format === "packed" ? "extension" : "crossOrigin",
      );
      const wrongOwner = await foreign.$fetch("/passkey/verify-registration", {
        method: "POST",
        headers: {
          cookie:
            foreignCookies.map((cookie) => cookie.split(";")[0]).join("; ") +
            "; " +
            challengeCookie,
        },
        body: { response: proof, createSession: true },
      });
      expect((wrongOwner.error as any).code).toBe("YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY");
      expect((await state(ctx, id)).passkeys).toEqual([]);
      expect(await physical(ctx, foreignId)).toEqual(foreignBefore);
      const fresh = await owner.$fetch("/passkey/generate-register-options", { method: "GET" });
      expect(fresh.error).toBeNull();
      const validProof = device.register(
        fresh.data,
        ctx.baseURL,
        format,
        format === "packed" ? "extension" : "crossOrigin",
      );
      const registered = await owner.$fetch("/passkey/verify-registration", {
        method: "POST",
        body: {
          response: validProof,
          createSession: true,
          name: " \uFEFF Certified device \u00a0 ",
        },
      });
      expect(registered.error).toBeNull();
      const saved = z
        .object({
          id: z.string(),
          userId: z.string(),
          name: z.string(),
          publicKey: z.string(),
          credentialID: z.string(),
          counter: z.number(),
          deviceType: z.string(),
          backedUp: z.boolean(),
          transports: z.string(),
          createdAt: z.date(),
          aaguid: z.string(),
          session: z.object({ id: z.string(), token: z.string(), userId: z.string() }),
          user: z.object({ id: z.string() }),
        })
        .parse(registered.data);
      expect(saved.name).toBe("Certified device");
      expect(saved.publicKey).toBe(publicKey.toString("base64"));
      expect(saved.userId).toBe(id);
      expect(saved.user.id).toBe(id);
      expect(saved.session.userId).toBe(id);
      expect(saved.counter).toBe(0);
      expect(saved.backedUp).toBe(false);
      expect(saved.deviceType).toBe("singleDevice");
      expect(saved.transports).toBe("internal");
      expect(saved.aaguid).toBe("00000000-0000-0000-0000-000000000000");
      const current = await owner.getSession();
      expect(current.data!.session.id).toBe(saved.session.id);
      expect(current.data!.session.token).toBe(saved.session.token);
      const enrolled = await physical(ctx, id);
      const replay = await owner.$fetch("/passkey/verify-registration", {
        method: "POST",
        body: { response: validProof, createSession: true },
      });
      expect((replay.error as any).code).toBe("CHALLENGE_NOT_FOUND");
      expect(await physical(ctx, id)).toEqual(enrolled);
      await owner.signOut();
      const beforeLogin = await physical(ctx, id);
      const authOptions = await owner.$fetch("/passkey/generate-authenticate-options", {
        method: "GET",
      });
      expect(authOptions.error).toBeNull();
      const invalid = device.authenticate(authOptions.data, ctx.baseURL, 1, true);
      const bad = await owner.$fetch("/passkey/verify-authentication", {
        method: "POST",
        body: { response: invalid },
      });
      expect((bad.error as any).code).toBe("AUTHENTICATION_FAILED");
      expect(await physical(ctx, id)).toEqual(beforeLogin);
      const newAuth = await owner.$fetch("/passkey/generate-authenticate-options", {
        method: "GET",
      });
      expect(newAuth.error).toBeNull();
      const assertion = device.authenticate(newAuth.data, ctx.baseURL);
      const login = await owner.$fetch("/passkey/verify-authentication", {
        method: "POST",
        body: { response: assertion },
      });
      expect(login.error).toBeNull();
      expect((login.data as any).user.id).toBe(id);
      expect((await state(ctx, id)).passkeys).toEqual([
        { userId: id, counter: 1, name: "Certified device" },
      ]);
      const final = await physical(ctx, id);
      const authReplay = await owner.$fetch("/passkey/verify-authentication", {
        method: "POST",
        body: { response: assertion },
      });
      expect((authReplay.error as any).code).toBe("CHALLENGE_NOT_FOUND");
      expect(await physical(ctx, id)).toEqual(final);
      const foreignAfter = await physical(ctx, foreignId);
      expect(foreignAfter.user).toEqual(foreignBefore.user);
      expect(foreignAfter.passkey.sessions).toEqual(foreignBefore.passkey.sessions);
      expect(foreignAfter.passkey.passkeys.filter((row) => row.userId === foreignId)).toEqual([]);
      await retain(ctx, `${format}-accepted`, {
        signup,
        other,
        fresh,
        validProof,
        registered,
        wrongOwner,
        replay,
        authOptions,
        invalid,
        bad,
        newAuth,
        assertion,
        login,
        authReplay,
        final,
        foreignBefore,
      });
      return {
        signup: ctx.snapshot(signup),
        other: ctx.snapshot(other),
        denied,
        wrongOwner: ctx.snapshot(wrongOwner),
        registered: ctx.snapshot(registered),
        current: ctx.snapshot(current),
        replay: ctx.snapshot(replay),
        bad: ctx.snapshot(bad),
        login: ctx.snapshot(login),
        authReplay: ctx.snapshot(authReplay),
        final,
        foreignBefore,
        foreignAfter,
      };
    },
  );
}

compatScenario(
  "passkey current publicKey authority and request admission preserve genuine ceremony order",
  async (ctx) => {
    const owner = client(ctx, "key-owner");
    const signup = await owner.signUp.email({
      email: ctx.uniqueEmail("key-authority"),
      name: "Key owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    const id = signup.data!.user.id;
    const options = await owner.$fetch("/passkey/generate-register-options", { method: "GET" });
    const device = new CertificateDevice("key-authority");
    const proof = device.register(options.data, ctx.baseURL, "packed");
    const before = await physical(ctx, id);
    const schema = [];
    for (const name of [null, 17, {}, []]) {
      const rejected = await owner.$fetch("/passkey/verify-registration", {
        method: "POST",
        body: { response: proof, name },
      });
      expect((rejected.error as any).code).toBe("VALIDATION_ERROR");
      expect(await physical(ctx, id)).toEqual(before);
      schema.push(ctx.snapshot(rejected));
    }
    const registered = await owner.$fetch("/passkey/verify-registration", {
      method: "POST",
      body: { response: proof, name: "First key" },
    });
    expect(registered.error).toBeNull();
    const row = registered.data as any;
    const invalidName = await owner.$fetch("/passkey/update-passkey", {
      method: "POST",
      body: { id: row.id, name: " \uFEFF \u00a0 " },
    });
    expect((invalidName.error as any).code).toBe("VALIDATION_ERROR");
    const renamed = await owner.$fetch("/passkey/update-passkey", {
      method: "POST",
      body: { id: row.id, name: " \uFEFF New key \u00a0 " },
    });
    expect(renamed.error).toBeNull();
    expect((await state(ctx, id)).passkeys[0]!.name).toBe("New key");
    await owner.signOut();
    const authOptions = await owner.$fetch("/passkey/generate-authenticate-options", {
      method: "GET",
    });
    const beforeSchema = await physical(ctx, id);
    const missingAuthentication = await owner.$fetch("/passkey/verify-authentication", {
      method: "POST",
      body: {},
    });
    expect((missingAuthentication.error as any).code).toBe("VALIDATION_ERROR");
    expect(await physical(ctx, id)).toEqual(beforeSchema);
    const swapped = await ctx.rawRequest({
      method: "POST",
      path: "/__test/passkey-public-key",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        credentialId: proof.id,
        publicKey: Buffer.concat([replacementPublicKey, Buffer.from([0])]).toString("base64"),
      }),
    });
    expect(swapped.body).toEqual({ updated: 1 });
    const prior = await physical(ctx, id);
    const stale = device.authenticate(authOptions.data, ctx.baseURL);
    const denied = await owner.$fetch("/passkey/verify-authentication", {
      method: "POST",
      body: { response: stale },
    });
    expect((denied.error as any).code).toBe("AUTHENTICATION_FAILED");
    expect(await physical(ctx, id)).toEqual({
      ...prior,
      passkey: { ...prior.passkey, challenges: { count: prior.passkey.challenges.count - 1 } },
    });
    const fresh = await owner.$fetch("/passkey/generate-authenticate-options", { method: "GET" });
    const assertion = device.authenticate(fresh.data, ctx.baseURL, 1, false, true);
    const accepted = await owner.$fetch("/passkey/verify-authentication", {
      method: "POST",
      body: { response: assertion },
    });
    expect(accepted.error).toBeNull();
    expect((accepted.data as any).user.id).toBe(id);
    expect((await state(ctx, id)).passkeys[0]!.counter).toBe(1);
    const enrolled = await physical(ctx, id);
    const replay = await owner.$fetch("/passkey/verify-authentication", {
      method: "POST",
      body: { response: assertion },
    });
    expect((replay.error as any).code).toBe("CHALLENGE_NOT_FOUND");
    expect(await physical(ctx, id)).toEqual(enrolled);
    const malformed = [];
    for (const mode of ["noncanonical", "duplicate"] as const) {
      const start = await physical(ctx, id);
      const opts = await owner.$fetch("/passkey/generate-register-options", { method: "GET" });
      const invalid = new CertificateDevice("malformed-" + mode).register(
        opts.data,
        ctx.baseURL,
        "packed",
        mode,
      );
      const rejected = await owner.$fetch("/passkey/verify-registration", {
        method: "POST",
        body: { response: invalid, createSession: true },
      });
      expect((rejected.error as any).code).toBe("FAILED_TO_VERIFY_REGISTRATION");
      expect(await physical(ctx, id)).toEqual(start);
      const retry = await owner.$fetch("/passkey/verify-registration", {
        method: "POST",
        body: { response: invalid },
      });
      expect((retry.error as any).code).toBe("CHALLENGE_NOT_FOUND");
      malformed.push(ctx.snapshot({ rejected, retry }));
      await retain(ctx, "cose-" + mode, {
        opts,
        invalid,
        rejected,
        retry,
        start,
        after: await physical(ctx, id),
      });
    }
    await retain(ctx, "public-key-authority", {
      options,
      proof,
      registered,
      schema,
      invalidName,
      renamed,
      authOptions,
      swapped,
      missingAuthentication,
      prior,
      stale,
      denied,
      fresh,
      assertion,
      accepted,
      replay,
      enrolled,
    });
    return {
      registered: ctx.snapshot(registered),
      schema,
      missingAuthentication: ctx.snapshot(missingAuthentication),
      invalidName: ctx.snapshot(invalidName),
      renamed: ctx.snapshot(renamed),
      denied: ctx.snapshot(denied),
      accepted: ctx.snapshot(accepted),
      replay: ctx.snapshot(replay),
      malformed,
      final: await physical(ctx, id),
    };
  },
);

compatScenario(
  "passkey certificate revocation rejects signed enrollment before credential or session writes",
  async (ctx) => {
    const owner = client(ctx, "revocation-owner");
    const signup = await owner.signUp.email({
      email: ctx.uniqueEmail("revocation"),
      name: "Revocation owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    const id = signup.data!.user.id;
    const device = new CertificateDevice("revoked-certificate");
    const before = await physical(ctx, id);
    const options = await owner.$fetch("/passkey/generate-register-options", { method: "GET" });
    const proof = device.register(options.data, ctx.baseURL, "packed", "revoked");
    const denied = await owner.$fetch("/passkey/verify-registration", {
      method: "POST",
      body: { response: proof, createSession: true },
    });
    expect((denied.error as any).code).toBe("FAILED_TO_VERIFY_REGISTRATION");
    expect(await physical(ctx, id)).toEqual(before);
    const replay = await owner.$fetch("/passkey/verify-registration", {
      method: "POST",
      body: { response: proof },
    });
    expect((replay.error as any).code).toBe("CHALLENGE_NOT_FOUND");
    const fresh = await owner.$fetch("/passkey/generate-register-options", { method: "GET" });
    const valid = device.register(fresh.data, ctx.baseURL, "packed");
    const accepted = await owner.$fetch("/passkey/verify-registration", {
      method: "POST",
      body: { response: valid, createSession: true },
    });
    expect(accepted.error).toBeNull();
    await retain(ctx, "revocation", {
      options,
      proof,
      denied,
      replay,
      before,
      fresh,
      valid,
      accepted,
      after: await physical(ctx, id),
    });
    return {
      denied: ctx.snapshot(denied),
      replay: ctx.snapshot(replay),
      accepted: ctx.snapshot(accepted),
      before,
      after: await physical(ctx, id),
    };
  },
);

compatScenario(
  "passkey transport metadata and missing response retain Source ceremony admission and writes",
  async (ctx) => {
    const owner = client(ctx, "transport-owner");
    const signup = await owner.signUp.email({
      email: ctx.uniqueEmail("transport-admission"),
      name: "Transport owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    const id = signup.data!.user.id;
    const cases = [];
    for (const [index, transport] of [
      null,
      ["internal", "unlisted", null, 17, {}],
      "internal",
      17,
    ].entries()) {
      const before = await physical(ctx, id);
      const options = await owner.$fetch("/passkey/generate-register-options", { method: "GET" });
      const proof = new CertificateDevice("transport-" + index).register(
        options.data,
        ctx.baseURL,
        "packed",
      );
      (proof.response as any).transports = transport;
      const result = await owner.$fetch("/passkey/verify-registration", {
        method: "POST",
        body: { response: proof, name: " ", createSession: true },
      });
      if (index < 2) {
        expect(result.error).toBeNull();
        expect((result.data as any).transports).toBe(
          index === 0 ? "" : "internal,unlisted,,17,[object Object]",
        );
        expect((result.data as any).name).toBeNull();
        expect((result.data as any).user.id).toBe(id);
      } else {
        expect((result.error as any).status).toBe(500);
        expect((result.error as any).code).toBe("FAILED_TO_VERIFY_REGISTRATION");
        expect(await physical(ctx, id)).toEqual(before);
      }
      const after = await physical(ctx, id);
      const replay = await owner.$fetch("/passkey/verify-registration", {
        method: "POST",
        body: { response: proof },
      });
      expect((replay.error as any).code).toBe("CHALLENGE_NOT_FOUND");
      expect(await physical(ctx, id)).toEqual(after);
      await retain(ctx, "transport-" + index, { before, options, proof, result, after, replay });
      cases.push({
        transport,
        result: ctx.snapshot(result),
        replay: ctx.snapshot(replay),
        before,
        after,
      });
    }
    const before = await physical(ctx, id);
    const options = await owner.$fetch("/passkey/generate-register-options", { method: "GET" });
    const missing = await owner.$fetch("/passkey/verify-registration", {
      method: "POST",
      body: { createSession: true },
    });
    expect((missing.error as any).status).toBe(500);
    expect((missing.error as any).code).toBe("FAILED_TO_VERIFY_REGISTRATION");
    expect(await physical(ctx, id)).toEqual(before);
    const replay = await owner.$fetch("/passkey/verify-registration", {
      method: "POST",
      body: { createSession: true },
    });
    expect((replay.error as any).code).toBe("CHALLENGE_NOT_FOUND");
    await retain(ctx, "missing-response", {
      before,
      options,
      missing,
      replay,
      after: await physical(ctx, id),
    });
    return {
      cases,
      missing: ctx.snapshot(missing),
      replay: ctx.snapshot(replay),
      final: await physical(ctx, id),
    };
  },
);

compatScenario(
  "passkey SafetyNet signed payload field coercion matches the pinned verifier",
  async (ctx) => {
    const owner = client(ctx, "safetynet-fields");
    const signup = await owner.signUp.email({
      email: ctx.uniqueEmail("safetynet-fields"),
      name: "SafetyNet fields",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    const id = signup.data!.user.id;
    const results = [];
    for (const mode of ["timestamp-omitted", "timestamp-string", "version-number"] as const) {
      const options = await owner.$fetch("/passkey/generate-register-options", { method: "GET" });
      const proof = new CertificateDevice("safetynet-" + mode).register(
        options.data,
        ctx.baseURL,
        "android-safetynet",
        mode,
      );
      const result = await owner.$fetch("/passkey/verify-registration", {
        method: "POST",
        body: { response: proof, name: "SafetyNet field proof" },
      });
      expect(result.error).toBeNull();
      expect((result.data as any).userId).toBe(id);
      const before = await physical(ctx, id);
      const replay = await owner.$fetch("/passkey/verify-registration", {
        method: "POST",
        body: { response: proof },
      });
      expect((replay.error as any).code).toBe("CHALLENGE_NOT_FOUND");
      expect(await physical(ctx, id)).toEqual(before);
      await retain(ctx, "safetynet-" + mode, { options, proof, result, replay, before });
      results.push({
        mode,
        result: ctx.snapshot(result),
        replay: ctx.snapshot(replay),
        physical: before,
      });
    }
    return { results };
  },
);

compatScenario(
  "passkey signed short RSA exponent, Ed25519 U2F and opaque Apple nonce retain Source authority",
  async (ctx) => {
    const owner = client(ctx, "source-key-variants");
    const signup = await owner.signUp.email({
      email: ctx.uniqueEmail("key-variants"),
      name: "Key variants",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    const id = signup.data!.user.id;
    const results = [];
    for (const [label, format, mode, rsa, ed] of [
      ["rsa-short-exponent", "packed", "valid", true, false],
      ["u2f-ed25519", "fido-u2f", "valid", false, true],
      ["apple-opaque", "apple", "apple-opaque", false, false],
      ["tpm-sha384-name", "tpm", "tpm-sha384-name", false, false],
    ] as const) {
      const device = new CertificateDevice(label, rsa, ed);
      if (rsa) {
        const before = await physical(ctx, id);
        const options = await owner.$fetch("/passkey/generate-register-options", { method: "GET" });
        const proof = device.register(options.data, ctx.baseURL, format, "signature");
        const denied = await owner.$fetch("/passkey/verify-registration", {
          method: "POST",
          body: { response: proof, createSession: true },
        });
        expect((denied.error as any).status).toBe(400);
        expect((denied.error as any).code).toBe("FAILED_TO_VERIFY_REGISTRATION");
        expect(await physical(ctx, id)).toEqual(before);
        const replay = await owner.$fetch("/passkey/verify-registration", {
          method: "POST",
          body: { response: proof },
        });
        expect((replay.error as any).code).toBe("CHALLENGE_NOT_FOUND");
        await retain(ctx, "rsa-invalid", {
          before,
          options,
          proof,
          denied,
          replay,
          after: await physical(ctx, id),
        });
      }
      const options = await owner.$fetch("/passkey/generate-register-options", { method: "GET" });
      const proof = device.register(options.data, ctx.baseURL, format, mode);
      const accepted = await owner.$fetch("/passkey/verify-registration", {
        method: "POST",
        body: { response: proof, name: "Source key variant", createSession: true },
      });
      expect(accepted.error).toBeNull();
      expect((accepted.data as any).user.id).toBe(id);
      await owner.signOut();
      const before = await physical(ctx, id);
      const badOptions = await owner.$fetch("/passkey/generate-authenticate-options", {
        method: "GET",
      });
      const invalid = device.authenticate(badOptions.data, ctx.baseURL, 1, true);
      const denied = await owner.$fetch("/passkey/verify-authentication", {
        method: "POST",
        body: { response: invalid },
      });
      expect((denied.error as any).code).toBe("AUTHENTICATION_FAILED");
      expect(await physical(ctx, id)).toEqual(before);
      const authOptions = await owner.$fetch("/passkey/generate-authenticate-options", {
        method: "GET",
      });
      const assertion = device.authenticate(authOptions.data, ctx.baseURL);
      const login = await owner.$fetch("/passkey/verify-authentication", {
        method: "POST",
        body: { response: assertion },
      });
      expect(login.error).toBeNull();
      expect((login.data as any).user.id).toBe(id);
      const final = await physical(ctx, id);
      const replay = await owner.$fetch("/passkey/verify-authentication", {
        method: "POST",
        body: { response: assertion },
      });
      expect((replay.error as any).code).toBe("CHALLENGE_NOT_FOUND");
      expect(await physical(ctx, id)).toEqual(final);
      await retain(ctx, label, {
        options,
        proof,
        accepted,
        before,
        badOptions,
        invalid,
        denied,
        authOptions,
        assertion,
        login,
        replay,
        final,
      });
      results.push({
        label,
        accepted: ctx.snapshot(accepted),
        denied: ctx.snapshot(denied),
        login: ctx.snapshot(login),
        replay: ctx.snapshot(replay),
        final,
      });
    }
    return { results };
  },
);
