import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { twoFactorClient, jwtClient } from "better-auth/client/plugins";
import { getCookieCache } from "better-auth/cookies";
import {
  symmetricDecrypt,
  symmetricEncrypt,
  symmetricDecodeJWT,
  symmetricEncodeJWT,
  makeSignature,
} from "better-auth/crypto";
import { decodeProtectedHeader, type JWK } from "jose";
import { z } from "zod";

import { authProfilePath, type FixtureProfile } from "../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { decodeBase32 } from "../../support/totp";
import { storedVerification, verificationCount } from "../../support/verification";
import { verifyWithOfficialJose } from "../plugins/jwt/helpers";
const old = "managed-old-reader-key-at-least-32-characters";
const current = "compat-test-only-key-not-real-minimum-32chars";
const legacy = "managed-legacy-reader-key-at-least-32-characters";
const keys = {
  keys: new Map([
    [2, current],
    [0, old],
  ]),
  currentVersion: 2,
  legacySecret: legacy,
};
const comparisonOptions = {
  managedAccountCookieProfiles: {
    [authProfilePath("managed-old")]: {
      credentialVersion: 0,
      secret: old,
      accessToken: "github-access-token",
      refreshToken: "github-refresh-token",
    },
    [authProfilePath("managed-retained")]: {
      credentialVersion: 0,
      secret: current,
      credentialSecret: old,
      renewal: true,
      accessToken: "github-access-token",
      refreshToken: "github-refresh-token",
    },
  },
  sessionCookieSecretsByAuthPath: {
    [authProfilePath("managed-old")]: old,
    [authProfilePath("managed-bare")]: legacy,
  },
};
function client(ctx: ScenarioContext, profile: FixtureProfile, actor = "owner") {
  const browser = ctx.actor(actor, profile);
  let headers = new Headers();
  return {
    browser,
    get headers() {
      return headers;
    },
    client: createAuthClient({
      baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
      plugins: [twoFactorClient(), jwtClient()],
      fetchOptions: {
        customFetchImpl: async (input, init) => {
          const response = await browser.fetch(input, init);
          headers = new Headers(response.headers);
          return response;
        },
      },
    }),
  };
}
async function request(
  ctx: ScenarioContext,
  profile: FixtureProfile,
  endpoint: string,
  body: unknown,
) {
  return ctx.rawRequest({
    path: `${authProfilePath(profile)}/${endpoint}`,
    method: "POST",
    json: body,
  });
}
async function delivery(ctx: ScenarioContext, email: string) {
  const response = await ctx.rawRequest({
    path: `/__test/managed-secrets/delivery?${new URLSearchParams({ email })}`,
  });
  expect(response.status).toBe(200);
  return (response.body as { otp: string }).otp;
}
async function encryptedRows(ctx: ScenarioContext, email: string) {
  const rows = await storedVerification(ctx, `sign-in-otp-${email}`);
  expect(rows).toHaveLength(1);
  const row = rows[0]!;
  const split = row.value.lastIndexOf(":");
  const ciphertext = row.value.slice(0, split);
  return {
    rows: rows.map((row) => ({ ...row, value: { token: row.value } })),
    ciphertext,
    attempts: row.value.slice(split + 1),
  };
}
compatScenario(
  "managed rotation retains encrypted proofs and factors, retires readers and invalidates old signed cookies",
  async (ctx) => {
    const results = [];
    for (const [write, read, version] of [
      ["managed-old", "managed-retained", 0],
      ["managed-bare", "managed-legacy", null],
    ] as const) {
      const email = ctx.uniqueEmail(write);
      const sent = await request(ctx, write, "email-otp/send-verification-otp", {
        email,
        type: "sign-in",
      });
      expect(sent.status).toBe(200);
      const otp = await delivery(ctx, email);
      const before = await encryptedRows(ctx, email);
      if (version === null) expect(before.ciphertext).toMatch(/^[0-9a-f]+$/);
      else expect(before.ciphertext).toMatch(/^\$ba\$0\$[0-9a-f]+$/);
      expect(await symmetricDecrypt({ key: keys, data: before.ciphertext })).toBe(otp);
      expect(before.attempts).toBe("0");
      const rejected = await request(ctx, "managed-retired", "sign-in/email-otp", { email, otp });
      expect(rejected.status).toBe(500);
      expect(await verificationCount(ctx, `sign-in-otp-${email}`)).toBe(0);
      const resent = await request(ctx, write, "email-otp/send-verification-otp", {
        email,
        type: "sign-in",
      });
      expect(resent.status).toBe(200);
      const replacement = await delivery(ctx, email);
      const signedIn = await request(ctx, read, "sign-in/email-otp", { email, otp: replacement });
      expect(signedIn.status).toBe(200);
      const replay = await request(ctx, read, "sign-in/email-otp", { email, otp: replacement });
      expect(replay.status).toBe(400);
      expect(await verificationCount(ctx, `sign-in-otp-${email}`)).toBe(0);
      results.push({ write, read, sent, before: before.rows, rejected, resent, signedIn, replay });
    }
    // Actual Source-encrypted imports exercise the installed envelope parser through
    // the public OTP admission owner, including malformed and authenticated controls.
    for (const [index, version, accepted] of [
      [0, "-0", true],
      [1, "\uFEFF0", true],
      [2, "0suffix", true],
      [3, "\u00850", false],
      [4, "9", false],
      [5, "x", false],
    ] as const) {
      const email = ctx.uniqueEmail(`version-${index}`);
      const otp = "654321";
      const encrypted = await symmetricEncrypt({
        key: { keys: new Map([[0, old]]), currentVersion: 0 },
        data: otp,
      });
      const value = encrypted.replace("$ba$0$", `$ba$${version}$`) + ":0";
      const seeded = await ctx.rawRequest({
        path: "/__test/verification-state",
        method: "POST",
        json: {
          action: "seed",
          identifier: `sign-in-otp-${email}`,
          value,
          expiresAt: new Date(Date.now() + 300_000).toISOString(),
        },
      });
      expect(seeded.status).toBe(200);
      const before = await storedVerification(ctx, `sign-in-otp-${email}`);
      const outcome = await request(ctx, "managed-retained", "sign-in/email-otp", { email, otp });
      expect(outcome.status).toBe(accepted ? 200 : 500);
      const after = await storedVerification(ctx, `sign-in-otp-${email}`);
      expect(after).toEqual([]);
      results.push({
        version,
        seeded,
        before: before.map((row) => ({ ...row, value: { token: row.value } })),
        outcome,
        after: after.map((row) => ({ ...row, value: { token: row.value } })),
      });
    }
    for (const mode of ["wrong-key", "tampered", "missing-separator", "truncated"]) {
      const email = ctx.uniqueEmail(`envelope-${mode}`);
      const otp = "654321";
      let ciphertext = await symmetricEncrypt({
        key: {
          keys: new Map([
            [0, mode === "wrong-key" ? "wrong-otp-context-key-at-least-32-characters" : old],
          ]),
          currentVersion: 0,
        },
        data: otp,
      });
      if (mode === "tampered") {
        const bytes = Buffer.from(ciphertext.slice("$ba$0$".length), "hex");
        bytes[bytes.length - 1]! ^= 1;
        ciphertext = "$ba$0$" + bytes.toString("hex");
      }
      if (mode === "missing-separator") ciphertext = ciphertext.replace("$ba$0$", "$ba$0");
      if (mode === "truncated") ciphertext = "$ba$0$ff";
      const seeded = await ctx.rawRequest({
        path: "/__test/verification-state",
        method: "POST",
        json: {
          action: "seed",
          identifier: `sign-in-otp-${email}`,
          value: ciphertext + ":0",
          expiresAt: new Date(Date.now() + 300_000).toISOString(),
        },
      });
      expect(seeded.status).toBe(200);
      const before = await storedVerification(ctx, `sign-in-otp-${email}`);
      expect(before).toHaveLength(1);
      const rejected = await request(ctx, "managed-retained", "sign-in/email-otp", { email, otp });
      expect(rejected.status).toBe(500);
      const after = await storedVerification(ctx, `sign-in-otp-${email}`);
      expect(after).toEqual([]);
      results.push({
        mode,
        seeded,
        before: before.map((row) => ({ ...row, value: { token: row.value } })),
        rejected,
        after,
      });
    }
    const account = client(ctx, "managed-old");
    const email = ctx.uniqueEmail("factor");
    const password = "password123";
    const signup = await account.client.signUp.email({ email, password, name: "Rotation owner" });
    expect(signup.error).toBeNull();
    const oldSession = await account.client.getSession();
    expect(oldSession.data?.user.id).toBe(signup.data!.user.id);
    const enabled = await account.client.twoFactor.enable({ password });
    expect(enabled.error).toBeNull();
    const enabledValue = z
      .object({ totpURI: z.string(), backupCodes: z.array(z.string()) })
      .parse(enabled.data);
    expect(enabledValue.backupCodes).toEqual(["backup-one", "backup-two"]);
    const oldURI = enabledValue.totpURI;
    // Same actual browser cookie sent to the rotated runtime must fail HMAC;
    // a fresh current-key sign-in gives a genuine pending factor challenge.
    const migrated = {
      browser: account.browser,
      client: createAuthClient({
        baseURL: `${ctx.baseURL}${authProfilePath("managed-retained")}`,
        plugins: [twoFactorClient(), jwtClient()],
        fetchOptions: { customFetchImpl: account.browser.fetch },
      }),
    };
    const inherited = await migrated.client.getSession();
    expect(inherited.data).toBeNull();
    const currentLogin = await migrated.client.signIn.email({ email, password });
    expect(currentLogin.data).toMatchObject({ twoFactorRedirect: true });
    const backup = await migrated.client.twoFactor.verifyBackupCode({ code: "backup-one" });
    expect(backup.error).toBeNull();
    const saved = await migrated.client.twoFactor.getTotpUri({ password });
    expect(saved.error).toBeNull();
    expect(saved.data!.totpURI).toBe(oldURI);
    const factorResponse = await ctx.rawRequest({
      path: "/__test/two-factor-policy",
      method: "POST",
      json: { userId: signup.data!.user.id },
    });
    expect(factorResponse.status).toBe(200);
    const factor = factorResponse.body as Record<string, unknown>;
    expect(String(factor.secret)).toMatch(/^\$ba\$0\$/);
    expect(String(factor.backupCodes)).toMatch(/^\$ba\$2\$/);
    expect(await symmetricDecrypt({ key: keys, data: String(factor.secret) })).toBe(
      new TextDecoder().decode(decodeBase32(new URL(oldURI).searchParams.get("secret")!)),
    );
    expect(
      JSON.parse(String(await symmetricDecrypt({ key: keys, data: String(factor.backupCodes) }))),
    ).toEqual(["backup-two"]);
    const retired = {
      browser: migrated.browser,
      client: createAuthClient({
        baseURL: `${ctx.baseURL}${authProfilePath("managed-retired")}`,
        plugins: [twoFactorClient(), jwtClient()],
        fetchOptions: { customFetchImpl: migrated.browser.fetch },
      }),
    };
    const noSecret = await retired.client.twoFactor.getTotpUri({ password });
    expect(noSecret.error?.status).toBe(500);
    const repeated = await migrated.client.twoFactor.verifyBackupCode({ code: "backup-one" });
    expect(repeated.error?.code).toBe("INVALID_BACKUP_CODE");
    return {
      results,
      signup,
      oldSession,
      enabled: { ...enabled, data: { ...enabled.data, totpURI: { token: oldURI } } },
      inherited,
      currentLogin,
      backup,
      saved: { ...saved, data: { ...saved.data, totpURI: { token: saved.data!.totpURI } } },
      factor: {
        ...factor,
        secret: { token: factor.secret },
        backupCodes: { token: factor.backupCodes },
      },
      noSecret,
      repeated,
      userState: await ctx.readUserState({ userId: signup.data!.user.id }),
    };
  },
  [],
  30_000,
  comparisonOptions,
);

type ManagedState = { accounts: Record<string, unknown>[]; keys: Record<string, unknown>[] };
async function managedState(ctx: ScenarioContext, userId: string): Promise<ManagedState> {
  const result = await ctx.rawRequest({
    path: `/__test/managed-secrets/state?${new URLSearchParams({ userId })}`,
  });
  expect(result.status).toBe(200);
  return result.body as ManagedState;
}
function rowsObservation(state: ManagedState) {
  return {
    ...state,
    accounts: state.accounts.map((row) => ({
      ...row,
      password: row.password === null ? null : { token: row.password },
      accessToken: row.accessToken === null ? null : { token: row.accessToken },
      refreshToken: row.refreshToken === null ? null : { token: row.refreshToken },
    })),
    keys: state.keys.map((row) => ({ ...row, privateKey: { token: row.privateKey } })),
  };
}
async function parsed(response: Response) {
  const text = await response.text();
  let body: unknown = text;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {}
  return { status: response.status, location: response.headers.get("location"), body };
}
async function callback(
  ctx: ScenarioContext,
  browser: ReturnType<ScenarioContext["actor"]>,
  profile: FixtureProfile,
  state: string,
) {
  return browser.fetch(
    `${ctx.baseURL}${authProfilePath(profile)}/callback/github?${new URLSearchParams({ code: "managed-provider-code", state })}`,
    { redirect: "manual" },
  );
}

compatScenario(
  "managed OAuth credentials and account cookies retain readers and bind rotated sessions to their owners",
  async (ctx) => {
    const password = "password123";
    const email = ctx.uniqueEmail("oauth-managed-owner");
    const owner = client(ctx, "managed-old", "oauth-owner");
    const signup = await owner.client.signUp.email({
      email,
      password,
      name: "x".repeat(6000),
    });
    expect(signup.error).toBeNull();
    await ctx.setGitHubProfile({
      id: "7654321",
      email,
      name: "Managed OAuth Owner",
      emails: [{ email, primary: true, verified: true }],
    });
    const linkStart = await owner.client.linkSocial({
      provider: "github",
      callbackURL: `${ctx.baseURL}/managed-linked`,
      disableRedirect: true,
    });
    expect(linkStart.error).toBeNull();
    const linked = await parsed(
      await callback(
        ctx,
        owner.browser,
        "managed-old",
        new URL(linkStart.data!.url!).searchParams.get("state")!,
      ),
    );
    expect(linked.location).toBe(`${ctx.baseURL}/managed-linked`);
    const started = await owner.client.signIn.social({
      provider: "github",
      callbackURL: `${ctx.baseURL}/managed-done`,
      disableRedirect: true,
    });
    expect(started.error).toBeNull();
    const authorization = new URL(started.data!.url!);
    const nonce = authorization.searchParams.get("state")!;
    const completedResponse = await callback(ctx, owner.browser, "managed-old", nonce);
    const setCookies = completedResponse.headers.getSetCookie();
    const encoded = setCookies
      .find((value) => value.startsWith("better-auth.account_data="))!
      .split(";")[0]!
      .slice("better-auth.account_data=".length);
    const token = decodeURIComponent(encoded);
    const payload = await symmetricDecodeJWT(token, keys, "better-auth-account");
    expect(payload?.userId).toBe(signup.data!.user.id);
    const accountCookie = { token, header: decodeProtectedHeader(token), payload };
    const completed = await parsed(completedResponse);
    expect(completed.status).toBe(302);
    const before = await managedState(ctx, signup.data!.user.id);
    const account = before.accounts.find((row) => row.providerId === "github")!;
    expect(payload?.accessToken).toBe(account.accessToken);
    expect(payload?.refreshToken).toBe(account.refreshToken);
    expect(String(account.accessToken)).toMatch(/^\$ba\$0\$/);
    expect(String(account.refreshToken)).toMatch(/^\$ba\$0\$/);
    expect(await symmetricDecrypt({ key: keys, data: String(account.accessToken) })).toBe(
      "github-access-token",
    );
    expect(await symmetricDecrypt({ key: keys, data: String(account.refreshToken) })).toBe(
      "github-refresh-token",
    );
    let loginHeaders = new Headers();
    const sdk = createAuthClient({
      baseURL: ctx.baseURL + authProfilePath("managed-retained"),
      fetchOptions: {
        customFetchImpl: async (input, init) => {
          const response = await owner.browser.fetch(input, init);
          loginHeaders = new Headers(response.headers);
          return response;
        },
      },
    });
    const inherited = await sdk.getSession();
    expect(inherited.data).toBeNull();
    const login = await sdk.signIn.email({ email, password });
    expect(login.error).toBeNull();
    const renewedRaw = loginHeaders
      .getSetCookie()
      .find((cookie) => cookie.startsWith("better-auth.account_data="))!;
    expect(renewedRaw).toBeDefined();
    const renewedToken = decodeURIComponent(
      renewedRaw.split(";")[0]!.slice("better-auth.account_data=".length),
    );
    const renewedPayload = await symmetricDecodeJWT(renewedToken, current, "better-auth-account");
    expect(renewedPayload?.userId).toBe(signup.data!.user.id);
    expect(renewedPayload?.accessToken).toBe(account.accessToken);
    expect(renewedPayload?.refreshToken).toBe(account.refreshToken);
    expect(await symmetricDecodeJWT(renewedToken, old, "better-auth-account")).toBeNull();
    const renewalRows = await managedState(ctx, signup.data!.user.id);
    expect(renewalRows.accounts).toEqual(before.accounts);
    const renewal = {
      managedAccountCookie: {
        authPath: authProfilePath("managed-retained"),
        token: renewedToken,
        header: decodeProtectedHeader(renewedToken),
        payload: renewedPayload,
        account: renewalRows.accounts.find((row) => row.id === account.id)!,
      },
    };
    const cacheCookies = loginHeaders
      .getSetCookie()
      .filter(
        (value) =>
          /^better-auth\.session_data(?:\.|=)/.test(value) && !/Max-Age=0(?:;|$)/i.test(value),
      );
    expect(cacheCookies.length).toBeGreaterThan(1);
    expect(cacheCookies.every((cookie) => cookie.startsWith("better-auth.session_data."))).toBe(
      true,
    );
    const cacheToken = cacheCookies
      .map((cookie) => cookie.split(";")[0]!.slice(cookie.indexOf("=") + 1))
      .join("");
    const observedAt = Date.now();
    const cacheEnvelope = JSON.parse(Buffer.from(cacheToken, "base64url").toString());
    const cached = await getCookieCache(
      new Headers({ cookie: `better-auth.session_data=${cacheToken}` }),
      { secret: current, strategy: "compact", isSecure: false },
    );
    expect(cached?.session.token).toBe(login.data!.token!);
    expect(
      await getCookieCache(new Headers({ cookie: `better-auth.session_data=${cacheToken}` }), {
        secret: legacy,
        strategy: "compact",
        isSecure: false,
      }),
    ).toBeNull();
    const compactSessionCache = {
      token: cacheToken,
      envelope: cacheEnvelope,
      decoded: cached,
      observedAt,
      effectiveMaxAgeSeconds: 300,
      rawCookies: cacheCookies,
    };
    const read = await sdk.getAccessToken({ accountId: String(account.id) });
    expect(read.data?.accessToken).toBe("github-access-token");
    const retiredSdk = createAuthClient({
      baseURL: ctx.baseURL + authProfilePath("managed-retired"),
      fetchOptions: { customFetchImpl: owner.browser.fetch },
    });
    const retired = await retiredSdk.getAccessToken({ accountId: String(account.id) });
    expect(retired.error?.code).toBe("FAILED_TO_GET_ACCESS_TOKEN");
    const foreign = client(ctx, "managed-retained", "oauth-foreign");
    const other = await foreign.client.signUp.email({
      email: ctx.uniqueEmail("managed-foreign"),
      password,
      name: "Foreign Owner",
    });
    expect(other.error).toBeNull();
    const cookieRead = async (
      value: string,
      session: string,
      profile: FixtureProfile = "managed-retained",
    ) => {
      const signed = encodeURIComponent(`${session}.${await makeSignature(session, current)}`);
      return parsed(
        await owner.browser.fetch(ctx.baseURL + authProfilePath(profile) + "/get-access-token", {
          method: "POST",
          credentials: "omit",
          headers: {
            "content-type": "application/json",
            cookie: `better-auth.session_token=${signed}; better-auth.account_data=${encodeURIComponent(value)}`,
          },
          body: JSON.stringify({ useAccountCookie: true }),
        }),
      );
    };
    const retainedCookie = await cookieRead(token, login.data!.token!);
    expect(retainedCookie.status).toBe(200);
    const foreignCookie = await cookieRead(token, other.data!.token!);
    expect(foreignCookie.status).toBe(400);
    expect(foreignCookie.body).toMatchObject({ code: "ACCOUNT_NOT_FOUND" });
    const retiredCookie = await cookieRead(token, login.data!.token!, "managed-retired");
    expect(retiredCookie.status).toBe(400);
    const changed = token.split(".");
    const encrypted = Buffer.from(changed[3]!, "base64url");
    encrypted[0]! ^= 1;
    changed[3] = encrypted.toString("base64url");
    const tampered = await cookieRead(changed.join("."), login.data!.token!);
    expect(tampered.status).toBe(400);
    const expired = await symmetricEncodeJWT(payload!, keys, "better-auth-account", -60);
    const expiredCookie = await cookieRead(expired, login.data!.token!);
    expect(expiredCookie.status).toBe(400);
    const unchanged = await managedState(ctx, signup.data!.user.id);
    expect(unchanged.accounts).toEqual(before.accounts);
    const refreshed = await sdk.refreshToken({ accountId: String(account.id) });
    expect(refreshed.error).toBeNull();
    const after = await managedState(ctx, signup.data!.user.id);
    const rewritten = after.accounts.find((row) => row.providerId === "github")!;
    expect(String(rewritten.accessToken)).toMatch(/^\$ba\$2\$/);
    expect(String(rewritten.refreshToken)).toMatch(/^\$ba\$2\$/);
    const currentRead = await retiredSdk.getAccessToken({ accountId: String(account.id) });
    expect(currentRead.error).toBeNull();
    return {
      signup,
      linkStart,
      linked,
      started,
      completed,
      managedAccountCookie: { ...accountCookie, account, authPath: authProfilePath("managed-old") },
      compactSessionCache,
      renewal,
      before: rowsObservation(before),
      inherited,
      login,
      read,
      retired,
      other,
      retainedCookie,
      foreignCookie,
      retiredCookie,
      tampered,
      expiredCookie,
      unchanged: rowsObservation(unchanged),
      refreshed,
      after: rowsObservation(after),
      currentRead,
      user: await ctx.readUserState({ userId: signup.data!.user.id }),
      foreignUser: await ctx.readUserState({ userId: other.data!.user.id }),
    };
  },
  [
    "POST /sign-up/email",
    "POST /link-social",
    "GET /callback/{}",
    "GET /get-session",
    "POST /sign-in/email",
    "POST /get-access-token",
    "POST /refresh-token",
  ],
  30_000,
  comparisonOptions,
);

compatScenario(
  "managed JWKS encryption retains private readers without exposing private keys and retires them before signing",
  async (ctx) => {
    const password = "password123";
    const email = ctx.uniqueEmail("managed-jwk-owner");
    const owner = client(ctx, "managed-old", "jwk-owner");
    const signup = await owner.client.signUp.email({ email, password, name: "Managed JWK Owner" });
    expect(signup.error).toBeNull();
    const first = await owner.client.token();
    expect(first.error).toBeNull();
    await Bun.sleep(1100);
    const publicOld = await owner.client.jwks();
    expect(publicOld.error).toBeNull();
    const proofOld = await verifyWithOfficialJose(
      first.data!.token,
      publicOld.data!.keys as JWK[],
      ctx.baseURL,
      ctx.baseURL,
    );
    expect(proofOld.payload.sub).toBe(signup.data!.user.id);
    const before = await managedState(ctx, signup.data!.user.id);
    expect(before.keys).toHaveLength(1);
    const stored = before.keys[0]!;
    expect(String(stored.privateKey)).toMatch(/^\$ba\$0\$/);
    const privateOld = JSON.parse(
      await symmetricDecrypt({ key: keys, data: String(stored.privateKey) }),
    );
    expect(typeof privateOld.d).toBe("string");
    expect(publicOld.data!.keys[0]!.d).toBeUndefined();
    const migrated = createAuthClient({
      baseURL: ctx.baseURL + authProfilePath("managed-retained"),
      plugins: [jwtClient()],
      fetchOptions: { customFetchImpl: owner.browser.fetch },
    });
    const login = await migrated.signIn.email({ email, password });
    expect(login.error).toBeNull();
    const retained = await migrated.token();
    expect(retained.error).toBeNull();
    const retainedProof = await verifyWithOfficialJose(
      retained.data!.token,
      publicOld.data!.keys as JWK[],
      ctx.baseURL,
      ctx.baseURL,
    );
    expect(retainedProof.header.kid).toBe(proofOld.header.kid);
    const retired = createAuthClient({
      baseURL: ctx.baseURL + authProfilePath("managed-retired"),
      plugins: [jwtClient()],
      fetchOptions: { customFetchImpl: owner.browser.fetch },
    });
    const rejected = await retired.token();
    expect(rejected.error?.status).toBe(500);
    const publicRetired = await retired.jwks();
    expect(publicRetired.error).toBeNull();
    expect(publicRetired.data).toEqual(publicOld.data);
    const unchanged = await managedState(ctx, signup.data!.user.id);
    expect(unchanged.keys).toEqual(before.keys);
    const created = await ctx.rawRequest({
      path: "/__test/managed-secrets/jwk",
      method: "POST",
      json: { profile: "managed-retained" },
    });
    expect(created.status).toBe(200);
    const after = await managedState(ctx, signup.data!.user.id);
    expect(after.keys).toHaveLength(2);
    const newKey = after.keys.find((row) => row.id !== stored.id)!;
    expect(String(newKey.privateKey)).toMatch(/^\$ba\$2\$/);
    expect(
      typeof JSON.parse(await symmetricDecrypt({ key: keys, data: String(newKey.privateKey) })).d,
    ).toBe("string");
    const currentToken = await retired.token();
    expect(currentToken.error).toBeNull();
    const publicCurrent = await retired.jwks();
    expect(publicCurrent.error).toBeNull();
    const currentProof = await verifyWithOfficialJose(
      currentToken.data!.token,
      publicCurrent.data!.keys as JWK[],
      ctx.baseURL,
      ctx.baseURL,
    );
    expect(currentProof.header.kid).toBe(String(newKey.id));
    return {
      signup,
      first,
      publicOld,
      proofOld,
      before: rowsObservation(before),
      login,
      retained,
      retainedProof,
      rejected,
      publicRetired,
      unchanged: rowsObservation(unchanged),
      created,
      after: rowsObservation(after),
      currentToken,
      publicCurrent,
      currentProof,
      user: await ctx.readUserState({ userId: signup.data!.user.id }),
    };
  },
  ["POST /sign-up/email", "GET /token", "GET /jwks", "POST /sign-in/email"],
  30_000,
  comparisonOptions,
);
