import { Database } from "bun:sqlite";
import { expect, test } from "bun:test";

import { betterAuth, type BetterAuthOptions } from "better-auth";
import { createAuthClient } from "better-auth/client";
import { symmetricDecodeJWT, symmetricEncodeJWT, symmetricEncrypt } from "better-auth/crypto";
import { getMigrations } from "better-auth/db/migration";
import { genericOAuth } from "better-auth/plugins";
import { decodeProtectedHeader } from "jose";

import { compareValues, type ComparisonContext } from "../support/compare";
import { normalizeClientValue } from "../support/normalize";
import { createTracingFetch, requestWindow, type TraceEntry } from "../support/trace";

const secret = "managed-cookie-harness-old-key-at-least-32-chars";
const path = "/__test/profiles/managed-cookie-harness/api/auth";
const encryption = { keys: new Map([[0, secret]]), currentVersion: 0 };
const profile = {
  credentialVersion: 0,
  secret,
  accessToken: "managed-fixture-access",
  refreshToken: "managed-fixture-refresh",
};
type Atom = {
  authPath: string;
  token: string;
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  account: Record<string, unknown>;
};

// The provider callbacks supply only provider data. The real Source callback
// owner creates the row and emits the JWE; the adapter independently reads it.
async function capture() {
  const database = new Database(":memory:");
  let auth: ReturnType<typeof betterAuth>;
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      if (new URL(request.url).pathname === "/__test/managed-secrets/state")
        return Response.json({
          accounts: await (
            await auth.$context
          ).adapter.findMany<Record<string, unknown>>({ model: "account" }),
        });
      return auth.handler(request);
    },
  });
  const baseURL = `http://127.0.0.1:${server.port}`;
  const options: BetterAuthOptions = {
    baseURL,
    basePath: path,
    database,
    secrets: [{ version: 0, value: secret }],
    rateLimit: { enabled: false },
    account: { encryptOAuthTokens: true, storeAccountCookie: true },
    session: { cookieCache: { enabled: true, strategy: "compact" } },
    plugins: [
      genericOAuth({
        config: [
          {
            providerId: "fixture-provider",
            clientId: "managed-client",
            authorizationUrl: baseURL + "/provider-authorize",
            getToken: async () => ({
              accessToken: profile.accessToken,
              refreshToken: profile.refreshToken,
              scopes: ["profile"],
              accessTokenExpiresAt: new Date(Date.now() + 3600_000),
            }),
            getUserInfo: async () => ({
              id: "managed-provider-owner",
              email: "managed-cookie@harness.test",
              name: "Managed Owner",
              emailVerified: true,
            }),
          },
        ],
      }),
    ],
  };
  try {
    await (await getMigrations(options)).runMigrations();
    auth = betterAuth(options);
    const startedAt = Date.now(),
      traces: TraceEntry[] = [];
    const fetch = createTracingFetch(baseURL, "owner", traces, path);
    const client = createAuthClient({
      baseURL: baseURL + path,
      fetchOptions: { customFetchImpl: fetch },
    });
    const started = await client.signIn.social({
      provider: "fixture-provider",
      callbackURL: baseURL + "/done",
      disableRedirect: true,
    });
    expect(started.error).toBeNull();
    const state = new URL(started.data!.url!).searchParams.get("state")!;
    const completed = await fetch(
      `${baseURL}${path}/callback/fixture-provider?${new URLSearchParams({ code: "managed-code", state })}`,
      { redirect: "manual" },
    );
    expect(completed.status).toBe(302);
    expect(completed.headers.get("location")).toBe(baseURL + "/done");
    const raw = completed.headers
      .getSetCookie()
      .find((cookie) => cookie.startsWith("better-auth.account_data="))!;
    const token = decodeURIComponent(raw.split(";")[0]!.slice("better-auth.account_data=".length));
    const payload = await symmetricDecodeJWT(token, encryption, "better-auth-account");
    expect(payload).not.toBeNull();
    const observed = (await (await fetch(baseURL + "/__test/managed-secrets/state")).json()) as {
      accounts: Record<string, unknown>[];
    };
    const account = observed.accounts[0]!;
    const fresh = await fetch(baseURL + path + "/get-session?disableCookieCache=true");
    expect(fresh.status).toBe(200);
    const renewedRaw = fresh.headers
      .getSetCookie()
      .find((cookie) => cookie.startsWith("better-auth.account_data="))!;
    expect(renewedRaw).toBeDefined();
    const renewedToken = decodeURIComponent(
      renewedRaw.split(";")[0]!.slice("better-auth.account_data=".length),
    );
    const renewedPayload = await symmetricDecodeJWT(
      renewedToken,
      encryption,
      "better-auth-account",
    );
    expect(renewedPayload).not.toBeNull();
    const renewalState = (await (
      await fetch(baseURL + "/__test/managed-secrets/state")
    ).json()) as { accounts: Record<string, unknown>[] };
    return {
      baseURL,
      startedAt,
      finishedAt: Date.now(),
      windows: traces.map((trace) => trace[requestWindow]),
      renewal: {
        authPath: path,
        token: renewedToken,
        header: decodeProtectedHeader(renewedToken),
        payload: renewedPayload,
        account: renewalState.accounts[0]!,
      } as Atom,
      atom: {
        authPath: path,
        token,
        header: decodeProtectedHeader(token),
        payload,
        account: normalizeClientValue(account),
      } as Atom,
    };
  } finally {
    server.stop(true);
    database.close();
  }
}

async function resignal(atom: Atom, payload: Record<string, unknown>, key = secret): Promise<Atom> {
  const token = await symmetricEncodeJWT(payload, key, "better-auth-account", 300);
  return {
    ...atom,
    token,
    header: decodeProtectedHeader(token),
    payload: (await symmetricDecodeJWT(token, key, "better-auth-account"))!,
  };
}

test("actual Source managed cookies bind authenticated inner plaintext version context and physical rows while unrelated claims stay literal", async () => {
  const left = await capture(),
    right = await capture();
  const context: ComparisonContext = {
    leftBaseURL: left.baseURL,
    rightBaseURL: right.baseURL,
    leftStartedAt: left.startedAt,
    rightStartedAt: right.startedAt,
    leftFinishedAt: left.finishedAt,
    rightFinishedAt: right.finishedAt,
    leftRequestWindows: left.windows,
    rightRequestWindows: right.windows,
    managedAccountCookieProfiles: { [path]: profile },
  };
  const compare = (a: Atom, b: Atom, ctx = context) =>
    compareValues({ managedAccountCookie: a }, { managedAccountCookie: b }, ctx);
  expect(compare(left.atom, right.atom)).toEqual([]);
  const renewalContext = {
    ...context,
    managedAccountCookieProfiles: { [path]: { ...profile, renewal: true } },
  };
  expect(compare(left.renewal, right.renewal, renewalContext)).toEqual([]);
  expect(
    compare(left.renewal, right.renewal, {
      ...renewalContext,
      rightRequestWindows: right.windows.slice(-2),
    }),
  ).toContainEqual({
    path: "managedAccountCookie",
    reason:
      "managed account-cookie lacks actual issuance, physical read or valid snapshot chronology",
  });
  expect(
    compare(left.renewal, right.renewal, {
      ...renewalContext,
      managedAccountCookieProfiles: {
        [path]: {
          ...profile,
          renewal: true,
          credentialSecret: "wrong-inner-reader-at-least-32-characters",
        },
      },
    }),
  ).toContainEqual({
    path: "managedAccountCookie",
    reason:
      "managed account-cookie authentication, version, plaintext or physical row relationship differs",
  });
  const rowMismatch = {
    ...right.atom,
    account: {
      ...right.atom.account,
      accessToken: await symmetricEncrypt({ key: encryption, data: profile.accessToken }),
    },
  };
  expect(compare(left.atom, rowMismatch)).toContainEqual({
    path: "managedAccountCookie",
    reason:
      "managed account-cookie authentication, version, plaintext or physical row relationship differs",
  });
  for (const [data, key] of [
    ["wrong-plaintext", encryption],
    [profile.accessToken, { keys: new Map([[2, secret]]), currentVersion: 2 }],
    [
      profile.accessToken,
      { keys: new Map([[0, "wrong-context-key-at-least-32-characters"]]), currentVersion: 0 },
    ],
  ] as const) {
    const accessToken = await symmetricEncrypt({ key, data });
    const mutated = await resignal(
      { ...right.atom, account: { ...right.atom.account, accessToken } },
      { ...right.atom.payload, accessToken },
    );
    expect(compare(left.atom, mutated)).toContainEqual({
      path: "managedAccountCookie",
      reason:
        "managed account-cookie authentication, version, plaintext or physical row relationship differs",
    });
  }
  const wrongOuter = await resignal(
    right.atom,
    right.atom.payload,
    "wrong-context-key-at-least-32-characters",
  );
  expect(compare(left.atom, wrongOuter).length).toBeGreaterThan(0);
  const parts = right.atom.token.split(".");
  const bytes = Buffer.from(parts[3]!, "base64url");
  bytes[0]! ^= 1;
  parts[3] = bytes.toString("base64url");
  expect(compare(left.atom, { ...right.atom, token: parts.join(".") }).length).toBeGreaterThan(0);
  expect(
    compare(left.atom, {
      ...right.atom,
      payload: { ...right.atom.payload, accessToken: "forged-copy" },
    }).length,
  ).toBeGreaterThan(0);
  expect(
    compare(left.atom, right.atom, { ...context, managedAccountCookieProfiles: {} }).length,
  ).toBeGreaterThan(0);
  expect(
    compare(left.atom, {
      ...right.atom,
      account: {
        ...right.atom.account,
        updatedAt: new Date(
          Date.parse(String(right.atom.payload.updatedAt)) - 60_000,
        ).toISOString(),
      },
    }),
  ).toContainEqual({
    path: "managedAccountCookie",
    reason:
      "managed account-cookie lacks actual issuance, physical read or valid snapshot chronology",
  });
  expect(
    compare(left.atom, {
      ...right.atom,
      account: { ...right.atom.account, updatedAt: "not-a-timestamp" },
    }).length,
  ).toBeGreaterThan(0);
  expect(
    compare(left.atom, right.atom, {
      ...context,
      rightRequestWindows: right.windows.map((window) =>
        window ? { ...window, issuedAccountCookie: undefined } : undefined,
      ),
    }).length,
  ).toBeGreaterThan(0);
  for (const field of ["custom", "metadata", "additionalFields"]) {
    const diffs = compareValues(
      {
        managedAccountCookie: left.atom,
        applicationData: {
          [field]: {
            accessToken: left.atom.payload.accessToken,
            refreshToken: left.atom.payload.refreshToken,
          },
        },
      },
      {
        managedAccountCookie: right.atom,
        applicationData: {
          [field]: {
            accessToken: right.atom.payload.accessToken,
            refreshToken: right.atom.payload.refreshToken,
          },
        },
      },
      context,
    );
    expect(diffs.some((diff) => diff.path.startsWith(`applicationData.${field}`))).toBe(true);
  }
});
