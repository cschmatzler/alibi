import { expect } from "bun:test";

import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../../support/scenario";

const secret = ["compat", "test", "only", "key", "not", "real", "minimum", "32chars"].join("-");
// Both scenario executions import the exact same genuine published ciphertext.
const publishedImport = symmetricEncrypt({ key: secret, data: "published-import-access" });

const wrongSecretImport = symmetricEncrypt({
  key: "wrong-actual-oauth-secret-32-chars",
  data: "wrong-secret-token",
});

type Row = Record<string, unknown>;
type Store = { users: Row[]; accounts: Row[]; sessions: Row[]; receipts: Row[] };

async function read(ctx: ScenarioContext): Promise<Store> {
  const result = await ctx.rawRequest({ path: "/__test/social-provider/state" });
  expect(result.status).toBe(200);
  return result.body as Store;
}

function observed(store: Store) {
  const cipher = (value: unknown) =>
    typeof value === "string" && value.length % 2 === 0 && /^[0-9a-f]+$/i.test(value)
      ? {
          token: value,
          byteLength: value.length / 2,
          encoding: value === value.toLowerCase() ? "hex-lower" : "hex-upper",
        }
      : value;
  // Reversible evidence retains every original column and ciphertext, plus its
  // actual byte length/case. Published authenticated decryption above establishes
  // the format; the existing token graph then proves rotation and references.
  return {
    ...store,
    accounts: store.accounts.map((row) => ({
      ...row,
      accessToken: cipher(row.accessToken),
      refreshToken: cipher(row.refreshToken),
    })),
    receipts: store.receipts.map((receipt) => {
      const body = receipt.body as Record<string, string> | null;
      return {
        ...receipt,
        body: body?.code_verifier
          ? {
              ...body,
              code_verifier: { token: body.code_verifier, length: body.code_verifier.length },
            }
          : body,
      };
    }),
  };
}

async function setup(ctx: ScenarioContext) {
  const profile = "social-gitlab-encrypted";
  const owner = ctx.actor("encrypted-owner", profile);
  const foreign = ctx.actor("encrypted-foreign", profile);
  const foreignSignup = await foreign.client.signUp.email({
    email: ctx.uniqueEmail("encrypted-foreign"),
    password: "password123",
    name: "Foreign Owner",
  });
  expect(foreignSignup.error).toBeNull();

  const configured = await ctx.rawRequest({
    path: "/__test/social-provider/profile",
    method: "POST",
    json: {
      id: 42,
      email: ctx.uniqueEmail("encrypted-owner"),
      name: "Encrypted Owner",
      state: "active",
      locked: false,
      email_verified: true,
      fixtureTokens: true,
    },
  });
  expect(configured.status).toBe(200);

  const before = await read(ctx);
  const issued = await owner.client.signIn.social({
    provider: "gitlab",
    callbackURL: "/encrypted-done",
    disableRedirect: true,
  });
  expect(issued.error).toBeNull();

  const url = new URL(issued.data!.url!);
  const state = url.searchParams.get("state");
  expect(state).toBeTruthy();

  const callbackPath = `${authProfilePath(profile)}/callback/gitlab?${new URLSearchParams({ state: state!, code: "encrypted-code" })}`;
  const response = await owner.fetch(callbackPath, { redirect: "manual" });
  const callback = {
    status: response.status,
    location: response.headers.get("location"),
    body: await response.text(),
  };
  expect(callback).toMatchObject({ status: 302, location: "/encrypted-done" });

  const current = await owner.client.getSession();
  expect(current.error).toBeNull();

  const stored = await read(ctx);
  const account = stored.accounts.find((row) => row.providerId === "gitlab")!;
  expect(account).toMatchObject({
    userId: current.data!.user.id,
    accountId: "42",
    idToken: "fixture-encrypted-id",
  });
  expect(stored.users).toHaveLength(before.users.length + 1);
  expect(stored.accounts).toHaveLength(before.accounts.length + 1);
  expect(stored.sessions).toHaveLength(before.sessions.length + 1);

  const foreignBefore = await ctx.readUserState({ userId: foreignSignup.data!.user.id });
  return {
    owner,
    foreign,
    foreignSignup,
    configured,
    before,
    issued,
    callbackPath,
    callback,
    current,
    stored,
    account,
    foreignBefore,
  };
}

async function importTokens(ctx: ScenarioContext, account: Row, patch: Row) {
  const imported = await ctx.rawRequest({
    path: "/__test/social-provider/import-tokens",
    method: "POST",
    json: { accountId: account.id, userId: account.userId, ...patch },
  });
  expect(imported.status).toBe(200);
  return imported;
}

async function assertCipher(account: Row, access: string, refresh: string, id: string) {
  expect(account.accessToken).toMatch(/^[0-9a-f]+$/);
  expect(account.refreshToken).toMatch(/^[0-9a-f]+$/);
  expect(account.accessToken).not.toBe(access);
  expect(account.refreshToken).not.toBe(refresh);
  expect(await symmetricDecrypt({ key: secret, data: String(account.accessToken) })).toBe(access);
  expect(await symmetricDecrypt({ key: secret, data: String(account.refreshToken) })).toBe(refresh);
  expect(account.idToken).toBe(id);
}

compatScenario(
  "encrypted OAuth actual persisted tokens decrypt with pinned crypto while refresh rotates only owned secrets",
  async (ctx) => {
    const s = await setup(ctx);
    await assertCipher(
      s.account,
      "fixture-gitlab-access",
      "fixture-gitlab-refresh",
      "fixture-encrypted-id",
    );
    const accessed = await s.owner.client.getAccessToken({ accountId: String(s.account.id) });
    expect(accessed.error).toBeNull();
    expect(accessed.data).toMatchObject({
      accessToken: "fixture-gitlab-access",
      idToken: "fixture-encrypted-id",
      scopes: ["read_user", "issued-scope"],
    });
    expect(await read(ctx)).toEqual(s.stored);

    const deniedRead = await s.foreign.client.getAccessToken({ accountId: String(s.account.id) });
    const deniedRefresh = await s.foreign.client.refreshToken({ accountId: String(s.account.id) });
    expect(deniedRead.error).not.toBeNull();
    expect(deniedRefresh.error).not.toBeNull();
    expect(await read(ctx)).toEqual(s.stored);

    const guest = ctx.actor("encrypted-guest", "social-gitlab-encrypted");
    const guestRead = await guest.client.getAccessToken({ accountId: String(s.account.id) });
    const guestRefresh = await guest.client.refreshToken({ accountId: String(s.account.id) });
    expect(guestRead.error).toEqual({ status: 401, statusText: "Unauthorized" });
    expect(guestRefresh.error).toEqual({ status: 401, statusText: "Unauthorized" });
    expect(await read(ctx)).toEqual(s.stored);

    const refreshed = await s.owner.client.refreshToken({ accountId: String(s.account.id) });
    expect(refreshed.error).toBeNull();
    expect(refreshed.data).toMatchObject({
      accessToken: "fixture-gitlab-refreshed-access",
      refreshToken: "fixture-gitlab-refreshed-refresh",
      idToken: "fixture-encrypted-id-rotated",
    });

    const rotated = await read(ctx);
    const account = rotated.accounts.find((row) => row.id === s.account.id)!;
    await assertCipher(
      account,
      "fixture-gitlab-refreshed-access",
      "fixture-gitlab-refreshed-refresh",
      "fixture-encrypted-id-rotated",
    );
    expect(account.accessToken).not.toBe(s.account.accessToken);
    expect(account.refreshToken).not.toBe(s.account.refreshToken);
    expect(account).toMatchObject({
      id: s.account.id,
      userId: s.account.userId,
      accountId: s.account.accountId,
      scope: s.account.scope,
      createdAt: s.account.createdAt,
    });
    expect(rotated.users).toEqual(s.stored.users);
    expect(rotated.sessions).toEqual(s.stored.sessions);
    expect(rotated.receipts.at(-1)).toMatchObject({
      path: "/__test/social-provider/gitlab/oauth/token",
      body: { grant_type: "refresh_token", refresh_token: "fixture-gitlab-refresh" },
    });

    const reread = await s.owner.client.getAccessToken({ accountId: String(s.account.id) });
    expect(reread.error).toBeNull();
    expect(reread.data).toMatchObject({
      accessToken: "fixture-gitlab-refreshed-access",
      idToken: "fixture-encrypted-id-rotated",
    });
    expect(await read(ctx)).toEqual(rotated);

    const replayResponse = await s.owner.fetch(s.callbackPath, { redirect: "manual" });
    const replay = {
      status: replayResponse.status,
      location: replayResponse.headers.get("location"),
      body: await replayResponse.text(),
    };
    expect(replay.location).toContain("state_mismatch");
    expect(await read(ctx)).toEqual(rotated);
    expect(await ctx.readUserState({ userId: s.foreignSignup.data!.user.id })).toEqual(
      s.foreignBefore,
    );

    return {
      foreignSignup: ctx.snapshot(s.foreignSignup),
      configured: s.configured,
      before: observed(s.before),
      issued: ctx.snapshot(s.issued),
      callback: s.callback,
      current: ctx.snapshot(s.current),
      stored: observed(s.stored),
      foreignBefore: s.foreignBefore,
      accessed: ctx.snapshot(accessed),
      deniedRead: ctx.snapshot(deniedRead),
      deniedRefresh: ctx.snapshot(deniedRefresh),
      guestRead: ctx.snapshot(guestRead),
      guestRefresh: ctx.snapshot(guestRefresh),
      refreshed: ctx.snapshot(refreshed),
      rotated: observed(rotated),
      reread: ctx.snapshot(reread),
      replay,
      foreignAfter: await ctx.readUserState({ userId: s.foreignSignup.data!.user.id }),
    };
  },
  ["GET /callback/{}", "POST /sign-in/social", "POST /get-access-token", "POST /refresh-token"],
);

compatScenario(
  "encrypted OAuth imports authenticate pinned ciphertext and reject corrupt secrets without touching any principal",
  async (ctx) => {
    const s = await setup(ctx);
    const outcomes = [];
    const published = await publishedImport;
    const wrongSecret = await wrongSecretImport;
    const altered = published.slice(0, -2) + (published.endsWith("00") ? "01" : "00");
    const cases = [
      { mode: "pinned", accessToken: published, expected: "published-import-access" },
      {
        mode: "uppercase",
        accessToken: published.toUpperCase(),
        expected: "published-import-access",
      },
      { mode: "empty", accessToken: "", expected: "" },
      {
        mode: "plain",
        accessToken: "legacy-plaintext-access",
        expected: "legacy-plaintext-access",
      },
      { mode: "odd-hex", accessToken: "abc", expected: "abc" },
      { mode: "corrupt", accessToken: altered, expected: null },
      { mode: "wrong-secret", accessToken: wrongSecret, expected: null },
      { mode: "short-even-hex", accessToken: "aabb", expected: null },
    ];

    for (const entry of cases) {
      const imported = await importTokens(ctx, s.account, { accessToken: entry.accessToken });
      const before = await read(ctx);
      const result = await s.owner.client.getAccessToken({ accountId: String(s.account.id) });

      if (entry.expected === null) {
        expect(result.error).toMatchObject({
          status: 400,
          code: "FAILED_TO_GET_ACCESS_TOKEN",
          message: "Failed to get a valid access token",
        });
      } else {
        expect(result.error).toBeNull();
        expect(result.data).toMatchObject({
          accessToken: entry.expected,
          idToken: "fixture-encrypted-id",
        });
      }

      expect(await read(ctx)).toEqual(before);

      const denied = await s.foreign.client.getAccessToken({ accountId: String(s.account.id) });
      expect(denied.error).not.toBeNull();
      expect(await read(ctx)).toEqual(before);

      outcomes.push({
        mode: entry.mode,
        imported,
        before: observed(before),
        result: ctx.snapshot(result),
        denied: ctx.snapshot(denied),
        after: observed(await read(ctx)),
      });
    }

    const refreshImported = await importTokens(ctx, s.account, {
      accessToken: published,
      refreshToken: wrongSecret,
    });
    const beforeRefresh = await read(ctx);
    const validRead = await s.owner.client.getAccessToken({ accountId: String(s.account.id) });
    expect(validRead.error).toBeNull();
    expect(validRead.data?.accessToken).toBe("published-import-access");

    const refreshDenied = await s.owner.client.refreshToken({ accountId: String(s.account.id) });
    expect(refreshDenied.error).toMatchObject({
      status: 400,
      code: "FAILED_TO_REFRESH_ACCESS_TOKEN",
      message: "Failed to refresh access token",
    });
    expect(await read(ctx)).toEqual(beforeRefresh);
    expect(await ctx.readUserState({ userId: s.foreignSignup.data!.user.id })).toEqual(
      s.foreignBefore,
    );

    return {
      foreignSignup: ctx.snapshot(s.foreignSignup),
      configured: s.configured,
      before: observed(s.before),
      issued: ctx.snapshot(s.issued),
      callback: s.callback,
      current: ctx.snapshot(s.current),
      stored: observed(s.stored),
      foreignBefore: s.foreignBefore,
      outcomes,
      refreshImported,
      beforeRefresh: observed(beforeRefresh),
      validRead: ctx.snapshot(validRead),
      refreshDenied: ctx.snapshot(refreshDenied),
      afterRefresh: observed(await read(ctx)),
      foreignAfter: await ctx.readUserState({ userId: s.foreignSignup.data!.user.id }),
    };
  },
  ["GET /callback/{}", "POST /sign-in/social", "POST /get-access-token", "POST /refresh-token"],
);
