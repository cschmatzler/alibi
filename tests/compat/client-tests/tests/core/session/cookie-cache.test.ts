import { expect } from "bun:test";
import { createHash, createHmac } from "node:crypto";

import { createAuthClient } from "better-auth/client";
import {
  anonymousClient,
  deviceAuthorizationClient,
  jwtClient,
  multiSessionClient,
  organizationClient,
  twoFactorClient,
} from "better-auth/client/plugins";
import { getCookieCache } from "better-auth/cookies";
import { verifyPassword } from "better-auth/crypto";
import { type JWK } from "jose";
import { Cookie } from "tough-cookie";

import { authProfilePath, type FixtureProfile } from "../../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../../support/scenario";
import { verifyWithOfficialJose } from "../../plugins/jwt/helpers";

// These owners reach ordinary HTTP consumers after real session revocation.
// The existing codec owners cannot observe these plugin middleware boundaries.
async function cacheGuardRequest(
  ctx: ScenarioContext,
  owner: ReturnType<typeof client>,
  route: string,
  cookies: readonly string[],
  body?: unknown,
  mode = "guards",
) {
  const r = await owner.fetch(
    ctx.baseURL + authProfilePath(`session-cache-${mode}` as FixtureProfile) + route,
    {
      credentials: "omit",
      method: body === undefined ? "GET" : "POST",
      headers: {
        cookie: cookies.join("; "),
        origin: ctx.baseURL,
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    },
  );
  const text = await r.text();
  return {
    headers: r.headers,
    observation: { status: r.status, body: text ? JSON.parse(text) : null },
  };
}

async function cacheOwnerRows(ctx: ScenarioContext, userId: string, mode?: string) {
  // Both selected runtimes share this actual SQL database. This existing
  // application control retains complete columns instead of the short public
  // user-state summary, which cannot observe a profile name mutation.
  const read = await ctx.rawRequest(
    mode
      ? {
          path: "/__test/session-cookie-cache/control",
          method: "POST",
          json: { mode, action: "rows", userId },
        }
      : {
          path: "/__test/user-lifecycle/control",
          method: "POST",
          json: { profile: "default", action: "state" },
        },
  );
  expect(read.status).toBe(200);

  const state = read.body as {
    users: Record<string, unknown>[];
    accounts: Record<string, unknown>[];
    sessions: Record<string, unknown>[];
    verifications: Record<string, unknown>[];
  };
  const accounts = await Promise.all(
    state.accounts
      .filter((account) => account.userId === userId)
      .map(async (account) => {
        if (account.providerId !== "credential" || typeof account.password !== "string") {
          return account;
        }

        const hash = account.password;
        expect(hash).toMatch(/^[a-f0-9]{32}:[a-f0-9]{128}$/);
        expect(await verifyPassword({ password: "password123", hash })).toBeTrue();

        const [salt, derivedKey] = hash.split(":");
        return {
          ...account,
          password: {
            token: hash,
            salt: { token: salt, length: salt!.length },
            derivedKey: { token: derivedKey, length: derivedKey!.length },
            encoding: "hex-lower",
          },
        };
      }),
  );
  return {
    users: state.users.filter((user) => user.id === userId),
    accounts,
    sessions: state.sessions.filter((session) => session.userId === userId),
    verifications: state.verifications,
  };
}

compatScenario(
  "compact ordinary phone verification consumes genuine delivery proof before updating the revoked cached owner",
  async (ctx) => {
    await control(ctx, "guards", { action: "reset" });
    const owner = client(ctx, "guards");
    const foreign = client(ctx, "guards", "foreign");
    const signup = await owner.sdk.signUp.email({
      email: ctx.uniqueEmail("compact-phone-owner"),
      name: "Cached Phone Owner",
      password: "password123",
    });
    const other = await foreign.sdk.signUp.email({
      email: ctx.uniqueEmail("compact-phone-foreign"),
      name: "Foreign Phone Owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    expect(other.error).toBeNull();

    const issued = owner.headers.at(-1)!;
    const signed = await atom(issued);
    const foreignBefore = await cacheOwnerRows(ctx, other.data!.user.id, "guards");
    const phoneNumber = `+1${String(Bun.hash(ctx.uniqueToken("compact-phone")))
      .padStart(10, "0")
      .slice(-10)}`;
    const delivery = await cacheGuardRequest(ctx, owner, "/phone-number/send-otp", [], {
      phoneNumber,
    });
    expect(delivery.observation.status).toBe(200);

    const events = await control(ctx, "guards", { action: "state" });
    const sent = events.events.find((event) => event.stage === "phone-delivery");
    expect(sent?.phoneNumber).toBe(phoneNumber);
    expect(sent?.code).toMatch(/^\d{6}$/);

    const proof = await cacheOwnerRows(ctx, signup.data!.user.id, "guards");
    expect(
      proof.verifications.some(
        (row) => row.identifier === phoneNumber && row.value === `${sent!.code}:0`,
      ),
    ).toBeTrue();

    await control(ctx, "guards", { action: "revoke", token: signup.data!.token });
    const verified = await cacheGuardRequest(
      ctx,
      owner,
      "/phone-number/verify",
      cookiePairs(issued),
      { phoneNumber, code: sent!.code, updatePhoneNumber: true },
    );
    expect(verified.observation.status).toBe(200);

    const after = await cacheOwnerRows(ctx, signup.data!.user.id, "guards");
    expect(after.users[0]!).toMatchObject({
      id: signup.data!.user.id,
      phoneNumber,
      phoneNumberVerified: true,
    });
    expect(after.sessions).toEqual([]);
    expect(after.verifications.some((row) => row.identifier === phoneNumber)).toBeFalse();

    const receipts = await control(ctx, "guards", { action: "state" });
    expect(receipts.events.filter((event) => event.stage === "phone-verified")).toHaveLength(1);
    expect(receipts.events.find((event) => event.stage === "phone-verified")!.user.id).toBe(
      signup.data!.user.id,
    );

    const replay = await cacheGuardRequest(
      ctx,
      owner,
      "/phone-number/verify",
      cookiePairs(issued),
      { phoneNumber, code: sent!.code, updatePhoneNumber: true },
    );
    expect(replay.observation.status).toBe(400);
    expect(await cacheOwnerRows(ctx, signup.data!.user.id, "guards")).toEqual(after);

    const foreignAfter = await cacheOwnerRows(ctx, other.data!.user.id, "guards");
    expect(foreignAfter.users).toEqual(foreignBefore.users);
    expect(foreignAfter.accounts).toEqual(foreignBefore.accounts);
    expect(foreignAfter.sessions).toEqual(foreignBefore.sessions);

    const observed = receipts.events.map((event) =>
      event.stage === "phone-delivery"
        ? { ...event, code: { token: event.code, length: event.code.length } }
        : event,
    );
    const observedProof = {
      ...proof,
      verifications: proof.verifications.map((row) => ({
        ...row,
        value: { token: row.value, length: String(row.value).length },
      })),
    };
    return {
      signup,
      other,
      signed,
      delivery: delivery.observation,
      proof: observedProof,
      events: observed,
      verified: verified.observation,
      replay: replay.observation,
      after,
      foreignBefore,
      foreignAfter,
    };
  },
  ["POST /phone-number/send-otp", "POST /phone-number/verify"],
);

compatScenario(
  "compact sensitive admin admission rejects genuine API-key virtual authority after physical revocation",
  async (ctx) => {
    await control(ctx, "guards", { action: "reset" });
    const owner = client(ctx, "guards");
    const foreign = client(ctx, "guards", "foreign");
    const signup = await owner.sdk.signUp.email({
      email: ctx.uniqueEmail("compact-admin-owner"),
      name: "Physical Admin Owner",
      password: "password123",
    });
    const other = await foreign.sdk.signUp.email({
      email: ctx.uniqueEmail("compact-admin-foreign"),
      name: "Foreign Admin Owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    expect(other.error).toBeNull();

    const issued = owner.headers.at(-1)!;
    const signed = await atom(issued);
    const created = await owner.sdk.$fetch<Record<string, any>>("/api-key/create", {
      method: "POST",
      body: { name: "actual-virtual-admin-key" },
    });
    expect(created.error).toBeNull();
    expect(typeof created.data!.key).toBe("string");

    const readKeys = async () => {
      const rows = await ctx.rawRequest({
        path: "/__test/session-cookie-cache/control",
        method: "POST",
        json: { mode: "guards", action: "api-key-rows", userId: signup.data!.user.id },
      });
      expect(rows.status).toBe(200);

      const keys = (rows.body as { keys: Record<string, any>[] }).keys;
      expect(keys).toHaveLength(1);
      expect(keys[0]!.key).toBe(createHash("sha256").update(created.data!.key).digest("base64url"));

      return keys.map((key) => ({
        ...key,
        key: { token: key.key, length: key.key.length },
        start: { token: key.start, length: key.start.length },
      }));
    };
    const keysBefore = await readKeys();
    await control(ctx, "guards", { action: "revoke", token: signup.data!.token });
    const before = await cacheOwnerRows(ctx, signup.data!.user.id, "guards");
    const foreignBefore = await cacheOwnerRows(ctx, other.data!.user.id, "guards");
    expect(before.sessions).toEqual([]);

    const request = async (route: string) => {
      const response = await owner.fetch(
        ctx.baseURL + authProfilePath("session-cache-guards") + route,
        { credentials: "omit", headers: { "x-api-key": created.data!.key, origin: ctx.baseURL } },
      );
      const text = await response.text();
      return {
        status: response.status,
        body: text ? JSON.parse(text) : null,
        cookies: response.headers.getSetCookie(),
      };
    };
    const virtual = await request("/get-session");
    expect(virtual.status).toBe(200);
    expect(virtual.body.user.id).toBe(signup.data!.user.id);
    expect(virtual.cookies).toEqual([]);

    const denied = await request("/admin/list-users");
    expect(denied.status).toBe(401);
    expect(denied.body).toBeNull();
    expect(await cacheOwnerRows(ctx, signup.data!.user.id, "guards")).toEqual(before);
    expect(await cacheOwnerRows(ctx, other.data!.user.id, "guards")).toEqual(foreignBefore);

    const keysAfter = await readKeys();
    expect((keysAfter[0]! as Record<string, any>).referenceId).toBe(signup.data!.user.id);

    return {
      signup,
      other,
      signed,
      created,
      keysBefore,
      virtual,
      denied,
      before,
      foreignBefore,
      keysAfter,
    };
  },
  ["POST /api-key/create", "GET /get-session", "GET /admin/list-users"],
);

compatScenario(
  "compact ordinary update retains the genuine cached user projection after actual user deletion without recreating rows",
  async (ctx) => {
    await control(ctx, "guards", { action: "reset" });
    const owner = client(ctx, "guards");
    const foreign = client(ctx, "guards", "foreign");
    const signup = await owner.sdk.signUp.email({
      email: ctx.uniqueEmail("compact-deleted-owner"),
      name: "Deleted Cached Owner",
      password: "password123",
    });
    const other = await foreign.sdk.signUp.email({
      email: ctx.uniqueEmail("compact-deleted-foreign"),
      name: "Foreign Existing Owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    expect(other.error).toBeNull();

    const issued = owner.headers.at(-1)!;
    const signed = await atom(issued);
    const foreignBefore = await cacheOwnerRows(ctx, other.data!.user.id, "guards");
    const deleted = await owner.sdk.deleteUser({ password: "password123" });
    expect(deleted.error).toBeNull();

    const before = await cacheOwnerRows(ctx, signup.data!.user.id, "guards");
    expect(before.users).toEqual([]);
    expect(before.accounts).toEqual([]);
    expect(before.sessions).toEqual([]);

    const update = await cacheGuardRequest(ctx, owner, "/update-user", cookiePairs(issued), {
      name: "Updated Deleted Snapshot",
    });
    expect(update.observation).toEqual({ status: 200, body: { status: true } });

    const renewed = await atom(update.headers);
    expect(renewed.compactSessionCache.decoded!.user).toEqual({
      ...signed.compactSessionCache.decoded!.user,
      name: "Updated Deleted Snapshot",
    });
    expect(renewed.compactSessionCache.decoded!.session).toEqual(
      signed.compactSessionCache.decoded!.session,
    );

    const bypass = await cacheGuardRequest(
      ctx,
      owner,
      "/update-user?disableCookieCache=true",
      cookiePairs(issued),
      { name: "Denied Bypass" },
    );
    expect(bypass.observation.status).toBe(401);

    const sensitive = await cacheGuardRequest(ctx, owner, "/change-password", cookiePairs(issued), {
      currentPassword: "password123",
      newPassword: "different-password123",
    });
    expect(sensitive.observation.status).toBe(401);
    expect(await cacheOwnerRows(ctx, signup.data!.user.id, "guards")).toEqual(before);
    expect(await cacheOwnerRows(ctx, other.data!.user.id, "guards")).toEqual(foreignBefore);

    return {
      signup,
      other,
      signed,
      deleted,
      before,
      foreignBefore,
      update: update.observation,
      renewed,
      bypass: bypass.observation,
      sensitive: sensitive.observation,
    };
  },
  ["POST /delete-user", "POST /update-user", "POST /change-password"],
);

for (const [label, route] of [
  ["fresh list-sessions", "/list-sessions"],
  ["API-key list", "/api-key/list"],
  ["passkey list", "/passkey/list-user-passkeys"],
  ["one-time-token generation", "/one-time-token/generate"],
] as const) {
  compatScenario(
    `compact ordinary ${label} retains genuinely signed revoked authority and rejects bypass expired and foreign-bound cache`,
    async (ctx) => {
      await control(ctx, "guards", { action: "reset" });
      const owner = client(ctx, "guards");
      const foreign = client(ctx, "guards", "foreign");
      const expired = client(ctx, "negative", "expired");
      const signup = await owner.sdk.signUp.email({
        email: ctx.uniqueEmail(`cache-guard-${label.replace(/[^a-z0-9-]/gi, "-")}`),
        name: "Ordinary Cached Owner",
        password: "password123",
      });
      const other = await foreign.sdk.signUp.email({
        email: ctx.uniqueEmail("cache-guard-foreign"),
        name: "Foreign Cached Owner",
        password: "password123",
      });
      const past = await expired.sdk.signUp.email({
        email: ctx.uniqueEmail("cache-guard-expired"),
        name: "Expired Cached Owner",
        password: "password123",
      });
      expect(signup.error).toBeNull();
      expect(other.error).toBeNull();
      expect(past.error).toBeNull();

      const issued = owner.headers.at(-1)!;
      const otherIssued = foreign.headers.at(-1)!;
      const pastIssued = expired.headers.at(-1)!;
      const signed = await atom(issued);
      const otherSigned = await atom(otherIssued);
      const pastSigned = await atom(pastIssued, -1, false);
      let completedProof: unknown = null;

      if (label === "one-time-token generation") {
        const genuine = await cacheGuardRequest(ctx, owner, route, cookiePairs(issued));
        expect(genuine.observation.status).toBe(200);

        const guest = client(ctx, "guards", "proof-consumer");
        const consumed = await cacheGuardRequest(ctx, guest, "/one-time-token/verify", [], {
          token: genuine.observation.body.token,
        });
        expect(consumed.observation.status).toBe(200);
        expect(consumed.observation.body.session.token).toBe(signup.data!.token);

        const selected = await atom(consumed.headers);
        expect(selected.compactSessionCache.decoded!.user.id).toBe(signup.data!.user.id);

        const replay = await cacheGuardRequest(ctx, guest, "/one-time-token/verify", [], {
          token: genuine.observation.body.token,
        });
        expect(replay.observation.status).toBe(400);

        completedProof = {
          genuine: genuine.observation,
          consumed: consumed.observation,
          selected,
          replay: replay.observation,
        };
      }

      await control(ctx, "guards", { action: "revoke", token: signup.data!.token });
      await control(ctx, "guards", { action: "revoke", token: other.data!.token });
      await control(ctx, "negative", { action: "revoke", token: past.data!.token });
      const before = await cacheOwnerRows(ctx, signup.data!.user.id);
      const foreignBefore = await cacheOwnerRows(ctx, other.data!.user.id);
      const pastBefore = await cacheOwnerRows(ctx, past.data!.user.id);
      expect((before as any).sessions).toEqual([]);
      expect((foreignBefore as any).sessions).toEqual([]);
      expect((pastBefore as any).sessions).toEqual([]);

      const retained = await cacheGuardRequest(ctx, owner, route, cookiePairs(issued));
      expect(retained.observation.status).toBe(200);

      if (label === "fresh list-sessions" || label === "passkey list") {
        expect(retained.observation.body).toEqual([]);
      }

      if (label === "API-key list") {
        expect((retained.observation.body as any).apiKeys).toEqual([]);
      }

      if (label === "one-time-token generation") {
        expect(typeof (retained.observation.body as any).token).toBe("string");
      }

      const bypass = await cacheGuardRequest(
        ctx,
        owner,
        route + "?disableCookieCache=true",
        cookiePairs(issued),
      );

      // Source's API-key query object strips unknown middleware flags before its
      // nested reader. It cannot be treated as a supported explicit bypass.
      expect(bypass.observation.status).toBe(label === "API-key list" ? 200 : 401);

      const expiredResult = await cacheGuardRequest(ctx, owner, route, cookiePairs(pastIssued));
      expect(expiredResult.observation.status).toBe(401);

      const graftCookies = [
        ...cookiePairs(otherIssued).filter((pair) => pair.startsWith("better-auth.session_token=")),
        ...cookiePairs(issued).filter((pair) => pair.startsWith(cookieName + "=")),
      ];
      const foreignBound = await cacheGuardRequest(ctx, owner, route, graftCookies);
      expect(foreignBound.observation.status).toBe(401);

      const after = await cacheOwnerRows(ctx, signup.data!.user.id);
      expect(after.users).toEqual(before.users);
      expect(after.accounts).toEqual(before.accounts);
      expect(after.sessions).toEqual(before.sessions);

      const foreignAfter = await cacheOwnerRows(ctx, other.data!.user.id);
      const pastAfter = await cacheOwnerRows(ctx, past.data!.user.id);
      expect(foreignAfter.users).toEqual(foreignBefore.users);
      expect(foreignAfter.accounts).toEqual(foreignBefore.accounts);
      expect(foreignAfter.sessions).toEqual(foreignBefore.sessions);
      expect(pastAfter.users).toEqual(pastBefore.users);
      expect(pastAfter.accounts).toEqual(pastBefore.accounts);
      expect(pastAfter.sessions).toEqual(pastBefore.sessions);

      return {
        signup,
        other,
        past,
        signed,
        otherSigned,
        pastSigned,
        completedProof,
        before,
        foreignBefore,
        pastBefore,
        retained: retained.observation,
        bypass: bypass.observation,
        expiredResult: expiredResult.observation,
        foreignBound: foreignBound.observation,
        after,
      };
    },
    [`GET ${route}`],
  );
}

compatScenario(
  "compact ordinary profile mutation publishes the real updated owner cache after physical revocation and preserves sensitive and corrupt denials",
  async (ctx) => {
    await control(ctx, "guards", { action: "reset" });
    const owner = client(ctx, "guards");
    const foreign = client(ctx, "guards", "foreign");
    const signup = await owner.sdk.signUp.email({
      email: ctx.uniqueEmail("cache-update-owner"),
      name: "Original Cached Owner",
      password: "password123",
    });
    const other = await foreign.sdk.signUp.email({
      email: ctx.uniqueEmail("cache-update-other"),
      name: "Foreign Untouched Owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    expect(other.error).toBeNull();

    const issued = owner.headers.at(-1)!;
    const signed = await atom(issued);
    const cookies = cookiePairs(issued);
    const foreignBefore = await cacheOwnerRows(ctx, other.data!.user.id);
    await control(ctx, "guards", { action: "revoke", token: signup.data!.token });
    const before = await cacheOwnerRows(ctx, signup.data!.user.id);
    expect(before.sessions).toEqual([]);

    const retained = await cacheGuardRequest(ctx, owner, "/update-user", cookies, {
      name: "Actual Revoked Cache Mutation",
    });
    expect(retained.observation).toEqual({ status: 200, body: { status: true } });

    const renewed = await atom(retained.headers);
    expect(renewed.compactSessionCache.decoded!.user.name).toBe("Actual Revoked Cache Mutation");
    expect(renewed.compactSessionCache.decoded!.session.token).toBe(signup.data!.token!);

    const after = await cacheOwnerRows(ctx, signup.data!.user.id);
    expect(after.users[0]!.name).toBe("Actual Revoked Cache Mutation");
    expect(after.sessions).toEqual([]);
    expect(after.accounts).toEqual(before.accounts);

    const bad = cookies.map((pair) =>
      pair.startsWith(cookieName + "=")
        ? pair.slice(0, -1) + (pair.endsWith("A") ? "B" : "A")
        : pair,
    );
    const corrupt = await cacheGuardRequest(ctx, owner, "/update-user", bad, {
      name: "Rejected Corrupt Mutation",
    });
    expect(corrupt.observation.status).toBe(401);

    const wrong = cookies.map((pair) =>
      pair.startsWith("better-auth.session_token=")
        ? pair.slice(0, -1) + (pair.endsWith("A") ? "B" : "A")
        : pair,
    );
    const signature = await cacheGuardRequest(ctx, owner, "/update-user", wrong, {
      name: "Rejected Signature Mutation",
    });
    expect(signature.observation.status).toBe(401);
    expect(signature.headers.getSetCookie()).toEqual([]);

    const sensitive = await cacheGuardRequest(ctx, owner, "/change-password", cookies, {
      currentPassword: "password123",
      newPassword: "different-password123",
    });
    expect(sensitive.observation.status).toBe(401);

    const admin = await cacheGuardRequest(ctx, owner, "/admin/list-users", cookies);
    expect(admin.observation.status).toBe(401);
    expect(await cacheOwnerRows(ctx, signup.data!.user.id)).toEqual(after);
    expect(await cacheOwnerRows(ctx, other.data!.user.id)).toEqual(foreignBefore);

    return {
      signup,
      other,
      signed,
      before,
      foreignBefore,
      retained: retained.observation,
      renewed,
      after,
      corrupt: corrupt.observation,
      corruptCookies: corrupt.headers.getSetCookie(),
      signature: signature.observation,
      sensitive: sensitive.observation,
      admin: admin.observation,
    };
  },
  ["POST /update-user", "POST /change-password", "GET /admin/list-users"],
);

compatScenario(
  "compact ordinary organization guards retain revoked identity while physical memberships still isolate the foreign organization",
  async (ctx) => {
    await control(ctx, "guards", { action: "reset" });
    const owner = client(ctx, "guards");
    const foreign = client(ctx, "guards", "foreign");
    const signup = await owner.sdk.signUp.email({
      email: ctx.uniqueEmail("compact-org-owner"),
      name: "Cached Organization Owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();

    const issued = owner.headers.at(-1)!;
    const signed = await atom(issued);
    const other = await foreign.sdk.signUp.email({
      email: ctx.uniqueEmail("compact-org-foreign"),
      name: "Foreign Organization Owner",
      password: "password123",
    });
    expect(other.error).toBeNull();

    const org = await owner.sdk.organization.create({
      name: "Actual Cached Organization",
      slug: ctx.uniqueToken("cached-org"),
      keepCurrentActiveOrganization: true,
    });
    expect(org.error).toBeNull();

    const foreignOrg = await foreign.sdk.organization.create({
      name: "Actual Foreign Organization",
      slug: ctx.uniqueToken("foreign-org"),
      keepCurrentActiveOrganization: true,
    });
    expect(foreignOrg.error).toBeNull();

    await control(ctx, "guards", { action: "revoke", token: signup.data!.token });
    const before = await cacheOwnerRows(ctx, signup.data!.user.id, "guards");
    const foreignBefore = await cacheOwnerRows(ctx, other.data!.user.id, "guards");
    expect(before.sessions).toEqual([]);

    const permissions = { organization: ["update"] };
    const body = { organizationId: org.data!.id, permissions };
    const retained = await cacheGuardRequest(
      ctx,
      owner,
      "/organization/has-permission",
      cookiePairs(issued),
      body,
    );
    expect(retained.observation).toEqual({ status: 200, body: { success: true, error: null } });

    const forbidden = await cacheGuardRequest(
      ctx,
      owner,
      "/organization/has-permission",
      cookiePairs(issued),
      { ...body, organizationId: foreignOrg.data!.id },
    );
    expect(forbidden.observation.status).toBe(401);

    const bypass = await cacheGuardRequest(
      ctx,
      owner,
      "/organization/has-permission?disableCookieCache=true",
      cookiePairs(issued),
      body,
    );
    expect(bypass.observation.status).toBe(401);

    const current = await owner.sdk.organization.getFullOrganization({
      query: { organizationId: org.data!.id },
    });
    expect(current.error).toBeNull();
    expect(current.data!.members.map((member) => member.userId)).toEqual([signup.data!.user.id]);

    const foreignCurrent = await foreign.sdk.organization.getFullOrganization({
      query: { organizationId: foreignOrg.data!.id },
    });
    expect(foreignCurrent.error).toBeNull();
    expect(foreignCurrent.data!.members.map((member) => member.userId)).toEqual([
      other.data!.user.id,
    ]);
    expect(await cacheOwnerRows(ctx, signup.data!.user.id, "guards")).toEqual(before);
    expect(await cacheOwnerRows(ctx, other.data!.user.id, "guards")).toEqual(foreignBefore);

    return {
      signup,
      other,
      signed,
      org,
      foreignOrg,
      before,
      foreignBefore,
      retained: retained.observation,
      forbidden: forbidden.observation,
      bypass: bypass.observation,
      current,
      foreignCurrent,
    };
  },
  ["POST /organization/has-permission", "GET /organization/get-full-organization"],
);

for (const decision of ["approve", "deny"] as const) {
  compatScenario(
    `compact ordinary device ${decision} claims actual grant through revoked cache and refuses a foreign decision`,
    async (ctx) => {
      await control(ctx, "guards", { action: "reset" });
      const owner = client(ctx, "guards");
      const foreign = client(ctx, "guards", "foreign");
      const signup = await owner.sdk.signUp.email({
        email: ctx.uniqueEmail(`compact-device-${decision}`),
        name: "Cached Device Owner",
        password: "password123",
      });
      expect(signup.error).toBeNull();

      const issued = owner.headers.at(-1)!;
      const signed = await atom(issued);
      const other = await foreign.sdk.signUp.email({
        email: ctx.uniqueEmail("compact-device-foreign"),
        name: "Foreign Device Owner",
        password: "password123",
      });
      expect(other.error).toBeNull();

      const foreignBefore = await cacheOwnerRows(ctx, other.data!.user.id, "guards");
      const code = await owner.sdk.device.code({
        client_id: "compact-actual-client",
        scope: "read write",
      });
      expect(code.error).toBeNull();

      await control(ctx, "guards", { action: "revoke", token: signup.data!.token });
      const before = await cacheOwnerRows(ctx, signup.data!.user.id, "guards");
      expect(before.sessions).toEqual([]);

      const claimed = await cacheGuardRequest(
        ctx,
        owner,
        `/device?user_code=${code.data!.user_code}`,
        cookiePairs(issued),
      );
      expect(claimed.observation).toEqual({
        status: 200,
        body: {
          user_code: code.data!.user_code,
          status: "pending",
          client_id: "compact-actual-client",
          scope: "read write",
        },
      });

      const row = (await ctx.readDeviceState({ deviceCode: code.data!.device_code })) as any;
      expect(row.userId).toBe(signup.data!.user.id);
      expect(row.status).toBe("pending");

      const forbidden = await foreign.sdk.device[decision]({ userCode: code.data!.user_code });
      expect(forbidden.error!.status).toBe(403);
      expect(await ctx.readDeviceState({ deviceCode: code.data!.device_code })).toEqual(row);

      const accepted = await cacheGuardRequest(
        ctx,
        owner,
        `/device/${decision}`,
        cookiePairs(issued),
        { userCode: code.data!.user_code },
      );
      expect(accepted.observation).toEqual({ status: 200, body: { success: true } });

      const afterGrant = (await ctx.readDeviceState({ deviceCode: code.data!.device_code })) as any;
      expect(afterGrant.userId).toBe(signup.data!.user.id);
      expect(afterGrant.status).toBe(decision === "approve" ? "approved" : "denied");

      const replay = await cacheGuardRequest(
        ctx,
        owner,
        `/device/${decision}`,
        cookiePairs(issued),
        { userCode: code.data!.user_code },
      );
      expect(replay.observation.status).toBe(400);
      expect(await cacheOwnerRows(ctx, signup.data!.user.id, "guards")).toEqual(before);
      expect(await cacheOwnerRows(ctx, other.data!.user.id, "guards")).toEqual(foreignBefore);

      const redemption = await owner.sdk.device.token({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: code.data!.device_code,
        client_id: "compact-actual-client",
      });

      if (decision === "approve") {
        expect(redemption.error).toBeNull();
        expect(redemption.data!.token_type).toBe("Bearer");
        expect(redemption.data!.scope).toBe("read write");
      } else {
        expect(redemption.error!.error).toBe("access_denied");
      }

      const redemptionCookies = owner.headers.at(-1)!.getSetCookie();
      expect(redemptionCookies).toEqual([]);
      expect(await ctx.readDeviceState({ deviceCode: code.data!.device_code })).toBeNull();

      const completed = await cacheOwnerRows(ctx, signup.data!.user.id, "guards");
      expect(completed.users).toEqual(before.users);
      expect(completed.accounts).toEqual(before.accounts);
      expect(completed.sessions).toHaveLength(decision === "approve" ? 1 : 0);

      if (decision === "approve") {
        expect(completed.sessions[0]!.token).toBe(redemption.data!.access_token);
      }

      return {
        signup,
        other,
        signed,
        code,
        before,
        foreignBefore,
        claimed: claimed.observation,
        row,
        forbidden,
        accepted: accepted.observation,
        afterGrant,
        replay: replay.observation,
        redemption,
        redemptionCookies,
        completed,
      };
    },
    ["GET /device", `POST /device/${decision}`],
  );
}

const secret = "compat-test-only-key-not-real-minimum-32chars";
const cookieName = "better-auth.session_data";

compatScenario(
  "compact interaction signed-email verification publishes the original authenticated projection through actual multi-session and JWT hooks",
  async (ctx) => {
    await control(ctx, "interactions", { action: "reset" });
    const owner = client(ctx, "interactions");
    const foreign = client(ctx, "interactions", "foreign");
    const email = ctx.uniqueEmail("compact-signed-email");
    const signup = await owner.sdk.signUp.email({
      email,
      name: "Original Signed Email Snapshot",
      password: "password123",
    });
    const other = await foreign.sdk.signUp.email({
      email: ctx.uniqueEmail("compact-signed-email-foreign"),
      name: "Foreign Email Snapshot",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    expect(other.error).toBeNull();

    const originalHeaders = owner.headers.at(-1)!;
    const original = await atom(originalHeaders);
    const foreignBefore = await cacheOwnerRows(ctx, other.data!.user.id, "interactions");
    await control(ctx, "interactions", { action: "clear-events" });
    const sent = await owner.sdk.sendVerificationEmail({
      email,
      fetchOptions: { headers: { "x-lifecycle-marker": "composed-email-delivery" } },
    });
    expect(sent.error).toBeNull();

    const delivered = await control(ctx, "interactions", { action: "state" });
    const mail = delivered.events.find((event) => event.stage === "verification-mail")!;
    expect(mail.user.id).toBe(signup.data!.user.id);

    const [header, payload, signature] = String(mail.token).split(".");
    expect(signature).toBe(
      createHmac("sha256", secret).update(`${header}.${payload}`).digest("base64url"),
    );

    const claims = JSON.parse(Buffer.from(payload!, "base64url").toString());
    expect(claims.email).toBe(email);
    expect(claims.exp - claims.iat).toBe(3600);

    await control(ctx, "interactions", {
      action: "rename",
      userId: signup.data!.user.id,
      name: "Current Physical Email Row",
    });
    const before = await cacheOwnerRows(ctx, signup.data!.user.id, "interactions");
    const verification = await cacheGuardRequest(
      ctx,
      owner,
      `/verify-email?token=${mail.token}`,
      cookiePairs(originalHeaders).filter((pair) => !pair.includes("_multi-")),
      undefined,
      "interactions",
    );
    const verified = verification.observation;
    expect(verified.status).toBe(200);

    const headers = verification.headers;
    const issued = await atom(headers);
    expect(issued.compactSessionCache.decoded!.user).toEqual({
      ...original.compactSessionCache.decoded!.user,
      emailVerified: true,
    });
    expect(issued.compactSessionCache.decoded!.session).toEqual(
      original.compactSessionCache.decoded!.session,
    );
    expect(headers.getSetCookie().some((raw) => raw.includes("_multi-"))).toBeTrue();

    const receipts = await control(ctx, "interactions", { action: "state" });
    expect(
      receipts.events
        .filter((event) => event.stage?.endsWith("verification"))
        .map((event) => event.stage),
    ).toEqual(["before-verification", "after-verification"]);
    expect(receipts.events.findLast((event) => event.session)!.user).toEqual(
      ctx.snapshot(issued.compactSessionCache.decoded!.user),
    );

    const after = await cacheOwnerRows(ctx, signup.data!.user.id, "interactions");
    expect(after.users[0]!).toMatchObject({
      name: "Current Physical Email Row",
      emailVerified: true,
    });
    expect(after.accounts).toEqual(before.accounts);
    expect(after.sessions).toEqual(before.sessions);
    expect(await cacheOwnerRows(ctx, other.data!.user.id, "interactions")).toEqual(foreignBefore);

    const active = await cacheGuardRequest(
      ctx,
      owner,
      "/get-session",
      cookiePairs(headers),
      undefined,
      "interactions",
    );
    const current = active.observation;
    expect(current.status).toBe(200);
    expect(current.body.user.name).toBe("Original Signed Email Snapshot");
    expect(current.body.user.emailVerified).toBeTrue();

    const jwks = await owner.sdk.jwks();
    expect(jwks.error).toBeNull();

    const checked = await verifyWithOfficialJose(
      active.headers.get("set-auth-jwt")!,
      jwks.data!.keys as JWK[],
      ctx.baseURL,
      ctx.baseURL,
    );
    expect(checked.payload.sub).toBe(signup.data!.user.id);

    // The delivered JWT already retains its exact bytes and all decoded claims
    // through the existing JWT comparator; avoid a second untyped numeric copy.
    return {
      signup,
      other,
      original,
      sent,
      delivered,
      before,
      verified,
      issued,
      receipts,
      after,
      foreignBefore,
      current,
      checked,
    };
  },
  ["POST /send-verification-email", "GET /verify-email", "GET /get-session", "GET /jwks"],
);

compatScenario(
  "compact interaction anonymous linking retains the original cached projection while later hooks publish the genuine completed owner",
  async (ctx) => {
    await control(ctx, "interactions", { action: "reset" });
    const owner = client(ctx, "interactions");
    const foreign = client(ctx, "interactions", "foreign");
    const anonymous = await owner.sdk.signIn.anonymous();
    expect(anonymous.error).toBeNull();

    const original = await atom(owner.headers.at(-1)!);
    const anonymousId = anonymous.data!.user.id;
    const other = await foreign.sdk.signUp.email({
      email: ctx.uniqueEmail("compact-anon-foreign"),
      name: "Foreign Anonymous Control",
      password: "password123",
    });
    expect(other.error).toBeNull();

    const foreignBefore = await cacheOwnerRows(ctx, other.data!.user.id, "interactions");
    await control(ctx, "interactions", {
      action: "rename",
      userId: anonymousId,
      name: "Current Physical Anonymous Row",
    });
    const before = await cacheOwnerRows(ctx, anonymousId, "interactions");
    await control(ctx, "interactions", { action: "clear-events" });
    const signup = await owner.sdk.signUp.email({
      email: ctx.uniqueEmail("compact-anon-linked"),
      name: "Actual Linked Owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();

    const headers = owner.headers.at(-1)!;
    const issued = await atom(headers);
    expect(issued.compactSessionCache.decoded!.user.id).toBe(signup.data!.user.id);
    expect(issued.compactSessionCache.decoded!.session.token).toBe(signup.data!.token!);
    expect(headers.getSetCookie().some((raw) => raw.includes("_multi-"))).toBeTrue();

    const receipts = await control(ctx, "interactions", { action: "state" });
    const linked = receipts.events.find((event) => event.link)!;
    expect(linked.link.anonymousUser.user).toEqual(
      ctx.snapshot(original.compactSessionCache.decoded!.user),
    );
    expect(linked.link.anonymousUser.session).toEqual(
      ctx.snapshot(original.compactSessionCache.decoded!.session),
    );
    expect(linked.link.newUser.user.id).toBe(signup.data!.user.id);
    expect(linked.link.newUser.session.token).toBe(signup.data!.token);

    const retired = await cacheOwnerRows(ctx, anonymousId, "interactions");
    expect(retired.users).toEqual([]);
    expect(retired.accounts).toEqual([]);
    expect(retired.sessions).toEqual([]);

    const completed = await cacheOwnerRows(ctx, signup.data!.user.id, "interactions");
    expect(completed.sessions).toHaveLength(1);
    expect(completed.sessions[0]!.token).toBe(signup.data!.token);
    expect(await cacheOwnerRows(ctx, other.data!.user.id, "interactions")).toEqual(foreignBefore);

    const current = await owner.sdk.getSession();
    expect(current.data!.user.id).toBe(signup.data!.user.id);

    const currentHeaders = owner.headers.at(-1)!;
    const jwks = await owner.sdk.jwks();
    expect(jwks.error).toBeNull();

    const checked = await verifyWithOfficialJose(
      currentHeaders.get("set-auth-jwt")!,
      jwks.data!.keys as JWK[],
      ctx.baseURL,
      ctx.baseURL,
    );
    expect(checked.payload.sub).toBe(signup.data!.user.id);

    return {
      anonymous,
      other,
      original,
      before,
      signup,
      issued,
      receipts,
      retired,
      completed,
      foreignBefore,
      current,
      checked,
    };
  },
  ["POST /sign-in/anonymous", "POST /sign-up/email", "GET /get-session", "GET /jwks"],
);

async function control(ctx: ScenarioContext, mode: string, body: Record<string, unknown>) {
  const r = await ctx.rawRequest({
    path: "/__test/session-cookie-cache/control",
    method: "POST",
    json: { mode, ...body },
  });
  expect(r.status).toBe(200);
  return r.body as { events: Record<string, any>[]; user?: unknown };
}

function client(ctx: ScenarioContext, mode: string, name = "owner") {
  const actor = ctx.actor(name, `session-cache-${mode}` as FixtureProfile);
  const headers: Headers[] = [];
  const sdk = createAuthClient({
    baseURL: ctx.baseURL + authProfilePath(`session-cache-${mode}` as FixtureProfile),
    plugins: [
      anonymousClient(),
      organizationClient(),
      twoFactorClient(),
      multiSessionClient(),
      jwtClient(),
      deviceAuthorizationClient(),
    ],
    fetchOptions: {
      customFetchImpl: async (input, init) => {
        const r = await actor.fetch(input, init);
        headers.push(new Headers(r.headers));
        return r;
      },
    },
  });
  return { sdk, headers, fetch: actor.fetch };
}

function cookiePairs(headers: Headers) {
  return headers.getSetCookie().map((x) => x.split(";")[0]!);
}

function assembled(header: string) {
  const pairs = new Map(
    header.split(";").map((pair) => {
      const i = pair.indexOf("=");
      return [pair.slice(0, i).trim(), decodeURIComponent(pair.slice(i + 1))];
    }),
  );
  const base = pairs.get(cookieName);

  if (base) {
    return base;
  }

  return [...pairs]
    .filter(([k]) => /^better-auth\.session_data\.\d+$/.test(k))
    .sort(([a], [b]) => Number(a.split(".").at(-1)) - Number(b.split(".").at(-1)))
    .map(([, v]) => v)
    .join("");
}

async function atom(headers: Headers, effectiveMaxAgeSeconds = 300, expectDecoded = true) {
  const cookie = cookiePairs(headers).join("; ");
  const token = assembled(cookie);
  expect(token.length).toBeGreaterThan(0);

  const envelope = JSON.parse(Buffer.from(token, "base64url").toString());
  const observedAt = Date.now();
  const decoded = await getCookieCache(new Headers({ cookie }), {
    secret,
    strategy: "compact",
    isSecure: false,
  });

  if (expectDecoded) {
    expect(decoded).not.toBeNull();
  } else {
    expect(decoded).toBeNull();
  }

  const rawCookies = headers
    .getSetCookie()
    .filter((header) => header.startsWith(cookieName + "=") || header.startsWith(cookieName + "."));
  return {
    compactSessionCache: {
      token,
      envelope,
      decoded,
      observedAt,
      effectiveMaxAgeSeconds,
      rawCookies,
    },
  };
}

async function response(r: Response) {
  return { status: r.status, body: await r.json() };
}

compatScenario(
  "compact interaction pending two-factor scrubs real issuance before later multi-session hooks and completes browser cache only after actual OTP",
  async (ctx) => {
    await control(ctx, "interactions", { action: "reset" });
    const owner = client(ctx, "interactions");
    const foreign = client(ctx, "interactions", "foreign");
    const email = ctx.uniqueEmail("compact-factor-pending");
    const signup = await owner.sdk.signUp.email({
      email,
      name: "Pending Compact Owner",
      password: "password123",
    });
    const other = await foreign.sdk.signUp.email({
      email: ctx.uniqueEmail("compact-factor-foreign"),
      name: "Untouched Foreign Owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    expect(other.error).toBeNull();

    const foreignBefore = await cacheOwnerRows(ctx, other.data!.user.id, "interactions");
    const enabled = await owner.sdk.twoFactor.enable({ password: "password123", method: "otp" });
    expect(enabled.error).toBeNull();
    expect((await owner.sdk.signOut()).error).toBeNull();

    await control(ctx, "interactions", { action: "clear-events" });
    const pending = await owner.sdk.signIn.email({
      email,
      password: "password123",
      rememberMe: false,
    });
    expect(pending.data).toMatchObject({ twoFactorRedirect: true, twoFactorMethods: ["otp"] });

    const pendingHeaders = owner.headers.at(-1)!;
    const pendingCookies = pendingHeaders.getSetCookie();
    expect(
      pendingCookies
        .filter(
          (raw) => raw.startsWith(cookieName + "=") || raw.startsWith("better-auth.session_token="),
        )
        .every((raw) => Cookie.parse(raw)?.maxAge === 0),
    ).toBeTrue();
    expect(pendingCookies.some((raw) => raw.includes("_multi-"))).toBeFalse();

    const afterPending = await control(ctx, "interactions", { action: "state" });
    expect(afterPending.events).toHaveLength(1);
    expect(afterPending.events[0]!.user.twoFactorEnabled).toBeTrue();

    const transient = afterPending.events[0]!.session;
    expect(transient.userId).toBe(signup.data!.user.id);
    expect(transient.hidden).toBe("cache-server-secret");

    const pendingRows = await cacheOwnerRows(ctx, signup.data!.user.id, "interactions");
    expect(pendingRows.sessions).toEqual([]);

    const absent = await owner.sdk.getSession();
    expect(absent.data).toBeNull();
    expect(owner.headers.at(-1)!.get("set-auth-jwt")).toBeNull();

    const sent = await owner.sdk.twoFactor.sendOtp({});
    expect(sent.error).toBeNull();

    const delivered = await control(ctx, "interactions", { action: "state" });
    const receipt = delivered.events.findLast((event) => typeof event.otp === "string")!;
    expect(receipt.user.id).toBe(signup.data!.user.id);
    expect(receipt.otp).toMatch(/^\d{6}$/);

    const verified = await owner.sdk.twoFactor.verifyOtp({ code: receipt.otp });
    expect(verified.error).toBeNull();
    expect(verified.data!.user.id).toBe(signup.data!.user.id);

    const verifiedHeaders = owner.headers.at(-1)!;
    const issued = await atom(verifiedHeaders, 60);
    expect(issued.compactSessionCache.decoded!.session.token).toBe(verified.data!.token);

    const live = verifiedHeaders.getSetCookie().filter((raw) => Cookie.parse(raw)?.value);
    expect(live.some((raw) => raw.includes("_multi-"))).toBeTrue();

    for (const raw of live.filter((raw) => !raw.includes("_multi-"))) {
      expect(raw).not.toMatch(/(?:Max-Age|Expires)=/i);
    }

    const completed = await cacheOwnerRows(ctx, signup.data!.user.id, "interactions");
    expect(completed.sessions).toHaveLength(1);
    expect(completed.sessions[0]!.token).toBe(verified.data!.token);
    expect(completed.verifications.some((row) => row.value === signup.data!.user.id)).toBeFalse();

    const current = await owner.sdk.getSession();
    expect(current.data!.session.token).toBe(verified.data!.token);

    const currentHeaders = owner.headers.at(-1)!;
    const jwks = await owner.sdk.jwks();
    expect(jwks.error).toBeNull();

    const checked = await verifyWithOfficialJose(
      currentHeaders.get("set-auth-jwt")!,
      jwks.data!.keys as JWK[],
      ctx.baseURL,
      ctx.baseURL,
    );
    expect(checked.payload.sub).toBe(signup.data!.user.id);
    expect((await cacheOwnerRows(ctx, other.data!.user.id, "interactions")).users).toEqual(
      foreignBefore.users,
    );
    expect((await cacheOwnerRows(ctx, other.data!.user.id, "interactions")).accounts).toEqual(
      foreignBefore.accounts,
    );
    expect((await cacheOwnerRows(ctx, other.data!.user.id, "interactions")).sessions).toEqual(
      foreignBefore.sessions,
    );

    return {
      signup,
      other,
      enabled,
      pending,
      pendingClears: pendingCookies.filter((raw) => Cookie.parse(raw)?.maxAge === 0),
      transient,
      sent,
      receipt: { ...receipt, otp: { token: receipt.otp, length: receipt.otp.length } },
      verified,
      issued,
      current,
      checked,
      completed: {
        ...completed,
        verifications: completed.verifications.map((row) => ({
          ...row,
          identifier: { token: row.identifier },
          value: { token: row.value },
        })),
      },
      foreignBefore,
    };
  },
  [
    "POST /sign-in/email",
    "POST /two-factor/enable",
    "POST /two-factor/send-otp",
    "POST /two-factor/verify-otp",
    "GET /get-session",
    "GET /jwks",
  ],
);

compatScenario(
  "compact interaction multi-session selection and revoked-current fallback replace genuine cache with the physically selected owner",
  async (ctx) => {
    await control(ctx, "interactions", { action: "reset" });
    const owner = client(ctx, "interactions");
    const foreign = client(ctx, "interactions", "foreign");
    const first = await owner.sdk.signUp.email({
      email: ctx.uniqueEmail("compact-multi-first"),
      name: "First Selected Owner",
      password: "password123",
    });
    expect(first.error).toBeNull();

    const firstIssued = await atom(owner.headers.at(-1)!);
    const second = await owner.sdk.signUp.email({
      email: ctx.uniqueEmail("compact-multi-second"),
      name: "Second Selected Owner",
      password: "password123",
    });
    expect(second.error).toBeNull();

    const secondIssued = await atom(owner.headers.at(-1)!);
    const other = await foreign.sdk.signUp.email({
      email: ctx.uniqueEmail("compact-multi-foreign"),
      name: "Foreign Browser Owner",
      password: "password123",
    });
    expect(other.error).toBeNull();

    const foreignBefore = await cacheOwnerRows(ctx, other.data!.user.id, "interactions");
    const list = await owner.sdk.multiSession.listDeviceSessions();
    expect(list.data).toHaveLength(2);

    const selected = await owner.sdk.multiSession.setActive({ sessionToken: first.data!.token! });
    expect(selected.error).toBeNull();

    const selectedCache = await atom(owner.headers.at(-1)!);
    expect(selectedCache.compactSessionCache.decoded!.user.id).toBe(first.data!.user.id);
    expect(selectedCache.compactSessionCache.decoded!.session.token).toBe(first.data!.token!);

    const active = await owner.sdk.getSession();
    expect(active.data!.user.id).toBe(first.data!.user.id);

    const activeHeader = owner.headers.at(-1)!;
    const jwks = await owner.sdk.jwks();
    expect(jwks.error).toBeNull();

    const checked = await verifyWithOfficialJose(
      activeHeader.get("set-auth-jwt")!,
      jwks.data!.keys as JWK[],
      ctx.baseURL,
      ctx.baseURL,
    );
    expect(checked.payload.sub).toBe(first.data!.user.id);

    await control(ctx, "interactions", { action: "revoke", token: first.data!.token });
    const firstBefore = await cacheOwnerRows(ctx, first.data!.user.id, "interactions");
    expect(firstBefore.sessions).toEqual([]);

    const revoked = await owner.sdk.multiSession.revoke({ sessionToken: first.data!.token! });
    expect(revoked.error).toBeNull();

    const fallbackCache = await atom(owner.headers.at(-1)!);
    expect(fallbackCache.compactSessionCache.decoded!.user.id).toBe(second.data!.user.id);
    expect(fallbackCache.compactSessionCache.decoded!.session.token).toBe(second.data!.token!);

    const fallback = await owner.sdk.getSession();
    expect(fallback.data!.user.id).toBe(second.data!.user.id);

    const denied = await foreign.sdk.multiSession.setActive({ sessionToken: second.data!.token! });
    expect(denied.error!.code).toBe("INVALID_SESSION_TOKEN");

    const beforeOut = await cacheOwnerRows(ctx, second.data!.user.id, "interactions");
    expect(beforeOut.sessions).toHaveLength(1);

    const signedOut = await owner.sdk.signOut();
    expect(signedOut.error).toBeNull();

    const after = await cacheOwnerRows(ctx, second.data!.user.id, "interactions");
    expect(after.sessions).toEqual([]);
    expect(after.users).toEqual(beforeOut.users);
    expect(after.accounts).toEqual(beforeOut.accounts);
    expect(await owner.sdk.multiSession.listDeviceSessions()).toMatchObject({ data: [] });
    expect(
      (await cacheOwnerRows(ctx, foreignBefore.users[0]!.id as string, "interactions")).users,
    ).toEqual(foreignBefore.users);
    expect((await cacheOwnerRows(ctx, other.data!.user.id, "interactions")).sessions).toEqual(
      foreignBefore.sessions,
    );

    return {
      first,
      second,
      other,
      firstIssued,
      secondIssued,
      list,
      selected,
      selectedCache,
      active,
      checked,
      firstBefore,
      revoked,
      fallbackCache,
      fallback,
      denied,
      beforeOut,
      signedOut,
      after,
      foreignBefore,
    };
  },
  [
    "GET /multi-session/list-device-sessions",
    "POST /multi-session/set-active",
    "POST /multi-session/revoke",
    "POST /sign-out",
  ],
);

compatScenario(
  "compact interaction factor enable and OTP session branch retain revoked ordinary authority while disable remains physical",
  async (ctx) => {
    await control(ctx, "interactions", { action: "reset" });
    const owner = client(ctx, "interactions");
    const signup = await owner.sdk.signUp.email({
      email: ctx.uniqueEmail("compact-factor-ordinary"),
      name: "Cached Factor Owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();

    const initial = await atom(owner.headers.at(-1)!);
    await control(ctx, "interactions", { action: "revoke", token: signup.data!.token });
    const enabled = await owner.sdk.twoFactor.enable({ password: "password123", method: "otp" });
    expect(enabled.error).toBeNull();

    const replacement = await atom(owner.headers.at(-1)!);
    expect(replacement.compactSessionCache.decoded!.user.twoFactorEnabled).toBeTrue();

    const current = await owner.sdk.getSession();
    expect(current.data!.session.token).not.toBe(signup.data!.token!);

    await control(ctx, "interactions", { action: "revoke", token: current.data!.session.token });
    const sent = await owner.sdk.twoFactor.sendOtp({});
    expect(sent.error).toBeNull();

    const state = await control(ctx, "interactions", { action: "state" });
    const receipt = state.events.findLast((event) => typeof event.otp === "string")!;
    expect(receipt.user.id).toBe(signup.data!.user.id);

    const verified = await owner.sdk.twoFactor.verifyOtp({ code: receipt.otp });
    expect(verified.error).toBeNull();
    expect(verified.data!.token).toBe(current.data!.session.token);

    const disabled = await owner.sdk.twoFactor.disable({ password: "password123" });
    expect(disabled.error!.status).toBe(401);

    const after = await cacheOwnerRows(ctx, signup.data!.user.id, "interactions");
    expect(after.sessions).toEqual([]);
    expect(after.users[0]!.twoFactorEnabled).toBeTrue();

    return {
      signup,
      initial,
      enabled,
      replacement,
      current,
      sent,
      receipt: { ...receipt, otp: { token: receipt.otp, length: receipt.otp.length } },
      verified,
      disabled,
      after,
    };
  },
  [
    "POST /two-factor/enable",
    "POST /two-factor/send-otp",
    "POST /two-factor/verify-otp",
    "POST /two-factor/disable",
  ],
);

compatScenario(
  "compact cache authenticates the signed token and complete payload while retaining revoked ordinary authority only until explicit bypass",
  async (ctx) => {
    await control(ctx, "standard", { action: "reset" });
    const owner = client(ctx, "standard");
    const foreign = client(ctx, "standard", "foreign");
    const signup = await owner.sdk.signUp.email({
      email: ctx.uniqueEmail("compact-owner"),
      name: "Original Cache Owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();

    const original = signup.data!;
    expect(typeof original.token).toBe("string");

    const issued = owner.headers.at(-1)!;
    const signed = await atom(issued);
    expect(signed.compactSessionCache.decoded!.session).toMatchObject({
      token: original.token,
      label: "cache-public-label",
    });
    expect(signed.compactSessionCache.decoded!.session).not.toHaveProperty("hidden");

    const other = await foreign.sdk.signUp.email({
      email: ctx.uniqueEmail("compact-foreign"),
      name: "Foreign Owner",
      password: "password123",
    });
    expect(other.error).toBeNull();

    const foreignBefore = await ctx.readUserState({ userId: other.data!.user.id });
    const foreignHeaders = foreign.headers.at(-1)!;
    await control(ctx, "standard", {
      action: "rename",
      userId: original.user.id,
      name: "Authoritative Stored Owner",
    });
    const cached = await owner.sdk.getSession();
    expect(cached.data!.user.name).toBe("Original Cache Owner");

    const bypass = await owner.sdk.getSession({
      query: { disableCookieCache: true, disableRefresh: true },
    });
    expect(bypass.data!.user.name).toBe("Authoritative Stored Owner");

    const oldCookies = cookiePairs(issued);
    const foreignCookies = cookiePairs(foreignHeaders);
    const graft = await response(
      await owner.fetch(ctx.baseURL + authProfilePath("session-cache-standard") + "/get-session", {
        credentials: "omit",
        headers: {
          cookie: [
            ...foreignCookies.filter((p) => p.startsWith("better-auth.session_token=")),
            ...oldCookies.filter((p) => p.startsWith(cookieName + "=")),
          ].join("; "),
        },
      }),
    );
    expect(graft.status).toBe(200);
    expect((graft.body as any).user.id).toBe(other.data!.user.id);

    const forged = JSON.parse(JSON.stringify(signed.compactSessionCache.envelope));
    forged.session.user.id = other.data!.user.id;
    forged.session.user.name = "Forged Foreign Name";
    const badToken = Buffer.from(JSON.stringify(forged)).toString("base64url");
    const tamper = await response(
      await owner.fetch(ctx.baseURL + authProfilePath("session-cache-standard") + "/get-session", {
        credentials: "omit",
        headers: {
          cookie: [
            ...oldCookies.filter((p) => p.startsWith("better-auth.session_token=")),
            cookieName + "=" + badToken,
          ].join("; "),
        },
      }),
    );
    expect((tamper.body as any).user.id).toBe(original.user.id);
    expect((tamper.body as any).user.name).toBe("Authoritative Stored Owner");
    expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(foreignBefore);

    await control(ctx, "standard", { action: "revoke", token: original.token });
    const before = await ctx.readUserState({ userId: original.user.id });
    expect((before as any).sessions).toEqual([]);

    const retained = await owner.sdk.getSession();
    expect(retained.data!.session.token).toBe(original.token!);

    const accounts = await owner.sdk.listAccounts();
    expect(accounts.error).toBeNull();
    expect(accounts.data!.length).toBe(1);

    const organizations = await owner.sdk.organization.list();
    expect(organizations.error).toBeNull();
    expect(organizations.data).toEqual([]);

    const authoritative = await owner.sdk.getSession({ query: { disableCookieCache: true } });
    expect(authoritative.data).toBeNull();
    expect(await ctx.readUserState({ userId: original.user.id })).toEqual(before);
    expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(foreignBefore);

    return {
      signup: ctx.snapshot(signup),
      signed,
      other: ctx.snapshot(other),
      foreignBefore,
      cached: ctx.snapshot(cached),
      bypass: ctx.snapshot(bypass),
      graft,
      tamper,
      before,
      retained: ctx.snapshot(retained),
      accounts: ctx.snapshot(accounts),
      organizations: ctx.snapshot(organizations),
      authoritative: ctx.snapshot(authoritative),
    };
  },
  ["GET /get-session", "GET /list-accounts", "GET /organization/list"],
);

compatScenario(
  "compact cache chunking uses real writer limits and canonical server chunk indices with base-cookie precedence",
  async (ctx) => {
    await control(ctx, "standard", { action: "reset" });
    const owner = client(ctx, "standard");
    const signup = await owner.sdk.signUp.email({
      email: ctx.uniqueEmail("compact-chunk"),
      name: "x".repeat(6000),
      password: "password123",
    });
    expect(signup.error).toBeNull();

    const headers = owner.headers.at(-1)!;
    const pairs = cookiePairs(headers);
    const parts = headers.getSetCookie().filter((p) => p.startsWith(cookieName + "."));
    expect(parts.length).toBeGreaterThan(1);

    for (const part of parts) {
      expect(Buffer.byteLength(part)).toBeLessThanOrEqual(4050);
    }

    const issued = await atom(headers);
    const attributes = parts[0]!.slice(parts[0]!.indexOf(";"));
    const capacity = 4050 - (cookieName + ".99=" + attributes).length;
    const values = parts.map((part) => part.split(";")[0]!.slice(part.indexOf("=") + 1));
    expect(values.join("")).toBe(issued.compactSessionCache.token);

    values.forEach((value, index) =>
      expect(value.length).toBe(
        Math.min(capacity, issued.compactSessionCache.token.length - index * capacity),
      ),
    );
    await control(ctx, "standard", {
      action: "rename",
      userId: signup.data!.user.id,
      name: "Stored Chunk Owner",
    });
    const token = pairs.find((p) => p.startsWith("better-auth.session_token="))!;
    const chunks = pairs.filter((p) => p.startsWith(cookieName + "."));
    const observations = [];

    for (const [mode, cache, expected] of [
      ["reverse", [...chunks].reverse(), "x".repeat(6000)],
      [
        "base-precedence",
        [
          cookieName + "=" + issued.compactSessionCache.token,
          ...chunks.map((p) => p.replace(/=.*/, "=invalid")),
        ],
        "x".repeat(6000),
      ],
      [
        "noncanonical",
        chunks.map((p) => p.replace(cookieName + ".0=", cookieName + ".00=")),
        "Stored Chunk Owner",
      ],
      ["missing", chunks.slice(1), "Stored Chunk Owner"],
    ] as const) {
      const r = await response(
        await owner.fetch(
          ctx.baseURL + authProfilePath("session-cache-standard") + "/get-session",
          { credentials: "omit", headers: { cookie: [token, ...cache].join("; ") } },
        ),
      );
      expect(r.status).toBe(200);
      expect((r.body as any).user.name).toBe(expected);

      observations.push({ mode, ...r });
    }

    const state = await ctx.readUserState({ userId: signup.data!.user.id });
    expect((state as any).sessions.length).toBe(1);

    return { signup: ctx.snapshot(signup), issued, chunkCount: parts.length, observations, state };
  },
  ["GET /get-session"],
);

compatScenario(
  "compact asynchronous version receives real stored private fields then filtered cache fields and invalidation falls back without mutating foreign state",
  async (ctx) => {
    await control(ctx, "version", { action: "reset" });
    const owner = client(ctx, "version");
    const signup = await owner.sdk.signUp.email({
      email: ctx.uniqueEmail("compact-version"),
      name: "Version Owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();

    const issued = await atom(owner.headers.at(-1)!);
    const cached = await owner.sdk.getSession();
    expect(cached.error).toBeNull();

    const first = await control(ctx, "version", { action: "state" });
    expect(first.events.length).toBe(2);
    expect(first.events[0]!.session.hidden).toBe("cache-server-secret");
    expect(first.events[1]!.session).not.toHaveProperty("hidden");

    await control(ctx, "version", {
      action: "rename",
      userId: signup.data!.user.id,
      name: "Changed Version Owner",
    });
    await control(ctx, "version", { action: "policy", version: "v2" });
    const changed = await owner.sdk.getSession();
    expect(changed.data!.user.name).toBe("Changed Version Owner");

    const renewed = await atom(owner.headers.at(-1)!);
    expect(renewed.compactSessionCache.envelope.session.version).toBe("v2");

    const suppressed = await owner.sdk.getSession({
      query: { disableCookieCache: true, disableRefresh: true },
    });
    expect(suppressed.error).toBeNull();
    expect(owner.headers.at(-1)!.getSetCookie()).toEqual([]);

    const events = await control(ctx, "version", { action: "state" });
    expect(events.events.length).toBe(4);
    expect(events.events[2]!.session).not.toHaveProperty("hidden");
    expect(events.events[3]!.session).not.toHaveProperty("hidden");

    return {
      signup: ctx.snapshot(signup),
      issued,
      cached: ctx.snapshot(cached),
      first,
      changed: ctx.snapshot(changed),
      renewed,
      suppressed: ctx.snapshot(suppressed),
      events,
      state: await ctx.readUserState({ userId: signup.data!.user.id }),
    };
  },
  ["GET /get-session"],
);

for (const mode of ["version-api", "version-ordinary"] as const) {
  compatScenario(
    `compact ${mode} issuance failure rolls email transaction back and does not link the authenticated anonymous account`,
    async (ctx) => {
      await control(ctx, mode, { action: "reset" });
      const owner = client(ctx, mode);
      const anonymous = await owner.sdk.signIn.anonymous();
      expect(anonymous.error).toBeNull();

      const before = await ctx.readUserState({ userId: anonymous.data!.user.id });
      const issued = await atom(owner.headers.at(-1)!);
      await control(ctx, mode, { action: "policy", failure: true });
      const email = ctx.uniqueEmail(`compact-failure-${mode}`);
      const signup = await owner.sdk.signUp.email({
        email,
        name: "Rejected Replacement",
        password: "password123",
      });
      expect(signup.error!.status).toBe(500);

      if (mode === "version-api") {
        expect(signup.error).toMatchObject({
          code: "APPLICATION_CACHE_DENIED",
          message: "Configured cache version rejected issuance",
        });
      }

      const failureHeaders = owner.headers.at(-1)!.getSetCookie();
      expect(failureHeaders.some((h) => h.startsWith("better-auth.session_token="))).toBe(
        mode === "version-api",
      );
      expect(failureHeaders.some((h) => h.startsWith(cookieName + "="))).toBe(false);
      expect(await ctx.readUserState({ userId: anonymous.data!.user.id })).toEqual(before);

      const lookup = await control(ctx, mode, { action: "lookup", email });
      expect(lookup.user).toBeNull();
      expect(Object.keys(lookup)).toEqual(["user"]);

      const events = await control(ctx, mode, { action: "state" });
      expect(events.events.some((e) => e.link)).toBe(false);
      expect(events.events.length).toBe(mode === "version-api" ? 3 : 2);

      const session = await owner.sdk.getSession();

      if (mode === "version-api") {
        expect(session.data).toBeNull();
      } else {
        expect(session.data!.user.id).toBe(anonymous.data!.user.id);
      }

      return {
        anonymous: ctx.snapshot(anonymous),
        before,
        issued,
        signup: ctx.snapshot(signup),
        lookup,
        events,
        session: ctx.snapshot(session),
        after: await ctx.readUserState({ userId: anonymous.data!.user.id }),
      };
    },
    ["POST /sign-up/email", "GET /get-session"],
  );
}

compatScenario(
  "compact browser preference authenticates dontRemember and refreshes a sixty-second browser cache without persistent cookie attributes",
  async (ctx) => {
    await control(ctx, "standard", { action: "reset" });
    const owner = client(ctx, "standard");
    const email = ctx.uniqueEmail("compact-browser");
    expect(
      (await owner.sdk.signUp.email({ email, name: "Browser Owner", password: "password123" }))
        .error,
    ).toBeNull();

    const signed = await owner.sdk.signIn.email({
      email,
      password: "password123",
      rememberMe: false,
    });
    expect(signed.error).toBeNull();

    const issued = await atom(owner.headers.at(-1)!, 60);
    const lifetime =
      issued.compactSessionCache.envelope.expiresAt -
      issued.compactSessionCache.envelope.session.updatedAt;
    expect(lifetime).toBeGreaterThanOrEqual(60000);
    expect(lifetime).toBeLessThanOrEqual(60010);

    for (const header of owner.headers.at(-1)!.getSetCookie()) {
      expect(header).not.toMatch(/(?:Max-Age|Expires)=/i);
    }

    const token = cookiePairs(owner.headers.at(-1)!).find((p) =>
      p.startsWith("better-auth.session_token="),
    )!;
    const invalidResponse = await owner.fetch(
      ctx.baseURL + authProfilePath("session-cache-standard") + "/get-session",
      {
        credentials: "omit",
        headers: { cookie: token + "; better-auth.dont_remember=true.invalid" },
      },
    );
    const invalid = await response(invalidResponse);
    expect(invalid.status).toBe(200);

    const persistent = await atom(invalidResponse.headers);
    expect(
      persistent.compactSessionCache.envelope.expiresAt -
        persistent.compactSessionCache.envelope.session.updatedAt,
    ).toBeGreaterThanOrEqual(300000);

    return {
      signed: ctx.snapshot(signed),
      issued,
      invalid,
      persistent,
      state: await ctx.readUserState({ userId: signed.data!.user.id }),
    };
  },
  ["GET /get-session"],
);

for (const mode of ["zero", "nan", "fractional"] as const) {
  compatScenario(
    `compact ${mode} raw max-age preserves actual writer lifetime and header flooring`,
    async (ctx) => {
      await control(ctx, mode, { action: "reset" });
      const owner = client(ctx, mode);
      const signup = await owner.sdk.signUp.email({
        email: ctx.uniqueEmail(`compact-age-${mode}`),
        name: "Numeric Cache Owner",
        password: "password123",
      });
      expect(signup.error).toBeNull();

      const issued = await atom(owner.headers.at(-1)!, mode === "fractional" ? 0.5 : 300);
      const lifetime =
        issued.compactSessionCache.envelope.expiresAt -
        issued.compactSessionCache.envelope.session.updatedAt;
      const expected = mode === "fractional" ? 500 : 300000;
      expect(lifetime).toBeGreaterThanOrEqual(expected);
      expect(lifetime).toBeLessThanOrEqual(expected + 10);
      expect(
        owner.headers
          .at(-1)!
          .getSetCookie()
          .find((h) => h.startsWith(cookieName + "=")),
      ).toContain(`Max-Age=${mode === "fractional" ? 0 : 300}`);

      return {
        signup: ctx.snapshot(signup),
        issued,
        state: await ctx.readUserState({ userId: signup.data!.user.id }),
      };
    },
    ["POST /sign-up/email"],
  );
}

for (const mode of ["negative", "negative-infinite", "date-version"] as const) {
  compatScenario(
    `compact ${mode} preserves the complete signed writer envelope while published decoding rejects it and the server uses storage`,
    async (ctx) => {
      await control(ctx, mode, { action: "reset" });
      const owner = client(ctx, mode);
      const signup = await owner.sdk.signUp.email({
        email: ctx.uniqueEmail(`compact-null-${mode}`),
        name: "Rejected Cache Envelope Owner",
        password: "password123",
      });
      expect(signup.error).toBeNull();

      const effective = mode === "negative" ? -1 : mode === "negative-infinite" ? -Infinity : 300;
      const issued = await atom(owner.headers.at(-1)!, effective, false);

      if (mode === "negative-infinite") {
        expect(issued.compactSessionCache.envelope.expiresAt).toBeNull();
      }

      if (mode === "date-version") {
        expect(issued.compactSessionCache.envelope.session.version).toBe(
          "2026-10-01T00:00:00.000Z",
        );
      }

      if (mode !== "date-version") {
        expect(
          owner.headers
            .at(-1)!
            .getSetCookie()
            .find((h) => h.startsWith(cookieName + "=")),
        ).not.toMatch(/(?:Max-Age|Expires)=/i);
      }

      await control(ctx, mode, {
        action: "rename",
        userId: signup.data!.user.id,
        name: "Actual Stored Fallback Owner",
      });
      const fallback = await owner.sdk.getSession();
      expect(fallback.data!.user.name).toBe("Actual Stored Fallback Owner");

      const renewed = await atom(owner.headers.at(-1)!, effective, false);
      expect(renewed.compactSessionCache.envelope.session.user.name).toBe(
        "Actual Stored Fallback Owner",
      );

      return {
        signup: ctx.snapshot(signup),
        issued,
        fallback: ctx.snapshot(fallback),
        renewed,
        state: await ctx.readUserState({ userId: signup.data!.user.id }),
      };
    },
    ["GET /get-session"],
  );
}

compatScenario(
  "compact infinite Max-Age fails actual cookie emission with empty500 and email signup rolls every new row back",
  async (ctx) => {
    await control(ctx, "infinite", { action: "reset" });
    const owner = client(ctx, "infinite");
    const email = ctx.uniqueEmail("compact-infinite");
    const signup = await owner.sdk.signUp.email({
      email,
      name: "Infinite Cache Owner",
      password: "password123",
    });
    expect(signup.error!.status).toBe(500);
    expect(owner.headers.at(-1)!.getSetCookie()).toEqual([]);

    const lookup = await control(ctx, "infinite", { action: "lookup", email });
    expect(lookup.user).toBeNull();
    expect(Object.keys(lookup)).toEqual(["user"]);

    const session = await owner.sdk.getSession();
    expect(session.data).toBeNull();

    return { signup: ctx.snapshot(signup), lookup, session: ctx.snapshot(session) };
  },
  ["POST /sign-up/email", "GET /get-session"],
);

// Original signed envelopes have fixed bytes and bind to the genuine first
// session issued by the exotic application's database hook. No comparator
// exception or cache-shaped entropy treatment is needed for these inputs.
compatScenario(
  "compact exotic original bytes preserve published decoding callback order HTTP fallback and physical owners",
  async (ctx) => {
    const vectors = (await Bun.file(
      new URL("../../../../../fixtures/session/compact-exotic-inputs.json", import.meta.url),
    ).json()) as {
      javascriptOnlyObservations: { name: string; header: string; decodedJSON: string }[];
      observations: {
        name: string;
        token: string;
        originalBytesHex: string;
        envelope: any;
        header: string;
        decoded: any;
        versionCalls: any[];
      }[];
    };
    // Measure the published helper's JavaScript-only representations explicitly.
    // Native UTF-8/prototype rejection and physical fallback have a separate
    // dual-store Rust API owner; these are never normalized into native values.
    for (const input of vectors.javascriptOnlyObservations) {
      const decoded = await getCookieCache(new Headers({ cookie: input.header }), {
        secret,
        isSecure: false,
      });
      expect(JSON.stringify(decoded)).toBe(input.decodedJSON);
    }
    await control(ctx, "exotic", { action: "reset" });
    const owner = client(ctx, "exotic");
    const foreign = client(ctx, "exotic", "foreign");
    const signup = await owner.sdk.signUp.email({
      email: ctx.uniqueEmail("exotic-owner"),
      name: "Physical Exotic Owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    expect(signup.data!.token).toBe("00010000000000000000000000000001");
    const original = owner.headers.at(-1)!;
    const issued = await atom(original);
    const other = await foreign.sdk.signUp.email({
      email: ctx.uniqueEmail("exotic-foreign"),
      name: "Physical Foreign Owner",
      password: "password123",
    });
    expect(other.error).toBeNull();
    const ownerBefore = await cacheOwnerRows(ctx, signup.data!.user.id, "exotic");
    const foreignBefore = await cacheOwnerRows(ctx, other.data!.user.id, "exotic");
    const token = cookiePairs(original).find((p) => p.startsWith("better-auth.session_token="))!;
    const foreignToken = cookiePairs(foreign.headers.at(-1)!).find((p) =>
      p.startsWith("better-auth.session_token="),
    )!;
    const results = [];
    for (const input of vectors.observations) {
      const versionCalls: unknown[] = [];
      const decoded = await getCookieCache(new Headers({ cookie: input.header }), {
        secret,
        isSecure: false,
        strategy: "compact",
        version: (session, user) => {
          versionCalls.push({ session, user });
          return "1";
        },
      });
      expect(ctx.snapshot(decoded)).toEqual(input.decoded);
      expect(ctx.snapshot(versionCalls)).toEqual(input.versionCalls);
      // Retain and compare all original bytes, signature and claims. Padding
      // tails are intentionally included in the original token as measured.
      expect(Buffer.from(input.token, "base64url").toString("hex")).toBe(input.originalBytesHex);
      await control(ctx, "exotic", { action: "clear-events" });
      const read = await response(
        await owner.fetch(ctx.baseURL + authProfilePath("session-cache-exotic") + "/get-session", {
          credentials: "omit",
          headers: { cookie: token + "; " + input.header },
        }),
      );
      expect(read.status).toBe(200);
      const hit = input.decoded !== null && input.name !== "wrong-token";
      expect((read.body as any).user.name).toBe(
        hit ? input.decoded.user.name : "Physical Exotic Owner",
      );
      if (hit) {
        expect((read.body as any).session).toEqual(input.decoded.session);
        expect((read.body as any).user).toEqual(input.decoded.user);
      }
      const events = (await control(ctx, "exotic", { action: "state" })).events;
      // HMAC/schema rejection and token mismatch precede the callback. A valid
      // expired/version-mismatched payload reaches the callback before fallback.
      const reached = input.versionCalls.length > 0 && input.name !== "wrong-token";
      expect(events, input.name).toHaveLength(hit ? 1 : reached ? 2 : 1);
      if (reached) expect(ctx.snapshot(events[0]!.session)).toEqual(input.versionCalls[0]!.session);
      if (!hit) expect(events.at(-1)!.user.name).toBe("Physical Exotic Owner");
      results.push({
        applicationData: { input },
        decoded: ctx.snapshot(decoded),
        versionCalls: ctx.snapshot(versionCalls),
        read,
        events,
      });
    }
    const canonical = vectors.observations.find((v) => v.name === "canonical")!;
    await control(ctx, "exotic", { action: "clear-events" });
    const graft = await response(
      await owner.fetch(ctx.baseURL + authProfilePath("session-cache-exotic") + "/get-session", {
        credentials: "omit",
        headers: { cookie: foreignToken + "; " + canonical.header },
      }),
    );
    expect((graft.body as any).user.id).toBe(other.data!.user.id);
    const graftEvents = (await control(ctx, "exotic", { action: "state" })).events;
    expect(graftEvents).toHaveLength(1);
    expect(graftEvents[0]!.user.id).toBe(other.data!.user.id);
    const noToken = await response(
      await owner.fetch(ctx.baseURL + authProfilePath("session-cache-exotic") + "/get-session", {
        credentials: "omit",
        headers: { cookie: canonical.header },
      }),
    );
    expect(noToken.body).toBeNull();
    expect(await cacheOwnerRows(ctx, signup.data!.user.id, "exotic")).toEqual(ownerBefore);
    expect(await cacheOwnerRows(ctx, other.data!.user.id, "exotic")).toEqual(foreignBefore);
    await control(ctx, "exotic", { action: "revoke", token: signup.data!.token });
    const revokedBefore = await cacheOwnerRows(ctx, signup.data!.user.id, "exotic");
    const expired = vectors.observations.find((v) => v.name === "outer-expired")!;
    const revoked = await response(
      await owner.fetch(ctx.baseURL + authProfilePath("session-cache-exotic") + "/get-session", {
        credentials: "omit",
        headers: { cookie: token + "; " + expired.header },
      }),
    );
    expect(revoked.body).toBeNull();
    expect(await cacheOwnerRows(ctx, signup.data!.user.id, "exotic")).toEqual(revokedBefore);
    expect(await cacheOwnerRows(ctx, other.data!.user.id, "exotic")).toEqual(foreignBefore);
    return {
      signup: ctx.snapshot(signup),
      issued,
      other: ctx.snapshot(other),
      ownerBefore,
      foreignBefore,
      applicationData: { javascriptOnlyObservations: vectors.javascriptOnlyObservations },
      results,
      graft,
      graftEvents,
      noToken,
      revokedBefore,
      revoked,
    };
  },
  ["GET /get-session"],
  120000,
);

compatScenario(
  "compact public helper and HTTP separately preserve noncanonical duplicate gap base and truncation parsing",
  async (ctx) => {
    const vectors = await Bun.file(
      new URL("../../../../../fixtures/session/compact-exotic-inputs.json", import.meta.url),
    ).json();
    const input = vectors.observations.find((v: any) => v.name === "canonical");
    await control(ctx, "exotic", { action: "reset" });
    const owner = client(ctx, "exotic");
    const signup = await owner.sdk.signUp.email({
      email: ctx.uniqueEmail("exotic-chunks"),
      name: "Physical Chunk Owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    const original = owner.headers.at(-1)!;
    const issued = await atom(original);
    const token = cookiePairs(original).find((p) => p.startsWith("better-auth.session_token="))!;
    const ownerBefore = await cacheOwnerRows(ctx, signup.data!.user.id, "exotic");
    const middle = Math.floor(input.token.length / 2);
    const a = input.token.slice(0, middle);
    const b = input.token.slice(middle);
    const cases: [string, string[], boolean, boolean][] = [
      ["canonical", [`${cookieName}.0=${a}`, `${cookieName}.1=${b}`], true, true],
      ["duplicate-index-alias", [`${cookieName}.00=${a}`, `${cookieName}.0=${b}`], true, false],
      [
        "invalid-duplicate-ignored",
        [`${cookieName}.0=${a}`, `${cookieName}.0=bad"`, `${cookieName}.1=${b}`],
        true,
        true,
      ],
      ["base-lone-quote", [`${cookieName}="`], false, false],
      ["base-unclosed-quote", [`${cookieName}="${input.token}X`], false, true],
      ["reverse", [`${cookieName}.1=${b}`, `${cookieName}.0=${a}`], true, true],
      ...["00", "+0", "-0", "0junk", "0.0", "0x0", "9007199254740992"].map(
        (index): [string, string[], boolean, boolean] => [
          index,
          [`${cookieName}.${index}=${a}`, `${cookieName}.9007199254740993=${b}`],
          true,
          false,
        ],
      ),
      ["nested-suffix", [`${cookieName}.junk.0=${a}`, `${cookieName}.junk.1=${b}`], true, false],
      ["empty-suffix", [`${cookieName}.=${a}`, `${cookieName}.1=${b}`], true, false],
      ["negative", [`${cookieName}.-1=${a}`, `${cookieName}.0=${b}`], true, false],
      ["gap", [`${cookieName}.2=${a}`, `${cookieName}.9=${b}`], true, true],
      [
        "duplicate-last-valid",
        [`${cookieName}.0=bad`, `${cookieName}.0=${a}`, `${cookieName}.1=${b}`],
        true,
        true,
      ],
      [
        "duplicate-last-invalid",
        [`${cookieName}.0=${a}`, `${cookieName}.0=bad`, `${cookieName}.1=${b}`],
        false,
        false,
      ],
      ["base-first-bad", [`${cookieName}=bad`, input.header], true, false],
      ["base-last-bad", [input.header, `${cookieName}=bad`], false, true],
      ["base-precedence", [input.header, `${cookieName}.0=bad`], true, true],
      [
        "empty-base",
        [`${cookieName}=`, `${cookieName}.0=${a}`, `${cookieName}.1=${b}`],
        true,
        true,
      ],
      ["missing-prefix", [`${cookieName}.1=${b}`], false, false],
      ["truncated", [`${cookieName}.0=${a}`, `${cookieName}.1=${b.slice(0, -12)}`], false, false],
      ["quoted", [`${cookieName}="${input.token}"`], true, true],
      [
        "percent",
        [
          `${cookieName}=${encodeURIComponent(input.token.slice(0, 1)) + "%" + input.token.charCodeAt(1).toString(16) + input.token.slice(2)}`,
        ],
        true,
        true,
      ],
      ["invalid-percent", [`${cookieName}=${input.token}%FF`], false, false],
      ["invalid-name-ignored", [input.header, `${cookieName}.0[=bad`], true, true],
    ];
    const results = [];
    for (const [name, pairs, helperHit, httpHit] of cases) {
      const header = pairs.join("; ");
      let decoded;
      try {
        decoded = await getCookieCache(new Headers({ cookie: header }), {
          secret,
          isSecure: false,
        });
      } catch (error) {
        decoded = { thrown: (error as Error).message };
      }
      expect(decoded !== null && !(decoded as any)?.thrown).toBe(helperHit);
      if (helperHit) {
        expect(ctx.snapshot(decoded)).toEqual(input.decoded);
      }
      const read = await response(
        await owner.fetch(ctx.baseURL + authProfilePath("session-cache-exotic") + "/get-session", {
          credentials: "omit",
          headers: { cookie: token + "; " + header },
        }),
      );
      expect(read.status, name).toBe(name === "invalid-percent" ? 500 : 200);
      if (read.status === 200) {
        expect((read.body as any).user.name, name).toBe(
          httpHit ? "Signed Exotic Owner" : "Physical Chunk Owner",
        );
      } else {
        expect(read.body).toEqual({
          code: "FAILED_TO_GET_SESSION",
          message: "Failed to get session",
        });
      }
      results.push({ name, header, decoded: ctx.snapshot(decoded), read });
    }
    expect(await cacheOwnerRows(ctx, signup.data!.user.id, "exotic")).toEqual(ownerBefore);
    return { signup: ctx.snapshot(signup), issued, input, ownerBefore, results };
  },
  ["GET /get-session"],
  120000,
);
