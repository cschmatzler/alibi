import { expect } from "bun:test";
import { createHash } from "node:crypto";

import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../../support/scenario";

const secret = "local-fixture-dedicated-oauth-proxy-secret-32";
const path = authProfilePath("oauth-proxy");

type Rows = {
  users: Record<string, unknown>[];
  accounts: Record<string, unknown>[];
  sessions: Record<string, unknown>[];
  verification: Record<string, unknown>[];
};

type Receipt = {
  stage: string;
  query?: Record<string, string>;
  body?: Record<string, string>;
  authorization?: string;
};

type State = {
  preview: Rows;
  production: Rows;
  receipts: Receipt[];
  sessionHooks: { userId: string; mode: string }[];
  afterRequests: { callbackURL: string }[];
};

async function state(ctx: ScenarioContext, cookie = false): Promise<State> {
  const r = await ctx.rawRequest({
    path: cookie ? "/__test/oauth-proxy-cookie/state" : "/__test/oauth-proxy/state",
  });
  expect(r.status).toBe(200);
  return r.body as State;
}

function observations(s: State) {
  return {
    ...s,
    receipts: s.receipts.map((r) => ({
      ...r,
      ...(r.body?.code_verifier
        ? {
            body: {
              ...r.body,
              code_verifier: { token: r.body.code_verifier, length: r.body.code_verifier.length },
            },
          }
        : {}),
    })),
  };
}

async function response(r: Response) {
  const text = await r.text();
  let body: unknown = text;

  if (text) {
    try {
      body = JSON.parse(text);
    } catch {}
  }

  return { status: r.status, location: r.headers.get("location"), body };
}

async function issue(
  ctx: ScenarioContext,
  actor: ReturnType<ScenarioContext["actor"]>,
  link = false,
  cookie = false,
) {
  const fixturePath = cookie ? authProfilePath("oauth-proxy-cookie") : path;
  const body = {
    provider: "gitlab",
    callbackURL: `${ctx.baseURL}/proxy-done?application=kept`,
    newUserCallbackURL: `${ctx.baseURL}/proxy-new`,
    errorCallbackURL: `${ctx.baseURL}/proxy-error`,
    disableRedirect: true,
    additionalData: {
      serverContext: { anonymousUserId: "forged-owner" },
      application: { kept: true },
    },
  };
  let issuedCookie: { raw: string; token: string; payload: any } | undefined;
  const start = cookie
    ? await actor.fetch(`${ctx.baseURL}${fixturePath}/${link ? "link-social" : "sign-in/social"}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
        redirect: "manual",
      })
    : undefined;
  if (start) {
    const raw = start.headers
      .getSetCookie()
      .find((value) => value.startsWith("better-auth.oauth_state="))!;
    expect(raw).toBeDefined();
    const token = raw.slice(raw.indexOf("=") + 1, raw.indexOf(";"));
    issuedCookie = {
      raw,
      token,
      payload: JSON.parse(
        await symmetricDecrypt({
          key: "compat-test-only-key-not-real-minimum-32chars",
          data: token,
        }),
      ),
    };
  }
  const started = start
    ? { data: await start.json(), error: null }
    : link
      ? await actor.client.linkSocial(body)
      : await actor.client.signIn.social(body);
  expect(started.error).toBeNull();

  const authorization = new URL(started.data!.url!);
  expect(authorization.searchParams.get("redirect_uri")).toBe(
    `${ctx.baseURL.replace("localhost", "127.0.0.1")}${fixturePath}/callback/gitlab`,
  );

  const raw = authorization.searchParams.get("state")!;
  const packageBytes = await symmetricDecrypt({ key: secret, data: raw });
  const pack = JSON.parse(packageBytes);
  expect(JSON.stringify(pack)).toBe(packageBytes);
  expect(pack.isOAuthProxy).toBe(true);

  const stateBytes = await symmetricDecrypt({ key: secret, data: pack.stateCookie });
  const original = JSON.parse(stateBytes);
  expect(JSON.stringify(original)).toBe(stateBytes);
  expect(original.oauthState).toBe(pack.state);
  expect(original.serverContext).toBeUndefined();
  expect(original.application).toEqual({ kept: true });

  const expiresAt = new Date(original.expiresAt).toISOString();
  expect(new Date(expiresAt).getTime()).toBe(original.expiresAt);

  const retained = {
    ...original,
    oauthState: { state: original.oauthState },
    codeVerifier: { token: original.codeVerifier },
    expiresAt,
  };
  expect(
    JSON.stringify({
      ...retained,
      oauthState: retained.oauthState.state,
      codeVerifier: retained.codeVerifier.token,
      expiresAt: new Date(retained.expiresAt).getTime(),
    }),
  ).toBe(stateBytes);

  if (issuedCookie) expect(issuedCookie.payload).toEqual(original);
  const issuedState = { ...pack, stateCookie: { token: pack.stateCookie, payload: retained } };
  expect(JSON.stringify({ ...issuedState, stateCookie: issuedState.stateCookie.token })).toBe(
    packageBytes,
  );

  return {
    started,
    authorization,
    state: pack.state,
    verifier: original.codeVerifier,
    issuedState,
    issuedCookie,
  };
}

async function forward(
  ctx: ScenarioContext,
  actor: ReturnType<ScenarioContext["actor"]>,
  issued: Awaited<ReturnType<typeof issue>>,
  cookie = false,
) {
  const fixturePath = cookie ? authProfilePath("oauth-proxy-cookie") : path;
  const approved = await response(await actor.fetch(issued.authorization, { redirect: "manual" }));
  expect(approved.status).toBe(302);

  const forwarded = await response(
    await actor.fetch(approved.location!, { redirect: "manual", credentials: "omit" }),
  );
  expect(forwarded.status).toBe(302);

  const bridge = new URL(forwarded.location!);
  expect(bridge.origin).toBe(ctx.baseURL);
  expect(bridge.pathname).toBe(`${fixturePath}/callback/gitlab/oauth-proxy`);

  const token = bridge.searchParams.get("profile")!;
  const payload = JSON.parse(await symmetricDecrypt({ key: secret, data: token }));
  expect(payload.state).toBe(issued.state);
  expect(payload.account.providerId).toBe("gitlab");
  expect(payload.userInfo.email).toBe("proxy-owner@fixture.test");

  const stored = await state(ctx, cookie);
  const receipt = stored.receipts.filter((r) => r.stage === "token").at(-1)!;
  expect(receipt.body!.code_verifier).toBe(issued.verifier);
  expect(issued.verifier).toHaveLength(128);
  expect(createHash("sha256").update(issued.verifier).digest("base64url")).toBe(
    issued.authorization.searchParams.get("code_challenge")!,
  );

  return { approved, forwarded, bridge, atom: { token, payload } };
}

const comparison = { oauthProxyProfileSecret: secret };

compatScenario(
  "OAuth proxy exchanges on production then consumes preview state for only the provider owner",
  async (ctx) => {
    const owner = ctx.actor("proxy-owner", "oauth-proxy");
    const foreign = ctx.actor("proxy-foreign", "oauth-proxy");
    const seeded = await foreign.client.signUp.email({
      email: ctx.uniqueEmail("proxy-foreign"),
      name: "Foreign",
      password: "password123",
    });
    expect(seeded.error).toBeNull();

    const before = await state(ctx);
    const issued = await issue(ctx, owner);
    const saved = await state(ctx);
    expect(saved.preview.verification).toHaveLength(1);

    const forwarded = await forward(ctx, owner, issued);
    const production = await state(ctx);
    expect(production.production).toEqual(before.production);
    expect(production.preview).toEqual(saved.preview);

    const completed = await response(await owner.fetch(forwarded.bridge, { redirect: "manual" }));
    expect(completed.status).toBe(302);
    expect(completed.location).toBe(`${ctx.baseURL}/proxy-new`);

    const current = await owner.client.getSession();
    expect(current.data!.user.email).toBe("proxy-owner@fixture.test");

    const after = await state(ctx);
    expect(after.preview.verification).toHaveLength(0);
    expect(after.preview.users).toHaveLength(2);
    expect(after.preview.accounts).toHaveLength(2);
    expect(after.preview.sessions).toHaveLength(2);

    const id = current.data!.user.id;
    expect(after.preview.accounts.find((r) => r.providerId === "gitlab")!.userId).toBe(id);
    expect(after.preview.sessions.find((r) => r.userId === id)!.token).toBe(
      current.data!.session.token,
    );
    expect(after.preview.users.find((r) => r.id === seeded.data!.user.id)).toEqual(
      before.preview.users[0],
    );
    expect(after.preview.sessions.filter((r) => r.userId === seeded.data!.user.id)).toEqual(
      before.preview.sessions,
    );

    const replay = await response(await owner.fetch(forwarded.bridge, { redirect: "manual" }));
    expect(new URL(replay.location!).searchParams.get("error")).toBe("state_mismatch");
    expect((await state(ctx)).preview).toEqual(after.preview);

    const codeReplay = await response(
      await owner.fetch(forwarded.approved.location!, { redirect: "manual", credentials: "omit" }),
    );
    expect(new URL(codeReplay.location!).searchParams.get("error")).toBe("invalid_code");

    const final = await state(ctx);
    expect(final.preview).toEqual(after.preview);
    expect(final.production).toEqual(before.production);

    return {
      before: observations(before),
      started: issued.started,
      issuedState: issued.issuedState,
      issued: observations(saved),
      approved: forwarded.approved,
      forwarded: forwarded.forwarded,
      oauthProxyProfile: forwarded.atom,
      afterProduction: observations(production),
      completed,
      current,
      after: observations(after),
      replay,
      codeReplay,
      final: observations(final),
    };
  },
  ["POST /sign-in/social", "GET /callback/{}/oauth-proxy"],
  undefined,
  comparison,
);

compatScenario(
  "OAuth proxy checks origin provider authenticated age and state before writes and retains legacy completion",
  async (ctx) => {
    const actor = ctx.actor("proxy-controls", "oauth-proxy");
    const issued = await issue(ctx, actor);
    const forwarded = await forward(ctx, actor, issued);
    const before = await state(ctx);
    const controls = [];

    for (const mode of [
      "origin",
      "legacy-origin",
      "provider",
      "expired",
      "future",
      "unknown-state",
      "bad-payload",
      "bad-cipher",
    ]) {
      const url = new URL(forwarded.bridge);
      const payload = structuredClone(forwarded.atom.payload);

      if (mode === "origin" || mode === "legacy-origin") {
        url.searchParams.set("callbackURL", "https://foreign.fixture.test/leak");
      }

      if (mode === "legacy-origin") {
        url.pathname = `${path}/oauth-proxy-callback`;
      }

      if (mode === "provider") {
        url.pathname = `${path}/callback/google/oauth-proxy`;
      }

      if (mode === "expired") {
        payload.timestamp = Date.now() - 61000;
      }

      if (mode === "future") {
        payload.timestamp = Date.now() + 11000;
      }

      if (mode === "unknown-state") {
        payload.state = "unknown-state";
      }

      const token =
        mode === "bad-cipher"
          ? "wrong"
          : await symmetricEncrypt({
              key: secret,
              data: JSON.stringify(mode === "bad-payload" ? {} : payload),
            });
      url.searchParams.set("profile", token);
      const result = await response(await actor.fetch(url, { redirect: "manual" }));
      const expected = (
        {
          provider: "provider_mismatch",
          expired: "payload_expired",
          future: "payload_expired",
          "unknown-state": "state_mismatch",
          "bad-payload": "invalid_payload",
          "bad-cipher": "invalid_profile",
        } as Record<string, string>
      )[mode];

      if (mode === "origin" || mode === "legacy-origin") {
        expect(result.status).toBe(403);
        expect(result.location).toBeNull();
      } else {
        expect(result.status).toBe(302);
        expect(new URL(result.location!).searchParams.get("error")).toBe(expected!);
      }

      const after = await state(ctx);
      expect(after.preview).toEqual(before.preview);
      expect(after.production).toEqual(before.production);

      controls.push({
        mode,
        url: url.href,
        result,
        oauthProxyProfile:
          mode === "bad-cipher" ? null : { token, payload: mode === "bad-payload" ? {} : payload },
        after: observations(after),
      });
    }

    const legacy = new URL(forwarded.bridge);
    legacy.pathname = `${path}/oauth-proxy-callback`;
    const completed = await response(await actor.fetch(legacy, { redirect: "manual" }));
    expect(completed.status).toBe(302);
    expect(completed.location).toBe(`${ctx.baseURL}/proxy-new`);

    const current = await actor.client.getSession();
    expect(current.data!.user.email).toBe("proxy-owner@fixture.test");

    const final = await state(ctx);
    expect(final.preview.verification).toHaveLength(0);
    expect(final.preview.sessions).toHaveLength(1);

    return {
      started: issued.started,
      issuedState: issued.issuedState,
      approved: forwarded.approved,
      forwarded: forwarded.forwarded,
      oauthProxyProfile: forwarded.atom,
      before: observations(before),
      controls,
      legacyURL: legacy.href,
      completed,
      current,
      final: observations(final),
    };
  },
  ["POST /sign-in/social", "GET /callback/{}/oauth-proxy", "GET /oauth-proxy-callback"],
  undefined,
  comparison,
);

compatScenario(
  "OAuth proxy linking follows the saved authenticated owner without creating any session",
  async (ctx) => {
    const owner = ctx.actor("proxy-link-owner", "oauth-proxy");
    const foreign = ctx.actor("proxy-link-foreign", "oauth-proxy");
    const signed = await owner.client.signUp.email({
      email: "proxy-owner@fixture.test",
      name: "Existing Owner",
      password: "password123",
    });
    const other = await foreign.client.signUp.email({
      email: ctx.uniqueEmail("proxy-link-foreign"),
      name: "Foreign",
      password: "password123",
    });
    expect(signed.error).toBeNull();
    expect(other.error).toBeNull();

    const before = await state(ctx);
    const issued = await issue(ctx, owner, true);
    const saved = await state(ctx);
    const forwarded = await forward(ctx, owner, issued);
    const completed = await response(
      await owner.fetch(forwarded.bridge, { redirect: "manual", credentials: "omit" }),
    );
    expect(completed.status).toBe(302);
    expect(completed.location).toBe(`${ctx.baseURL}/proxy-done?application=kept`);

    const after = await state(ctx);
    expect(after.production).toEqual(before.production);
    expect(after.preview.users).toEqual(before.preview.users);
    expect(after.preview.sessions).toEqual(before.preview.sessions);
    expect(after.preview.accounts).toHaveLength(3);
    expect(after.preview.accounts.find((r) => r.providerId === "gitlab")!.userId).toBe(
      signed.data!.user.id,
    );
    expect(after.preview.verification).toHaveLength(0);

    const current = await owner.client.getSession();
    expect(current.data!.session.token).toBe(signed.data!.token!);

    const foreignCurrent = await foreign.client.getSession();
    expect(foreignCurrent.data!.session.token).toBe(other.data!.token!);

    const replay = await response(await foreign.fetch(forwarded.bridge, { redirect: "manual" }));
    expect(new URL(replay.location!).searchParams.get("error")).toBe("state_mismatch");
    expect((await state(ctx)).preview).toEqual(after.preview);

    const denied = [];

    for (const mode of ["different-email", "foreign-account"]) {
      if (mode === "foreign-account") {
        const configured = await ctx.rawRequest({
          path: "/__test/oauth-proxy/profile",
          method: "POST",
          json: {
            id: 777,
            email: other.data!.user.email,
            email_verified: true,
            name: "Proxy Owner",
            avatar_url: "https://assets.fixture.test/avatar.png",
            state: "active",
            locked: false,
          },
        });
        expect(configured.status).toBe(200);
      }

      const attempt = await issue(ctx, foreign, true);
      const pending = await state(ctx);
      const approval = await response(
        await foreign.fetch(attempt.authorization, { redirect: "manual" }),
      );
      const transfer = await response(
        await foreign.fetch(approval.location!, { redirect: "manual", credentials: "omit" }),
      );
      const bridge = new URL(transfer.location!);
      const token = bridge.searchParams.get("profile")!;
      const payload = JSON.parse(await symmetricDecrypt({ key: secret, data: token }));
      expect(payload.state).toBe(attempt.state);

      const rejection = await response(
        await foreign.fetch(bridge, { redirect: "manual", credentials: "omit" }),
      );
      expect(new URL(rejection.location!).searchParams.get("error")).toBe(
        mode === "different-email"
          ? "email_does_not_match"
          : "account_already_linked_to_different_user",
      );

      const stored = await state(ctx);
      expect(stored.preview.users).toEqual(after.preview.users);
      expect(stored.preview.accounts).toEqual(after.preview.accounts);
      expect(stored.preview.sessions).toEqual(after.preview.sessions);
      expect(stored.preview.verification).toHaveLength(0);
      expect(stored.production).toEqual(before.production);

      denied.push({
        mode,
        started: attempt.started,
        issuedState: attempt.issuedState,
        pending: observations(pending),
        approval,
        transfer,
        oauthProxyProfile: { token, payload },
        rejection,
        after: observations(stored),
      });
    }

    return {
      signed,
      other,
      before: observations(before),
      started: issued.started,
      issuedState: issued.issuedState,
      saved: observations(saved),
      approved: forwarded.approved,
      forwarded: forwarded.forwarded,
      oauthProxyProfile: forwarded.atom,
      completed,
      after: observations(after),
      current,
      foreignCurrent,
      replay,
      denied,
    };
  },
  ["POST /link-social", "GET /callback/{}/oauth-proxy"],
  undefined,
  comparison,
);

compatScenario(
  "OAuth proxy restoration and session failures preserve exact stages rows and retry",
  async (ctx) => {
    const actor = ctx.actor("proxy-failure-owner", "oauth-proxy");
    const foreign = ctx.actor("proxy-failure-foreign", "oauth-proxy");
    const seeded = await foreign.client.signUp.email({
      email: ctx.uniqueEmail("proxy-failure-foreign"),
      name: "Foreign",
      password: "password123",
    });
    expect(seeded.error).toBeNull();

    const initial = await state(ctx);
    const issued = await issue(ctx, actor);
    const forwarded = await forward(ctx, actor, issued);
    const pending = await state(ctx);
    const control = async (mode: string) => {
      const result = await ctx.rawRequest({
        path: "/__test/oauth-proxy/control",
        method: "POST",
        json: { mode },
      });
      expect(result.status).toBe(200);
      return result;
    };
    const configuredDelete = await control("delete-veto");
    const deletion = await response(await actor.fetch(forwarded.bridge, { redirect: "manual" }));
    expect(deletion.status).toBe(302);
    expect(new URL(deletion.location!).searchParams.get("error")).toBe("state_mismatch");

    const afterDeletion = await state(ctx);
    expect(afterDeletion).toEqual({
      ...pending,
      afterRequests: [{ callbackURL: `${ctx.baseURL}/proxy-done?application=kept` }],
    });

    const configuredOrdinary = await control("ordinary-session-error");
    const ordinary = await response(await actor.fetch(forwarded.bridge, { redirect: "manual" }));
    expect(ordinary).toEqual({ status: 500, location: null, body: "" });

    const afterOrdinary = await state(ctx);
    expect(afterOrdinary.preview.verification).toHaveLength(0);
    expect(afterOrdinary.preview.users).toHaveLength(initial.preview.users.length + 1);
    expect(afterOrdinary.preview.accounts).toHaveLength(initial.preview.accounts.length + 1);
    expect(afterOrdinary.preview.sessions).toEqual(initial.preview.sessions);
    expect(afterOrdinary.production).toEqual(initial.production);
    expect(afterOrdinary.afterRequests).toEqual(afterDeletion.afterRequests);

    const created = afterOrdinary.preview.users.find(
      (row) => row.email === "proxy-owner@fixture.test",
    )!;
    expect(afterOrdinary.sessionHooks).toEqual([
      { userId: created.id as string, mode: "ordinary-session-error" },
    ]);
    expect(afterOrdinary.preview.users.find((row) => row.id === seeded.data!.user.id)).toEqual(
      initial.preview.users[0],
    );

    const replay = await response(await actor.fetch(forwarded.bridge, { redirect: "manual" }));
    expect(new URL(replay.location!).searchParams.get("error")).toBe("state_mismatch");

    const afterOrdinaryReplay = await state(ctx);
    expect(afterOrdinaryReplay).toEqual({
      ...afterOrdinary,
      afterRequests: [
        ...afterOrdinary.afterRequests,
        { callbackURL: `${ctx.baseURL}/proxy-done?application=kept` },
      ],
    });

    const codedIssued = await issue(ctx, actor);
    const codedForward = await forward(ctx, actor, codedIssued);
    const configuredCoded = await control("coded-session-error");
    const coded = await response(await actor.fetch(codedForward.bridge, { redirect: "manual" }));
    expect(coded.status).toBe(302);
    expect(new URL(coded.location!).searchParams.get("error")).toBe("PROXY_SESSION_DENIED");
    expect(new URL(coded.location!).searchParams.get("error_description")).toBe(
      "Configured proxy session denied",
    );

    const afterCoded = await state(ctx);
    expect(afterCoded.preview.users).toEqual(afterOrdinary.preview.users);
    expect(afterCoded.preview.sessions).toEqual(afterOrdinary.preview.sessions);
    expect(afterCoded.preview.verification).toEqual(afterOrdinary.preview.verification);

    const renewed = (rows: Rows, previous: Rows, payload: any) => {
      const old = previous.accounts.find((row) => row.providerId === "gitlab")!;
      const current = rows.accounts.find((row) => row.providerId === "gitlab")!;
      expect(rows.accounts).toEqual(
        previous.accounts.map((row) =>
          row === old
            ? {
                ...row,
                accessTokenExpiresAt: payload.account.accessTokenExpiresAt,
                updatedAt: current.updatedAt,
              }
            : row,
        ),
      );
      expect(Date.parse(current.updatedAt as string)).toBeGreaterThanOrEqual(
        Date.parse(old.updatedAt as string),
      );
    };
    renewed(afterCoded.preview, afterOrdinary.preview, codedForward.atom.payload);
    expect(afterCoded.production).toEqual(initial.production);
    expect(afterCoded.afterRequests).toEqual([
      ...afterOrdinaryReplay.afterRequests,
      { callbackURL: `${ctx.baseURL}/proxy-done?application=kept` },
    ]);
    expect(afterCoded.sessionHooks).toEqual([
      ...afterOrdinary.sessionHooks,
      { userId: created.id as string, mode: "coded-session-error" },
    ]);

    const cancelledIssued = await issue(ctx, actor);
    const cancelledForward = await forward(ctx, actor, cancelledIssued);
    const configuredCancelled = await control("cancel-session");
    const cancelled = await response(
      await actor.fetch(cancelledForward.bridge, { redirect: "manual" }),
    );
    expect(cancelled.status).toBe(302);
    expect(new URL(cancelled.location!).searchParams.get("error")).toBe("unable_to_create_session");

    const afterCancelled = await state(ctx);
    expect(afterCancelled.preview.users).toEqual(afterCoded.preview.users);
    expect(afterCancelled.preview.sessions).toEqual(afterCoded.preview.sessions);
    expect(afterCancelled.preview.verification).toEqual(afterCoded.preview.verification);

    renewed(afterCancelled.preview, afterCoded.preview, cancelledForward.atom.payload);
    expect(afterCancelled.production).toEqual(initial.production);
    expect(afterCancelled.afterRequests).toEqual([
      ...afterCoded.afterRequests,
      { callbackURL: `${ctx.baseURL}/proxy-done?application=kept` },
    ]);
    expect(afterCancelled.sessionHooks).toEqual([
      ...afterCoded.sessionHooks,
      { userId: created.id as string, mode: "cancel-session" },
    ]);

    const retryIssued = await issue(ctx, actor);
    const retryForward = await forward(ctx, actor, retryIssued);
    const configuredRetry = await control("none");
    const retry = await response(await actor.fetch(retryForward.bridge, { redirect: "manual" }));
    expect(retry.status).toBe(302);
    expect(retry.location).toBe(`${ctx.baseURL}/proxy-done?application=kept`);

    const current = await actor.client.getSession();
    expect(current.data!.user.id).toBe(created.id as string);

    const final = await state(ctx);
    expect(final.preview.users).toEqual(afterCancelled.preview.users);

    renewed(final.preview, afterCancelled.preview, retryForward.atom.payload);
    expect(final.preview.sessions).toHaveLength(initial.preview.sessions.length + 1);
    expect(final.preview.sessions.find((row) => row.userId === created.id)!.token).toBe(
      current.data!.session.token,
    );
    expect(final.preview.sessions.filter((row) => row.userId === seeded.data!.user.id)).toEqual(
      initial.preview.sessions,
    );
    expect(final.production).toEqual(initial.production);
    expect(final.afterRequests).toEqual([
      ...afterCancelled.afterRequests,
      { callbackURL: `${ctx.baseURL}/proxy-done?application=kept` },
    ]);
    expect(final.sessionHooks).toEqual([
      ...afterCancelled.sessionHooks,
      { userId: created.id as string, mode: "none" },
    ]);

    return {
      seeded,
      initial: observations(initial),
      started: issued.started,
      issuedState: issued.issuedState,
      forwarded: forwarded.forwarded,
      oauthProxyProfile: forwarded.atom,
      pending: observations(pending),
      configuredDelete,
      deletion,
      afterDeletion: observations(afterDeletion),
      configuredOrdinary,
      ordinary,
      afterOrdinary: observations(afterOrdinary),
      replay,
      afterOrdinaryReplay: observations(afterOrdinaryReplay),
      codedIssued: codedIssued.issuedState,
      codedProfile: { oauthProxyProfile: codedForward.atom },
      configuredCoded,
      coded,
      afterCoded: observations(afterCoded),
      cancelledIssued: cancelledIssued.issuedState,
      cancelledProfile: { oauthProxyProfile: cancelledForward.atom },
      configuredCancelled,
      cancelled,
      afterCancelled: observations(afterCancelled),
      retryIssued: retryIssued.issuedState,
      retryProfile: { oauthProxyProfile: retryForward.atom },
      configuredRetry,
      retry,
      current,
      final: observations(final),
    };
  },
  ["POST /sign-in/social", "GET /callback/{}/oauth-proxy"],
  undefined,
  comparison,
);

compatScenario(
  "OAuth proxy cookie state authenticates nonce consumes expiry and retains Source replay semantics",
  async (ctx) => {
    const owner = ctx.actor("cookie-owner", "oauth-proxy-cookie");
    const foreign = ctx.actor("cookie-foreign", "oauth-proxy-cookie");
    const before = await state(ctx, true);
    const issued = await issue(ctx, owner, false, true);
    const pending = await state(ctx, true);
    expect(pending.preview.verification).toEqual([]);
    expect(pending.production).toEqual(before.production);
    const forwarded = await forward(ctx, owner, issued, true);
    const afterProduction = await state(ctx, true);
    expect(afterProduction.preview).toEqual(before.preview);
    expect(afterProduction.production).toEqual(before.production);
    const controls = [];
    const unchanged = afterProduction.preview;
    const cookieName = "better-auth.oauth_state";
    const cookieKey = "compat-test-only-key-not-real-minimum-32chars";

    // Invalid cookies fail before browser consumption; expired but matching
    // state is consumed before rejecting. All profiles came from a real grant.
    for (const mode of ["missing", "bad-cipher", "nonce", "missing-nonce", "expired"]) {
      const stored = structuredClone(issued.issuedCookie!.payload);
      if (mode === "nonce") stored.oauthState = "foreign-nonce";
      if (mode === "missing-nonce") delete stored.oauthState;
      if (mode === "expired") stored.expiresAt = Date.now() - 60000;
      const token =
        mode === "bad-cipher"
          ? "wrong"
          : await symmetricEncrypt({ key: cookieKey, data: JSON.stringify(stored) });
      const r = await foreign.fetch(forwarded.bridge, {
        redirect: "manual",
        credentials: "omit",
        headers: mode === "missing" ? {} : { cookie: `${cookieName}=${token}` },
      });
      const cookies = r.headers.getSetCookie();
      const result = await response(r);
      expect(new URL(result.location!).searchParams.get("error")).toBe("state_mismatch");
      expect(cookies.some((value) => value.startsWith(`${cookieName}=`))).toBe(mode === "expired");
      const after = await state(ctx, true);
      expect(after.preview).toEqual(unchanged);
      expect(after.production).toEqual(before.production);
      controls.push({ mode, result, after: observations(after) });
    }
    const result = await owner.fetch(forwarded.bridge, { redirect: "manual" });
    const clear = result.headers.getSetCookie().find((value) => value.startsWith(`${cookieName}=`));
    expect(clear).toContain("Max-Age=0");
    const completed = await response(result);
    expect(completed.location).toBe(`${ctx.baseURL}/proxy-new`);
    const current = await owner.client.getSession();
    expect(current.data!.user.email).toBe("proxy-owner@fixture.test");
    const after = await state(ctx, true);
    expect(after.preview.users).toHaveLength(1);
    expect(after.preview.accounts).toHaveLength(1);
    expect(after.preview.sessions).toHaveLength(1);
    expect(after.preview.verification).toEqual([]);
    expect(after.production).toEqual(before.production);
    const replay = await response(await owner.fetch(forwarded.bridge, { redirect: "manual" }));
    expect(new URL(replay.location!).searchParams.get("error")).toBe("state_mismatch");
    expect((await state(ctx, true)).preview).toEqual(after.preview);
    // Source has no server ledger for cookie state. An explicitly restored
    // still-valid authenticated cookie can be replayed within profile maxAge.
    const restored = await response(
      await owner.fetch(forwarded.bridge, {
        redirect: "manual",
        credentials: "omit",
        headers: { cookie: `${cookieName}=${issued.issuedCookie!.token}` },
      }),
    );
    expect(restored.location).toBe(`${ctx.baseURL}/proxy-done?application=kept`);
    const final = await state(ctx, true);
    expect(final.preview.users).toEqual(after.preview.users);
    expect(final.preview.sessions).toHaveLength(2);
    expect(final.production).toEqual(before.production);
    return {
      before: observations(before),
      started: issued.started,
      issuedState: issued.issuedState,
      cookieState: {
        token: issued.issuedCookie!.token,
        payload: issued.issuedState.stateCookie.payload,
      },
      pending: observations(pending),
      approved: forwarded.approved,
      forwarded: forwarded.forwarded,
      oauthProxyProfile: forwarded.atom,
      afterProduction: observations(afterProduction),
      controls,
      completed,
      current,
      after: observations(after),
      replay,
      restored,
      final: observations(final),
    };
  },
  ["POST /sign-in/social", "GET /callback/{}/oauth-proxy"],
  undefined,
  comparison,
);

compatScenario(
  "OAuth proxy cookie linking restores the saved owner across browser session changes",
  async (ctx) => {
    const owner = ctx.actor("cookie-link-owner", "oauth-proxy-cookie");
    const foreign = ctx.actor("cookie-link-foreign", "oauth-proxy-cookie");
    const signed = await owner.client.signUp.email({
      email: "proxy-owner@fixture.test",
      name: "Owner",
      password: "password123",
    });
    const registered = await foreign.fetch(
      `${ctx.baseURL}${authProfilePath("oauth-proxy-cookie")}/sign-up/email`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          email: ctx.uniqueEmail("cookie-link-foreign"),
          name: "Foreign",
          password: "password123",
        }),
      },
    );
    expect(registered.status).toBe(200);
    const foreignSession = registered.headers
      .getSetCookie()
      .find((value) => value.startsWith("better-auth.session_token="))!
      .split(";")[0]!;
    const other = { data: await registered.json(), error: null };
    const foreignBefore = await foreign.client.getSession();
    expect(foreignBefore.data!.user.id).toBe(other.data.user.id);
    expect(signed.error).toBeNull();
    expect(other.error).toBeNull();
    const before = await state(ctx, true);
    const issued = await issue(ctx, owner, true, true);
    expect(issued.issuedCookie!.payload.link).toEqual({
      email: signed.data!.user.email,
      userId: signed.data!.user.id,
    });
    const forwarded = await forward(ctx, owner, issued, true);
    const missing = await response(await foreign.fetch(forwarded.bridge, { redirect: "manual" }));
    expect(new URL(missing.location!).searchParams.get("error")).toBe("state_mismatch");
    expect((await state(ctx, true)).preview).toEqual(before.preview);
    // Authentic state chooses the initiating owner even if the current
    // browser session belongs to another user. No identity is read from profile.
    const completed = await response(
      await foreign.fetch(forwarded.bridge, {
        redirect: "manual",
        headers: {
          cookie: `better-auth.oauth_state=${issued.issuedCookie!.token}; ${foreignSession}`,
        },
      }),
    );
    expect(completed.location).toBe(`${ctx.baseURL}/proxy-done?application=kept`);
    const after = await state(ctx, true);
    expect(after.preview.users).toEqual(before.preview.users);
    expect(after.preview.sessions).toEqual(before.preview.sessions);
    expect(after.preview.accounts).toHaveLength(3);
    expect(after.preview.accounts.find((row) => row.providerId === "gitlab")!.userId).toBe(
      signed.data!.user.id,
    );
    expect(after.preview.verification).toEqual([]);
    expect(after.production).toEqual(before.production);
    const replay = await response(await foreign.fetch(forwarded.bridge, { redirect: "manual" }));
    expect(new URL(replay.location!).searchParams.get("error")).toBe("state_mismatch");
    expect((await state(ctx, true)).preview).toEqual(after.preview);
    const foreignAfter = await foreign.client.getSession();
    expect(foreignAfter.data!.session.token).toBe(foreignBefore.data!.session.token);
    return {
      signed,
      other,
      foreignBefore,
      foreignAfter,
      before: observations(before),
      started: issued.started,
      issuedState: issued.issuedState,
      cookieState: {
        token: issued.issuedCookie!.token,
        payload: issued.issuedState.stateCookie.payload,
      },
      approved: forwarded.approved,
      forwarded: forwarded.forwarded,
      oauthProxyProfile: forwarded.atom,
      missing,
      completed,
      after: observations(after),
      replay,
    };
  },
  ["POST /link-social", "GET /callback/{}/oauth-proxy"],
  undefined,
  comparison,
);

// These owners exercise remaining configuration contracts through the actual
// two-host endpoint; default login/link proofs above are not replayed.
compatScenario(
  "OAuth proxy remaining URL POST error and pending maxAge configuration contracts",
  async (ctx) => {
    const owner = ctx.actor("remaining-options", "oauth-proxy");
    const options = async (mode: string, origin?: string) => {
      const result = await ctx.rawRequest({
        path: "/__test/oauth-proxy/options",
        method: "POST",
        json: { mode, origin },
      });
      expect(result.status).toBe(200);
      return result;
    };
    const initial = await state(ctx);
    const selectedRequest = await options("request");
    const issued = await issue(ctx, owner);
    const approval = await response(
      await owner.fetch(issued.authorization, { redirect: "manual" }),
    );
    const approved = new URL(approval.location!);
    const postURL = new URL(approved);
    postURL.searchParams.delete("state");
    postURL.searchParams.delete("code");
    // Query code wins over the deliberately invalid body code; state comes
    // from the form body, so GET-only forwarding cannot satisfy this owner.
    postURL.searchParams.set("code", approved.searchParams.get("code")!);
    const posted = await response(
      await owner.fetch(postURL, {
        method: "POST",
        redirect: "manual",
        credentials: "omit",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          state: approved.searchParams.get("state")!,
          code: "invalid-body-code",
        }),
      }),
    );
    expect(posted.status).toBe(302);
    const bridge = new URL(posted.location!);
    expect(bridge.origin).toBe(ctx.baseURL);
    const token = bridge.searchParams.get("profile")!;
    const payload = JSON.parse(await symmetricDecrypt({ key: secret, data: token }));
    expect(payload.state).toBe(issued.state);
    const afterExchange = await state(ctx);
    expect(afterExchange.production).toEqual(initial.production);
    expect(afterExchange.preview.users).toEqual(initial.preview.users);
    expect(
      afterExchange.receipts.filter((receipt) => receipt.stage === "token").at(-1)!.body!.code,
    ).toBe(approved.searchParams.get("code")!);
    const selectedError = await options("error", ctx.baseURL);
    const noProfile = new URL(bridge);
    noProfile.searchParams.delete("profile");
    const missing = await response(await owner.fetch(noProfile, { redirect: "manual" }));
    expect(missing.location).toBe(`${ctx.baseURL}/configured-error?kept=yes&error=missing_profile`);
    const selectedEmpty = await options("empty-error", ctx.baseURL);
    const empty = await response(await owner.fetch(noProfile, { redirect: "manual" }));
    expect(empty.location).toBe(`${ctx.baseURL}/api/auth/error?error=missing_profile`);
    const selectedFractional = await options("fractional", ctx.baseURL);
    await new Promise((resolve) => setTimeout(resolve, 200));
    const expired = await response(await owner.fetch(bridge, { redirect: "manual" }));
    expect(new URL(expired.location!).searchParams.get("error")).toBe("payload_expired");
    expect((await state(ctx)).preview.verification).toHaveLength(1);
    const selectedNegative = await options("negative-infinity", ctx.baseURL);
    const negative = await response(await owner.fetch(bridge, { redirect: "manual" }));
    expect(new URL(negative.location!).searchParams.get("error")).toBe("payload_expired");
    const selectedNaN = await options("nan", ctx.baseURL);
    const accepted = await response(await owner.fetch(bridge, { redirect: "manual" }));
    expect(accepted.location).toBe(`${ctx.baseURL}/proxy-new`);
    const current = await owner.client.getSession();
    expect(current.data!.user.email).toBe("proxy-owner@fixture.test");
    const final = await state(ctx);
    expect(final.preview.verification).toHaveLength(0);
    expect(final.preview.sessions).toHaveLength(1);
    expect(final.production).toEqual(initial.production);
    // Positive infinity is exercised on a second genuine grant, using the
    // existing account so this assertion owns age selection rather than signup.
    await options("dedicated");
    const second = await issue(ctx, owner);
    const forwarded = await forward(ctx, owner, second);
    const selectedInfinity = await options("infinity", ctx.baseURL);
    const infinite = await response(await owner.fetch(forwarded.bridge, { redirect: "manual" }));
    expect(infinite.location).toBe(`${ctx.baseURL}/proxy-done?application=kept`);
    const afterInfinity = await state(ctx);
    expect(afterInfinity.preview.sessions).toHaveLength(2);
    expect(afterInfinity.production).toEqual(initial.production);
    return {
      selectedRequest,
      issuedState: issued.issuedState,
      approval,
      posted,
      oauthProxyProfile: { token, payload },
      initial: observations(initial),
      afterExchange: observations(afterExchange),
      selectedError,
      missing,
      selectedEmpty,
      empty,
      selectedFractional,
      expired,
      selectedNegative,
      negative,
      selectedNaN,
      accepted,
      current,
      final: observations(final),
      secondState: second.issuedState,
      secondProfile: { oauthProxyProfile: forwarded.atom },
      selectedInfinity,
      infinite,
      afterInfinity: observations(afterInfinity),
    };
  },
  ["POST /sign-in/social", "POST /callback/{id}", "GET /callback/{id}/oauth-proxy"],
  undefined,
  comparison,
);

compatScenario(
  "OAuth proxy remaining signed preference cache and concurrent cookie restoration composition",
  async (ctx) => {
    const owner = ctx.actor("remaining-composition", "oauth-proxy-cookie");
    const initial = await state(ctx, true);
    // Seed the actual signed preference through a public email signin.
    const signup = await owner.client.signUp.email({
      email: ctx.uniqueEmail("remaining-preference"),
      name: "Preference",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    const signin = await owner.fetch(
      `${ctx.baseURL}${authProfilePath("oauth-proxy-cookie")}/sign-in/email`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          email: signup.data!.user.email,
          password: "password123",
          rememberMe: false,
        }),
      },
    );
    expect(signin.status).toBe(200);
    const signedPreference = signin.headers
      .getSetCookie()
      .find((cookie) => cookie.startsWith("better-auth.dont_remember="))!;
    expect(signedPreference).toBeDefined();
    const preference = signedPreference.split(";")[0]!;
    const issued = await issue(ctx, owner, false, true);
    const forwarded = await forward(ctx, owner, issued, true);
    const selected = await ctx.rawRequest({
      path: "/__test/oauth-proxy-cookie/options",
      method: "POST",
      json: { mode: "cache", origin: ctx.baseURL },
    });
    expect(selected.status).toBe(200);
    const raw = await owner.fetch(forwarded.bridge, {
      redirect: "manual",
      headers: { cookie: `${preference}; better-auth.oauth_state=${issued.issuedCookie!.token}` },
    });
    const cookies = raw.headers.getSetCookie();
    expect(cookies.find((cookie) => cookie.startsWith("better-auth.session_token="))).not.toContain(
      "Max-Age",
    );
    expect(cookies.find((cookie) => cookie.startsWith("better-auth.dont_remember="))).toBeDefined();
    expect(cookies.find((cookie) => cookie.startsWith("better-auth.session_data="))).not.toContain(
      "Max-Age",
    );
    const completed = await response(raw);
    expect(completed.location).toBe(`${ctx.baseURL}/proxy-new`);
    const current = await owner.client.getSession();
    expect(current.data!.user.email).toBe("proxy-owner@fixture.test");
    const beforeConcurrent = await state(ctx, true);
    // Source allows restored live cookie replay. Two requests with the exact
    // authentic cookie exercise concurrent completion, with no invented ledger.
    const completions = await Promise.all(
      [0, 1].map(async () =>
        response(
          await owner.fetch(forwarded.bridge, {
            redirect: "manual",
            credentials: "omit",
            headers: { cookie: `better-auth.oauth_state=${issued.issuedCookie!.token}` },
          }),
        ),
      ),
    );
    for (const completion of completions)
      expect(completion.location).toBe(`${ctx.baseURL}/proxy-done?application=kept`);
    const final = await state(ctx, true);
    expect(final.preview.sessions).toHaveLength(beforeConcurrent.preview.sessions.length + 2);
    expect(final.preview.users).toEqual(beforeConcurrent.preview.users);
    expect(final.preview.verification).toEqual([]);
    expect(final.production).toEqual(initial.production);
    return {
      initial: observations(initial),
      signup,
      signin: { status: signin.status, body: await signin.json() },
      signedPreference,
      issuedState: issued.issuedState,
      cookieState: {
        token: issued.issuedCookie!.token,
        payload: issued.issuedState.stateCookie.payload,
      },
      oauthProxyProfile: forwarded.atom,
      selected,
      completed,
      current,
      beforeConcurrent: observations(beforeConcurrent),
      completions,
      final: observations(final),
    };
  },
  ["POST /sign-in/social", "GET /callback/{id}/oauth-proxy"],
  undefined,
  comparison,
);

compatScenario(
  "OAuth proxy remaining dynamic transport and environment URL resolution",
  async (ctx) => {
    const owner = ctx.actor("remaining-urls", "oauth-proxy");
    const initial = await state(ctx);
    const dynamic = await ctx.rawRequest({
      path: "/__test/oauth-proxy/options",
      method: "POST",
      json: { mode: "dynamic" },
    });
    expect(dynamic.status).toBe(200);
    const issued = await issue(ctx, owner);
    const forwarded = await forward(ctx, owner, issued);
    const result = await response(await owner.fetch(forwarded.bridge, { redirect: "manual" }));
    expect(result.location).toBe(`${ctx.baseURL}/proxy-new`);
    const afterDynamic = await state(ctx);
    expect(afterDynamic.production).toEqual(initial.production);
    const environment = await ctx.rawRequest({
      path: "/__test/oauth-proxy/options",
      method: "POST",
      json: { mode: "environment" },
    });
    expect(environment.status).toBe(200);
    // An untrusted transport Host must fall back to the configured vendor URL,
    // never receive the authenticated provider profile.
    const vendorStart = await owner.fetch(`${ctx.baseURL}${path}/sign-in/social`, {
      method: "POST",
      redirect: "manual",
      headers: { host: "untrusted.fixture.test", "content-type": "application/json" },
      body: JSON.stringify({
        provider: "gitlab",
        callbackURL: `${ctx.baseURL}/vendor-done`,
        disableRedirect: true,
      }),
    });
    expect(vendorStart.status).toBe(200);
    const vendorBody = await vendorStart.json();
    const vendorURL = new URL(vendorBody.url);
    const vendorPack = JSON.parse(
      await symmetricDecrypt({ key: secret, data: vendorURL.searchParams.get("state")! }),
    );
    const vendorState = JSON.parse(
      await symmetricDecrypt({ key: secret, data: vendorPack.stateCookie }),
    );
    expect(new URL(vendorState.callbackURL).origin).toBe(ctx.baseURL);
    const vendorApproved = await response(await owner.fetch(vendorURL, { redirect: "manual" }));
    const vendorTransfer = await response(
      await owner.fetch(vendorApproved.location!, { redirect: "manual", credentials: "omit" }),
    );
    const vendorBridge = new URL(vendorTransfer.location!);
    const vendorToken = vendorBridge.searchParams.get("profile")!;
    const vendorPayload = JSON.parse(await symmetricDecrypt({ key: secret, data: vendorToken }));
    const vendorCompleted = await response(await owner.fetch(vendorBridge, { redirect: "manual" }));
    expect(vendorCompleted.location).toBe(`${ctx.baseURL}/vendor-done`);
    // BETTER_AUTH_URL selects whether to skip; it does not replace the auth
    // base for exchange when productionURL is absent in the plugin options.
    const start = await owner.fetch(`${ctx.baseURL}${path}/sign-in/social`, {
      method: "POST",
      redirect: "manual",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        provider: "gitlab",
        callbackURL: `${ctx.baseURL}/environment-done`,
        disableRedirect: true,
      }),
    });
    expect(start.status).toBe(200);
    const started = await start.json();
    const authURL = new URL(started.url);
    const packed = JSON.parse(
      await symmetricDecrypt({ key: secret, data: authURL.searchParams.get("state")! }),
    );
    expect(packed.isOAuthProxy).toBe(true);
    expect(authURL.searchParams.get("redirect_uri")).toBe(`${ctx.baseURL}${path}/callback/gitlab`);
    const stateBytes = await symmetricDecrypt({ key: secret, data: packed.stateCookie });
    const saved = JSON.parse(stateBytes);
    expect(saved.oauthState).toBe(packed.state);
    const retained = {
      ...saved,
      oauthState: { state: saved.oauthState },
      codeVerifier: { token: saved.codeVerifier },
      expiresAt: new Date(saved.expiresAt).toISOString(),
    };
    const approved = await response(await owner.fetch(authURL, { redirect: "manual" }));
    const transfer = await response(
      await owner.fetch(approved.location!, { redirect: "manual", credentials: "omit" }),
    );
    const bridge = new URL(transfer.location!);
    const token = bridge.searchParams.get("profile")!;
    const payload = JSON.parse(await symmetricDecrypt({ key: secret, data: token }));
    const completed = await response(await owner.fetch(bridge, { redirect: "manual" }));
    expect(completed.location).toBe(`${ctx.baseURL}/environment-done`);
    // The actual production transport matches BETTER_AUTH_URL and skips the
    // wrapper. This separate request only issues ordinary production state.
    const production = ctx.baseURL.replace("localhost", "127.0.0.1");
    const skipped = await owner.fetch(`${production}${path}/sign-in/social`, {
      method: "POST",
      redirect: "manual",
      credentials: "omit",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        provider: "gitlab",
        callbackURL: `${ctx.baseURL}/environment-done`,
        disableRedirect: true,
      }),
    });
    expect(skipped.status).toBe(200);
    const skippedBody = await skipped.json();
    const ordinaryState = new URL(skippedBody.url).searchParams.get("state")!;
    expect(ordinaryState).toHaveLength(32);
    return {
      vendorBody,
      vendorState: {
        ...vendorPack,
        stateCookie: {
          token: vendorPack.stateCookie,
          payload: {
            ...vendorState,
            oauthState: { state: vendorState.oauthState },
            codeVerifier: { token: vendorState.codeVerifier },
            expiresAt: new Date(vendorState.expiresAt).toISOString(),
          },
        },
      },
      vendorApproved,
      vendorTransfer,
      vendorProfile: { oauthProxyProfile: { token: vendorToken, payload: vendorPayload } },
      vendorCompleted,
      dynamic,
      issuedState: issued.issuedState,
      oauthProxyProfile: forwarded.atom,
      result,
      initial: observations(initial),
      afterDynamic: observations(afterDynamic),
      environment,
      started,
      environmentState: {
        ...packed,
        stateCookie: { token: packed.stateCookie, payload: retained },
      },
      approved,
      transfer,
      environmentProfile: { oauthProxyProfile: { token, payload } },
      completed,
      skipped: { status: skipped.status, body: skippedBody },
      final: observations(await state(ctx)),
    };
  },
  ["POST /sign-in/social", "GET /callback/{id}/oauth-proxy"],
  undefined,
  comparison,
);
