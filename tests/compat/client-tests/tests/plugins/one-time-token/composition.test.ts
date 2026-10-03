import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import {
  anonymousClient,
  jwtClient,
  multiSessionClient,
  oneTimeTokenClient,
  twoFactorClient,
} from "better-auth/client/plugins";

import { compatScenario } from "../../../support/scenario";
import { generateCurrentTotp, redactTwoFactorPayload } from "../../../support/totp";
import { verifyWithOfficialJose } from "../jwt/helpers";

compatScenario(
  "OTT issuance and transfer compose with anonymous upgrade, device sessions, two-factor and compact JWT publication",
  async (ctx) => {
    const profile = "ott-composed";
    function actor(name: string) {
      const transport = ctx.actor(name, profile);
      return createAuthClient({
        baseURL: ctx.baseURL,
        plugins: [
          anonymousClient(),
          jwtClient(),
          multiSessionClient(),
          oneTimeTokenClient(),
          twoFactorClient(),
        ],
        fetchOptions: { customFetchImpl: transport.fetch },
      });
    }
    const owner = actor("composed-owner"),
      consumer = actor("composed-consumer"),
      guest = actor("composed-guest"),
      factor = actor("composed-factor");
    const email = ctx.uniqueEmail("composed-upgrade"),
      password = "password123";
    const anonymous = await owner.signIn.anonymous();
    expect(anonymous.error).toBeNull();
    const anonymousSession = await owner.getSession();
    if (!anonymousSession.data) throw new Error("actual anonymous session required");
    const anonymousProof = await owner.oneTimeToken.generate();
    expect(anonymousProof.error).toBeNull();
    const upgrade = await owner.signUp.email({ email, password, name: "Composed upgraded owner" });
    expect(upgrade.error).toBeNull();
    const upgraded = await owner.getSession();
    if (!upgraded.data || !anonymousProof.data) throw new Error("actual upgrade/proof required");
    expect(upgraded.data.user.id).not.toBe(anonymousSession.data.user.id);
    const anonymousAfter = await ctx.readUserState({ userId: anonymousSession.data.user.id });
    expect(anonymousAfter).toMatchObject({ user: null, sessions: [] });
    const revokedAnonymous = await guest.oneTimeToken.verify({ token: anonymousProof.data.token });
    expect(revokedAnonymous.error?.message).toBe("Session not found");
    expect(
      await ctx.readVerificationState({
        identifier: `one-time-token:${anonymousProof.data.token}`,
      }),
    ).toEqual([]);
    const second = await owner.signUp.email({
      email: ctx.uniqueEmail("composed-second"),
      password,
      name: "Second device account",
    });
    expect(second.error).toBeNull();
    expect((await owner.multiSession.listDeviceSessions()).data).toHaveLength(2);
    const selected = await owner.multiSession.setActive({
      sessionToken: upgraded.data.session.token,
    });
    expect(selected.data?.user.id).toBe(upgraded.data.user.id);
    const foreign = await consumer.signUp.email({
      email: ctx.uniqueEmail("composed-foreign"),
      password,
      name: "Foreign receiver",
    });
    expect(foreign.error).toBeNull();
    const deniedSelector = await consumer.multiSession.setActive({
      sessionToken: upgraded.data.session.token,
    });
    expect(deniedSelector.error?.code).toBe("INVALID_SESSION_TOKEN");
    const cancellationControl = async (mode?: string) => {
      const response = await ctx
        .actor("composed-owner", profile)
        .fetch(`${ctx.baseURL}/__test/one-time-token`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ operation: "callbacks", mode }),
        });
      expect(response.status).toBe(200);
      return response.json();
    };
    const beforeCancel = await ctx.readUserState({ userId: upgraded.data.user.id });
    await cancellationControl("verification-cancel");
    const canceled = await owner.oneTimeToken.generate();
    expect(canceled.error).toBeNull();
    if (!canceled.data)
      throw new Error("Source returns the generated token after verification cancellation");
    expect(
      await ctx.readVerificationState({ identifier: `one-time-token:${canceled.data.token}` }),
    ).toEqual([]);
    const canceledReceipt = await cancellationControl();
    expect(canceledReceipt.events).toEqual([
      {
        stage: "verification-cancel",
        identifier: `one-time-token:${canceled.data.token}`,
        value: upgraded.data.session.token,
      },
    ]);
    const canceledConsume = await guest.oneTimeToken.verify({ token: canceled.data.token });
    expect(canceledConsume.error?.message).toBe("Invalid token");
    expect(await ctx.readUserState({ userId: upgraded.data.user.id })).toEqual(beforeCancel);
    await cancellationControl("success");
    const generated = await owner.oneTimeToken.generate();
    if (!generated.data) throw new Error("actual transfer proof required");
    const identifier = `one-time-token:${generated.data.token}`;
    const pending = await ctx.readVerificationState({ identifier });
    expect(pending).toMatchObject([{ value: upgraded.data.session.token }]);
    const ownerBefore = await ctx.readUserState({ userId: upgraded.data.user.id });
    const foreignBefore = await ctx.readUserState({ userId: foreign.data!.user.id });
    const transferred = await consumer.oneTimeToken.verify({ token: generated.data.token });
    expect(transferred.error).toBeNull();
    expect(transferred.data?.session).toEqual(upgraded.data.session);
    const devices = await consumer.multiSession.listDeviceSessions();
    expect(new Set(devices.data?.map((item) => item.user.id))).toEqual(
      new Set([upgraded.data.user.id, foreign.data!.user.id]),
    );
    let header: string | null = null,
      exposed: string | null = null;
    const current = await consumer.getSession({
      fetchOptions: {
        onSuccess({ response }) {
          header = response.headers.get("set-auth-jwt");
          exposed = response.headers.get("access-control-expose-headers");
        },
      },
    });
    expect(current.data?.session).toEqual(upgraded.data.session);
    expect(header).toBeTruthy();
    expect((exposed as string | null)?.split(",").map((s) => s.trim())).toContain("set-auth-jwt");
    const jwks = await consumer.jwks();
    if (!header || !jwks.data) throw new Error("actual JWT and JWKS required");
    const jwt = await verifyWithOfficialJose(header, jwks.data.keys, ctx.baseURL, ctx.baseURL);
    expect(jwt.payload.sub).toBe(upgraded.data.user.id);
    expect(await ctx.readVerificationState({ identifier })).toEqual([]);
    const replay = await guest.oneTimeToken.verify({ token: generated.data.token });
    expect(replay.error?.message).toBe("Invalid token");
    const ownerAfter = await ctx.readUserState({ userId: upgraded.data.user.id });
    const foreignAfter = await ctx.readUserState({ userId: foreign.data!.user.id });
    expect(ownerAfter).toEqual(ownerBefore);
    expect(foreignAfter).toEqual(foreignBefore);
    const enabled = await consumer.twoFactor.enable({ password });
    expect(enabled.error).toBeNull();
    if (!enabled.data || !("totpURI" in enabled.data))
      throw new Error("actual TOTP enrollment required");
    const code = await generateCurrentTotp(enabled.data.totpURI);
    expect((await consumer.twoFactor.verifyTotp({ code })).error).toBeNull();
    let pendingHeader: string | null = null;
    const challenged = await factor.signIn.email({
      email,
      password,
      fetchOptions: {
        onSuccess({ response }) {
          pendingHeader = response.headers.get("set-ott");
        },
      },
    });
    expect(challenged.data).toMatchObject({ twoFactorRedirect: true });
    const challengeState = await ctx.readUserState({ userId: upgraded.data.user.id });
    const deniedFactor = await guest.twoFactor.verifyTotp({ code });
    expect(deniedFactor.error?.code).toBe("INVALID_TWO_FACTOR_COOKIE");
    const wrong = await factor.twoFactor.verifyTotp({
      code: String((Number(code[0]) + 1) % 10) + code.slice(1),
    });
    expect(wrong.error?.code).toBe("INVALID_CODE");
    expect(await ctx.readUserState({ userId: upgraded.data.user.id })).toEqual(challengeState);
    let factorOtt: string | null = null;
    const completed = await factor.twoFactor.verifyTotp({
      code,
      fetchOptions: {
        onSuccess({ response }) {
          factorOtt = response.headers.get("set-ott");
        },
      },
    });
    expect(completed.error).toBeNull();
    expect(factorOtt).toBeTruthy();
    const factorSession = await factor.getSession();
    const factorTransfer = await guest.oneTimeToken.verify({ token: factorOtt! });
    expect(factorTransfer.error).toBeNull();
    expect(factorTransfer.data?.session).toEqual(factorSession.data?.session);
    expect(factorTransfer.data?.user.id).toBe(upgraded.data.user.id);
    const factorRows = await ctx.readUserState({ userId: upgraded.data.user.id });
    const result = {
      anonymous: ctx.snapshot(anonymous),
      anonymousSession: ctx.snapshot(anonymousSession),
      anonymousProof,
      upgrade: ctx.snapshot(upgrade),
      upgraded: ctx.snapshot(upgraded),
      anonymousAfter,
      revokedAnonymous: ctx.snapshot(revokedAnonymous),
      second: ctx.snapshot(second),
      selected: ctx.snapshot(selected),
      foreign: ctx.snapshot(foreign),
      deniedSelector,
      canceled,
      canceledReceipt,
      canceledConsume,
      generated,
      pending,
      transferred: ctx.snapshot(transferred),
      devices: ctx.snapshot(devices),
      current: ctx.snapshot(current),
      jwt,
      ownerBefore,
      ownerAfter,
      foreignBefore,
      foreignAfter,
      replay,
      enabled: redactTwoFactorPayload(enabled),
      challenged: ctx.snapshot(challenged),
      pendingHeader,
      challengeState,
      deniedFactor,
      wrong,
      completed: ctx.snapshot(completed),
      factorHeader: { token: factorOtt },
      factorSession: ctx.snapshot(factorSession),
      factorTransfer: ctx.snapshot(factorTransfer),
      factorRows,
    };
    if (process.env.OTT210_PROOF_DIR)
      await Bun.write(
        `${process.env.OTT210_PROOF_DIR}/${new URL(ctx.baseURL).port}.json`,
        JSON.stringify(result, null, 2),
      );
    return result;
  },
  [
    "GET /one-time-token/generate",
    "POST /one-time-token/verify",
    "POST /sign-in/anonymous",
    "POST /sign-up/email",
    "POST /multi-session/set-active",
    "POST /two-factor/verify-totp",
  ],
);
