import { expect } from "bun:test";
import { z } from "zod";
import { compatScenario } from "../../support/scenario";
import {
  CONTRACT,
  control,
  EOA,
  identity,
  message,
  nonce,
  SECOND_EOA,
  signature,
  siweActor,
  state,
  verify,
} from "./helpers";

compatScenario(
  "SIWE official client binds real Unicode signatures to nonce wallet account and rotated session state",
  async (ctx) => {
    const actor = siweActor(ctx);
    const firstNonce = await nonce(actor);
    const issued = await state(ctx);
    expect(issued.proofs).toHaveLength(1);
    expect(issued.proofs[0]?.identifier).toBe(`siwe:${firstNonce}`);
    expect(issued.proofs[0]?.value).toBe(firstNonce);
    expect(
      Date.parse(issued.proofs[0]!.expiresAt) - Date.parse(issued.proofs[0]!.createdAt),
    ).toBeGreaterThan(899_000);
    expect(
      Date.parse(issued.proofs[0]!.expiresAt) - Date.parse(issued.proofs[0]!.createdAt),
    ).toBeLessThanOrEqual(900_000);
    const firstMessage = message(firstNonce, { address: EOA.toLowerCase() });
    const first = await verify(actor, firstMessage, { email: "ignored@fixture.test" });
    expect(first.error).toBeNull();
    const owner = identity.parse(first.data);
    expect(owner.user.walletAddress).toBe(EOA);
    expect(owner.user.chainId).toBe(1);
    const firstState = await state(ctx);
    expect(firstState.users).toHaveLength(1);
    expect(firstState.wallets).toHaveLength(1);
    expect(firstState.accounts).toHaveLength(1);
    expect(firstState.sessions).toHaveLength(1);
    expect(firstState.proofs).toEqual([]);
    expect(firstState.users[0]).toMatchObject({
      id: owner.user.id,
      email: `${EOA.toLowerCase()}@siwe.placeholder.invalid`,
      name: EOA,
      image: "",
      emailVerified: false,
    });
    expect(firstState.wallets[0]).toMatchObject({
      userId: owner.user.id,
      address: EOA,
      chainId: 1,
      isPrimary: true,
    });
    expect(firstState.accounts[0]).toMatchObject({
      userId: owner.user.id,
      accountId: `${EOA}:1`,
      providerId: "siwe",
    });
    expect(firstState.sessions[0]).toMatchObject({ userId: owner.user.id, token: owner.token });
    const session = await actor.client.getSession();
    expect(session.data?.user.id).toBe(owner.user.id);
    expect(session.data?.session.token).toBe(owner.token);
    const replay = await verify(actor, firstMessage);
    expect(replay.error).toMatchObject({
      status: 401,
      code: "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE",
    });
    const observations = [];
    for (const [chain, expected, compact] of [
      ["1", 1, true],
      ["0x10", 16, false],
      ["1e21", 1e21, false],
    ] as const) {
      const challenge = await nonce(actor, true);
      const signed = message(challenge, {
        chain,
        extra: "Expiration Time: invalid\nNot Before: invalid",
      });
      const result = await verify(actor, signed, { compact });
      expect(result.error).toBeNull();
      const value = identity.parse(result.data);
      expect(value.user.id).toBe(owner.user.id);
      expect(value.user.chainId).toBe(expected);
      expect(value.token).not.toBe(owner.token);
      observations.push({ result: ctx.snapshot(result), persisted: await state(ctx) });
    }
    const after = await state(ctx);
    expect(after.users).toEqual(firstState.users);
    expect(after.wallets).toHaveLength(3);
    expect(after.accounts).toHaveLength(3);
    expect(after.sessions).toHaveLength(4);
    expect(
      after.wallets.map((wallet) => ({ chainId: wallet.chainId, isPrimary: wallet.isPrimary })),
    ).toEqual([
      { chainId: 1, isPrimary: true },
      { chainId: 16, isPrimary: false },
      { chainId: 1e21, isPrimary: false },
    ]);
    expect(after.accounts.map((account) => account.accountId)).toEqual([
      `${EOA}:1`,
      `${EOA}:16`,
      `${EOA}:1e+21`,
    ]);
    expect(after.inputs[0]?.cacao.p).toEqual({
      domain: "HTTPS://Fixture.Example/ignored",
      aud: "HTTPS://Fixture.Example/ignored",
      nonce: firstNonce,
      iss: "HTTPS://Fixture.Example/ignored",
      version: "1",
    });
    expect(
      after.inputs.every((input) => input.cacao.s.s === input.signature && input.address === EOA),
    ).toBe(true);
    return {
      issued,
      first: ctx.snapshot(first),
      firstState,
      session: ctx.snapshot(session),
      replay: ctx.snapshot(replay),
      observations,
      after,
    };
  },
  ["POST /siwe/nonce", "POST /siwe/get-nonce", "POST /siwe/verify"],
);

compatScenario(
  "SIWE wrong wallet domain chain and signature burn proofs while invalid nonce syntax preserves the issued generation",
  async (ctx) => {
    const actor = siweActor(ctx);
    const observations = [];
    for (const [options, scalar, code] of [
      [{ domain: "attacker.fixture.test" }, 1, "UNAUTHORIZED_SIWE_MESSAGE_MISMATCH"],
      [{ address: "0x123" }, 1, "UNAUTHORIZED_SIWE_MESSAGE_MISMATCH"],
      [{ chain: "1.5" }, 1, "UNAUTHORIZED_SIWE_MESSAGE_MISMATCH"],
      [{ chain: "0" }, 1, "UNAUTHORIZED_SIWE_MESSAGE_MISMATCH"],
      [{ extra: "Expiration Time: 2001-02-30T00:00:00Z" }, 1, "UNAUTHORIZED_SIWE_MESSAGE_EXPIRED"],
      [
        { extra: "Expiration Time: Jan 1 2000 00:00:00 GMT" },
        1,
        "UNAUTHORIZED_SIWE_MESSAGE_EXPIRED",
      ],
      [
        { extra: "Not Before: Sep 30 2099 12:00:00 UTC" },
        1,
        "UNAUTHORIZED_SIWE_MESSAGE_NOT_YET_VALID",
      ],
      [
        { extra: "Not Before: September 30, 2099 12:00:00 GMT" },
        1,
        "UNAUTHORIZED_SIWE_MESSAGE_NOT_YET_VALID",
      ],
      [{ extra: "Not Before: January 1 2099" }, 1, "UNAUTHORIZED_SIWE_MESSAGE_NOT_YET_VALID"],
      [
        { extra: "Not Before: Jan 1 2099 00:00:00 PST" },
        1,
        "UNAUTHORIZED_SIWE_MESSAGE_NOT_YET_VALID",
      ],
      [
        { extra: "Not Before: 2099-01-01T00:00:00+05:30" },
        1,
        "UNAUTHORIZED_SIWE_MESSAGE_NOT_YET_VALID",
      ],
      [
        { extra: "Not Before: 2099-01-01T00:00:00-0330" },
        1,
        "UNAUTHORIZED_SIWE_MESSAGE_NOT_YET_VALID",
      ],
      [{ extra: "Expiration Time: 1999/12/31 23:59:59" }, 1, "UNAUTHORIZED_SIWE_MESSAGE_EXPIRED"],
      [
        { extra: "Not Before: 2099-01-01T00:00:00.123456789012Z" },
        1,
        "UNAUTHORIZED_SIWE_MESSAGE_NOT_YET_VALID",
      ],
      [{}, 2, undefined],
    ] as const) {
      const challenge = await nonce(actor);
      const rejected = await verify(actor, message(challenge, options), { scalar });
      expect(rejected.error?.status).toBe(401);
      if (code === undefined)
        expect(rejected.error?.message).toBe("Unauthorized: Invalid SIWE signature");
      else expect(rejected.error?.code).toBe(code);
      const after = await state(ctx);
      expect(after.proofs).toEqual([]);
      expect(after.users).toEqual([]);
      expect(after.wallets).toEqual([]);
      expect(after.sessions).toEqual([]);
      expect(after.accounts).toEqual([]);
      const retry = await verify(actor, message(challenge));
      expect(retry.error).toMatchObject({
        status: 401,
        code: "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE",
      });
      observations.push({ rejected: ctx.snapshot(rejected), after, retry: ctx.snapshot(retry) });
    }
    const challenge = await nonce(actor);
    const before = await state(ctx);
    const invalidSyntax = await verify(actor, message("short"));
    expect(invalidSyntax.error?.code).toBe("UNAUTHORIZED_SIWE_MESSAGE_MISMATCH");
    expect(await state(ctx)).toEqual(before);
    await control(ctx, { operation: "proof", nonce: challenge, value: "different stored value" });
    const success = await verify(actor, message(challenge));
    expect(success.error).toBeNull();
    const after = await state(ctx);
    expect(after.users).toHaveLength(1);
    expect(after.wallets).toHaveLength(1);
    expect(after.proofs).toEqual([]);
    return {
      observations,
      before,
      invalidSyntax: ctx.snapshot(invalidSyntax),
      success: ctx.snapshot(success),
      after,
    };
  },
  ["POST /siwe/verify"],
);

compatScenario(
  "SIWE expired stored nonce is removed and replay cannot create an identity",
  async (ctx) => {
    const actor = siweActor(ctx);
    const challenge = await nonce(actor, true);
    const expiredAt = "2001-02-03T04:05:06.000Z";
    await control(ctx, { operation: "proof", nonce: challenge, expiresAt: expiredAt });
    const before = await state(ctx);
    expect(before.proofs[0]?.expiresAt).toBe(expiredAt);
    const rejected = await verify(actor, message(challenge));
    expect(rejected.error).toMatchObject({
      status: 401,
      code: "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE",
    });
    const replay = await verify(actor, message(challenge));
    expect(replay.error).toMatchObject({
      status: 401,
      code: "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE",
    });
    const after = await state(ctx);
    expect(after).toMatchObject({
      users: [],
      wallets: [],
      accounts: [],
      sessions: [],
      proofs: [],
      inputs: [],
    });
    return { before, rejected: ctx.snapshot(rejected), replay: ctx.snapshot(replay), after };
  },
  ["POST /siwe/get-nonce", "POST /siwe/verify"],
);

compatScenario(
  "SIWE required email and ENS preserve claims without linking a taken email identity",
  async (ctx) => {
    const actor = siweActor(ctx, "required-email", "siwe-email");
    const email = ctx.uniqueEmail("siwe-existing");
    const existing = (await control(ctx, { operation: "create-user", email })) as {
      userId: string;
    };
    const before = await state(ctx);
    const challenge = await nonce(actor);
    const signed = message(challenge);
    const missing = await verify(actor, signed);
    expect(missing.error?.status).toBe(400);
    expect((await state(ctx)).proofs).toHaveLength(1);
    const first = await verify(actor, signed, { email: email.toUpperCase() });
    expect(first.error).toBeNull();
    const owner = identity.parse(first.data);
    expect(owner.user.id).not.toBe(existing.userId);
    const collision = await state(ctx);
    expect(collision.users[0]).toEqual(before.users[0]);
    expect(collision.users[1]).toMatchObject({
      id: owner.user.id,
      name: "Wallet Fixture",
      image: "https://fixture.example/avatar.png",
      email: `${EOA.toLowerCase()}@wallet.fixture.test`,
      emailVerified: false,
    });
    expect(collision.sessions.every((session) => session.userId === owner.user.id)).toBe(true);
    expect(collision.accounts.every((account) => account.userId === owner.user.id)).toBe(true);
    expect(collision.proofs).toEqual([]);
    const unused = ctx.uniqueEmail("siwe-unused");
    await control(ctx, { operation: "configure", ens: "throw" });
    const secondNonce = await nonce(actor);
    const secondSigned = message(secondNonce, { address: SECOND_EOA });
    const failure = await verify(actor, secondSigned, { scalar: 2, email: unused });
    expect(failure.error).toMatchObject({
      status: 401,
      message: "Something went wrong. Please try again later.",
      error: "deterministic ENS failure",
    });
    const reservation = await state(ctx);
    expect(reservation.users).toEqual(collision.users);
    expect(reservation.wallets).toEqual(collision.wallets);
    expect(reservation.sessions).toEqual(collision.sessions);
    expect(reservation.proofs).toHaveLength(1);
    expect(reservation.proofs[0]).toMatchObject({
      identifier: `siwe-email-claim-${unused}`,
      value: SECOND_EOA,
    });
    expect(
      Date.parse(reservation.proofs[0]!.expiresAt) - Date.parse(reservation.proofs[0]!.createdAt),
    ).toBeGreaterThan(59_000);
    await control(ctx, { operation: "configure", ens: "resolve" });
    const thirdNonce = await nonce(actor);
    const fallback = await verify(actor, message(thirdNonce, { address: SECOND_EOA }), {
      scalar: 2,
      email: unused,
    });
    expect(fallback.error).toBeNull();
    const after = await state(ctx);
    expect(after.users[2]).toMatchObject({
      email: `${SECOND_EOA.toLowerCase()}@wallet.fixture.test`,
      emailVerified: false,
    });
    expect(after.proofs).toEqual(reservation.proofs);
    return {
      before,
      missing: ctx.snapshot(missing),
      first: ctx.snapshot(first),
      collision,
      failure: ctx.snapshot(failure),
      reservation,
      fallback: ctx.snapshot(fallback),
      after,
    };
  },
  ["POST /siwe/verify"],
);

compatScenario(
  "SIWE local ERC1271 RPC verifies the contract owner chain and signed bytes",
  async (ctx) => {
    const actor = siweActor(ctx, "contract-owner", "siwe-contract");
    const challenge = await nonce(actor);
    const signed = message(challenge, { address: CONTRACT, chain: "31337" });
    const success = await verify(actor, signed, { scalar: 3 });
    expect(success.error).toBeNull();
    const owner = identity.parse(success.data);
    expect(owner.user).toMatchObject({ walletAddress: CONTRACT, chainId: 31337 });
    const first = await state(ctx);
    expect(first.rpcCalls).toHaveLength(1);
    expect(first.wallets[0]).toMatchObject({
      userId: owner.user.id,
      address: CONTRACT,
      chainId: 31337,
      isPrimary: true,
    });
    const wrongNonce = await nonce(actor);
    const wrongOwner = await verify(
      actor,
      message(wrongNonce, { address: CONTRACT, chain: "31337" }),
      { scalar: 2 },
    );
    expect(wrongOwner.error?.status).toBe(401);
    expect(wrongOwner.error?.message).toBe("Unauthorized: Invalid SIWE signature");
    const retry = await verify(actor, message(wrongNonce, { address: CONTRACT, chain: "31337" }), {
      scalar: 3,
    });
    expect(retry.error?.code).toBe("UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE");
    const chainNonce = await nonce(actor);
    const wrongChain = await verify(actor, message(chainNonce, { address: CONTRACT, chain: "1" }), {
      scalar: 3,
    });
    expect(wrongChain.error?.status).toBe(401);
    const after = await state(ctx);
    expect(after.rpcCalls).toHaveLength(2);
    expect(after.users).toEqual(first.users);
    expect(after.wallets).toEqual(first.wallets);
    expect(after.accounts).toEqual(first.accounts);
    expect(after.sessions).toEqual(first.sessions);
    expect(after.proofs).toEqual([]);
    return {
      success: ctx.snapshot(success),
      first,
      wrongOwner: ctx.snapshot(wrongOwner),
      retry: ctx.snapshot(retry),
      wrongChain: ctx.snapshot(wrongChain),
      after,
    };
  },
  ["POST /siwe/nonce", "POST /siwe/verify"],
);

compatScenario(
  "SIWE callback API errors remain distinct from signature rejection and provider failure",
  async (ctx) => {
    const actor = siweActor(ctx);
    const observations = [];
    for (const mode of ["false", "throw", "api-error"]) {
      await control(ctx, { operation: "configure", verifier: mode });
      const challenge = await nonce(actor);
      const result = await verify(actor, message(challenge));
      if (mode === "api-error")
        expect(result.error).toMatchObject({
          status: 403,
          code: "WALLET_POLICY_REJECTED",
          message: "configured wallet policy rejected",
        });
      else if (mode === "throw")
        expect(result.error).toMatchObject({
          status: 401,
          error: "deterministic verifier failure",
          message: "Something went wrong. Please try again later.",
        });
      else
        expect(result.error).toMatchObject({
          status: 401,
          message: "Unauthorized: Invalid SIWE signature",
        });
      const persisted = await state(ctx);
      expect(persisted).toMatchObject({
        users: [],
        wallets: [],
        accounts: [],
        sessions: [],
        proofs: [],
      });
      observations.push({ mode, result: ctx.snapshot(result), persisted });
    }
    await control(ctx, { operation: "configure", nonce: "short" });
    const invalid = await actor.client.siwe.getNonce();
    expect(invalid.error).toMatchObject({ status: 500, code: "SIWE_INVALID_NONCE" });
    const after = await state(ctx);
    expect(after.proofs).toEqual([]);
    return { observations, invalid: ctx.snapshot(invalid), after };
  },
  ["POST /siwe/get-nonce", "POST /siwe/verify"],
);

compatScenario(
  "SIWE overlapping consumers issue one wallet session before the verifier completes",
  async (ctx) => {
    const actor = siweActor(ctx);
    await control(ctx, { operation: "configure", verifier: "hold" });
    const challenge = await nonce(actor);
    const signed = message(challenge);
    const winner = verify(actor, signed);
    await control(ctx, { operation: "wait-verifier" });
    const entered = await state(ctx);
    expect(entered.inputs).toHaveLength(1);
    expect(entered.proofs).toEqual([]);
    expect(entered.wallets).toEqual([]);
    const loser = await verify(actor, signed);
    expect(loser.error).toMatchObject({
      status: 401,
      code: "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE",
    });
    await control(ctx, { operation: "release-verifier" });
    const success = await winner;
    expect(success.error).toBeNull();
    const owner = identity.parse(success.data);
    const after = await state(ctx);
    expect(after.users).toHaveLength(1);
    expect(after.wallets).toHaveLength(1);
    expect(after.accounts).toHaveLength(1);
    expect(after.sessions).toHaveLength(1);
    expect(after.inputs).toHaveLength(1);
    expect(after.proofs).toEqual([]);
    expect(after.sessions[0]).toMatchObject({ userId: owner.user.id, token: owner.token });
    return { entered, loser: ctx.snapshot(loser), success: ctx.snapshot(success), after };
  },
  ["POST /siwe/verify"],
);

compatScenario(
  "SIWE reserves unused email and preserves existing wallet ownership through bans and two factor",
  async (ctx) => {
    const actor = siweActor(ctx, "email-owner", "siwe-email");
    const email = ctx.uniqueEmail("siwe-unused-success");
    const challenge = await nonce(actor);
    const first = await verify(actor, message(challenge), { email: email.toUpperCase() });
    expect(first.error).toBeNull();
    const owner = identity.parse(first.data);
    const persisted = await state(ctx);
    expect(persisted.users).toHaveLength(1);
    expect(persisted.users[0]).toMatchObject({ id: owner.user.id, email, emailVerified: false });
    expect(persisted.proofs).toEqual([]);
    await control(ctx, { operation: "update-user", userId: owner.user.id, banned: true });
    const banNonce = await nonce(actor);
    const denied = await verify(actor, message(banNonce), { email });
    expect(denied.error?.status).toBe(403);
    const banned = await state(ctx);
    expect(banned.sessions).toEqual(persisted.sessions);
    expect(banned.accounts).toEqual(persisted.accounts);
    expect(banned.wallets).toEqual(persisted.wallets);
    expect(banned.proofs).toEqual([]);
    await control(ctx, {
      operation: "update-user",
      userId: owner.user.id,
      banned: false,
      twoFactorEnabled: true,
    });
    const nextNonce = await nonce(actor);
    const next = await verify(actor, message(nextNonce), {
      email: ctx.uniqueEmail("untrusted-replacement"),
    });
    expect(next.error).toBeNull();
    expect(identity.parse(next.data).user.id).toBe(owner.user.id);
    const after = await state(ctx);
    expect(after.users[0]?.email).toBe(email);
    expect(after.users[0]?.twoFactorEnabled).toBe(true);
    expect(after.sessions).toHaveLength(2);
    expect(after.wallets).toEqual(persisted.wallets);
    expect(after.accounts).toEqual(persisted.accounts);
    expect(after.proofs).toEqual([]);
    return {
      first: ctx.snapshot(first),
      persisted,
      denied: ctx.snapshot(denied),
      banned,
      next: ctx.snapshot(next),
      after,
    };
  },
  ["POST /siwe/verify"],
);

compatScenario(
  "SIWE nonce aliases reject wallet body fields and strict verification prevents user ownership injection",
  async (ctx) => {
    const actor = siweActor(ctx);
    const prior = (await control(ctx, {
      operation: "create-user",
      email: ctx.uniqueEmail("protected-user"),
    })) as { userId: string };
    const before = await state(ctx);
    const rejections = [];
    for (const alias of ["nonce", "get-nonce"]) {
      const rejection = await ctx.rawRequest({
        path: `/__test/profiles/siwe/api/auth/siwe/${alias}`,
        method: "POST",
        json: { address: EOA, chainId: 1 },
      });
      expect(rejection.status).toBe(400);
      expect(rejection.body).toMatchObject({
        code: "VALIDATION_ERROR",
        message: '[body] Unrecognized keys: "address", "chainId"',
      });
      expect(await state(ctx)).toEqual(before);
      rejections.push(rejection);
    }
    const absentBody = await ctx.rawRequest({
      path: "/__test/profiles/siwe/api/auth/siwe/get-nonce",
      method: "POST",
    });
    expect(absentBody.status).toBe(200);
    const challenge = (absentBody.body as { nonce: string }).nonce;
    const signed = message(challenge);
    const injected = await ctx.rawRequest({
      path: "/__test/profiles/siwe/api/auth/siwe/verify",
      method: "POST",
      json: { message: signed, signature: "invalid", userId: prior.userId },
    });
    expect(injected.status).toBe(400);
    expect(injected.body).toMatchObject({
      code: "VALIDATION_ERROR",
      message: '[body] Unrecognized key: "userId"',
    });
    const invalidBody = await ctx.rawRequest({
      path: "/__test/profiles/siwe/api/auth/siwe/verify",
      method: "POST",
      json: { message: "", signature: false, email: 2, unknown: true },
    });
    expect(invalidBody.status).toBe(400);
    expect(invalidBody.body).toEqual({
      code: "VALIDATION_ERROR",
      message:
        '[body.message] Too small: expected string to have >=1 characters; [body.signature] Invalid input: expected string, received boolean; [body.email] Invalid input: expected string, received number; [body] Unrecognized key: "unknown"',
    });
    const pending = await state(ctx);
    expect(pending.users).toEqual(before.users);
    expect(pending.proofs).toHaveLength(1);
    expect(pending.inputs).toEqual([]);
    const success = await verify(actor, signed);
    expect(success.error).toBeNull();
    const owner = identity.parse(success.data);
    expect(owner.user.id).not.toBe(prior.userId);
    const after = await state(ctx);
    expect(after.users[0]).toEqual(before.users[0]);
    expect(after.sessions).toHaveLength(1);
    expect(after.sessions[0]?.userId).toBe(owner.user.id);
    expect(after.accounts[0]?.userId).toBe(owner.user.id);
    expect(after.wallets[0]?.userId).toBe(owner.user.id);
    expect(after.proofs).toEqual([]);
    const alternateChallenge = await nonce(actor);
    const alternate = await verify(actor, message(alternateChallenge));
    expect(alternate.error).toBeNull();
    expect(identity.parse(alternate.data).user.id).toBe(owner.user.id);
    const alternateState = await state(ctx);
    expect(alternateState.proofs).toEqual([]);
    expect(alternateState.users).toEqual(after.users);
    expect(alternateState.accounts).toEqual(after.accounts);
    expect(alternateState.wallets).toEqual(after.wallets);
    expect(alternateState.sessions).toHaveLength(2);
    return {
      before,
      rejections,
      absentBody,
      injected,
      invalidBody,
      pending,
      success: ctx.snapshot(success),
      after,
      alternate: ctx.snapshot(alternate),
      alternateState,
    };
  },
  ["POST /siwe/nonce", "POST /siwe/get-nonce", "POST /siwe/verify"],
);

compatScenario(
  "SIWE media validation preserves signed nonce and verifier state before successful JSON retry",
  async (ctx) => {
    const foreign = siweActor(ctx, "media-foreign");
    const foreignChallenge = await nonce(foreign);
    const foreignResult = await verify(
      foreign,
      message(foreignChallenge, { address: SECOND_EOA }),
      { scalar: 2 },
    );
    expect(foreignResult.error).toBeNull();
    const foreignIdentity = identity.parse(foreignResult.data);
    const foreignSession = await foreign.client.getSession();
    expect(foreignSession.data?.session.token).toBe(foreignIdentity.token);
    const actor = siweActor(ctx);
    const challenge = await nonce(actor);
    const signed = message(challenge);
    const before = await state(ctx);
    const observations = [];
    const rawMediaResponses: unknown[] = [];
    const retainMedia = async (path: string, media: string, response: Response, body: unknown) => {
      rawMediaResponses.push({
        path,
        media,
        status: response.status,
        headers: Object.fromEntries(response.headers),
        body,
      });
      await Bun.write(
        new URL(`../../artifacts/siwe-media-${new URL(ctx.baseURL).port}.json`, import.meta.url),
        JSON.stringify(rawMediaResponses, null, 2),
      );
    };
    for (const path of ["/siwe/nonce", "/siwe/get-nonce", "/siwe/verify"]) {
      for (const media of [
        "text/plain",
        "application/x-www-form-urlencoded",
        "application/problem+json",
        "",
      ]) {
        const payload =
          path === "/siwe/verify" ? { message: signed, signature: signature(signed) } : {};
        const response = await actor.fetch(`${ctx.baseURL}/api/auth${path}`, {
          method: "POST",
          body: new TextEncoder().encode(JSON.stringify(payload)),
          headers: media ? { "content-type": media } : {},
        });
        expect(response.status).toBe(415);
        const body = await response.json();
        await retainMedia(path, media, response, body);
        expect(body).toEqual({
          code: "UNSUPPORTED_MEDIA_TYPE",
          message: media
            ? `Content-Type "${media}" is not allowed. Allowed types: application/json`
            : "Content-Type is required. Allowed types: application/json",
        });
        expect(await state(ctx)).toEqual(before);
        observations.push({ path, media, body });
      }
    }
    for (const path of ["/siwe/nonce", "/siwe/get-nonce", "/siwe/verify"])
      for (const media of [
        "text/plainapplication/json",
        "TEXT/PLAINapplication/json; charset=UTF-8",
      ]) {
        const response = await actor.fetch(`${ctx.baseURL}/api/auth${path}`, {
          method: "POST",
          body: JSON.stringify(
            path.endsWith("verify") ? { message: signed, signature: signature(signed) } : {},
          ),
          headers: { "content-type": media },
        });
        expect(response.status).toBe(400);
        const headers = Object.fromEntries(
          [...response.headers].filter(
            ([key]) =>
              ![
                "date",
                "content-length",
                "server",
                "connection",
                "keep-alive",
                "transfer-encoding",
              ].includes(key),
          ),
        );
        const body = await response.json();
        await retainMedia(path, media, response, body);
        expect(body).toEqual({
          code: "VALIDATION_ERROR",
          message: "[body] Invalid input: expected object, received string",
        });
        expect(await state(ctx)).toEqual(before);
        observations.push({ path, media, headers, body });
      }
    const arrayRejected = await actor.fetch(`${ctx.baseURL}/api/auth/siwe/verify`, {
      method: "POST",
      body: JSON.stringify({ message: signed, signature: signature(signed) }),
      headers: { "content-type": "application/octet-streamapplication/json" },
    });
    expect(arrayRejected.status).toBe(400);
    const arrayBody = await arrayRejected.json();
    await retainMedia(
      "/siwe/verify",
      "application/octet-streamapplication/json",
      arrayRejected,
      arrayBody,
    );
    expect(arrayBody).toEqual({
      code: "VALIDATION_ERROR",
      message:
        "[body.message] Invalid input: expected string, received undefined; [body.signature] Invalid input: expected string, received undefined",
    });
    expect(await state(ctx)).toEqual(before);
    observations.push({
      path: "/siwe/verify",
      media: "application/octet-streamapplication/json",
      headers: Object.fromEntries(
        [...arrayRejected.headers].filter(
          ([key]) =>
            ![
              "date",
              "content-length",
              "server",
              "connection",
              "keep-alive",
              "transfer-encoding",
            ].includes(key),
        ),
      ),
      body: arrayBody,
    });
    const accepted = await actor.fetch(`${ctx.baseURL}/api/auth/siwe/verify`, {
      method: "POST",
      body: JSON.stringify({ message: signed, signature: signature(signed) }),
      headers: { "content-type": "APPLICATION/JSON; charset=UTF-8" },
    });
    expect(accepted.status).toBe(200);
    const result = identity.parse(await accepted.json());
    const after = await state(ctx);
    expect(after.proofs).toEqual([]);
    expect(after.inputs).toHaveLength(2);
    expect(after.users).toHaveLength(2);
    expect(after.wallets[1]?.userId).toBe(result.user.id);
    expect(after.users[0]).toEqual(before.users[0]);
    expect(after.wallets[0]).toEqual(before.wallets[0]);
    expect(after.accounts[0]).toEqual(before.accounts[0]);
    expect(after.sessions[0]).toEqual(before.sessions[0]);
    const replay = await verify(actor, signed);
    expect(replay.error).toMatchObject({
      status: 401,
      code: "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE",
    });
    expect(await state(ctx)).toEqual(after);
    const aliasRetry = await actor.fetch(`${ctx.baseURL}/api/auth/siwe/get-nonce`, {
      method: "POST",
      body: "{}",
      headers: { "content-type": "APPLICATION/JSON; charset=UTF-8" },
    });
    expect(aliasRetry.status).toBe(200);
    const aliasNonce = z.object({ nonce: z.string() }).parse(await aliasRetry.json());
    const aliasPending = await state(ctx);
    expect(aliasPending.inputs).toEqual(after.inputs);
    expect(aliasPending.proofs).toHaveLength(1);
    const aliasVerified = await verify(actor, message(aliasNonce.nonce));
    expect(aliasVerified.error).toBeNull();
    expect(identity.parse(aliasVerified.data).user.id).toBe(result.user.id);
    const aliasAfter = await state(ctx);
    expect(aliasAfter.proofs).toEqual([]);
    expect(aliasAfter.wallets).toEqual(after.wallets);
    expect(aliasAfter.accounts).toEqual(after.accounts);
    expect(aliasAfter.sessions).toHaveLength(3);
    return {
      foreignResult: ctx.snapshot(foreignResult),
      foreignSession: ctx.snapshot(foreignSession),
      before,
      observations,
      result,
      after,
      replay: ctx.snapshot(replay),
      aliasNonce,
      aliasPending,
      aliasVerified: ctx.snapshot(aliasVerified),
      aliasAfter,
    };
  },
  ["POST /siwe/nonce", "POST /siwe/get-nonce", "POST /siwe/verify"],
);

compatScenario(
  "SIWE hour 24 validates every fraction digit before applying date bounds",
  async (ctx) => {
    const actor = siweActor(ctx);
    const observations = [];
    for (const [fraction, accepted] of [
      ["0000", false],
      ["0001", true],
    ] as const) {
      const challenge = await nonce(actor);
      const signed = message(challenge, { extra: `Not Before: 2099-01-01T24:00:00.${fraction}Z` });
      const result = await verify(actor, signed);
      if (accepted) {
        expect(result.error).toBeNull();
        identity.parse(result.data);
      } else
        expect(result.error).toMatchObject({
          status: 401,
          code: "UNAUTHORIZED_SIWE_MESSAGE_NOT_YET_VALID",
        });
      const after = await state(ctx);
      expect(after.proofs).toEqual([]);
      expect(after.inputs).toHaveLength(accepted ? 1 : 0);
      expect(after.users).toHaveLength(accepted ? 1 : 0);
      observations.push({ fraction, result: ctx.snapshot(result), after });
    }
    return observations;
  },
  ["POST /siwe/nonce", "POST /siwe/verify"],
);

compatScenario(
  "SIWE signed legacy date bounds distinguish parser admission from verifier delivery and preserve a foreign wallet",
  async (ctx) => {
    const foreign = siweActor(ctx, "date-foreign");
    const foreignNonce = await nonce(foreign);
    const foreignResult = await verify(foreign, message(foreignNonce, { address: SECOND_EOA }), {
      scalar: 2,
    });
    expect(foreignResult.error).toBeNull();
    const foreignIdentity = identity.parse(foreignResult.data);
    const foreignSession = await foreign.client.getSession();
    expect(foreignSession.data?.session.token).toBe(foreignIdentity.token);
    const actor = siweActor(ctx, "date-owner");
    const original = await state(ctx);
    const observations = [];
    for (const [date, position] of [
      ["September 30, 2099 12:00:00 GMT", "future"],
      ["September 30, 2000 12:00:00 GMT", "past"],
      ["January 1 2099", "future"],
      ["January 1 2000", "past"],
      ["Jan 1 2099 00:00:00 PST", "future"],
      ["Jan 1 2000 00:00:00 PST", "past"],
      ["2099-01-01T00:00:00.123456789012+05:30", "future"],
      ["2000-01-01T00:00:00.123456789012-0330", "past"],
      ["invalid legacy timestamp", "invalid"],
      ["+275760-09-13T00:00:00.000Z", "future"],
      ["+275760-09-13T00:00:00.001Z", "invalid"],
      ...[
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "October",
        "November",
        "December",
      ].map((month) => [`${month} 1 2099 00:00:00 GMT`, "future"] as const),
      ...["UT", "UTC", "GMT", "EST", "EDT", "CST", "CDT", "MST", "MDT", "PDT"].map(
        (zone) => [`Jan 1 2099 00:00:00 ${zone}`, "future"] as const,
      ),
    ] as const)
      for (const field of ["Not Before", "Expiration Time"] as const) {
        const challenge = await nonce(actor);
        const before = await state(ctx);
        const signed = message(challenge, { extra: `${field}: ${date}` });
        const rejected =
          (field === "Not Before" && position === "future") ||
          (field === "Expiration Time" && position === "past");
        const result = await verify(actor, signed);
        let session: unknown = null;
        if (rejected)
          expect(result.error).toMatchObject({
            status: 401,
            code:
              field === "Not Before"
                ? "UNAUTHORIZED_SIWE_MESSAGE_NOT_YET_VALID"
                : "UNAUTHORIZED_SIWE_MESSAGE_EXPIRED",
          });
        else {
          expect(result.error).toBeNull();
          const principal = identity.parse(result.data);
          const read = await actor.client.getSession();
          expect(read.data?.user.id).toBe(principal.user.id);
          expect(read.data?.session.token).toBe(principal.token);
          session = ctx.snapshot(read);
        }
        const after = await state(ctx);
        expect(after.proofs).toEqual([]);
        expect(after.users[0]).toEqual(original.users[0]);
        expect(after.accounts[0]).toEqual(original.accounts[0]);
        expect(after.wallets[0]).toEqual(original.wallets[0]);
        expect(after.sessions[0]).toEqual(original.sessions[0]);
        if (rejected) {
          expect(after.users).toEqual(before.users);
          expect(after.accounts).toEqual(before.accounts);
          expect(after.wallets).toEqual(before.wallets);
          expect(after.sessions).toEqual(before.sessions);
          expect(after.inputs).toEqual(before.inputs);
        } else {
          expect(after.inputs).toHaveLength(before.inputs.length + 1);
          expect(after.inputs.at(-1)?.message).toBe(signed);
          expect(after.inputs.at(-1)?.signature).toBe(signature(signed));
          expect(after.sessions).toHaveLength(before.sessions.length + 1);
        }
        const replay = await verify(actor, signed);
        expect(replay.error).toMatchObject({
          status: 401,
          code: "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE",
        });
        expect(await state(ctx)).toEqual(after);
        observations.push({
          field,
          date,
          position,
          before,
          result: ctx.snapshot(result),
          session,
          after,
          replay: ctx.snapshot(replay),
        });
      }
    return {
      foreignResult: ctx.snapshot(foreignResult),
      foreignSession: ctx.snapshot(foreignSession),
      original,
      observations,
    };
  },
  ["POST /siwe/nonce", "POST /siwe/verify"],
);
