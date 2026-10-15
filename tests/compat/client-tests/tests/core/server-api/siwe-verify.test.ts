import { expect } from "vitest";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import { message, signature, EOA } from "../../../support/siwe-wallet";
import { stateSchema } from "../../plugins/siwe/helpers";

compatScenario(
  "server verifySiweMessage requires the original request and publishes a usable single-use session",
  async (ctx) => {
    const actor = ctx.actor("siwe-server", "siwe");
    const issued = await ctx.rawRequest({
      path: "/__test/server-api/siwe-nonce",
      method: "POST",
      json: { operation: "getSiweNonce" },
    });
    expect(issued.status).toBe(200);
    const signed = message((issued.body as { nonce: string }).nonce);
    const input = { message: signed, signature: signature(signed) };
    async function invoke(body?: unknown, physicalRequest = false) {
      const response = await actor.fetch(ctx.baseURL + "/__test/server-api/siwe-verify", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "user-agent": "siwe-server-sdk",
          "x-forwarded-for": "198.51.100.19",
        },
        body: JSON.stringify({ ...(body === undefined ? {} : { body }), physicalRequest }),
      });
      return { response, status: response.status, body: await response.json() };
    }
    async function state() {
      return stateSchema.parse((await ctx.rawRequest({ path: "/__test/siwe-state" })).body);
    }
    const before = await state();
    const denied = [];
    for (const body of [
      undefined,
      {},
      { message: "", signature: "" },
      { message: "m", signature: "s", extra: true },
      input,
    ]) {
      const result = await invoke(body);
      expect(result.status).toBe(400);
      expect(result.body.code).toBe("VALIDATION_ERROR");
      expect(result.response.headers.getSetCookie()).toEqual([]);
      denied.push({ status: result.status, body: result.body });
    }
    expect(await state()).toEqual(before);
    const accepted = await invoke(input, true);
    expect(accepted.status).toBe(200);
    expect(accepted.body).toMatchObject({
      success: true,
      user: { walletAddress: EOA, chainId: 1 },
    });
    const cookies = accepted.response.headers.getSetCookie();
    expect(cookies.some((cookie) => cookie.startsWith("better-auth.session_token="))).toBe(true);
    const cookie = cookies.map((raw) => raw.split(";")[0]).join("; ");
    const sessionResponse = await actor.fetch(
      ctx.baseURL + authProfilePath("siwe") + "/get-session",
      { headers: { cookie } },
    );
    expect(sessionResponse.status).toBe(200);
    const session = await sessionResponse.json();
    expect(session.user.id).toBe(accepted.body.user.id);
    expect(session.session.token).toBe(accepted.body.token);
    const after = await state();
    expect(after.users).toHaveLength(1);
    expect(after.accounts).toHaveLength(1);
    expect(after.wallets).toHaveLength(1);
    expect(after.sessions).toHaveLength(1);
    expect(after.proofs).toEqual([]);
    expect(after.sessions[0]).toMatchObject({
      userId: accepted.body.user.id,
      ipAddress: "198.51.100.19",
      userAgent: "siwe-server-sdk",
    });
    const replay = await invoke(input, true);
    expect(replay.status).toBe(401);
    expect(replay.body.code).toBe("UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE");
    expect(replay.response.headers.getSetCookie()).toEqual([]);
    expect(await state()).toEqual(after);
    const freshNonce = await ctx.rawRequest({
      path: "/__test/server-api/siwe-nonce",
      method: "POST",
      json: { operation: "getSiweNonce" },
    });
    expect(freshNonce.status).toBe(200);
    const wrongSignerMessage = message((freshNonce.body as { nonce: string }).nonce);
    const rejected = await invoke(
      { message: wrongSignerMessage, signature: signature(wrongSignerMessage, 2) },
      true,
    );
    expect(rejected.status).toBe(401);
    expect(rejected.body).toEqual({ message: "Unauthorized: Invalid SIWE signature", status: 401 });
    expect(rejected.response.headers.getSetCookie()).toEqual([]);
    const unchanged = await state();
    expect(unchanged.proofs).toEqual([]);
    expect(unchanged.users).toEqual(after.users);
    expect(unchanged.wallets).toEqual(after.wallets);
    expect(unchanged.accounts).toEqual(after.accounts);
    expect(unchanged.sessions).toEqual(after.sessions);
    expect(unchanged.inputs).toHaveLength(after.inputs.length + 1);
    return ctx.snapshot({
      issued,
      freshNonce,
      rejected: { status: rejected.status, body: rejected.body },
      unchanged,
      before,
      denied,
      accepted: { status: accepted.status, body: accepted.body },
      session,
      after,
      replay: { status: replay.status, body: replay.body },
    });
  },
);
