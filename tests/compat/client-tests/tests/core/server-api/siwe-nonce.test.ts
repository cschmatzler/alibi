import { expect } from "vitest";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import { message } from "../../../support/siwe-wallet";
import { stateSchema } from "../../plugins/siwe/helpers";

compatScenario(
  "server SIWE nonce aliases validate before callbacks and persist consumable proofs",
  async (ctx) => {
    async function invoke(operation: string, body?: unknown) {
      return ctx.rawRequest({
        path: "/__test/server-api/siwe-nonce",
        method: "POST",
        json: { operation, ...(body === undefined ? {} : { body }) },
      });
    }
    async function state() {
      return stateSchema.parse((await ctx.rawRequest({ path: "/__test/siwe-state" })).body);
    }
    const before = await state();
    const denied = [];
    for (const operation of ["getSiweNonce", "getNonce"]) {
      for (const body of [
        null,
        [],
        false,
        { walletAddress: "ignored" },
        { "2": true, "1": false, ordinary: 1 },
      ]) {
        const result = await invoke(operation, body);
        expect(result.status).toBe(400);
        expect((result.body as { code: string }).code).toBe("VALIDATION_ERROR");
        denied.push(result);
      }
    }
    expect(await state()).toEqual(before);
    const issued = [];
    for (const [operation, body] of [
      ["getSiweNonce", undefined],
      ["getSiweNonce", {}],
      ["getNonce", undefined],
      ["getNonce", {}],
    ] as const) {
      const start = Date.now();
      const result = await invoke(operation, body);
      expect(result.status).toBe(200);
      const nonce = (result.body as { nonce: string }).nonce;
      expect(nonce).toBe(`SiweFixtureNonce${String(issued.length).padStart(16, "0")}`);
      const stored = await state();
      expect(stored.proofs).toHaveLength(1);
      expect(stored.proofs[0]).toMatchObject({ identifier: `siwe:${nonce}`, value: nonce });
      const expiresAt = Date.parse(stored.proofs[0]!.expiresAt);
      expect(expiresAt).toBeGreaterThanOrEqual(start + 899_000);
      expect(expiresAt).toBeLessThanOrEqual(Date.now() + 901_000);
      const consumed = await ctx.rawRequest({
        path: authProfilePath("siwe") + "/siwe/verify",
        method: "POST",
        json: { message: message(nonce, { domain: "wrong.example" }), signature: "unused" },
      });
      expect(consumed.status).toBe(401);
      expect((consumed.body as { code: string }).code).toBe("UNAUTHORIZED_SIWE_MESSAGE_MISMATCH");
      expect(await state()).toEqual(before);
      issued.push({ result, stored, consumed });
    }
    const invalidProviders = [];
    for (const nonce of ["short", "a".repeat(251), "invalid_nonce", "é".repeat(8)]) {
      const configured = await ctx.rawRequest({
        path: "/__test/siwe-control",
        method: "POST",
        json: { operation: "configure", nonce },
      });
      expect(configured.status).toBe(200);
      const result = await invoke("getSiweNonce");
      expect(result.status).toBe(500);
      expect(result.body).toEqual({
        message: "SIWE getNonce must return an ERC-4361 nonce: 8-250 alphanumeric characters.",
        status: 500,
        code: "SIWE_INVALID_NONCE",
      });
      expect(await state()).toEqual(before);
      invalidProviders.push(result);
    }
    return ctx.snapshot({ before, denied, issued, invalidProviders });
  },
);
