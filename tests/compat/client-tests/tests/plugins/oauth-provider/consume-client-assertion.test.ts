import { expect } from "bun:test";
import { createHash } from "node:crypto";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "The exported assertion consumer checks claims and namespaces durable replay identifiers",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: object) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "assertion-helper", ...input }),
      });
    const audience = "https://resource.fixture.test/token";
    const now = Math.floor(Date.now() / 1000);
    const cases: [string, string, unknown, string?][] = [
      ["audience", "aud", "other", "client assertion aud does not match the endpoint"],
      ["missing-exp", "exp", undefined, "client assertion must include exp claim"],
      ["expired", "exp", now - 60, "client assertion has expired"],
      ["long-exp", "exp", now + 600, "client assertion exp is too far in the future (max 300s)"],
      ["old-iat", "iat", now - 600, "client assertion iat is too far in the past (max 300s)"],
      ["missing-jti", "jti", undefined, "client assertion must include jti claim"],
      ["empty-jti", "jti", "", "client assertion must include jti claim"],
      ["ignored-iat-type", "iat", "old"],
      ["future-iat", "iat", now + 600],
      ["mixed-audiences", "aud", [false, audience]],
      ["whitespace-jti", "jti", " \t "],
    ];
    const results = [];
    for (const [name, field, value, detail] of cases) {
      const namespace = `extension:${name}`;
      const original = { aud: audience, exp: now + 90, iat: now, jti: "proof" };
      const payload: any = { ...original };
      if (value === undefined) {
        delete payload[field];
      } else {
        payload[field] = value;
      }
      const response = await control({
        action: "consume-assertion",
        params: { namespace, payload, expectedAudience: audience },
      });
      expect(response.status, name).toBe(detail ? 400 : 200);
      const body = await response.json();
      expect(body).toEqual(
        detail ? { error: "invalid_client", error_description: detail } : { consumed: true },
      );
      if (detail) {
        const retry = await control({
          mode: "assertion-helper-peer",
          action: "consume-assertion",
          params: { namespace, payload: original, expectedAudience: audience },
        });
        expect(retry.status, `${name} must not consume jti`).toBe(200);
        expect(await retry.json()).toEqual({ consumed: true });
      }
      results.push({ name, status: response.status, body });
    }
    const payload = { aud: audience, exp: now + 90, iat: now, jti: "shared" };
    const receipts = [];
    for (const namespace of ["extension:client", "other-method:client", "extension:other-client"]) {
      const response = await control({
        action: "consume-assertion",
        params: { namespace, payload, expectedAudience: audience },
      });
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ consumed: true });
      const id = createHash("sha256")
        .update(`${namespace}:shared`)
        .digest()
        .subarray(0, 24)
        .toString("base64url");
      const rowResponse = await control({ action: "assertion-row", id });
      expect(rowResponse.status).toBe(200);
      const row = (await rowResponse.json()) as any;
      expect(row.id).toBe(id);
      expect(id.length).toBe(32);
      expect(Date.parse(row.expiresAt) / 1000).toBe(now + 90);
      receipts.push({ namespace, id, lifetime: Date.parse(row.expiresAt) / 1000 - now });
    }
    const replay = await control({
      mode: "assertion-helper-peer",
      action: "consume-assertion",
      params: { namespace: "extension:client", payload, expectedAudience: audience },
    });
    expect(replay.status).toBe(400);
    const replayBody = await replay.json();
    expect(replayBody).toEqual({
      error: "invalid_client",
      error_description: "client assertion jti has already been used",
    });
    return ctx.snapshot({ results, receipts, replay: { status: replay.status, body: replayBody } });
  },
);
