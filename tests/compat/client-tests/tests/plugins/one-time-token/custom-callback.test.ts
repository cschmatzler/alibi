import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { oneTimeTokenClient } from "better-auth/client/plugins";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "OTT custom callbacks preserve context, failure transport and pending session ownership",
  async (ctx) => {
    const profile = "ott-custom-callback";
    const owner = ctx.actor("callback-owner", profile);
    const consumer = ctx.actor("callback-consumer", profile);
    const client = createAuthClient({
      baseURL: ctx.baseURL,
      plugins: [oneTimeTokenClient()],
      fetchOptions: { customFetchImpl: owner.fetch },
    });
    async function control(operation: string, mode?: string) {
      const response = await owner.fetch(`${ctx.baseURL}/__test/one-time-token`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ operation, profile, mode }),
      });
      expect(response.status).toBe(200);
      return response.json();
    }
    await control("callbacks", "success");
    const signup = await client.signUp.email({
      email: ctx.uniqueEmail("ott-callback"),
      password: "password123",
      name: "OTT callback owner",
    });
    expect(signup.error).toBeNull();
    const original = await client.getSession();
    if (!original.data) throw new Error("missing original session");
    const identifier = "one-time-token:digest-ott-custom-token";
    const before = await ctx.readUserState({ userId: original.data.user.id });
    const observations: unknown[] = [];
    const ordinaryBodies: string[] = [];
    for (const stage of ["generate", "hash"]) {
      for (const kind of ["ordinary", "veto"]) {
        const mode = `${stage}-${kind}`;
        await control("callbacks", mode);
        // Exercise the official client as well as its actual response transport.
        let rawBody = "";
        const rejected = await client.oneTimeToken.generate({
          fetchOptions: {
            headers: { "x-ott-marker": "callback-http" },
            onResponse: async ({ response }) => {
              rawBody = await response.clone().text();
            },
          },
        });
        expect(rejected.error?.status).toBe(kind === "ordinary" ? 500 : 403);
        if (kind === "ordinary") ordinaryBodies.push(rawBody);
        else {
          expect(JSON.parse(rawBody)).toEqual({ code: "OTT_VETO", message: "OTT callback veto" });
        }
        const receipt = await control("callbacks");
        expect(receipt.events.map((event: { stage: string }) => event.stage)).toEqual(
          stage === "generate" ? ["generate"] : ["generate", "hash"],
        );
        expect(receipt.events[0]).toMatchObject({
          userId: original.data.user.id,
          session: {
            id: original.data.session.id,
            userId: original.data.user.id,
            token: original.data.session.token,
            expiresAt: original.data.session.expiresAt.toISOString(),
          },
          request: { path: "/one-time-token/generate", method: "GET", marker: "callback-http" },
        });
        const pending = await ctx.readVerificationState({ identifier });
        expect(pending).toEqual([]);
        observations.push({ mode, rejected: ctx.snapshot(rejected), rawBody, receipt, pending });
        await control("callbacks", mode);
        const server = await control("generate-endpoint");
        expect(server).toEqual(
          kind === "ordinary"
            ? { status: 500, ordinary: true, message: null }
            : { status: 403, ordinary: false, message: "OTT callback veto" },
        );
        const serverReceipt = await control("callbacks");
        expect(serverReceipt.events[0].request).toBeNull();
        expect(serverReceipt.events[0].session).toMatchObject({
          id: original.data.session.id,
          token: original.data.session.token,
          expiresAt: original.data.session.expiresAt.toISOString(),
        });
        expect(await ctx.readVerificationState({ identifier })).toEqual([]);
        observations.push({ server, serverReceipt });
      }
    }
    await control("callbacks", "success");
    const serverGenerated = await control("generate-endpoint");
    expect(serverGenerated).toEqual({ token: "ott-custom-server-token" });
    const serverReceipt = await control("callbacks");
    expect(serverReceipt.events.map((event: { stage: string }) => event.stage)).toEqual([
      "generate",
      "hash",
    ]);
    expect(serverReceipt.events[0].request).toBeNull();
    const serverIdentifier = "one-time-token:digest-ott-custom-server-token";
    const serverPending = await ctx.readVerificationState({ identifier: serverIdentifier });
    expect(serverPending).toMatchObject([{ value: original.data.session.token }]);
    const serverConsumed = await client.oneTimeToken.verify({ token: serverGenerated.token });
    expect(serverConsumed.data?.session).toEqual(original.data.session);
    expect(await ctx.readVerificationState({ identifier: serverIdentifier })).toEqual([]);
    observations.push({
      serverGenerated,
      serverReceipt,
      serverPending,
      serverConsumed: ctx.snapshot(serverConsumed),
    });
    const generated = await client.oneTimeToken.generate();
    expect(generated.data?.token).toBe("ott-custom-token");
    const pending = await ctx.readVerificationState({ identifier });
    expect(pending).toMatchObject([{ identifier, value: original.data.session.token }]);
    for (const kind of ["ordinary", "veto"]) {
      await control("callbacks", `hash-${kind}`);
      const response = await consumer.fetch(
        `${ctx.baseURL}/__test/profiles/${profile}/api/auth/one-time-token/verify`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ token: "ott-custom-token" }),
        },
      );
      const rawBody = await response.text();
      expect(response.status).toBe(kind === "ordinary" ? 500 : 403);
      expect(response.headers.get("set-cookie")).toBeNull();
      if (kind === "ordinary") ordinaryBodies.push(rawBody);
      else expect(JSON.parse(rawBody)).toEqual({ code: "OTT_VETO", message: "OTT callback veto" });
      const retained = await ctx.readVerificationState({ identifier });
      expect(retained).toEqual(pending);
      const receipt = await control("callbacks");
      expect(receipt.events).toEqual([{ stage: "hash", token: "ott-custom-token" }]);
      observations.push({ kind, status: response.status, rawBody, retained, receipt });
    }
    await control("callbacks", "success");
    const consumerClient = createAuthClient({
      baseURL: ctx.baseURL,
      plugins: [oneTimeTokenClient()],
      fetchOptions: { customFetchImpl: consumer.fetch },
    });
    const verified = await consumerClient.oneTimeToken.verify({ token: "ott-custom-token" });
    expect(verified.error).toBeNull();
    expect(verified.data?.session).toEqual(original.data.session);
    expect(verified.data?.user.id).toBe(original.data.user.id);
    expect(await ctx.readVerificationState({ identifier })).toEqual([]);
    const replay = await consumerClient.oneTimeToken.verify({ token: "ott-custom-token" });
    expect(replay.error).toMatchObject({ status: 400, message: "Invalid token" });
    const after = await ctx.readUserState({ userId: original.data.user.id });
    expect(after).toEqual(before);
    const result = {
      original: ctx.snapshot(original),
      observations,
      pending,
      verified: ctx.snapshot(verified),
      replay: ctx.snapshot(replay),
      before,
      after,
    };
    if (process.env.OTT210_PROOF_DIR) {
      await Bun.write(
        `${process.env.OTT210_PROOF_DIR}/${new URL(ctx.baseURL).port}.json`,
        JSON.stringify(result, null, 2),
      );
    }
    expect(ordinaryBodies).toEqual(["", "", ""]);
    return result;
  },
  ["GET /one-time-token/generate", "POST /one-time-token/verify"],
);
