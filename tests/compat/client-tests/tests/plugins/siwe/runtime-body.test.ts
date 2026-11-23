import { createAuthClient } from "better-auth/client";
import { siweClient } from "better-auth/client/plugins";
import { expect, test } from "vitest";

import { writeArtifact } from "../../../../support/files.ts";
import { RUST_BASE_URL, requireHealthy, TS_BASE_URL } from "../../../support/config";
import { resetServerState } from "../../../support/controls";
import { message, SECOND_EOA, signature } from "../../../support/siwe-wallet";
import { createTracingFetch, requestWindow, type TraceEntry } from "../../../support/trace";
import { identity, stateSchema } from "./helpers";

test("SIWE opaque runtime bodies reject before verification and preserve the same signed nonce and foreign wallet", async () => {
  const observations = [];
  for (const [runtime, baseURL] of [
    ["Source", TS_BASE_URL],
    ["Native", RUST_BASE_URL],
  ] as const) {
    await requireHealthy(baseURL, runtime);
    await resetServerState(baseURL);
    const traces: TraceEntry[] = [];
    const fetcher = createTracingFetch(
      baseURL,
      "runtime-owner",
      traces,
      "/__test/profiles/siwe/api/auth",
    );
    const client = createAuthClient({
      baseURL,
      plugins: [siweClient()],
      fetchOptions: { customFetchImpl: fetcher },
    });
    const physical = async () => {
      const response = await fetch(`${baseURL}/__test/siwe-state`);
      expect(response.status).toBe(200);
      return stateSchema.parse(await response.json());
    };
    const firstNonce = await client.siwe.nonce();
    expect(firstNonce.error).toBeNull();

    const foreignMessage = message(firstNonce.data!.nonce, { address: SECOND_EOA });
    const foreign = await client.siwe.verify({
      message: foreignMessage,
      signature: signature(foreignMessage, 2),
    });
    expect(foreign.error).toBeNull();

    const foreignIdentity = identity.parse(foreign.data);
    const foreignSession = await client.getSession();
    expect(foreignSession.data?.session.token).toBe(foreignIdentity.token);

    const issued = await client.siwe.nonce();
    expect(issued.error).toBeNull();

    const signed = message(issued.data!.nonce);
    const before = await physical();
    const responses = [];
    for (const path of ["/siwe/nonce", "/siwe/get-nonce", "/siwe/verify"]) {
      for (const media of [
        "x-application/json",
        "application/streamapplication/json",
        "text/htmlapplication/json",
        "image/pngapplication/json",
        "application/pdfapplication/json",
        "video/webmapplication/json",
        "application/octet-streamapplication/json",
      ]) {
        const response = await fetcher(`${baseURL}/api/auth${path}`, {
          method: "POST",
          headers: { "content-type": media },
          body: JSON.stringify(
            path.endsWith("verify") ? { message: signed, signature: signature(signed) } : {},
          ),
        });
        expect(response.status, `${runtime}: ${path} with ${media}`).toBe(415);

        const body = await response.json();
        expect(body).toEqual({
          message: `Content-Type "${media}" is not allowed. Allowed types: application/json`,
          code: "UNSUPPORTED_MEDIA_TYPE",
        });

        const unchanged = await physical();
        expect(unchanged).toEqual(before);

        responses.push({
          path,
          media,
          status: response.status,
          headers: Object.fromEntries(response.headers),
          body,
          unchanged,
        });
      }
    }

    const pending = await physical();
    expect(pending).toEqual(before);

    const accepted = await client.siwe.verify({ message: signed, signature: signature(signed) });
    expect(accepted.error).toBeNull();

    const principal = identity.parse(accepted.data);
    const session = await client.getSession();
    expect(session.data?.session.token).toBe(principal.token);

    const after = await physical();
    expect(after.inputs).toHaveLength(2);
    expect(after.proofs).toHaveLength(0);
    expect(after.users[0]).toEqual(before.users[0]);
    expect(after.accounts[0]).toEqual(before.accounts[0]);
    expect(after.wallets[0]).toEqual(before.wallets[0]);
    expect(after.sessions[0]).toEqual(before.sessions[0]);

    const replay = await client.siwe.verify({ message: signed, signature: signature(signed) });
    expect(replay.error).toMatchObject({
      status: 401,
      code: "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE",
    });
    expect(await physical()).toEqual(after);

    observations.push({
      runtime,
      before,
      responses,
      pending,
      foreign,
      foreignSession,
      accepted,
      session,
      replay,
      after,
      traces: traces.map((trace) => ({ ...trace, requestWindow: trace[requestWindow] })),
    });
    await writeArtifact(
      new URL("../../../artifacts/siwe-runtime-body-observations.json", import.meta.url),
      JSON.stringify(observations, null, 2),
    );
  }
  await writeArtifact(
    new URL("../../../artifacts/siwe-runtime-body-observations.json", import.meta.url),
    JSON.stringify(observations, null, 2),
  );
});
