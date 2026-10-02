import { expect, test } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { siweClient } from "better-auth/client/plugins";

import { RUST_BASE_URL, requireHealthy, TS_BASE_URL } from "../../support/config";
import { resetServerState } from "../../support/controls";
import { message, SECOND_EOA, signature } from "../../support/siwe-wallet";
import { createTracingFetch, requestWindow, type TraceEntry } from "../../support/trace";
import { identity, stateSchema } from "./helpers";

// This owner intentionally asserts each runtime's literal opaque diagnostic:
// Bun's enumerable methods have no native transport-object representation.
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
    const streamKeys = [
      "locked",
      "cancel",
      "getReader",
      "pipeThrough",
      "pipeTo",
      "tee",
      "values",
      "blob",
      "bytes",
      "json",
      "text",
    ];
    const blobKeys = [
      "arrayBuffer",
      "bytes",
      "delete",
      "exists",
      "formData",
      "image",
      "json",
      "lastModified",
      "name",
      "size",
      "slice",
      "stat",
      "stream",
      "text",
      "type",
      "unlink",
      "write",
      "writer",
    ];

    for (const path of ["/siwe/nonce", "/siwe/get-nonce", "/siwe/verify"]) {
      for (const [media, kind] of [
        ["x-application/json", "ReadableStream"],
        ["application/streamapplication/json", "ReadableStream"],
        ["text/htmlapplication/json", "ReadableStream"],
        ["image/pngapplication/json", "Blob"],
        ["application/pdfapplication/json", "Blob"],
        ["video/webmapplication/json", "Blob"],
      ] as const) {
        const response = await fetcher(`${baseURL}/api/auth${path}`, {
          method: "POST",
          headers: { "content-type": media },
          body: JSON.stringify(
            path.endsWith("verify") ? { message: signed, signature: signature(signed) } : {},
          ),
        });
        expect(response.status).toBe(400);

        const body = await response.json();
        const keys = kind === "Blob" ? blobKeys : streamKeys;
        const missing = path.endsWith("verify")
          ? "[body.message] Invalid input: expected string, received undefined; [body.signature] Invalid input: expected string, received undefined; "
          : "";
        const expected =
          runtime === "Source"
            ? `${missing}[body] Unrecognized keys: ${keys.map((key) => JSON.stringify(key)).join(", ")}`
            : `[body] Invalid input: expected object, received ${kind}`;
        expect(body).toEqual({ message: expected, code: "VALIDATION_ERROR" });

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

    // ArrayBuffer has no enumerable schema fields: both nonce aliases accept it.
    const arrayNonces = [];

    for (const path of ["/siwe/nonce", "/siwe/get-nonce"]) {
      const response = await fetcher(`${baseURL}/api/auth${path}`, {
        method: "POST",
        headers: { "content-type": "application/octet-streamapplication/json" },
        body: "{broken-json",
      });
      expect(response.status).toBe(200);

      const body = (await response.json()) as { nonce: string };
      expect(typeof body.nonce).toBe("string");

      arrayNonces.push({ path, headers: Object.fromEntries(response.headers), body });
    }

    const pending = await physical();
    expect(pending.proofs).toHaveLength(3);
    expect(pending.users).toEqual(before.users);
    expect(pending.accounts).toEqual(before.accounts);
    expect(pending.wallets).toEqual(before.wallets);
    expect(pending.sessions).toEqual(before.sessions);
    expect(pending.inputs).toEqual(before.inputs);

    const accepted = await client.siwe.verify({ message: signed, signature: signature(signed) });
    expect(accepted.error).toBeNull();

    const principal = identity.parse(accepted.data);
    const session = await client.getSession();
    expect(session.data?.session.token).toBe(principal.token);

    const after = await physical();
    expect(after.inputs).toHaveLength(2);
    expect(after.proofs).toHaveLength(2);
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
      arrayNonces,
      pending,
      foreign,
      foreignSession,
      accepted,
      session,
      replay,
      after,
      traces: traces.map((trace) => ({ ...trace, requestWindow: trace[requestWindow] })),
    });
    await Bun.write(
      new URL("../../artifacts/siwe-runtime-body-observations.json", import.meta.url),
      JSON.stringify(observations, null, 2),
    );
  }
  await Bun.write(
    new URL("../../artifacts/siwe-runtime-body-observations.json", import.meta.url),
    JSON.stringify(observations, null, 2),
  );
});
