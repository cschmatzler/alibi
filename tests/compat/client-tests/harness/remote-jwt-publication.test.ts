import { expect, test } from "bun:test";
import { createHash } from "node:crypto";

import { betterAuth, type BetterAuthOptions } from "better-auth";
import { jwt, signJWT } from "better-auth/plugins/jwt";
import { compactVerify, CompactSign } from "jose";

import { compareValues, type ComparisonContext } from "../support/compare";
import { createTracingFetch, requestWindow, type TraceEntry } from "../support/trace";

type Row = Record<string, any>;
const secret = "remote-jwt-application-secret-minimum-32-characters";
const key = new TextEncoder().encode(secret);
const clone = <T>(value: T): T => structuredClone(value);
function refresh(windows: any[]) {
  for (const window of windows) {
    if (window?.remoteJwtSigning) {
      const receipt = window.remoteJwtSigning;
      receipt.digest = createHash("sha256")
        .update(JSON.stringify([receipt.input, receipt.response]))
        .digest("hex");
    }
    if (window?.remoteJwtObserver) {
      const receipt = window.remoteJwtObserver;
      receipt.digest = createHash("sha256").update(JSON.stringify(receipt.body)).digest("hex");
    }
  }
}

async function source(delay: boolean) {
  const events: Row[] = [];
  const options: Parameters<typeof jwt>[0] = {
    jwks: {
      remoteUrl: "https://keys.fixture.test/remote-jwks",
      keyPairConfig: { alg: "EdDSA", crv: "Ed25519" },
    },
    jwt: {
      issuer: "remote-application-issuer",
      audience: "remote-application-audience",
      async sign(payload, header, overrides) {
        events.push({
          payload: clone(payload),
          ownKeys: Object.keys(payload),
          header: clone(header),
          options: clone(overrides),
        });
        return new CompactSign(new TextEncoder().encode(JSON.stringify(payload)))
          .setProtectedHeader({ ...header, alg: "HS256", kid: "application-remote-key" })
          .sign(key);
      },
    },
  };
  let auth: ReturnType<typeof betterAuth>;
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      const body = request.method === "POST" ? await request.clone().json() : undefined;
      if (delay && body?.operation === "sign") {
        await Bun.sleep(1010 - (Date.now() % 1000));
      }
      if (request.method === "GET") return Response.json({ events });
      const token = await signJWT({ context: await auth.$context } as any, {
        options,
        payload: body.payload,
        header: body.header,
        signingKeyId: body.signingKeyId,
        signingAlgorithm: body.signingAlgorithm,
      });
      return Response.json({ token });
    },
  });
  const baseURL = `http://127.0.0.1:${server.port}`;
  const authOptions: BetterAuthOptions = {
    baseURL,
    secret: "actual-remote-jwt-harness-secret-at-least-32-characters",
    plugins: [jwt(options)],
    rateLimit: { enabled: false },
  };
  auth = betterAuth(authOptions);
  const traces: TraceEntry[] = [];
  const fetch = createTracingFetch(baseURL, "signer", traces, "/api/auth");
  const startedAt = Date.now();
  try {
    const input = {
      operation: "sign",
      profile: "jwt-remote-raw",
      payload: { exp: null, iat: null, nbf: null, iss: null, aud: null, sub: null, jti: null },
      nanFields: [],
      header: { typ: "application+jwt", custom: "retained" },
      signingKeyId: "application-selected-key",
      signingAlgorithm: "ES256",
    };
    const response = await fetch(baseURL + "/__test/jwt-remote", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(input),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { token: string };
    const verified = await compactVerify(body.token, key, { algorithms: ["HS256"] });
    const payload = JSON.parse(new TextDecoder().decode(verified.payload));
    const captured = await (await fetch(baseURL + "/__test/jwt-remote")).json();
    expect(captured.events).toHaveLength(1);
    expect(captured.events[0].payload).toEqual(payload);
    expect(payload.iat).toBeNull();
    expect(payload.exp).toBeNumber();
    const window = traces[0]![requestWindow]!;
    expect(payload.exp).toBeGreaterThanOrEqual(Math.floor(window.startedAt / 1000) + 900);
    expect(payload.exp).toBeLessThanOrEqual(Math.floor(window.finishedAt / 1000) + 900);
    return {
      baseURL,
      startedAt,
      finishedAt: Date.now(),
      windows: traces.map((trace) => trace[requestWindow]),
      root: {
        observation: {
          response: { status: 200, body },
          verified: { token: body.token, header: verified.protectedHeader, payload },
          captured,
        },
        traces,
      },
    };
  } finally {
    server.stop(true);
  }
}

async function reissue(
  root: Row,
  windows: any[],
  patch: Row,
  signingSecret = secret,
  headerPatch: Row = {},
) {
  const original = root.observation.verified;
  const payload = { ...original.payload, ...patch };
  const header = { ...original.header, ...headerPatch };
  const token = await new CompactSign(new TextEncoder().encode(JSON.stringify(payload)))
    .setProtectedHeader(header)
    .sign(new TextEncoder().encode(signingSecret));
  root.observation.response.body.token = token;
  root.observation.verified = { token, header, payload };
  root.observation.captured.events[0].payload = payload;
  if (windows[0]?.remoteJwtSigning) {
    windows[0].remoteJwtSigning.response = { token };
  }
  if (windows[1]?.remoteJwtObserver) {
    windows[1].remoteJwtObserver.body = clone(root.observation.captured);
  }
  refresh(windows);
}

test("actual Source remote signer null defaults bind signed publication exact callback and request clocks while caller claims stay literal", async () => {
  const left = await source(false);
  const right = await source(true);
  expect(right.root.observation.verified.payload.exp).toBeGreaterThan(
    left.root.observation.verified.payload.exp,
  );
  const context: ComparisonContext = {
    leftBaseURL: left.baseURL,
    rightBaseURL: right.baseURL,
    leftStartedAt: left.startedAt,
    rightStartedAt: right.startedAt,
    leftFinishedAt: left.finishedAt,
    rightFinishedAt: right.finishedAt,
    leftRequestWindows: left.windows,
    rightRequestWindows: right.windows,
    remoteJwtSignerSecret: secret,
  };
  const before = compareValues(left.root, right.root, {
    ...context,
    remoteJwtSignerSecret: undefined,
  });
  for (const path of [
    "observation.captured.events.0.payload.exp",
    "observation.response.body.token.payload.exp",
    "observation.verified.payload.exp",
    "observation.verified.token.payload.exp",
  ]) {
    expect(before.some((difference) => difference.path === path)).toBe(true);
  }
  expect(compareValues(left.root, right.root, context)).toEqual([]);

  const rejects = (root: Row, windows = right.windows, extra: Partial<ComparisonContext> = {}) => {
    expect(
      compareValues(left.root, root, { ...context, rightRequestWindows: windows, ...extra }),
    ).toContainEqual({
      path: "observation",
      reason:
        "remote JWT default expiry lacks its original signed publication, request or exact callback proof",
    });
  };
  for (const exp of [
    right.root.observation.verified.payload.exp + 1,
    right.root.observation.verified.payload.exp + 1800,
  ]) {
    const root = clone(right.root);
    const windows = clone(right.windows);
    await reissue(root, windows, { exp });
    rejects(root, windows);
  }
  for (const field of ["iat", "exp", "profile"]) {
    const windows = clone(right.windows);
    const receipt = windows[0]?.remoteJwtSigning as { input: Row } | undefined;
    if (receipt) {
      if (field === "profile") receipt.input.profile = "jwt-remote-configured";
      else {
        receipt.input.payload[field] =
          field === "iat" ? 100 : right.root.observation.verified.payload.exp;
      }
    }
    refresh(windows);
    rejects(right.root, windows);
  }
  const copied = clone(right.root);
  copied.observation.verified.payload.exp += 1;
  rejects(copied);
  const alteredCallback = clone(right.root);
  alteredCallback.observation.captured.events[0].payload.iat = 100;
  rejects(alteredCallback);
  for (const [signingSecret, header] of [
    ["foreign-remote-signing-key-at-least-32-characters", {}],
    [secret, { kid: "foreign-key" }],
    [secret, { custom: "foreign-header" }],
  ] as const) {
    const root = clone(right.root);
    const windows = clone(right.windows);
    await reissue(root, windows, {}, signingSecret, header);
    rejects(root, windows);
  }
  rejects(right.root, right.windows, { remoteJwtSignerSecret: "foreign-expected-key" });
  rejects(right.root, []);
  const unrelated: Row = clone(right.root);
  unrelated.observation.applicationData = clone(right.root.observation.verified.payload);
  const peer: Row = clone(left.root);
  peer.observation.applicationData = clone(left.root.observation.verified.payload);
  expect(
    compareValues(peer, unrelated, context).some(
      (difference) => difference.path === "observation.applicationData.exp",
    ),
  ).toBe(true);
});
