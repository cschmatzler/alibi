import { expect, test } from "bun:test";
import { createHash } from "node:crypto";

import { createAuthClient } from "better-auth/client";
import { jwtClient } from "better-auth/client/plugins";
import { importJWK, jwtVerify, type JWK } from "jose";

import { startFixture } from "../support/assurance/processes";
import { compareValues, type ComparisonContext } from "../support/compare";
import { normalizeClientValue } from "../support/normalize";
import { createTracingFetch, requestWindow, type TraceEntry } from "../support/trace";

type Key = {
  id: string;
  publicKey: JWK;
  createdAt: string;
  expiresAt: string | null;
  alg: string | null;
};
type State = { keys: Key[]; events: { operation: string; key?: Omit<Key, "id"> }[] };

async function capture(role: string, delay: number, profile: string) {
  const authPath = `/__test/profiles/${profile}/api/auth`;
  const fixture = await startFixture({
    directory: `/tmp/better-auth-keyring-clock-${crypto.randomUUID()}`,
    runId: crypto.randomUUID(),
    role,
    inventoryPath: "/tmp/better-auth-keyring-clock-unused-inventory.json",
  });
  try {
    const traces: TraceEntry[] = [];
    const transport = createTracingFetch(fixture.url, "owner", traces, authPath);
    const client = createAuthClient({
      baseURL: fixture.url,
      plugins: [jwtClient()],
      fetchOptions: {
        customFetchImpl: transport,
        headers: { "x-keyring-proof": "application-marker" },
      },
    });
    async function control(operation: string, id?: string, failure?: unknown) {
      const response = await transport(`${fixture.url}/__test/jwt-keyring`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          profile,
          operation,
          ...(id ? { id } : {}),
          ...(failure !== undefined ? { failure } : {}),
        }),
      });
      expect(response.status).toBe(200);
      return (await response.json()) as State;
    }
    await control("reset");
    const signup = await client.signUp.email({
      name: "Key Owner",
      email: "owner@keyring-clock.local",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    const initial = await client.jwks();
    expect(initial.error).toBeNull();
    for (const key of (await control("state")).keys) {
      await control("delete", key.id);
    }
    await control("clear-events");
    const startedAt = Date.now();
    // Force different actual issuance offsets without changing Source, its clocks or stored data.
    await Bun.sleep(delay);
    await control("failure", undefined, { operation: "create", kind: "api500" });
    const rejected = await client.jwks();
    expect(rejected.error).toMatchObject({ status: 500, code: "APPLICATION_KEYRING_DENIED" });
    const rejectedState = await control("state");
    expect(rejectedState.keys).toEqual([]);
    expect(rejectedState.events.filter((event) => event.operation === "create")).toHaveLength(1);
    await control("failure", undefined, null);
    await control("clear-events");
    const recovered = await client.jwks();
    expect(recovered.error).toBeNull();
    const recoveredState = await control("state");
    expect(recoveredState.keys).toHaveLength(1);
    const row = recoveredState.keys[0]!;
    const producer = traces.findLast((trace) => trace.path === `${authPath}/jwks`)![requestWindow]!;
    expect(Date.parse(row.createdAt)).toBeGreaterThanOrEqual(producer.startedAt);
    expect(Date.parse(row.createdAt)).toBeLessThanOrEqual(producer.finishedAt);
    if (profile === "jwt-keyring-plain") {
      // Source reads createdAt and expiresAt from separate clock calls.
      expect(Date.parse(row.expiresAt!) - 3600000).toBeGreaterThanOrEqual(producer.startedAt);
      expect(Date.parse(row.expiresAt!) - 3600000).toBeLessThanOrEqual(producer.finishedAt);
    } else {
      expect(row.expiresAt).toBeNull();
    }
    const published = recovered.data!.keys.find((key) => key.kid === row.id)! as JWK;
    expect(published.n).toBe(row.publicKey.n);
    expect(published.e).toBe(row.publicKey.e);
    const signed = await client.token();
    expect(signed.error).toBeNull();
    const checked = await jwtVerify(
      signed.data!.token,
      await importJWK(published, profile === "jwt-keyring-plain" ? "RS256" : "EdDSA"),
      {
        algorithms: [profile === "jwt-keyring-plain" ? "RS256" : "EdDSA"],
        issuer: fixture.url,
        audience: fixture.url,
      },
    );
    expect(checked.protectedHeader.kid).toBe(row.id);
    const legacy = await control("legacy", row.id);
    const legacyState = await control("state");
    expect(legacyState.keys[0]!.createdAt).toBe(row.createdAt);
    expect(legacyState.keys[0]!.expiresAt).toBe(row.expiresAt);
    expect(legacyState.keys[0]!.alg).toBeNull();
    return {
      baseURL: fixture.url,
      startedAt,
      finishedAt: Date.now(),
      windows: traces.map((trace) => trace[requestWindow]),
      value: {
        observation: {
          recoveredState,
          rejected: normalizeClientValue(rejected),
          rejectedState,
          legacy,
          legacyState,
          recovered: normalizeClientValue(recovered),
          signed: normalizeClientValue(signed),
        },
        traces,
      },
    };
  } finally {
    await fixture.stop();
  }
}

for (const profile of [
  "jwt-keyring-plain",
  "jwt-keyring-standard",
  "jwt-keyring-empty-subject",
  "jwt-keyring-null-subject",
]) {
  test(`actual Source ${profile} recovery binds raw key and event clocks to signed public publication and exact lifetime`, async () => {
    const authPath = `/__test/profiles/${profile}/api/auth`;
    const left = await capture("source-left", 0, profile);
    const leftOffset =
      Date.parse(left.value.observation.recoveredState.keys[0]!.createdAt) - left.startedAt;
    const right = await capture("source-right", 2300 + Math.max(0, leftOffset), profile);
    const context = {
      leftBaseURL: left.baseURL,
      rightBaseURL: right.baseURL,
      leftStartedAt: left.startedAt,
      rightStartedAt: right.startedAt,
      leftFinishedAt: left.finishedAt,
      rightFinishedAt: right.finishedAt,
      leftRequestWindows: left.windows,
      rightRequestWindows: right.windows,
    } satisfies ComparisonContext;
    expect(
      Math.abs(
        Date.parse(right.value.observation.recoveredState.keys[0]!.createdAt) -
          right.startedAt -
          leftOffset,
      ),
    ).toBeGreaterThan(1500);
    expect(compareValues(left.value, right.value, context)).toEqual([]);

    for (const change of [
      "failed-route",
      "failed-status",
      "failed-profile",
      "failed-operation",
      "missing-failed-control",
      "tampered-failed-control",
      "failed-clock-window",
    ]) {
      const altered = structuredClone(right.value);
      const clocks = structuredClone(context);
      const failed = altered.traces.find(
        (trace) => trace.path === `${authPath}/jwks` && trace.responseStatus === 500,
      )!;
      const failedIndex = altered.traces.indexOf(failed);
      if (change === "failed-route") failed.path = "/__test/profiles/foreign/api/auth/jwks";
      if (change === "failed-status") failed.responseStatus = 200;
      if (change === "failed-clock-window") {
        clocks.rightRequestWindows![failedIndex]!.startedAt += 60000;
        clocks.rightRequestWindows![failedIndex]!.finishedAt += 60000;
      }
      for (const window of clocks.rightRequestWindows!) {
        const receipt = window?.controlObservation;
        const body = receipt?.body as State | undefined;
        if (
          !body?.events?.some(
            (event) =>
              event.operation === "create" &&
              event.key?.createdAt ===
                right.value.observation.rejectedState.events.find(
                  (event) => event.operation === "create",
                )!.key!.createdAt,
          )
        ) {
          continue;
        }
        if (change === "missing-failed-control") delete window!.controlObservation;
        if (change === "tampered-failed-control") receipt!.digest = "invalid";
        if (change === "failed-profile" || change === "failed-operation") {
          const event = body.events.find((event) => event.operation === "create")! as Record<
            string,
            unknown
          >;
          event[change === "failed-profile" ? "profile" : "operation"] = "foreign";
          receipt!.digest = createHash("sha256").update(JSON.stringify(body)).digest("hex");
        }
      }
      expect(
        compareValues(left.value, altered, clocks).some(
          (difference) =>
            difference.path.startsWith("observation.rejectedState.events.") &&
            difference.path.endsWith(".key.createdAt"),
        ),
      ).toBe(true);
    }

    for (const change of [
      "wrong-deadline",
      "foreign-kid",
      "foreign-material",
      "wrong-algorithm",
      "failed-publication",
      "missing-control",
      "tampered-control",
      "foreign-profile",
      "foreign-control-profile",
      "foreign-control-operation",
      "invalid-signature",
      "legacy-copy",
    ]) {
      const altered = structuredClone(right.value);
      const clocks = structuredClone(context);
      const publicTrace = altered.traces.findLast((trace) => trace.path === `${authPath}/jwks`)!;
      const row = altered.observation.recoveredState.keys[0]!;
      if (change === "wrong-deadline") {
        const old = row.expiresAt;
        const replacement = new Date((old ? Date.parse(old) : Date.now()) + 60000).toISOString();
        function corrupt(value: unknown) {
          if (Array.isArray(value)) {
            value.forEach(corrupt);
          } else if (value && typeof value === "object") {
            for (const [key, child] of Object.entries(value)) {
              if (key === "expiresAt" && child === old) {
                (value as Record<string, unknown>)[key] = replacement;
              } else {
                corrupt(child);
              }
            }
          }
        }
        corrupt(altered);
        clocks.rightRequestWindows!.forEach((window) => {
          if (window?.controlObservation) {
            corrupt(window.controlObservation.body);
            window.controlObservation.digest = createHash("sha256")
              .update(JSON.stringify(window.controlObservation.body))
              .digest("hex");
          }
        });
      }
      const body = publicTrace.responseBody as { keys: JWK[] };
      if (change === "foreign-kid") {
        body.keys[0]!.kid = "unpublished-key";
      }
      if (change === "foreign-material") {
        if (profile === "jwt-keyring-plain") body.keys[0]!.n = "foreign-material";
        else body.keys[0]!.x = "foreign-material";
      }
      if (change === "wrong-algorithm") {
        body.keys[0]!.alg = "HS256";
      }
      if (change === "failed-publication") {
        publicTrace.responseStatus = 500;
      }
      if (change === "foreign-profile") {
        publicTrace.path = "/__test/profiles/foreign/api/auth/jwks";
      }
      if (change === "foreign-control-profile") {
        clocks.rightRequestWindows!.forEach((window) => {
          if (window?.jwtKeyringInput) {
            window.jwtKeyringInput.profile = "foreign";
          }
        });
      }
      if (change === "foreign-control-operation") {
        clocks.rightRequestWindows!.forEach((window) => {
          if (window?.jwtKeyringInput) {
            window.jwtKeyringInput.operation = "create";
          }
        });
      }
      if (change === "invalid-signature") {
        const trace = altered.traces.find((entry) => entry.path === `${authPath}/token`)!;
        const token = trace.responseBody as { token: string };
        token.token = `${token.token.slice(0, -8)}invalidx`;
      }
      if (change === "missing-control") {
        clocks.rightRequestWindows!.forEach((window) => {
          if (window) {
            delete window.controlObservation;
          }
        });
      }
      if (change === "tampered-control") {
        clocks.rightRequestWindows!.forEach((window) => {
          if (window?.controlObservation) {
            window.controlObservation.digest = "invalid";
          }
        });
      }
      if (change === "legacy-copy") {
        altered.observation.legacyState.keys[0]!.createdAt = new Date(
          Date.parse(row.createdAt) + 1,
        ).toISOString();
      }
      const expected =
        change === "legacy-copy"
          ? "observation.legacyState.keys.0.createdAt"
          : profile === "jwt-keyring-plain" || change === "wrong-deadline"
            ? "observation.recoveredState.keys.0.expiresAt"
            : "observation.recoveredState.keys.0.createdAt";
      expect(
        compareValues(left.value, altered, clocks).some(
          (difference) => difference.path === expected,
        ),
      ).toBe(true);
    }
  }, 30_000);
}
