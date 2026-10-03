import { expect, test } from "bun:test";
import { createHash, createHmac } from "node:crypto";

import { createAuthClient } from "better-auth/client";

import { startFixture } from "../support/assurance/processes";
import {
  compareValues,
  type ComparisonContext,
  type PhysicalObservation,
} from "../support/compare";
import { readUserState } from "../support/controls";
import { normalizeClientValue } from "../support/normalize";
import { createTracingFetch, requestWindow, type TraceEntry } from "../support/trace";

const secret = "compat-test-only-key-not-real-minimum-32chars";
const authPath = "/__test/profiles/dispatch-default/api/auth";
type State = {
  user: { id: string };
  sessions: { id: string; token: string; userId: string; expiresAt: string }[];
};

async function capture(role: string, delay: number) {
  const fixture = await startFixture({
    directory: `/tmp/better-auth-physical-clock-${crypto.randomUUID()}`,
    runId: crypto.randomUUID(),
    role,
    inventoryPath: "/tmp/better-auth-physical-clock-unused-inventory.json",
  });
  try {
    const traces: TraceEntry[] = [];
    const transport = createTracingFetch(fixture.url, "owner", traces, authPath);
    const client = createAuthClient({
      baseURL: fixture.url,
      fetchOptions: { customFetchImpl: transport },
    });
    const startedAt = Date.now();
    const signup = await client.signUp.email({
      name: "Owner",
      email: "owner@physical-clock.local",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    const observations: PhysicalObservation[] = [];
    const states: State[] = [];
    async function observe() {
      const state = (await readUserState(fixture.url, { userId: signup.data!.user.id })) as State;
      const body = structuredClone(state);
      observations.push({
        kind: "session",
        owner: state.user.id,
        body,
        digest: createHash("sha256").update(JSON.stringify(body)).digest("hex"),
      });
      states.push(state);
      return state;
    }
    await observe();
    // Delay the genuine request, rather than changing its clock or SQL values.
    await Bun.sleep(delay);
    for (const [contentType, body] of [
      [
        "multipart/form-dataapplication/json; boundary=clock-boundary",
        '--clock-boundary\r\nContent-Disposition: form-data; name="email"\r\n\r\nowner@physical-clock.local\r\n--clock-boundary\r\nContent-Disposition: form-data; name="password"\r\n\r\npassword123\r\n--clock-boundary--\r\n',
      ],
      [
        "application/x-www-form-urlencoded",
        new URLSearchParams({
          email: "owner@physical-clock.local",
          password: "password123",
        }).toString(),
      ],
    ]) {
      const response = await transport(`${fixture.url}${authPath}/sign-in/email`, {
        method: "POST",
        headers: { "content-type": contentType! },
        body,
      });
      expect(response.status).toBe(200);
      const result = (await response.json()) as { token: string; user: { id: string } };
      const trace = traces.at(-1)!;
      const window = trace[requestWindow]!;
      const signed = decodeURIComponent(
        window.issuedSessionCookie!.split(";")[0]!.split("=").slice(1).join("="),
      );
      expect(signed).toBe(
        `${result.token}.${createHmac("sha256", secret).update(result.token).digest("base64")}`,
      );
      const state = await observe();
      const row = state.sessions.find((session) => session.token === result.token)!;
      expect(row.userId).toBe(result.user.id);
      expect(row).not.toHaveProperty("createdAt");
      const issued = Date.parse(row.expiresAt) - 604800000;
      expect(issued).toBeGreaterThanOrEqual(window.startedAt);
      expect(issued).toBeLessThanOrEqual(window.finishedAt);
    }
    const session = await client.getSession();
    expect(session.error).toBeNull();
    expect(session.data!.session.token).toBe(states.at(-1)!.sessions.at(-1)!.token);
    return {
      baseURL: fixture.url,
      startedAt,
      finishedAt: Date.now(),
      observations,
      windows: traces.map((trace) => trace[requestWindow]),
      value: { observation: { states, session: normalizeClientValue(session) }, traces },
    };
  } finally {
    await fixture.stop();
  }
}

test("actual Source dispatch physical expiry requires its signed seven-day issuer and immutable SQL observations", async () => {
  const left = await capture("source-left", 0);
  const leftIssueOffset =
    Date.parse(left.value.observation.states.at(-1)!.sessions[1]!.expiresAt) -
    604800000 -
    left.startedAt;
  const right = await capture("source-right", 2200 + Math.max(0, leftIssueOffset));
  const context = {
    leftBaseURL: left.baseURL,
    rightBaseURL: right.baseURL,
    leftStartedAt: left.startedAt,
    rightStartedAt: right.startedAt,
    leftFinishedAt: left.finishedAt,
    rightFinishedAt: right.finishedAt,
    leftRequestWindows: left.windows,
    rightRequestWindows: right.windows,
    leftPhysicalObservations: left.observations,
    rightPhysicalObservations: right.observations,
    sessionCookieSecret: secret,
  } satisfies ComparisonContext;
  const relativeExpiry = (captured: Awaited<ReturnType<typeof capture>>) =>
    Date.parse(captured.value.observation.states.at(-1)!.sessions[1]!.expiresAt) -
    captured.startedAt;
  expect(Math.abs(relativeExpiry(right) - relativeExpiry(left))).toBeGreaterThan(1500);
  expect(compareValues(left.value, right.value, context)).toEqual([]);

  for (const change of [
    "wrong-lifetime",
    "foreign-token",
    "foreign-owner",
    "invalid-signature",
    "foreign-profile",
    "missing-observation",
    "tampered-observation",
  ]) {
    const altered = structuredClone(right.value);
    const clocks = {
      ...structuredClone(context),
      rightPhysicalObservations: context.rightPhysicalObservations.map((observation) => ({
        ...structuredClone(observation),
      })),
    };
    const row = altered.observation.states.at(-1)!.sessions[1]!;
    if (change === "wrong-lifetime") {
      row.expiresAt = new Date(Date.parse(row.expiresAt) + 60000).toISOString();
    }
    if (change === "foreign-token") {
      row.token = "unissued-token";
    }
    if (change === "foreign-owner") {
      row.userId = "foreign-owner";
    }
    if (change === "invalid-signature") {
      clocks.rightRequestWindows![1]!.issuedSessionCookie += "invalid";
    }
    if (change === "foreign-profile") {
      altered.traces[1]!.path = "/__test/profiles/foreign/api/auth/sign-in/email";
    }
    if (change === "missing-observation") {
      clocks.rightPhysicalObservations = [];
    }
    if (change === "tampered-observation") {
      for (const observation of clocks.rightPhysicalObservations!) {
        observation.digest = "invalid";
      }
    }
    // Coherent SQL counterfactuals still need the genuine issuer, owner and lifetime.
    if (["wrong-lifetime", "foreign-token", "foreign-owner"].includes(change)) {
      const body = structuredClone(altered.observation.states.at(-1)!);
      clocks.rightPhysicalObservations = [
        {
          kind: "session",
          owner: body.user.id,
          body,
          digest: createHash("sha256").update(JSON.stringify(body)).digest("hex"),
        },
      ];
    }
    expect(
      compareValues(left.value, altered, clocks).some(
        (diff) => diff.path === "observation.states.2.sessions.1.expiresAt",
      ),
    ).toBe(true);
  }
}, 30_000);
