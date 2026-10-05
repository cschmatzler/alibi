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

type State = {
  user: { id: string };
  sessions: { id: string; token: string; userId: string; expiresAt: string }[];
};

async function capture(role: string, delay: number, method: "email" | "username") {
  const authPath = method === "email" ? "/__test/profiles/dispatch-default/api/auth" : "/api/auth";
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
      ...(method === "username" ? { username: "clock_owner" } : {}),
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
    const loginField = method === "email" ? "email" : "username";
    const loginValue = method === "email" ? "owner@physical-clock.local" : "clock_owner";
    const formats =
      method === "username"
        ? [["application/json", JSON.stringify({ username: loginValue, password: "password123" })]]
        : [
            [
              "multipart/form-dataapplication/json; boundary=clock-boundary",
              `--clock-boundary\r\nContent-Disposition: form-data; name="${loginField}"\r\n\r\n${loginValue}\r\n--clock-boundary\r\nContent-Disposition: form-data; name="password"\r\n\r\npassword123\r\n--clock-boundary--\r\n`,
            ],
            [
              "application/x-www-form-urlencoded",
              new URLSearchParams({
                [loginField]: loginValue,
                password: "password123",
              }).toString(),
            ],
          ];
    for (const [contentType, body] of formats) {
      const response = await transport(`${fixture.url}${authPath}/sign-in/${method}`, {
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
      // Exclude the later public read from the username comparison so issuer
      // negative controls cannot borrow a separate, valid read-clock receipt.
      value: {
        observation: {
          states,
          ...(method === "email" ? { session: normalizeClientValue(session) } : {}),
        },
        traces: method === "email" ? traces : traces.slice(0, -1),
      },
    };
  } finally {
    await fixture.stop();
  }
}

for (const method of ["email", "username"] as const) {
  test(`actual Source ${method} physical expiry requires its signed seven-day issuer and immutable SQL observations`, async () => {
    const left = await capture("source-left", 0, method);
    const leftIssueOffset =
      Date.parse(left.value.observation.states.at(-1)!.sessions[1]!.expiresAt) -
      604800000 -
      left.startedAt;
    const right = await capture("source-right", 2200 + Math.max(0, leftIssueOffset), method);
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
          (diff) =>
            diff.path === `observation.states.${method === "email" ? 2 : 1}.sessions.1.expiresAt`,
        ),
      ).toBe(true);
    }
  }, 30_000);
}

const discordPath = "/__test/profiles/social-discord-default/api/auth";
type SocialState = {
  users: Record<string, unknown>[];
  accounts: Record<string, unknown>[];
  sessions: Record<string, unknown>[];
  receipts: unknown[];
};

async function captureDiscord(role: string, delay: number) {
  const directory = `/tmp/better-auth-social-clock-${crypto.randomUUID()}`;
  const fixture = await startFixture({
    directory,
    runId: crypto.randomUUID(),
    role,
    inventoryPath: `${directory}/unused-inventory.json`,
  });
  try {
    const traces: TraceEntry[] = [];
    const transport = createTracingFetch(fixture.url, "control", traces, discordPath);
    const startedAt = Date.now();
    const foreignTransport = createTracingFetch(fixture.url, "foreign", traces, discordPath);
    const foreign = createAuthClient({
      baseURL: fixture.url,
      fetchOptions: { customFetchImpl: foreignTransport },
    });
    const signup = await foreign.signUp.email({
      email: "foreign@social-clock.local",
      name: "Foreign Owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    const foreignBefore = await readUserState(fixture.url, { userId: signup.data!.user.id });
    const observe = async () =>
      (await (await transport("/__test/social-provider/state")).json()) as SocialState;
    const before = await observe();
    const results = [];
    await Bun.sleep(delay);
    for (const [index, subject] of ["4194304", "8388608"].entries()) {
      const profile = {
        id: subject,
        email: `provider-${index}@social-clock.local`,
        username: `Provider ${index}`,
        global_name: `Global ${index}`,
        avatar: "fixture",
        discriminator: "0",
        verified: true,
      };
      const control = await transport("/__test/social-provider/profile", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(profile),
      });
      expect(control.status).toBe(200);
      expect(await control.json()).toEqual({ status: true, profile });
      const actorFetch = createTracingFetch(fixture.url, `owner-${index}`, traces, discordPath);
      const client = createAuthClient({
        baseURL: fixture.url,
        fetchOptions: { customFetchImpl: actorFetch },
      });
      const signin = await client.signIn.social({
        provider: "discord",
        callbackURL: fixture.url + "/done",
        disableRedirect: true,
      });
      expect(signin.error).toBeNull();
      const state = new URL(signin.data!.url!).searchParams.get("state")!;
      expect(state).toBeTruthy();
      const callbackURL = `${fixture.url}${discordPath}/callback/discord?${new URLSearchParams({ code: "fixture-code", state })}`;
      const callback = await actorFetch(callbackURL, { redirect: "manual" });
      expect(callback.status).toBe(302);
      expect(callback.headers.get("location")).toBe(fixture.url + "/done");
      const producerIndex = traces.length - 1;
      const current = await client.getSession();
      expect(current.error).toBeNull();
      expect(current.data!.user.email).toBe(profile.email);
      const after = await observe();
      const session = after.sessions.find((row) => row.token === current.data!.session.token)!;
      const account = after.accounts.find((row) => row.userId === current.data!.user.id)!;
      expect(session.userId).toBe(current.data!.user.id);
      expect(account).toMatchObject({
        providerId: "discord",
        accountId: subject,
        accessToken: "fixture-discord-access",
      });
      const window = traces[producerIndex]![requestWindow]!;
      const signed = decodeURIComponent(window.issuedSessionCookie!.split("=").slice(1).join("="));
      expect(signed).toBe(
        `${session.token}.${createHmac("sha256", secret).update(String(session.token)).digest("base64")}`,
      );
      for (const [row, field, lifetime] of [
        [account, "accessTokenExpiresAt", 3600000],
        [session, "expiresAt", 604800000],
      ] as const) {
        const clock = Date.parse(String(row[field])) - lifetime;
        expect(clock).toBeGreaterThanOrEqual(window.startedAt);
        expect(clock).toBeLessThanOrEqual(window.finishedAt);
      }
      expect(await readUserState(fixture.url, { userId: signup.data!.user.id })).toEqual(
        foreignBefore,
      );
      const ownedBefore = await readUserState(fixture.url, { userId: current.data!.user.id });
      const failed = await actorFetch(callbackURL, { redirect: "manual" });
      const failedIndex = traces.length - 1;
      expect(failed.status).toBe(302);
      expect(failed.headers.get("location")).toContain("error=state_mismatch");
      expect(traces[failedIndex]![requestWindow]!.issuedSessionCookie).toBeUndefined();
      expect(await readUserState(fixture.url, { userId: current.data!.user.id })).toEqual(
        ownedBefore,
      );
      results.push({
        profile,
        current: normalizeClientValue(current),
        after,
        producerIndex,
        failedIndex,
      });
    }
    return {
      baseURL: fixture.url,
      startedAt,
      finishedAt: Date.now(),
      windows: traces.map((trace) => trace[requestWindow]),
      value: { observation: { before, results }, traces },
    };
  } finally {
    await fixture.stop();
  }
}

test("actual Source Discord callback clocks require signed issuance public session and raw subject-bound SQL controls", async () => {
  const left = await captureDiscord("source-left", 0);
  const offset =
    Date.parse(String(left.value.observation.results.at(-1)!.after.accounts.at(-1)!.createdAt)) -
    left.startedAt;
  const right = await captureDiscord("source-right", 2200 + Math.max(0, offset));
  const context = {
    leftBaseURL: left.baseURL,
    rightBaseURL: right.baseURL,
    leftStartedAt: left.startedAt,
    rightStartedAt: right.startedAt,
    leftFinishedAt: left.finishedAt,
    rightFinishedAt: right.finishedAt,
    leftRequestWindows: left.windows,
    rightRequestWindows: right.windows,
    sessionCookieSecret: secret,
  } satisfies ComparisonContext;
  const relativeCreated = (capture: Awaited<ReturnType<typeof captureDiscord>>) =>
    Date.parse(String(capture.value.observation.results.at(-1)!.after.accounts.at(-1)!.createdAt)) -
    capture.startedAt;
  expect(relativeCreated(right) - relativeCreated(left)).toBeGreaterThan(1500);
  expect(compareValues(left.value, right.value, context)).toEqual([]);

  for (const change of [
    "wrong-expiry",
    "foreign-owner",
    "wrong-token",
    "wrong-session-token",
    "wrong-subject",
    "control-receipt",
    "failed-callback",
    "tampered-profile",
    "invalid-signature",
    "missing-session-read",
    "foreign-profile",
    "provider-receipt",
    "callback-window",
  ]) {
    const altered = structuredClone(right.value);
    const clocks = structuredClone(context);
    const result = altered.observation.results.at(-1)!;
    const producerIndex = result.producerIndex;
    const observerIndex = producerIndex + 2;
    const control = clocks.rightRequestWindows[observerIndex]!.controlObservation!;
    const row = result.after.accounts.at(-1)!;
    if (change === "wrong-expiry") {
      row.accessTokenExpiresAt = new Date(
        Date.parse(String(row.accessTokenExpiresAt)) + 60000,
      ).toISOString();
    }
    if (change === "foreign-owner") row.userId = result.after.users[0]!.id;
    if (change === "wrong-token") row.accessToken = "undeclared-provider-token";
    if (change === "wrong-subject") row.accountId = "foreign-provider-subject";
    if (change === "wrong-session-token") result.after.sessions.at(-1)!.token = "unissued-token";
    if (change === "provider-receipt") {
      (result.after.receipts.at(-1) as { authorization: string }).authorization =
        "Bearer foreign-token";
    }
    if (
      [
        "wrong-expiry",
        "foreign-owner",
        "wrong-token",
        "wrong-subject",
        "wrong-session-token",
        "provider-receipt",
      ].includes(change)
    ) {
      control.body = structuredClone(result.after);
      control.digest = createHash("sha256").update(JSON.stringify(control.body)).digest("hex");
    }
    if (change === "control-receipt") control.digest = "invalid";
    if (change === "failed-callback") {
      altered.traces[producerIndex] = structuredClone(altered.traces[result.failedIndex]!);
      clocks.rightRequestWindows[producerIndex] = structuredClone(
        clocks.rightRequestWindows[result.failedIndex],
      );
    }
    if (change === "tampered-profile") {
      (clocks.rightRequestWindows[producerIndex - 2]!.verificationInput as { id: string }).id =
        "unobserved-subject";
    }
    if (change === "invalid-signature") {
      clocks.rightRequestWindows[producerIndex]!.issuedSessionCookie += "invalid";
    }
    if (change === "missing-session-read") {
      altered.traces[producerIndex + 1]!.responseStatus = 401;
    }
    if (change === "foreign-profile") {
      altered.traces[producerIndex]!.path = altered.traces[producerIndex]!.path.replace(
        "social-discord-default",
        "social-discord-configured",
      );
    }
    if (change === "callback-window") {
      clocks.rightRequestWindows[producerIndex]!.startedAt += 60000;
      clocks.rightRequestWindows[producerIndex]!.finishedAt += 60000;
    }
    expect(
      compareValues(left.value, altered, clocks).some(
        (difference) =>
          difference.path === "observation.results.1.after.accounts.2.accessTokenExpiresAt",
      ),
    ).toBe(true);
  }
}, 45_000);
