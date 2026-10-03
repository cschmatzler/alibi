import { expect, test } from "bun:test";
import { createHash } from "node:crypto";

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

const authPath = "/__test/profiles/org-member-addition/api/auth";
const root = "/__test/organization-member-addition";
const secret = "compat-test-only-key-not-real-minimum-32chars";
type SessionContext = {
  session: {
    id: string;
    token: string;
    userId: string;
    activeOrganizationId?: string | null;
    createdAt: string;
    expiresAt: string;
    updatedAt: string;
  };
  user: { id: string };
};
type AdditionState = {
  receipts: [
    { phase: string; user: { id: string }; organization: { id: string } },
    { phase: string; context: { session: SessionContext } },
    { phase: string },
  ];
};

async function capture(delay: number) {
  const fixture = await startFixture({
    directory: `/tmp/better-auth-363-clock-${crypto.randomUUID()}`,
    runId: crypto.randomUUID(),
    role: "source",
    inventoryPath: "/tmp/better-auth-363-unused-inventory.json",
  });
  try {
    const traces: TraceEntry[] = [];
    const startedAt = Date.now();
    // Real request pacing makes scenario-relative dates differ; no SQL or
    // recorded request clocks are rewritten to manufacture the regression.
    await Bun.sleep(delay);
    async function actor(name: string) {
      const transport = createTracingFetch(fixture.url, name, traces, authPath);
      const client = createAuthClient({
        baseURL: fixture.url,
        fetchOptions: { customFetchImpl: transport },
      });
      const signup = await client.signUp.email({
        name,
        email: `${name}@addition-clock.local`,
        password: "password123",
      });
      expect(signup.error).toBeNull();
      return { client, transport, user: signup.data!.user };
    }
    const owner = await actor("owner");
    const target = await actor("target");
    const foreign = await actor("foreign");
    async function organization(actor: typeof owner, name: string) {
      const created = await actor.client.$fetch<{ id: string }>("/organization/create", {
        method: "POST",
        body: { name, slug: name },
      });
      expect(created.error).toBeNull();
      return created.data!;
    }
    const org = await organization(owner, "target-org");
    await organization(foreign, "foreign-org");
    const team = await owner.client.$fetch<{ id: string }>("/organization/create-team", {
      method: "POST",
      body: { organizationId: org.id, name: "target-team" },
    });
    expect(team.error).toBeNull();
    const siblingTransport = createTracingFetch(fixture.url, "foreign-sibling", traces, authPath);
    const siblingClient = createAuthClient({
      baseURL: fixture.url,
      fetchOptions: { customFetchImpl: siblingTransport },
    });
    expect(
      (
        await siblingClient.signIn.email({
          email: "foreign@addition-clock.local",
          password: "password123",
        })
      ).error,
    ).toBeNull();
    const selected = await foreign.client.getSession();
    const sibling = await siblingClient.getSession();
    expect(selected.error).toBeNull();
    expect(sibling.error).toBeNull();
    expect(selected.data!.session.token).not.toBe(sibling.data!.session.token);
    const physical = await readUserState(fixture.url, { userId: foreign.user.id });
    const physicalObservations: PhysicalObservation[] = [
      {
        kind: "session",
        owner: foreign.user.id,
        body: structuredClone(physical),
        digest: createHash("sha256").update(JSON.stringify(physical)).digest("hex"),
      },
    ];
    async function control(path: string, body?: unknown) {
      const response = await foreign.transport(
        `${fixture.url}${root}/${path}`,
        body
          ? {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify(body),
            }
          : {},
      );
      expect(response.status).toBe(200);
      return response.json();
    }
    await control("configure", { mode: "record" });
    await control("server", {
      profile: "org-member-addition-team-callback",
      useHeaders: true,
      body: {
        organizationId: org.id,
        userId: target.user.id,
        role: "member",
        teamId: team.data!.id,
      },
    });
    const state = (await control("state")) as AdditionState;
    expect(state.receipts.map((receipt: { phase: string }) => receipt.phase)).toEqual([
      "before-add",
      "team-limit",
      "after-add",
    ]);
    expect(state.receipts[1].context.session).toEqual(
      normalizeClientValue(selected.data) as SessionContext,
    );
    return {
      baseURL: fixture.url,
      startedAt,
      finishedAt: Date.now(),
      physicalObservations,
      windows: traces.map((trace) => trace[requestWindow]),
      value: {
        observation: {
          selected: normalizeClientValue(selected.data) as SessionContext,
          sibling: normalizeClientValue(sibling.data) as SessionContext,
          state,
          physical,
        },
        traces,
      },
    };
  } finally {
    await fixture.stop();
  }
}

test("actual organization callback clocks require the exact signed session and authenticated organization write", async () => {
  const left = await capture(0);
  const right = await capture(2200);
  const context = {
    leftBaseURL: left.baseURL,
    rightBaseURL: right.baseURL,
    leftStartedAt: left.startedAt,
    rightStartedAt: right.startedAt,
    leftFinishedAt: left.finishedAt,
    rightFinishedAt: right.finishedAt,
    leftRequestWindows: left.windows,
    rightRequestWindows: right.windows,
    leftPhysicalObservations: left.physicalObservations,
    rightPhysicalObservations: right.physicalObservations,
    sessionCookieSecret: secret,
  } satisfies ComparisonContext;
  expect(
    Math.abs(
      Date.parse(left.value.observation.selected.session.updatedAt) -
        left.startedAt -
        (Date.parse(right.value.observation.selected.session.updatedAt) - right.startedAt),
    ),
  ).toBeGreaterThan(1500);
  expect(compareValues(left.value, right.value, context)).toEqual([]);

  for (const mutation of [
    "token",
    "user",
    "organization",
    "sibling",
    "foreign",
    "updatedAt",
    "createdAt",
    "expiresAt",
    "create-cookie",
    "read-cookie",
    "create-owner",
    "missing-create",
  ]) {
    const altered = structuredClone(right.value);
    const clocks = structuredClone(context);
    const selected = altered.observation.selected;
    const read = altered.traces.findLastIndex(
      (trace) => trace.actor === "foreign" && trace.path === `${authPath}/get-session`,
    );
    const create = altered.traces.findLastIndex(
      (trace) => trace.actor === "foreign" && trace.path === `${authPath}/organization/create`,
    );
    if (mutation === "token") selected.session.token = "unissued-token";
    if (mutation === "user") selected.session.userId = "unissued-user";
    if (mutation === "organization") {
      selected.session.activeOrganizationId = altered.observation.state.receipts[0].organization.id;
    }
    if (mutation === "sibling") {
      selected.session = structuredClone(altered.observation.sibling.session);
    }
    if (mutation === "foreign") {
      selected.session.userId = altered.observation.state.receipts[0].user.id;
      selected.user = structuredClone(altered.observation.state.receipts[0].user);
    }
    if (mutation === "updatedAt" || mutation === "createdAt" || mutation === "expiresAt") {
      selected.session[mutation] = new Date(
        Date.parse(selected.session[mutation]) + 60000,
      ).toISOString();
    }
    // Alter the public row and its callback copy coherently; the unchanged
    // signed issuer and write receipts must independently reject the forgery.
    altered.traces[read]!.responseBody = structuredClone(selected);
    altered.observation.state.receipts[1].context.session = structuredClone(selected);
    if (mutation === "create-cookie") {
      clocks.rightRequestWindows![create]!.sessionCookie =
        clocks.rightRequestWindows![read]!.sessionCookie + "invalid";
    }
    if (mutation === "read-cookie") clocks.rightRequestWindows![read]!.sessionCookie += "invalid";
    if (mutation === "create-owner") {
      (
        altered.traces[create]!.responseBody as { members: { userId: string }[] }
      ).members[0]!.userId = "unrelated-user";
    }
    if (mutation === "missing-create") altered.traces[create]!.responseStatus = 403;
    const differences = compareValues(left.value, altered, clocks);
    expect(
      differences.some(
        (difference) =>
          difference.path === "observation.state.receipts.1.context.session.session.updatedAt",
      ),
      mutation,
    ).toBe(true);
  }
}, 60_000);
