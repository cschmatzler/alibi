import { test } from "bun:test";
import { ZodError } from "zod";
import { authProfilePath, type FixtureProfile } from "./profiles";
import { recordCoverage } from "./coverage";
import { createHash } from "node:crypto";
import { compareValues, type PhysicalObservation, type Difference } from "./compare";
import { createAuthClient } from "better-auth/client";
import {
  usernameClient,
  adminClient,
  emailOTPClient,
  magicLinkClient,
} from "better-auth/client/plugins";

function configuredClient(
  baseURL: string,
  fetchImpl: (
    input: string | URL | Request,
    init?: RequestInit,
  ) => Promise<Response>,
) {
  return createAuthClient({
    baseURL,
    plugins: [
      usernameClient(),
      adminClient(),
      emailOTPClient(),
      magicLinkClient(),
    ],
    fetchOptions: { customFetchImpl: fetchImpl },
  });
}
import { RUST_BASE_URL, TS_BASE_URL, requireHealthy } from "./config";
import {
  type GitHubEmailRecord,
  readChangeEmailConfirmation,
  promoteAdmin,
  readTwoFactorOtp,
  readVerificationEmail,
  removeCredentialAccount,
  resetServerState,
  readDeviceState,
  expireDevice,
  readUserState,
  expireInvitation,
  readVerificationState,
  seedDeleteUserToken,
  seedOAuthAccount,
  setGitHubProfile,
  seedResetPasswordToken,
  setOAuthRefreshMode,
  setResetPasswordMode,
  setSocialProfile,
} from "./controls";
import { normalizeClientValue } from "./normalize";
import { createTracingFetch, requestWindow, type TraceEntry } from "./trace";
import {
  assuranceEvent,
  scenarioCoverage,
  setAssurancePhase,
  type ScenarioCoverage,
  type ScenarioOutcome,
} from "./assurance/evidence";

type ScenarioServerContext = {
  baseURL: string;
  actor(
    name?: string,
    profile?: FixtureProfile,
  ): {
    client: ReturnType<typeof configuredClient>;
    fetch(input: string | URL | Request, init?: RequestInit): Promise<Response>;
  };
  uniqueEmail(prefix: string): string;
  uniqueToken(prefix: string): string;
  snapshot<T>(value: T): unknown;
  /** Record complete transport observations from separately captured concurrent requests. */
  recordTransport(entries: readonly TraceEntry[]): void;
  rawRequest(args: {
    actor?: string;
    path: string;
    method?: string;
    body?: BodyInit;
    headers?: HeadersInit;
    json?: unknown;
    redirect?: RequestRedirect;
  }): Promise<{
    status: number;
    location: string | null;
    body: unknown;
  }>;
  expireInvitation(args: {
    invitationId: string;
    expiresAt: string;
  }): Promise<unknown>;
  readUserState(args: { userId: string }): Promise<unknown>;
  readDeviceState(args: { deviceCode: string }): Promise<unknown>;
  expireDevice(args: {
    deviceCode: string;
    expiresAt: string;
  }): Promise<unknown>;
  readVerificationState(args: { identifier: string }): Promise<unknown>;
  resetServerState(): Promise<unknown>;
  setResetPasswordMode(mode: "capture" | "throw"): Promise<unknown>;
  seedResetPasswordToken(args: {
    email: string;
    token: string;
    expiresAt: string;
  }): Promise<unknown>;
  setOAuthRefreshMode(mode: "success" | "error"): Promise<unknown>;
  setSocialProfile(args: {
    sub?: string;
    email?: string;
    name?: string;
    image?: string | null;
    emailVerified?: boolean;
    idTokenValid?: boolean;
  }): Promise<unknown>;
  setGitHubProfile(args: {
    id?: string;
    login?: string;
    name?: string | null;
    email?: string | null;
    avatarUrl?: string | null;
    emails?: GitHubEmailRecord[];
  }): Promise<unknown>;
  seedOAuthAccount(args: {
    email: string;
    providerId?: string;
    accountId?: string;
    accessToken?: string | null;
    refreshToken?: string | null;
    idToken?: string | null;
    accessTokenExpiresAt?: string | null;
    refreshTokenExpiresAt?: string | null;
    scope?: string | null;
  }): Promise<string>;
  readUserState(args: { userId: string }): Promise<unknown>;
  readVerificationEmail(args: { email: string }): Promise<unknown>;
  readTwoFactorOtp(args: { email: string }): Promise<unknown>;
  readChangeEmailConfirmation(args: { email: string }): Promise<unknown>;
  seedDeleteUserToken(args: {
    email: string;
    token: string;
    expiresAt: string;
  }): Promise<unknown>;
  removeCredentialAccount(args: { email: string }): Promise<unknown>;
  promoteAdmin(args: { email: string }): Promise<unknown>;
};

export type ScenarioContext = ScenarioServerContext;

type ScenarioRun = {
  oauthURL: string;
  startedAt: number;
  finishedAt: number;
  observation: unknown;
  traces: TraceEntry[];
  physicalObservations: PhysicalObservation[];
};

async function runScenario(
  label: "TS" | "Rust",
  baseURL: string,
  seed: string,
  scenario: (ctx: ScenarioServerContext) => Promise<unknown>,
  scenarioName: string,
  onCoverage: (coverage: ScenarioCoverage) => void,
): Promise<ScenarioRun> {
  setAssurancePhase(scenarioName, label);
  const health = await requireHealthy(baseURL, label);
  await resetServerState(baseURL);

  const startedAt = Date.now();
  const traces: TraceEntry[] = [];
  const physicalObservations: PhysicalObservation[] = [];
  async function physical(kind: PhysicalObservation["kind"], owner: string, read: Promise<unknown>) {
    const value = await read, body = structuredClone(value);
    physicalObservations.push({kind, owner, body, digest: createHash("sha256").update(JSON.stringify(body)).digest("hex")});
    return value;
  }
  const actors = new Map<
    string,
    {
      client: ReturnType<typeof configuredClient>;
      fetch(
        input: string | URL | Request,
        init?: RequestInit,
      ): Promise<Response>;
    }
  >();
  const shortSeed = seed.replace(/-/g, "").slice(0, 12);

  const context: ScenarioServerContext = {
    baseURL,
    actor(name = "primary", profile) {
      const actorKey = `${profile ?? "default"}:${name}`;
      const existing = actors.get(actorKey);
      if (existing) {
        return existing;
      }

      const authPath = profile ? authProfilePath(profile) : "/api/auth";
      const fetchImpl = createTracingFetch(baseURL, name, traces, authPath);
      const actor = {
        client: configuredClient(`${baseURL}${authPath}`, fetchImpl),
        fetch(input: string | URL | Request, init?: RequestInit) {
          return fetchImpl(input, init);
        },
      };
      actors.set(actorKey, actor);
      return actor;
    },
    uniqueEmail(prefix) {
      return `${prefix}-${shortSeed}@test.com`;
    },
    uniqueToken(prefix) {
      return `${prefix}-${shortSeed}`;
    },
    snapshot(value) {
      return normalizeClientValue(value);
    },
    async rawRequest({
      actor = "primary",
      path,
      method = "GET",
      body,
      headers,
      json,
      redirect,
    }) {
      const requestHeaders = new Headers(headers);
      let requestBody = body;
      if (json !== undefined) {
        requestHeaders.set("content-type", "application/json");
        requestBody = JSON.stringify(json);
      }

      const response = await context.actor(actor).fetch(path, {
        method,
        headers: requestHeaders,
        body: requestBody,
        redirect,
      });
      const text = await response.text();
      let parsed: unknown = null;
      if (text) {
        try {
          parsed = JSON.parse(text);
        } catch {
          parsed = text;
        }
      }
      return {
        status: response.status,
        location: response.headers.get("location"),
        body: parsed,
      };
    },
    recordTransport(entries) {
      traces.push(...entries);
    },
    readDeviceState(args) {
      return readDeviceState(baseURL, args);
    },
    expireDevice(args) {
      return expireDevice(baseURL, args);
    },
    readVerificationState(args) {
      return physical("verification", args.identifier, readVerificationState(baseURL, args));
    },
    resetServerState() {
      return resetServerState(baseURL);
    },
    setResetPasswordMode(mode) {
      return setResetPasswordMode(baseURL, mode);
    },
    seedResetPasswordToken(args) {
      return seedResetPasswordToken(baseURL, args);
    },
    setOAuthRefreshMode(mode) {
      return setOAuthRefreshMode(baseURL, mode);
    },
    setSocialProfile(args) {
      return setSocialProfile(baseURL, args);
    },
    setGitHubProfile(args) {
      return setGitHubProfile(baseURL, args);
    },
    seedOAuthAccount(args) {
      return seedOAuthAccount(baseURL, args);
    },
    readUserState(args) {
      return physical("session", args.userId, readUserState(baseURL, args));
    },
    expireInvitation(args) {
      return expireInvitation(baseURL, args);
    },
    readVerificationEmail(args) {
      return readVerificationEmail(baseURL, args);
    },
    readTwoFactorOtp(args) {
      return readTwoFactorOtp(baseURL, args);
    },
    readChangeEmailConfirmation(args) {
      return readChangeEmailConfirmation(baseURL, args);
    },
    seedDeleteUserToken(args) {
      return seedDeleteUserToken(baseURL, args);
    },
    removeCredentialAccount(args) {
      return removeCredentialAccount(baseURL, args);
    },
    promoteAdmin(args) {
      return promoteAdmin(baseURL, args);
    },
  };

  await scenarioCoverage("begin", label, scenarioName);
  try {
    return {
      oauthURL:
        health.oauthBaseURL ?? baseURL.replace("localhost", "127.0.0.1"),
      startedAt,
      observation: normalizeClientValue(await scenario(context)),
      finishedAt: Date.now(),
      traces,
      physicalObservations,
    };
  } finally {
    const coverage = await scenarioCoverage("end", label, scenarioName);
    if (coverage) onCoverage(coverage);
  }
}

function formatDiffs(title: string, differences: Difference[]) {
  return [
    title,
    ...differences.map((entry) => `- ${entry.path}: ${entry.reason}`),
  ].join("\n");
}

/** Split comparator output into client-visible and raw-transport drift. Every difference must land in exactly one bucket. */
export function classifyDifferences(
  differences: readonly Difference[],
) {
  const clientDiffs = differences.filter(
    (entry) =>
      entry.path === "observation" || entry.path.startsWith("observation."),
  );
  const rawDiffs = differences.filter(
    (entry) => entry.path === "traces" || entry.path.startsWith("traces."),
  );
  const unclassified = differences.filter(
    (entry) => !clientDiffs.includes(entry) && !rawDiffs.includes(entry),
  );
  return { clientDiffs, rawDiffs, unclassified };
}

export function compatScenario(
  scenarioName: string,
  scenario: (ctx: ScenarioServerContext) => Promise<unknown>,
  stateTransitions: readonly string[] = [],
  timeoutMs = 30_000,
  comparisonOptions: { readonly oauthProxyProfileSecret?: string } = {},
  reproduction?: unknown,
) {
  assuranceEvent({ event: "registered", name: scenarioName });
  test.serial(
    scenarioName,
    async () => {
      const seed = `${Date.now()}-${crypto.randomUUID()}`;
      const outcome: ScenarioOutcome = {
        name: scenarioName,
        status: "failed",
        coverage: {},
      };
      let phase: "TS" | "Rust" = "TS";
      let failure: ScenarioOutcome["failure"] = "scenario";
      assuranceEvent({ event: "started", name: scenarioName });
      try {
        const ts = await runScenario(
          "TS",
          TS_BASE_URL,
          seed,
          scenario,
          scenarioName,
          (coverage) => {
            outcome.coverage.TS = coverage;
          },
        );
        phase = "Rust";
        const rust = await runScenario(
          "Rust",
          RUST_BASE_URL,
          seed,
          scenario,
          scenarioName,
          (coverage) => {
            outcome.coverage.Rust = coverage;
          },
        );
        const comparison = {
          sessionCookieSecret:
            "compat-test-only-key-not-real-minimum-32chars",
          compactSessionCacheSecret:
            "compat-test-only-key-not-real-minimum-32chars",
          ...comparisonOptions,
          leftBaseURL: TS_BASE_URL,
          rightBaseURL: RUST_BASE_URL,
          leftStartedAt: ts.startedAt,
          rightStartedAt: rust.startedAt,
          leftFinishedAt: ts.finishedAt,
          rightFinishedAt: rust.finishedAt,
          leftPhysicalObservations: ts.physicalObservations,
          rightPhysicalObservations: rust.physicalObservations,
          leftRequestWindows: ts.traces.map((trace) => trace[requestWindow]),
          rightRequestWindows: rust.traces.map((trace) => trace[requestWindow]),
          leftOAuthURL: ts.oauthURL,
          rightOAuthURL: rust.oauthURL,
        };
        // Retain one identity graph across values and transport, and give the
        // trace shape markers their explicit scope when comparing type labels.
        const differences = compareValues(
          { observation: ts.observation, traces: ts.traces },
          { observation: rust.observation, traces: rust.traces },
          comparison,
        );
        const { clientDiffs, rawDiffs, unclassified } = classifyDifferences(differences);
        outcome.paths = differences.map((difference) => difference.path);
        failure = "comparison";
        if (unclassified.length)
          throw new Error(
            formatDiffs(
              `Comparator reported drift outside the observation and trace roots: ${scenarioName}`,
              unclassified,
            ),
          );
        if (clientDiffs.length)
          throw new Error(
            formatDiffs(`Client-visible drift: ${scenarioName}`, clientDiffs),
          );
        if (rawDiffs.length)
          throw new Error(
            formatDiffs(`Raw trace drift: ${scenarioName}`, rawDiffs),
          );
        failure = "infrastructure";
        await recordCoverage(
          scenarioName,
          ts.traces,
          stateTransitions,
          TS_BASE_URL,
        );
        outcome.status = "passed";
      } catch (error) {
        outcome.failure =
          failure === "comparison" || failure === "infrastructure"
            ? failure
            : error instanceof Error && error.name === "InvalidSequence"
              ? "invalid-sequence"
              : error instanceof Error && error.name === "ModelViolation"
                ? "model"
                : error instanceof Error &&
                    (/^expect\(/.test(error.message) ||
                      error.name === "ZodError")
                  ? "assertion"
                  : "scenario";
        outcome.phase = phase;
        outcome.signature = `${phase}:${outcome.failure}:${
          outcome.failure === "comparison"
            ? outcome.paths
                ?.map((path) => path.replace(/\.\d+(?=\.|$)/g, ".[]"))
                .sort()
                .join(",")
            : error instanceof Error
              ? error.message.split("\n")[0]
              : String(error)
        }`;
        if (outcome.failure === "assertion" && error instanceof Error)
          outcome.signature += `:${error.stack?.split("\n").find((line) => line.includes("/tests/") && !line.includes("/support/")) ?? "unknown-assertion-site"}`;
        if (error instanceof ZodError)
          outcome.signature = `${phase}:assertion:validation:${JSON.stringify(error.issues.map((issue) => ({ code: issue.code, path: issue.path })))}`;
        outcome.reproduction = reproduction;
        throw error;
      } finally {
        assuranceEvent({ event: "finished", ...outcome });
      }
    },
    timeoutMs,
  );
}
