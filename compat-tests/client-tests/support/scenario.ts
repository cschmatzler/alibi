import { test } from "bun:test";
import { authProfilePath, type FixtureProfile } from "./profiles";
import { recordCoverage } from "./coverage";
import { compareValues, type Difference } from "./compare";
import { createAuthClient } from "better-auth/client";
import { authProfilePath, type FixtureProfile } from "./profiles";
import { usernameClient, adminClient, emailOTPClient, magicLinkClient } from "better-auth/client/plugins";

function configuredClient(baseURL: string, fetchImpl: (input: string | URL | Request, init?: RequestInit) => Promise<Response>) {
  return createAuthClient({ baseURL, plugins: [usernameClient(), adminClient(), emailOTPClient(), magicLinkClient()], fetchOptions: { customFetchImpl: fetchImpl } });
}
import { RAW_DIFF_ALLOWLIST } from "./allowlist";
import { RUST_BASE_URL, TS_BASE_URL, requireHealthy } from "./config";
import {
  type GitHubEmailRecord,
  readChangeEmailConfirmation,
  readUserState,
  promoteAdmin,
  readTwoFactorOtp,
  readVerificationEmail,
  removeCredentialAccount,
  resetServerState,
  seedDeleteUserToken,
  seedOAuthAccount,
  setGitHubProfile,
  seedResetPasswordToken,
  setOAuthRefreshMode,
  setResetPasswordMode,
  setSocialProfile,
} from "./controls";
import { normalizeClientValue } from "./normalize";
import { createTracingFetch, type TraceEntry } from "./trace";

type ScenarioServerContext = {
  baseURL: string;
  actor(name?: string, profile?: FixtureProfile): {
    client: ReturnType<typeof configuredClient>;
    fetch(input: string | URL | Request, init?: RequestInit): Promise<Response>;
  };
  uniqueEmail(prefix: string): string;
  uniqueToken(prefix: string): string;
  snapshot<T>(value: T): unknown;
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
  readVerificationEmail(args: {
    email: string;
  }): Promise<unknown>;
  readTwoFactorOtp(args: {
    email: string;
  }): Promise<unknown>;
  readChangeEmailConfirmation(args: {
    email: string;
  }): Promise<unknown>;
  seedDeleteUserToken(args: {
    email: string;
    token: string;
    expiresAt: string;
  }): Promise<unknown>;
  removeCredentialAccount(args: {
    email: string;
  }): Promise<unknown>;
  promoteAdmin(args: {
    email: string;
  }): Promise<unknown>;
};

type ScenarioRun = {
  oauthURL: string;
  startedAt: number;
  observation: unknown;
  traces: TraceEntry[];
};

async function runScenario(
  label: string,
  baseURL: string,
  seed: string,
  scenario: (ctx: ScenarioServerContext) => Promise<unknown>,
): Promise<ScenarioRun> {
  const health = await requireHealthy(baseURL, label);
  await resetServerState(baseURL);

  const startedAt = Date.now();
  const traces: TraceEntry[] = [];
  const actors = new Map<
    string,
    {
      client: ReturnType<typeof configuredClient>;
      fetch(input: string | URL | Request, init?: RequestInit): Promise<Response>;
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
    readUserState(args) { return readUserState(baseURL, args); },
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

  return {
    oauthURL: health.oauthBaseURL ?? baseURL.replace("localhost", "127.0.0.1"),
    startedAt,
    observation: normalizeClientValue(await scenario(context)),
    traces,
  };
}

function formatDiffs(title: string, differences: Difference[]) {
  return [title, ...differences.map(entry => `- ${entry.path}: ${entry.reason}`)].join("\n");
}

export function compatScenario(
  scenarioName: string,
  scenario: (ctx: ScenarioServerContext) => Promise<unknown>,
  stateTransitions: readonly string[] = [],
) {
  test.serial(scenarioName, async () => {
    const seed = `${Date.now()}-${crypto.randomUUID()}`;
    const ts = await runScenario("TS", TS_BASE_URL, seed, scenario);
    const rust = await runScenario("Rust", RUST_BASE_URL, seed, scenario);
    const comparison = {
      leftBaseURL: TS_BASE_URL, rightBaseURL: RUST_BASE_URL,
      leftStartedAt: ts.startedAt, rightStartedAt: rust.startedAt,
      leftOAuthURL: ts.oauthURL, rightOAuthURL: rust.oauthURL,
    };
    // Retain one identity graph across values and transport, and give the
    // trace shape markers their explicit scope when comparing type labels.
    const differences = compareValues({ observation: ts.observation, traces: ts.traces }, { observation: rust.observation, traces: rust.traces }, comparison);
    const clientDiffs = differences.filter(entry => entry.path.startsWith("observation"));
    if (clientDiffs.length) throw new Error(formatDiffs(`Client-visible drift: ${scenarioName}`, clientDiffs));
    const rawDiffs = differences.filter(entry => entry.path.startsWith("traces")).filter(entry =>
      !RAW_DIFF_ALLOWLIST.some(allowance => allowance.scenario.test(scenarioName) && allowance.path.test(entry.path)));
    if (rawDiffs.length) throw new Error(formatDiffs(`Raw trace drift: ${scenarioName}`, rawDiffs));
    await recordCoverage(scenarioName, ts.traces, stateTransitions);
  });
}
