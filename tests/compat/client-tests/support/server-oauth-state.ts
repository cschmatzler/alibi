import { expect } from "bun:test";
import { createHash, createHmac } from "node:crypto";

import type { ScenarioContext } from "./scenario";

export type LogicalOAuthStart = {
  status: number;
  body: Record<string, unknown> | null;
  location: string | null;
  cookies: string[];
};

/** Inspect the real logical issuer, persisted proof and authenticated cookie together. */
export async function observeLogicalOAuthState(
  ctx: ScenarioContext,
  start: LogicalOAuthStart,
  startedAt: number,
  finishedAt: number,
  expected: Record<string, unknown>,
) {
  const url = new URL(start.body!.url as string);
  const state = url.searchParams.get("state")!;
  expect(state).toMatch(/^[A-Za-z0-9_-]{32}$/);
  const rows = (await ctx.readVerificationState({ identifier: `auth-state:${state}` })) as {
    id: string;
    identifier: string;
    value: string;
    createdAt: string;
    updatedAt: string;
    expiresAt: string;
  }[];
  expect(rows).toHaveLength(1);
  expect(rows[0]!.identifier).toBe(`auth-state:${state}`);
  const payload = JSON.parse(rows[0]!.value) as {
    codeVerifier: string;
    expiresAt: number;
    oauthState: string;
  };
  expect(payload.codeVerifier).toMatch(/^[A-Za-z0-9_-]{128}$/);
  expect(createHash("sha256").update(payload.codeVerifier).digest("base64url")).toBe(
    url.searchParams.get("code_challenge")!,
  );
  expect(payload).toEqual({
    ...expected,
    codeVerifier: payload.codeVerifier,
    oauthState: state,
    expiresAt: payload.expiresAt,
  });
  for (const expiresAt of [payload.expiresAt, Date.parse(rows[0]!.expiresAt)]) {
    expect(expiresAt).toBeGreaterThanOrEqual(startedAt + 600_000);
    expect(expiresAt).toBeLessThanOrEqual(finishedAt + 600_000);
  }
  for (const field of ["createdAt", "updatedAt"] as const) {
    expect(Date.parse(rows[0]![field])).toBeGreaterThanOrEqual(startedAt);
    expect(Date.parse(rows[0]![field])).toBeLessThanOrEqual(finishedAt);
  }
  const rawCookie = start.cookies.find((cookie) => cookie.startsWith("better-auth.state="))!;
  const encoded = rawCookie.split(";")[0]!.slice("better-auth.state=".length);
  expect(decodeURIComponent(encoded)).toBe(
    `${state}.${createHmac("sha256", "compat-test-only-key-not-real-minimum-32chars").update(state).digest("base64")}`,
  );
  // Decode authenticated protocol entropy into the comparator's semantic
  // identities, retaining cookie attributes and every stored field.
  const observation = {
    start: {
      ...start,
      cookies: start.cookies.map((cookie) =>
        cookie === rawCookie ? { state, attributes: cookie.slice(cookie.indexOf(";")) } : cookie,
      ),
    },
    state,
    rows: rows.map((row) => ({
      ...row,
      identifier: { prefix: "auth-state:", state },
      value: {
        ...payload,
        codeVerifier: { token: payload.codeVerifier },
        oauthState: { state: payload.oauthState },
        expiresAt: new Date(payload.expiresAt).toISOString(),
      },
    })),
  };
  return { state, payload, observation };
}
