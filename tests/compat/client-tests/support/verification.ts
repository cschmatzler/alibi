import { expect } from "bun:test";
import { z } from "zod";
import type { compatScenario } from "./scenario";

export type ScenarioContext = Parameters<Parameters<typeof compatScenario>[1]>[0];

const userState = z.object({
  user: z.object({ id: z.string(), email: z.string(), emailVerified: z.boolean() }).passthrough().nullable(),
  accounts: z.array(z.object({ id: z.string(), userId: z.string(), providerId: z.string(), accountId: z.string() }).passthrough()),
  sessions: z.array(z.object({ id: z.string(), token: z.string(), userId: z.string(), expiresAt: z.string() }).passthrough()),
  twoFactorExists: z.boolean(),
});

export async function fixtureValue(ctx: ScenarioContext, path: string, query: Readonly<Record<string, string>>) {
  const url = new URL(path, ctx.baseURL);
  for (const [name, value] of Object.entries(query)) url.searchParams.set(name, value);
  const response = await fetch(url);
  expect(response.status).toBe(200);
  const value: unknown = await response.json();
  return value;
}

export async function readUserState(ctx: ScenarioContext, userId: string) {
  const parsed = userState.safeParse(await fixtureValue(ctx, "/__test/user-state", { userId }));
  if (!parsed.success) throw new Error("Fixture must return complete persisted user state");
  return parsed.data;
}

export async function verificationCount(ctx: ScenarioContext, identifier: string) {
  const parsed = z.array(z.unknown()).safeParse(await fixtureValue(ctx, "/__test/verification-state", { identifier }));
  if (!parsed.success) throw new Error("Fixture must return the persisted verification rows");
  return parsed.data.length;
}

export async function expireVerification(ctx: ScenarioContext, identifier: string) {
  const result = await ctx.rawRequest({
    path: "/__test/verification-state",
    method: "POST",
    json: { action: "expire", identifier, expiresAt: "2020-01-01T00:00:00.000Z" },
  });
  expect(result.status).toBe(200);
}

export function requireUser<T extends { id: string }>(user: T | null | undefined): T {
  if (!user) throw new Error("Successful authentication must return a user");
  return user;
}

export async function storedVerification(ctx: ScenarioContext, identifier: string) {
  const schema = z.array(z.object({ id: z.string(), identifier: z.string(), value: z.string(), expiresAt: z.string() }).passthrough());
  const parsed = schema.safeParse(await fixtureValue(ctx, "/__test/verification-state", { identifier }));
  if (!parsed.success) throw new Error("Verification fixture must return stored representation and expiry");
  return parsed.data;
}
