import { expect } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { organizationClient } from "better-auth/client/plugins";
import { z } from "zod";
import type { FixtureProfile } from "../../support/profiles";
import type { compatScenario } from "../../support/scenario";

export type CompatContext = Parameters<Parameters<typeof compatScenario>[1]>[0];

export function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("expected object response body");
  }
  return value as Record<string, unknown>;
}

export function asArray(value: unknown): unknown[] {
  if (!Array.isArray(value)) {
    throw new Error("expected array response body");
  }
  return value;
}

export function organizationActor(ctx: CompatContext, name = "primary") {
  const actor = ctx.actor(name);

  return {
    ...actor,
    orgClient: createAuthClient({
      baseURL: ctx.baseURL,
      plugins: [organizationClient()],
      fetchOptions: {
        customFetchImpl: actor.fetch,
      },
    }),
  };
}

export async function signUpUser(
  ctx: CompatContext,
  name: string,
  prefix: string,
  displayName: string,
) {
  const actor = organizationActor(ctx, name);
  const email = ctx.uniqueEmail(prefix);
  const signup = await actor.client.signUp.email({
    email,
    password: "password123",
    name: displayName,
  });

  return {
    ...actor,
    email,
    signup,
  };
}

export function orgActor(ctx: CompatContext, name: string, profile: FixtureProfile = "org-teams") {
  return createAuthClient({
    baseURL: ctx.baseURL,
    plugins: [
      organizationClient({ teams: { enabled: true }, dynamicAccessControl: { enabled: true } }),
    ],
    fetchOptions: { customFetchImpl: ctx.actor(name, profile).fetch },
  });
}

export function data<T>(response: { data: T | null; error: unknown }): T {
  expect(response.error).toBeNull();
  if (response.data === null) throw new Error("Successful organization operation must return data");
  return response.data;
}

const stateSchema = z.object({
  teams: z.array(
    z.object({
      id: z.string(),
      organizationId: z.string(),
      name: z.string(),
      memberCount: z.number(),
      createdAt: z.string(),
      updatedAt: z.string().nullable(),
    }),
  ),
  teamMembers: z.array(
    z.object({ id: z.string(), teamId: z.string(), userId: z.string(), createdAt: z.string() }),
  ),
  roles: z.array(
    z.object({
      id: z.string(),
      organizationId: z.string(),
      role: z.string(),
      permission: z.string(),
      createdAt: z.string(),
      updatedAt: z.string().nullable(),
    }),
  ),
  members: z.array(
    z.object({
      id: z.string(),
      organizationId: z.string(),
      userId: z.string(),
      role: z.string(),
      createdAt: z.string(),
    }),
  ),
  invitations: z.array(
    z.object({
      id: z.string(),
      organizationId: z.string(),
      email: z.string(),
      role: z.string(),
      teamId: z.string().nullable(),
      status: z.string(),
      expiresAt: z.string(),
      createdAt: z.string(),
    }),
  ),
});

export async function state(
  ctx: CompatContext,
  organizationId: string,
  profile: FixtureProfile = "org-teams",
) {
  const url = new URL("/__test/organization-state", ctx.baseURL);
  url.searchParams.set("organizationId", organizationId);
  url.searchParams.set("profile", profile);
  const response = await fetch(url);
  expect(response.status).toBe(200);
  const raw: unknown = await response.json();
  const parsed = stateSchema.parse(raw);
  for (const team of parsed.teams) {
    expect(team.memberCount).toBe(
      parsed.teamMembers.filter((member) => member.teamId === team.id).length,
    );
  }
  return { raw, parsed };
}

export async function signUp(
  ctx: CompatContext,
  name: string,
  profile: FixtureProfile = "org-teams",
) {
  const client = orgActor(ctx, name, profile);
  const email = ctx.uniqueEmail(`org-extension-${name}`);
  const signup = await client.signUp.email({ email, password: "password123", name });
  const user = data(signup).user;
  return { client, email, signup, user };
}

/** Invoke server-only APIs through the controlled fixture interface. */
export async function serverOperation(
  ctx: CompatContext,
  body: Record<string, unknown>,
  profile: FixtureProfile = "org-teams",
) {
  const response = await fetch(new URL("/__test/organization-api", ctx.baseURL), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ...body, profile }),
  });
  const result: unknown = await response.json();
  return { status: response.status, body: result };
}
