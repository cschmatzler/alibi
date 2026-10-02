import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { adminClient, siweClient, twoFactorClient } from "better-auth/client/plugins";
import { z } from "zod";

import type { FixtureProfile } from "../../../support/profiles";
import type { ScenarioContext } from "../../../support/scenario";
import { signature } from "../../../support/siwe-wallet";

export function siweActor(ctx: ScenarioContext, name = "wallet", profile: FixtureProfile = "siwe") {
  const actor = ctx.actor(name, profile);
  const client = createAuthClient({
    baseURL: ctx.baseURL,
    plugins: [siweClient(), adminClient(), twoFactorClient()],
    fetchOptions: { customFetchImpl: actor.fetch },
  });
  return { client, fetch: actor.fetch };
}

export const identity = z
  .object({
    success: z.literal(true),
    token: z.string().length(32),
    user: z.object({ id: z.string(), walletAddress: z.string(), chainId: z.number() }).strict(),
  })
  .strict();

const dated = { createdAt: z.string(), updatedAt: z.string() };

export const stateSchema = z
  .object({
    users: z.array(
      z
        .object({
          id: z.string(),
          name: z.string().nullable(),
          email: z.string(),
          emailVerified: z.boolean(),
          image: z.string().nullable(),
          role: z.string().nullable(),
          banned: z.boolean().nullable(),
          twoFactorEnabled: z.boolean().nullable(),
          ...dated,
        })
        .strict(),
    ),
    wallets: z.array(
      z
        .object({
          id: z.string(),
          userId: z.string(),
          address: z.string(),
          chainId: z.number(),
          isPrimary: z.boolean(),
          createdAt: z.string(),
        })
        .strict(),
    ),
    accounts: z.array(
      z
        .object({
          id: z.string(),
          userId: z.string(),
          accountId: z.string(),
          providerId: z.string(),
          ...dated,
        })
        .strict(),
    ),
    sessions: z.array(
      z
        .object({
          id: z.string(),
          userId: z.string(),
          token: z.string(),
          expiresAt: z.string(),
          ipAddress: z.string().nullable(),
          userAgent: z.string().nullable(),
          ...dated,
        })
        .strict(),
    ),
    proofs: z.array(
      z
        .object({
          id: z.string(),
          identifier: z.string(),
          value: z.string(),
          expiresAt: z.string(),
          ...dated,
        })
        .strict(),
    ),
    inputs: z.array(
      z
        .object({
          message: z.string(),
          signature: z.string(),
          address: z.string(),
          chainId: z.number(),
          cacao: z.object({
            h: z.object({ t: z.literal("caip122") }),
            p: z.object({
              domain: z.string(),
              aud: z.string(),
              nonce: z.string(),
              iss: z.string(),
              version: z.literal("1"),
            }),
            s: z.object({ t: z.literal("eip191"), s: z.string() }),
          }),
        })
        .strict(),
    ),
    lookups: z.array(z.string()),
    rpcCalls: z.array(z.unknown()),
  })
  .strict();

export async function state(ctx: ScenarioContext) {
  const response = await ctx.rawRequest({ path: "/__test/siwe-state" });
  expect(response.status).toBe(200);
  return stateSchema.parse(response.body);
}

export async function control(ctx: ScenarioContext, body: unknown) {
  const response = await ctx.rawRequest({
    path: "/__test/siwe-control",
    method: "POST",
    json: body,
  });
  expect(response.status).toBe(200);
  return response.body;
}

export async function nonce(actor: ReturnType<typeof siweActor>, alias = false) {
  const response = alias ? await actor.client.siwe.getNonce() : await actor.client.siwe.nonce();
  expect(response.error).toBeNull();
  return z.object({ nonce: z.string() }).parse(response.data).nonce;
}

export async function verify(
  actor: ReturnType<typeof siweActor>,
  signed: string,
  {
    scalar = 1,
    email,
    compact = false,
  }: { scalar?: number; email?: string; compact?: boolean } = {},
) {
  return actor.client.siwe.verify({
    message: signed,
    signature: signature(signed, scalar, compact),
    ...(email === undefined ? {} : { email }),
  });
}
