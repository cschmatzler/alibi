import { expect } from "bun:test";
import { createHmac } from "node:crypto";

import { createAuthClient } from "better-auth/client";
import { phoneNumberClient, twoFactorClient } from "better-auth/client/plugins";
import { z } from "zod";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

export type ScenarioContext = Parameters<Parameters<typeof compatScenario>[1]>[0];
export type PhoneProfile = "phone-default" | "phone-signup" | "phone-proof" | "phone-custom";

export function phoneClient(ctx: ScenarioContext, profile: PhoneProfile, actor = "primary") {
  return createAuthClient({
    baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
    plugins: [phoneNumberClient(), twoFactorClient()],
    fetchOptions: { customFetchImpl: ctx.actor(actor, profile).fetch },
  });
}

export function phoneEnrollmentCode(uri: string) {
  const url = new URL(uri);
  const secret = z.string().min(1).parse(url.searchParams.get("secret"));
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes: number[] = [];
  let bits = 0;
  let value = 0;

  for (const character of secret.toUpperCase().replace(/=+$/g, "")) {
    const digit = alphabet.indexOf(character);

    if (digit < 0) {
      throw new Error("Enrollment secret must use base32");
    }

    value = (value << 5) | digit;
    bits += 5;

    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >>> bits) & 255);
    }
  }

  const period = Number(url.searchParams.get("period") ?? "30");
  const digits = Number(url.searchParams.get("digits") ?? "6");
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 1000 / period)));
  const digest = createHmac("sha1", Uint8Array.from(bytes)).update(counter).digest();
  const offset = digest.at(-1)! & 15;
  return String((digest.readUInt32BE(offset) & 0x7fffffff) % 10 ** digits).padStart(digits, "0");
}

export function uniquePhone(ctx: ScenarioContext, prefix: string) {
  const digits = String(Bun.hash(ctx.uniqueToken(prefix)))
    .padStart(10, "0")
    .slice(-10);
  return `+1${digits}`;
}

export async function readPhoneOtp(
  ctx: ScenarioContext,
  phoneNumber: string,
  type: "verification" | "password-reset" = "verification",
) {
  const url = new URL("/__test/phone-otp", ctx.baseURL);
  url.searchParams.set("phoneNumber", phoneNumber);
  url.searchParams.set("type", type);
  const response = await fetch(url);
  expect(response.status).toBe(200);

  const value: unknown = await response.json();
  const parsed = z.object({ code: z.string().min(1) }).safeParse(value);

  if (!parsed.success) {
    throw new Error("Phone challenge issuance must deliver a code for the intended number");
  }

  return parsed.data.code;
}

const stateSchema = z.object({
  user: z
    .object({
      id: z.string(),
      email: z.string(),
      emailVerified: z.boolean(),
      phoneNumber: z.string().nullable(),
      phoneNumberVerified: z.boolean().nullable(),
    })
    .passthrough()
    .nullable(),
  accounts: z.array(
    z.object({ id: z.string(), userId: z.string(), accountId: z.string(), providerId: z.string() }),
  ),
  sessions: z.array(
    z.object({ id: z.string(), token: z.string(), userId: z.string(), expiresAt: z.string() }),
  ),
  twoFactorExists: z.boolean(),
});

export async function readPhoneState(ctx: ScenarioContext, profile: PhoneProfile, userId: string) {
  const url = new URL("/__test/user-state", ctx.baseURL);
  url.searchParams.set("userId", userId);
  url.searchParams.set("profile", profile);
  const response = await fetch(url);
  expect(response.status).toBe(200);

  const value: unknown = await response.json();
  const parsed = stateSchema.safeParse(value);

  if (!parsed.success) {
    throw new Error("Phone fixture must expose persisted phone ownership and verification fields");
  }

  return parsed.data;
}

export async function phoneRequest(
  ctx: ScenarioContext,
  profile: PhoneProfile,
  path: string,
  body: unknown,
  actor = "primary",
) {
  const response = await ctx
    .actor(actor, profile)
    .fetch(new URL(`${authProfilePath(profile)}${path}`, ctx.baseURL), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  const text = await response.text();
  let value: unknown = null;

  if (text) {
    try {
      value = JSON.parse(text);
    } catch {
      value = text;
    }
  }

  return { status: response.status, body: value };
}

export function phoneUser<T extends { id: string }>(user: T | null | undefined): T {
  if (!user) {
    throw new Error("Successful phone authentication must return the persisted user");
  }
  return user;
}
