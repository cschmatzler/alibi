import { expect } from "bun:test";

import { type ScenarioContext } from "../../../support/scenario";

export async function events(ctx: ScenarioContext) {
  const result = await ctx.rawRequest({ path: "/__test/captcha-events" });
  expect(result.status).toBe(200);
  return result.body as Record<string, unknown>[];
}

export const ip = { "x-forwarded-for": "203.0.113.7" };

export async function restoreAttempt(
  ctx: ScenarioContext,
  actor: string,
  body: unknown,
  userId: string,
) {
  const token = (body as { token?: unknown }).token;

  if (typeof token !== "string") {
    throw new Error("Admitted sign-in must return a genuine session token");
  }

  const read = await ctx.actor(actor).client.getSession();
  expect(read.error).toBeNull();
  expect(read.data!.user.id).toBe(userId);
  expect(read.data!.session.token).toBe(token);

  return ctx.snapshot(read);
}

export async function principals(ctx: ScenarioContext) {
  const owner = ctx.actor("owner");
  const foreign = ctx.actor("foreign");
  const signup = await owner.client.signUp.email({
    email: ctx.uniqueEmail("owner"),
    password: "password123",
    name: "Owner",
  });
  const other = await foreign.client.signUp.email({
    email: ctx.uniqueEmail("foreign"),
    password: "password123",
    name: "Foreign",
  });
  expect(signup.error).toBeNull();
  expect(other.error).toBeNull();

  await events(ctx);
  return { signup, other, foreignBefore: await ctx.readUserState({ userId: other.data!.user.id }) };
}
