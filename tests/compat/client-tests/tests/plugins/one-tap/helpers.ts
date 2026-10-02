import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { oneTapClient } from "better-auth/client/plugins";
import { symmetricDecodeJWT } from "better-auth/crypto";
import { decodeProtectedHeader } from "jose";
import { Cookie } from "tough-cookie";
import { z } from "zod";

import { authProfilePath, type FixtureProfile } from "../../../support/profiles";
import { type ScenarioContext } from "../../../support/scenario";

export const stateSchema = z.object({
  jwksFetches: z.number(),
  users: z.array(
    z.object({
      id: z.string(),
      email: z.string(),
      name: z.string().nullable(),
      emailVerified: z.boolean(),
      image: z.string().nullable(),
    }),
  ),
  accounts: z.array(
    z.object({
      id: z.string(),
      userId: z.string(),
      providerId: z.string(),
      accountId: z.string(),
      scope: z.string().nullable(),
      idToken: z.string().nullable(),
    }),
  ),
  sessions: z.array(z.object({ id: z.string(), userId: z.string(), token: z.string() })),
});

export async function state(ctx: ScenarioContext) {
  const result = await ctx.rawRequest({ path: "/__test/one-tap/state" });
  expect(result.status).toBe(200);
  return stateSchema.parse(result.body);
}

const accountPayloadSchema = z
  .object({
    id: z.string(),
    userId: z.string(),
    providerId: z.string(),
    accountId: z.string(),
    idToken: z.string().nullable().optional(),
    scope: z.string().nullable().optional(),
    accessToken: z.string().nullable().optional(),
    refreshToken: z.string().nullable().optional(),
  })
  .passthrough();

const accountCookieSchema = z.object({
  token: z.string(),
  header: z.record(z.string(), z.unknown()),
  payload: accountPayloadSchema,
});

const successSchema = z.object({
  token: z.string(),
  user: z
    .object({
      id: z.string(),
      email: z.string(),
      name: z.string(),
      emailVerified: z.boolean(),
      image: z.string().nullable().optional(),
    })
    .passthrough(),
});

export async function oneTap(
  ctx: ScenarioContext,
  token: string,
  profile: FixtureProfile = "one-tap-default",
  actorName = "google",
  callbackURL?: string,
) {
  const actor = ctx.actor(actorName, profile);
  let callback: ((response: { credential: string }) => Promise<void>) | undefined;
  let received: unknown;
  let sessionMaxAge: number | null = null;
  let accountCookie: z.infer<typeof accountCookieSchema> | null = null;
  const browser = {
    document: {},
    googleScriptInitialized: true,
    location: { href: "/before" },
    google: {
      accounts: {
        id: {
          initialize(options: { callback: (response: { credential: string }) => Promise<void> }) {
            callback = options.callback;
          },
          prompt() {
            void callback!({ credential: token });
          },
        },
      },
    },
  };
  const original = Object.getOwnPropertyDescriptor(globalThis, "window");
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: browser,
  });

  try {
    const client = createAuthClient({
      baseURL: ctx.baseURL + authProfilePath(profile),
      plugins: [
        oneTapClient({
          clientId: "one-tap-plugin-client",
          promptOptions: { fedCM: false },
        }),
      ],
      fetchOptions: { customFetchImpl: actor.fetch },
    });
    await client.oneTap({
      callbackURL,
      fetchOptions: {
        async onSuccess(context) {
          const account = context.response.headers
            .getSetCookie()
            .map((value) => Cookie.parse(value))
            .find((cookie) => cookie?.key.endsWith("account_data"));

          if (account) {
            const token = decodeURIComponent(account.value);
            accountCookie = accountCookieSchema.parse({
              token,
              header: decodeProtectedHeader(token),
              payload: await symmetricDecodeJWT(
                token,
                "compat-test-only-key-not-real-minimum-32chars",
                "better-auth-account",
              ),
            });
          }

          const cookie = context.response.headers
            .getSetCookie()
            .map((value) => Cookie.parse(value))
            .find((cookie) => cookie?.key.endsWith("session_token"));
          sessionMaxAge = typeof cookie?.maxAge === "number" ? cookie.maxAge : null;
          received = { data: successSchema.parse(context.data), error: null };
        },
        onError(context) {
          received = { data: null, error: context.error };
        },
      },
    });
    expect(received).toBeDefined();

    return {
      response: received,
      location: browser.location.href,
      sessionMaxAge,
      accountCookie,
    };
  } finally {
    if (original) {
      Object.defineProperty(globalThis, "window", original);
    } else {
      Reflect.deleteProperty(globalThis, "window");
    }
  }
}

export const responseSchema = z.object({
  response: z.object({
    data: successSchema.nullable(),
    error: z
      .object({
        status: z.number(),
        message: z.string(),
        code: z.string().optional(),
      })
      .passthrough()
      .nullable(),
  }),
  location: z.string(),
  sessionMaxAge: z.number().nullable(),
  accountCookie: accountCookieSchema.nullable(),
});

export async function successful(
  ctx: ScenarioContext,
  token: string,
  profile: FixtureProfile = "one-tap-default",
  actorName = "google",
  callbackURL?: string,
) {
  const result = responseSchema.parse(await oneTap(ctx, token, profile, actorName, callbackURL));
  expect(result.response.error).toBeNull();
  expect(result.response.data).not.toBeNull();

  return result;
}
