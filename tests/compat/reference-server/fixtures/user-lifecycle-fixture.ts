/** Real configured mailbox and deletion callbacks on the pinned application. */

import type { Database } from "bun:sqlite";

import { type BetterAuthOptions, betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import { hashPassword, verifyPassword } from "better-auth/crypto";

export function createUserLifecycleFixture(base: BetterAuthOptions, database: Database) {
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  const states = new Map<
    string,
    {
      events: Record<string, unknown>[];
      failure: string;
      holdNext: boolean;
      held: boolean;
      release?: () => void;
    }
  >();

  for (const name of [
    "disabled",
    "default",
    "required",
    "delivery",
    "request-body",
    "auto",
    "change",
    "promotion",
    "promotion-no-mail",
    "verification-expired",
    "no-mail",
    "delete",
    "delete-mail",
    "delete-zero",
    "delete-expired",
    "delete-policy",
    "delete-no-freshness",
  ]) {
    const state = {
      events: [] as Record<string, unknown>[],
      failure: "",
      holdNext: false,
      held: false,
      release: undefined as (() => void) | undefined,
    };
    states.set(name, state);
    const requestReceipt = async (request?: Request) =>
      request
        ? {
            method: request.method,
            url: request.url,
            marker: request.headers.get("x-lifecycle-marker"),
          }
        : null;
    const hook = async (
      stage: string,
      user: unknown,
      request?: Request,
      extra: Record<string, unknown> = {},
    ) => {
      state.events.push({
        stage,
        user: structuredClone(user),
        request: await requestReceipt(request),
        ...extra,
      });
      if (stage === "before-delete" && state.holdNext) {
        state.holdNext = false;
        state.held = true;
        await new Promise<void>((resolve) => {
          state.release = resolve;
        });
        state.held = false;
        state.release = undefined;
      }
      if (state.failure === stage) {
        throw new APIError("BAD_REQUEST", {
          code: "LIFECYCLE_REJECTED",
          message: `Application ${stage} rejected`,
        });
      }
    };
    const options: BetterAuthOptions = {
      ...base,
      basePath: `/__test/profiles/user-lifecycle-${name}/api/auth`,
      plugins: [],
      emailAndPassword: {
        ...base.emailAndPassword,
        enabled: true,
        requireEmailVerification:
          name === "required" || name === "delivery" || name === "request-body",
        ...(name === "delete-policy"
          ? {
              maxPasswordLength: 12,
              password: {
                hash: hashPassword,
                async verify(input) {
                  state.events.push({
                    stage: "password-verify",
                    password: input.password,
                    hash: input.hash,
                  });
                  if (state.failure === "password-verify") {
                    throw new APIError("BAD_REQUEST", {
                      code: "LIFECYCLE_REJECTED",
                      message: "Application password-verify rejected",
                    });
                  }
                  return verifyPassword(input);
                },
              },
            }
          : {}),
      },
      session: {
        ...base.session,
        freshAge: name === "delete-no-freshness" ? 0 : 60,
        ...(name === "auto" || name === "change" || name === "promotion"
          ? {
              cookieCache: {
                enabled: true,
                maxAge: 300,
                version: async (session, user) => {
                  state.events.push({
                    stage: "cache",
                    session: structuredClone(session),
                    user: structuredClone(user),
                  });
                  return "1";
                },
              },
            }
          : {}),
      },
      emailVerification: {
        expiresIn: name === "verification-expired" ? -1 : 90,
        sendOnSignUp:
          name === "delivery" || name === "request-body"
            ? true
            : name === "required" || name === "default"
              ? undefined
              : false,
        sendOnSignIn: name === "delivery" || name === "request-body" ? true : undefined,
        autoSignInAfterVerification: name === "auto",
        ...(!["no-mail", "promotion-no-mail"].includes(name)
          ? {
              sendVerificationEmail: async ({ user, url, token }, request) => {
                const requestBody = name === "request-body" ? await request!.json() : undefined;
                return hook("verification-mail", user, request, {
                  url,
                  token,
                  ...(requestBody === undefined ? {} : { requestBody }),
                });
              },
            }
          : {}),
        beforeEmailVerification: async (user, request) =>
          hook("before-verification", user, request),
        afterEmailVerification: async (user, request) => hook("after-verification", user, request),
      },
      user: {
        ...base.user,
        changeEmail: {
          enabled: name !== "disabled",
          updateEmailWithoutVerification: name.startsWith("promotion"),
          ...(name === "change"
            ? {
                sendChangeEmailConfirmation: async ({ user, newEmail, url, token }, request) =>
                  hook("confirmation-mail", user, request, { newEmail, url, token }),
              }
            : {}),
        },
        deleteUser: {
          enabled: name !== "disabled",
          deleteTokenExpiresIn: name === "delete-zero" ? 0 : name === "delete-expired" ? -1 : 90,
          ...(name.startsWith("delete-") && !["delete-policy", "delete-no-freshness"].includes(name)
            ? {
                sendDeleteAccountVerification: async ({ user, url, token }, request) =>
                  hook("deletion-mail", user, request, { url, token }),
              }
            : {}),
          beforeDelete: async (user, request) => hook("before-delete", user, request),
          afterDelete: async (user, request) => hook("after-delete", user, request),
        },
      },
    };
    profiles.set(options.basePath!, betterAuth(options));
  }

  return {
    profiles,
    async handle(request: Request): Promise<Response | undefined> {
      const url = new URL(request.url);

      if (url.pathname !== "/__test/user-lifecycle/control") {
        return;
      }

      const body = (await request.json()) as {
        profile: string;
        action: string;
        failure?: string;
        userId?: string;
        name?: string;
        token?: string;
        createdAt?: string;
        expiresAt?: string;
      };
      const state = states.get(body.profile);
      const instance = profiles.get(`/__test/profiles/user-lifecycle-${body.profile}/api/auth`);

      if (!state || !instance) {
        return Response.json({ error: "Unknown lifecycle profile" }, { status: 400 });
      }

      const context = await instance.$context;

      if (body.action === "reset") {
        state.events.length = 0;
        state.failure = "";
      } else if (body.action === "hold") {
        state.holdNext = true;
        state.held = false;
      } else if (body.action === "release") {
        /* Snapshot the held request before releasing it below. */
      } else if (body.action === "ready") {
        const deadline = Date.now() + 3000;
        while (!state.held && Date.now() < deadline) {
          await Bun.sleep(10);
        }
        if (!state.held) {
          return Response.json(
            { error: "Application deletion hook did not arrive" },
            { status: 408 },
          );
        }
      } else if (body.action === "failure") {
        state.failure = body.failure ?? "";
      } else if (body.action === "rename") {
        if (!body.userId || typeof body.name !== "string") {
          return Response.json({ error: "Missing rename" }, { status: 400 });
        }
        await context.internalAdapter.updateUser(body.userId, { name: body.name });
      } else if (body.action === "session-clock") {
        if (!body.token || !body.createdAt) {
          return Response.json({ error: "Missing session clock" }, { status: 400 });
        }
        await context.adapter.update({
          model: "session",
          where: [{ field: "token", value: body.token }],
          update: {
            createdAt: new Date(body.createdAt),
            expiresAt: new Date(body.expiresAt ?? "2099-01-01T00:00:00Z"),
          },
        });
      } else if (body.action !== "state") {
        return Response.json({ error: "Unknown lifecycle action" }, { status: 400 });
      }

      const read = (model: "user" | "session" | "account" | "verification") =>
        context.adapter.findMany<Record<string, unknown>>({
          model,
          sortBy: { field: "createdAt", direction: "asc" },
        });
      const verifications = (await read("verification")).map(({ identifier, value, ...row }) =>
        typeof identifier === "string" && identifier.startsWith("delete-account-")
          ? {
              ...row,
              identifierPrefix: "delete-account-",
              token: identifier.slice("delete-account-".length),
              userId: value,
            }
          : { ...row, identifier, value },
      );
      const response = Response.json({
        users: await read("user"),
        accounts: await read("account"),
        sessions: await read("session"),
        verifications,
        events: state.events,
      });

      // Serialize all rows and receipts while deletion is blocked, before any writes resume.
      if (body.action === "release") {
        state.release?.();
      }

      return response;
    },
  };
}
