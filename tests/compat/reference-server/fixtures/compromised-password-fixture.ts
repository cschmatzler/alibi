/** Actual published hash policy, real HTTP range service and physical SQLite evidence. */

import type { Database } from "bun:sqlite";
import { type BetterAuthOptions, betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import { hashPassword, verifyPassword } from "better-auth/crypto";
import { getMigrations } from "better-auth/db/migration";
import { admin, emailOTP, phoneNumber } from "better-auth/plugins";
import { haveIBeenPwned, isPasswordCompromised } from "better-auth/plugins/haveibeenpwned";

export async function createCompromisedPasswordFixture(
  database: Database,
  shared: BetterAuthOptions,
) {
  const events: Record<string, unknown>[] = [],
    receipts: Record<string, unknown>[] = [];
  let hashFailure = false;
  let service = { body: "", status: 200, contentType: "text/plain" };
  const range = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      const url = new URL(request.url);
      receipts.push({
        method: request.method,
        path: url.pathname,
        query: url.search,
        headers: {
          addPadding: request.headers.get("add-padding"),
          userAgent: request.headers.get("user-agent"),
          authorization: request.headers.get("authorization"),
          cookie: request.headers.get("cookie"),
        },
        body: await request.text(),
      });
      events.push({ stage: "range" });
      return new Response(service.body, {
        status: service.status,
        headers: { "content-type": service.contentType },
      });
    },
  });
  // Keep the published helper unchanged. Only its fixed service origin is
  // forwarded to this fixture's bound, actual HTTP range service.
  const previousFetch = globalThis.fetch;
  globalThis.fetch = (async (
    input: Parameters<typeof fetch>[0],
    init?: Parameters<typeof fetch>[1],
  ) => {
    const url = new URL(input instanceof Request ? input.url : input.toString());
    if (
      url.origin === "https://api.pwnedpasswords.com" &&
      /^\/range\/[A-F0-9]{5}$/.test(url.pathname) &&
      !url.search
    ) {
      const forwarded = `http://127.0.0.1:${range.port}${url.pathname}`;
      return previousFetch(
        input instanceof Request ? new Request(forwarded, input) : forwarded,
        init,
      );
    }
    return previousFetch(input, init);
  }) as typeof fetch;
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  for (const name of [
    "pwned-default",
    "pwned-disabled",
    "pwned-empty",
    "pwned-custom",
    "pwned-message",
    "pwned-empty-message",
    "pwned-no-auto",
    "pwned-virtual",
    "pwned-wildcard",
  ]) {
    const options = {
      ...shared,
      database,
      basePath: `/__test/profiles/${name}/api/auth`,
      databaseHooks: {
        user: {
          create: {
            before: async (user: { name?: string; email: string }) => {
              events.push({ stage: "user-create", name: user.name, email: user.email });
            },
          },
        },
      },
      emailAndPassword: {
        ...shared.emailAndPassword,
        enabled: true,
        autoSignIn: name !== "pwned-no-auto",
        revokeSessionsOnPasswordReset: true,
        password: {
          async hash(password: string) {
            events.push({ stage: "hash-enter", password });
            const hash = await hashPassword(password);
            events.push({ stage: "hash-result", password, hash });
            if (hashFailure)
              throw new APIError("FORBIDDEN", {
                code: "ORIGINAL_HASH_REJECTED",
                message: "Original password hash rejected",
              });
            return hash;
          },
          verify: verifyPassword,
        },
        async sendResetPassword({
          user,
          url,
          token,
        }: {
          user: Record<string, unknown>;
          url: string;
          token: string;
        }) {
          events.push({ stage: "reset-delivery", user, url, token });
        },
        async onPasswordReset({ user }: { user: Record<string, unknown> }) {
          events.push({ stage: "password-reset", user });
        },
      },
      plugins: [
        admin(),
        emailOTP({
          async sendVerificationOTP(delivery) {
            events.push({ stage: "email-otp", ...delivery });
          },
        }),
        phoneNumber({
          async sendOTP(delivery) {
            events.push({ stage: "phone-otp", ...delivery });
          },
          async sendPasswordResetOTP(delivery) {
            events.push({ stage: "phone-reset-otp", ...delivery });
          },
        }),
        haveIBeenPwned({
          ...(name === "pwned-disabled" ? { enabled: false } : {}),
          ...(name === "pwned-empty"
            ? { paths: [] }
            : name === "pwned-custom"
              ? { paths: ["/set-password", "/sign-in/email"] }
              : name === "pwned-virtual"
                ? { paths: ["virtual:"] }
                : name === "pwned-wildcard"
                  ? { paths: ["*"] }
                  : {}),
          ...(name === "pwned-message"
            ? { customPasswordCompromisedMessage: "Application forbids leaked passwords" }
            : name === "pwned-empty-message"
              ? { customPasswordCompromisedMessage: "" }
              : {}),
        }),
      ],
    } satisfies BetterAuthOptions;
    await (await getMigrations(options)).runMigrations();
    profiles.set(name, betterAuth(options));
  }
  return {
    profiles,
    async handle(request: Request): Promise<Response | undefined> {
      const url = new URL(request.url);
      if (url.pathname === "/__test/compromised-password/state") {
        const context = await profiles.get("pwned-default")!.$context;
        const read = (model: "user" | "account" | "session" | "verification") =>
          context.adapter.findMany<Record<string, unknown>>({
            model,
            sortBy: { field: "createdAt", direction: "asc" },
          });
        return Response.json({
          users: await read("user"),
          accounts: await read("account"),
          sessions: await read("session"),
          verifications: await read("verification"),
          events,
          receipts,
        });
      }
      if (
        !["/__test/compromised-password", "/__test/server-api/compromised-password"].includes(
          url.pathname,
        ) ||
        request.method !== "POST"
      )
        return;
      const body = (await request.json()) as {
        operation: string;
        profile?: string;
        body?: string;
        status?: number;
        contentType?: string;
        password?: string;
        accountId?: string;
        newPassword?: string;
        hashFailure?: boolean;
      };
      if (body.operation === "range") {
        hashFailure = body.hashFailure === true;
        service = {
          body: body.body ?? "",
          status: body.status ?? 200,
          contentType: body.contentType ?? "text/plain",
        };
        events.length = 0;
        receipts.length = 0;
        return Response.json({ status: true });
      }
      const instance = profiles.get(body.profile ?? "pwned-default")!;
      const context = await instance.$context;
      if (body.operation === "clear-password") {
        await context.internalAdapter.updateAccount(body.accountId!, { password: null });
        return Response.json({ status: true });
      }
      if (body.operation === "helper") {
        try {
          return Response.json({ compromised: await isPasswordCompromised(body.password!) });
        } catch (error) {
          if (error instanceof APIError) return Response.json(error.body, { status: 500 });
          throw error;
        }
      }
      if (body.operation === "set")
        return instance.api.setPassword({
          body: { newPassword: body.newPassword! },
          headers: request.headers,
          asResponse: true,
        });
      return Response.json({ message: "unknown fixture operation" }, { status: 400 });
    },
  };
}
