import { Database } from "bun:sqlite";

import { passkey } from "@better-auth/passkey";
import { type BetterAuthOptions, betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import { getMigrations } from "better-auth/db/migration";
import { anonymous, emailOTP, magicLink, oneTap, phoneNumber } from "better-auth/plugins";

/** Application identity/link callbacks; all receipts come from actual plugin calls. */
export async function anonymousFixture(base: BetterAuthOptions, database: Database) {
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  const events: unknown[] = [];
  const deliveries = new Map<string, unknown>();
  let sequence = 0;
  const modes = [
    "standard",
    "defaults",
    "attributes",
    "disabled",
    "link-error",
    "user-cancel",
    "user-forbidden",
    "session-cancel",
    "session-forbidden",
    "snapshot",
    "invalid-email",
    "empty-name",
    "methods",
    "custom",
    "custom-methods",
    "custom-cache",
    "link-ordinary",
    "link-uncoded",
    "recovery",
    "recovery-disabled",
  ];

  for (const mode of modes) {
    const path = `/__test/profiles/anonymous-${mode}/api/auth`;
    const options: BetterAuthOptions = {
      ...base,
      basePath: path,
      ...(mode === "attributes"
        ? {
            advanced: {
              ...base.advanced,
              ipAddress: { ipAddressHeaders: ["x-anonymous-ip", "x-forwarded-for"] },
            },
          }
        : {}),
      ...(mode.startsWith("custom") || mode.startsWith("recovery")
        ? {
            user: {
              ...base.user,
              additionalFields: {
                cargoLabel: {
                  required: false,
                  type: "string" as const,
                  fieldName: "cargo_label",
                  defaultValue: () => "Application Original",
                },
                cargoHidden: {
                  required: false,
                  type: "string" as const,
                  fieldName: "cargo_hidden",
                  defaultValue: () => "Application Secret",
                  returned: false,
                },
              },
            },
          }
        : {}),
      ...(mode === "custom-cache"
        ? {
            session: {
              ...base.session,
              cookieCache: { enabled: true, strategy: "compact" as const },
            },
          }
        : {}),
      socialProviders: {
        gitlab: {
          clientId: "fixture-social-client",
          clientSecret: "fixture-social-secret",
          issuer: `${base.baseURL}/__test/social-provider/gitlab`,
        },
      },
      ...(mode.endsWith("methods")
        ? {
            emailVerification: {
              ...base.emailVerification,
              sendOnSignUp: false,
              autoSignInAfterVerification: true,
              async sendVerificationEmail({
                user,
                url,
                token,
              }: {
                user: { email: string };
                url: string;
                token: string;
              }) {
                deliveries.set(`verification:${user.email}`, { email: user.email, url, token });
              },
            },
          }
        : {}),
      databaseHooks: {
        user: {
          create: {
            before: async (user, context) => {
              if (context?.path !== "/sign-in/anonymous") {
                return;
              }
              if (mode === "user-cancel") {
                return false;
              }
              if (mode === "user-forbidden") {
                throw new APIError("FORBIDDEN", {
                  message: "user creation cancelled by database hook",
                });
              }
            },
          },
        },
        session: {
          create: {
            before: async (_session, context) => {
              if (context?.path !== "/sign-in/anonymous") {
                return;
              }
              if (mode === "session-cancel") {
                return false;
              }
              if (mode === "session-forbidden") {
                throw new APIError("FORBIDDEN", {
                  message: "session creation cancelled by database hook",
                });
              }
            },
            after: async (session, context) => {
              if (
                (mode === "snapshot" || mode.startsWith("custom")) &&
                context?.path === "/sign-up/email"
              ) {
                database
                  .query("UPDATE user SET name=? WHERE id=?")
                  .run("Stored Hook Name", session.userId);
                if (mode.startsWith("custom")) {
                  database
                    .query("UPDATE user SET cargo_label=?, cargo_hidden=? WHERE id=?")
                    .run("Application Stored", "Stored Secret", session.userId);
                }
              }
            },
          },
        },
      },
      plugins: [
        ...(mode.endsWith("methods")
          ? [
              magicLink({
                async sendMagicLink({ email, url, token, metadata }) {
                  deliveries.set(`magic:${email}`, {
                    email,
                    url,
                    token,
                    metadata: metadata ?? null,
                  });
                },
              }),
              emailOTP({
                async sendVerificationOTP({ email, otp, type }) {
                  deliveries.set(`${type}:${email}`, { email, otp, type });
                },
              }),
              phoneNumber({
                async sendOTP({ phoneNumber, code }) {
                  deliveries.set(`phone:${phoneNumber}`, { phoneNumber, code });
                },
                signUpOnVerification: {
                  getTempEmail: (phone: string) => `${phone}@phone.fixture.test`,
                  getTempName: (phone: string) => phone,
                },
              }),
              passkey(),
              oneTap({ clientId: "one-tap-plugin-client" }),
            ]
          : []),
        anonymous({
          disableDeleteAnonymousUser: mode === "disabled" || mode === "recovery-disabled",
          ...(mode === "defaults"
            ? {}
            : {
                generateRandomEmail: () =>
                  mode === "invalid-email"
                    ? "not an email"
                    : `anonymous-${++sequence}@fixture.test`,
                generateName: async () => {
                  await Promise.resolve();
                  return mode === "empty-name" ? "" : "Configured Anonymous";
                },
              }),
          onLinkAccount: async ({ anonymousUser, newUser, ctx: context }) => {
            await Promise.resolve();
            events.push({
              mode,
              path: new URL(context.request!.url).pathname.slice(path.length),
              anonymousUser,
              newUser,
            });
            if (["custom", "custom-cache", "recovery", "recovery-disabled"].includes(mode)) {
              database
                .query("UPDATE user SET cargo_label=? WHERE id=?")
                .run(`Transferred ${(anonymousUser.user as any).cargoLabel}`, newUser.user.id);
            }
            if (mode === "link-ordinary") throw new Error("Configured anonymous transfer denied");
            if (mode === "link-uncoded") {
              throw new APIError("FORBIDDEN", { message: "Configured anonymous transfer denied" });
            }
            if (mode === "link-error") {
              throw new APIError("FORBIDDEN", {
                code: "APPLICATION_LINK_DENIED",
                message: "Configured anonymous transfer denied",
              });
            }
          },
        }),
      ],
    };

    if (mode === "standard" || mode.endsWith("methods") || mode === "custom") {
      const { runMigrations } = await getMigrations(options);
      await runMigrations();
    }

    profiles.set(path, betterAuth(options));
  }

  return {
    profiles,
    reset() {
      sequence = 0;
      events.length = 0;
      deliveries.clear();
    },
    async handle(request: Request) {
      const url = new URL(request.url);

      if (url.pathname === "/__test/anonymous/prepare" && request.method === "POST") {
        const { userId, expireOriginal, expireAll } = (await request.json()) as {
          userId: string;
          expireOriginal: boolean;
          expireAll?: boolean;
        };
        const { internalAdapter, adapter } = await profiles.get(
          "/__test/profiles/anonymous-recovery/api/auth",
        )!.$context;
        if (expireOriginal || expireAll) {
          await adapter.updateMany({
            model: "session",
            where: [{ field: "userId", value: userId }],
            update: { expiresAt: new Date(Date.now() - 60_000) },
          });
        }
        if (expireAll) return Response.json({ success: true });
        await internalAdapter.createSession(
          userId,
          false,
          { expiresAt: new Date(Date.now() - 60_000), ipAddress: "", userAgent: "historical" },
          true,
        );
        await internalAdapter.createSession(
          userId,
          false,
          {
            expiresAt: new Date(Date.now() + 86_400_000),
            ipAddress: "",
            userAgent: "recovery-first",
          },
          true,
        );
        await internalAdapter.createSession(
          userId,
          false,
          {
            expiresAt: new Date(Date.now() + 172_800_000),
            ipAddress: "",
            userAgent: "recovery-second",
          },
          true,
        );
        await internalAdapter.createAccount({
          userId,
          accountId: "anonymous-application-account",
          providerId: "fixture-application",
        });
        return Response.json({ success: true });
      }
      if (url.pathname === "/__test/anonymous/delivery") {
        return Response.json(deliveries.get(url.searchParams.get("key") ?? "") ?? null);
      }

      if (new URL(request.url).pathname !== "/__test/anonymous/state") {
        return null;
      }

      const { adapter } = await profiles.get("/__test/profiles/anonymous-standard/api/auth")!
        .$context;
      const [users, accounts, sessions] = await Promise.all([
        adapter.findMany<any>({ model: "user", sortBy: { field: "createdAt", direction: "asc" } }),
        adapter.findMany<any>({
          model: "account",
          sortBy: { field: "createdAt", direction: "asc" },
        }),
        adapter.findMany<any>({
          model: "session",
          sortBy: { field: "createdAt", direction: "asc" },
        }),
      ]);
      return Response.json({
        users: users.map((row) => ({
          id: row.id,
          name: row.name,
          email: row.email,
          emailVerified: row.emailVerified,
          image: row.image ?? null,
          isAnonymous: row.isAnonymous ?? false,
          cargoLabel:
            database
              .query<{ cargo_label: string | null }, [string]>(
                "SELECT cargo_label FROM user WHERE id=?",
              )
              .get(row.id)?.cargo_label ?? null,
          cargoHidden:
            database
              .query<{ cargo_hidden: string | null }, [string]>(
                "SELECT cargo_hidden FROM user WHERE id=?",
              )
              .get(row.id)?.cargo_hidden ?? null,
          createdAt: row.createdAt,
          updatedAt: row.updatedAt,
        })),
        accounts: accounts.map((row) => ({
          id: row.id,
          userId: row.userId,
          accountId: row.accountId,
          providerId: row.providerId,
          accessToken: row.accessToken ?? null,
          refreshToken: row.refreshToken ?? null,
          idToken: row.idToken ?? null,
          scope: row.scope ?? null,
          accessTokenExpiresAt: row.accessTokenExpiresAt ?? null,
          refreshTokenExpiresAt: row.refreshTokenExpiresAt ?? null,
          createdAt: row.createdAt,
          updatedAt: row.updatedAt,
        })),
        sessions: sessions.map((row) => ({
          id: row.id,
          userId: row.userId,
          token: row.token,
          expiresAt: row.expiresAt,
          createdAt: row.createdAt,
          updatedAt: row.updatedAt,
          ipAddress: row.ipAddress ?? null,
          userAgent: row.userAgent ?? null,
        })),
        events,
      });
    },
  };
}
