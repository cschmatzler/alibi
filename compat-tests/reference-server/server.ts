#!/usr/bin/env bun

import { Database } from "bun:sqlite";
import { passkey } from "@better-auth/passkey";
import { betterAuth, type BetterAuthPlugin } from "better-auth";
import { lifecycleEvents, lifecycleFixture } from "./lifecycle-fixture";
import { getMigrations } from "better-auth/db/migration";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { apiKey } from "@better-auth/api-key";
import { admin, deviceAuthorization, twoFactor, username, oneTimeToken } from "better-auth/plugins";
import { organization } from "better-auth/plugins/organization";
import { genericOAuth } from "better-auth/plugins/generic-oauth";

function getPort() {
  const idx = process.argv.indexOf("--port");
  if (idx !== -1 && process.argv[idx + 1]) {
    return Number(process.argv[idx + 1]);
  }
  return Number(process.env.PORT ?? Bun.env.PORT ?? 3100);
}

function jsonResponse(body: unknown, init?: ResponseInit) {
  return Response.json(body, init);
}

async function readJson(request: Request) {
  if (request.method === "GET" || request.method === "HEAD") {
    return null;
  }
  const text = await request.text();
  if (!text) {
    return null;
  }
  return JSON.parse(text);
}

function hasOwn(obj: unknown, key: string) {
  return !!obj && typeof obj === "object" && Object.prototype.hasOwnProperty.call(obj, key);
}

const PORT = getPort();
const database = new Database(":memory:");
const resetPasswordOutbox = new Map<string, { url: string; token: string }>();
const verificationEmailOutbox = new Map<string, { url: string; token: string }>();
const changeEmailOutbox = new Map<string, { newEmail: string; url: string; token: string }>();
const twoFactorOtpOutbox = new Map<string, { otp: string }>();
let resetPasswordMode: "capture" | "throw" = "capture";
let oauthRefreshMode: "success" | "error" = "success";
type SocialProfile = {
  sub: string;
  email: string;
  name: string;
  image: string | null;
  emailVerified: boolean;
};
const defaultSocialProfile = (): SocialProfile => ({
  sub: "google-account-id",
  email: "google@example.com",
  name: "Google Compat User",
  image: null,
  emailVerified: true,
});
let socialProfile = defaultSocialProfile();
let socialIdTokenValid = true;
type GitHubEmailRecord = {
  email: string;
  primary: boolean;
  verified: boolean;
  visibility: "public" | "private" | null;
};
type GitHubProfile = {
  id: string;
  login: string;
  name: string | null;
  email: string | null;
  avatarUrl: string | null;
  emails: GitHubEmailRecord[];
};
const defaultGitHubProfile = (): GitHubProfile => ({
  id: "github-account-id",
  login: "github-compat-user",
  name: null,
  email: null,
  avatarUrl: "https://avatars.githubusercontent.com/u/1?v=4",
  emails: [
    {
      email: "github@example.com",
      primary: true,
      verified: true,
      visibility: "private",
    },
  ],
});
let githubProfile = defaultGitHubProfile();
const oauthServer = Bun.serve({
  port: 0,
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/oauth/authorize" && request.method === "GET") {
      const redirectURI = url.searchParams.get("redirect_uri");
      const state = url.searchParams.get("state");
      if (!redirectURI || !state) {
        return jsonResponse({ message: "redirect_uri and state are required" }, { status: 400 });
      }
      const location = new URL(redirectURI);
      location.searchParams.set("code", "compat-code");
      location.searchParams.set("state", state);
      return Response.redirect(location.toString(), 302);
    }

    if (url.pathname === "/oauth/token" && request.method === "POST") {
      if (oauthRefreshMode === "error") {
        return jsonResponse(
          {
            error: "invalid_grant",
            error_description: "invalid refresh token",
          },
          { status: 400 },
        );
      }

      return jsonResponse({
        access_token: "new-access-token",
        refresh_token: "new-refresh-token",
        id_token: "google-id-token",
        expires_in: 3600,
        refresh_token_expires_in: 7200,
        scope: "openid,email,profile",
        token_type: "Bearer",
      });
    }

    if (url.pathname === "/oauth/userinfo") {
      return jsonResponse({
        sub: socialProfile.sub,
        email: socialProfile.email,
        name: socialProfile.name,
        picture: socialProfile.image,
        email_verified: socialProfile.emailVerified,
      });
    }

    return jsonResponse({ message: "Not found" }, { status: 404 });
  },
});
const oauthBaseURL = `http://127.0.0.1:${oauthServer.port}`;

const originalFetch = globalThis.fetch.bind(globalThis);
globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
  const request = input instanceof Request ? input : new Request(input, init);
  const url = new URL(request.url);

  if (url.origin === "https://oauth2.googleapis.com" && url.pathname === "/token") {
    if (oauthRefreshMode === "error") {
      return jsonResponse(
        {
          error: "invalid_grant",
          error_description: "invalid refresh token",
        },
        { status: 400 },
      );
    }

    return jsonResponse({
      access_token: "google-access-token",
      refresh_token: "google-refresh-token",
      id_token: "google-id-token",
      expires_in: 3600,
      refresh_token_expires_in: 7200,
      scope: "openid email profile",
      token_type: "Bearer",
    });
  }

  if (url.origin === "https://github.com" && url.pathname === "/login/oauth/access_token") {
    if (oauthRefreshMode === "error") {
      return jsonResponse(
        {
          error: "invalid_grant",
          error_description: "invalid refresh token",
        },
        { status: 400 },
      );
    }

    return jsonResponse({
      access_token: "github-access-token",
      refresh_token: "github-refresh-token",
      expires_in: 3600,
      refresh_token_expires_in: 7200,
      scope: "read:user user:email",
      token_type: "bearer",
    });
  }

  if (url.origin === "https://api.github.com" && url.pathname === "/user") {
    return jsonResponse({
      id: githubProfile.id,
      login: githubProfile.login,
      name: githubProfile.name,
      email: githubProfile.email,
      avatar_url: githubProfile.avatarUrl,
    });
  }

  if (url.origin === "https://api.github.com" && url.pathname === "/user/emails") {
    return jsonResponse(githubProfile.emails);
  }

  return originalFetch(request);
};

const authOptions = {
  baseURL: `http://localhost:${PORT}`,
  basePath: "/api/auth",
  secret: ["compat", "test", "only", "key", "not", "real", "minimum", "32chars"].join("-"),
  database,
  emailAndPassword: {
    enabled: true,
    requireEmailVerification: false,
    minPasswordLength: 8,
    async sendResetPassword({ user, url, token }: { user: { email?: string } | null; url: string; token: string }) {
      if (resetPasswordMode === "throw") {
        throw new Error("compat reset sender failure");
      }
      if (user?.email) {
        resetPasswordOutbox.set(user.email, { url, token });
      }
    },
  },
  emailVerification: {
    async sendVerificationEmail({
      user,
      url,
      token,
    }: {
      user: { email?: string } | null;
      url: string;
      token: string;
    }) {
      if (user?.email) {
        verificationEmailOutbox.set(user.email, { url, token });
      }
    },
  },
  user: {
    changeEmail: {
      enabled: true,
      async sendChangeEmailConfirmation({
        user,
        newEmail,
        url,
        token,
      }: {
        user: { email?: string } | null;
        newEmail: string;
        url: string;
        token: string;
      }) {
        if (user?.email) {
          changeEmailOutbox.set(user.email, { newEmail, url, token });
        }
      },
    },
    deleteUser: {
      enabled: true,
    },
  },
  rateLimit: {
    enabled: false,
  },
  socialProviders: {
    github: {
      clientId: "github-client-id",
      clientSecret: "github-client-secret",
      authorizationEndpoint: `${oauthBaseURL}/oauth/authorize`,
    },
    google: {
      clientId: "google-client-id",
      clientSecret: "google-client-secret",
      enabled: true,
      authorizationEndpoint: `${oauthBaseURL}/oauth/authorize`,
      async verifyIdToken() {
        return socialIdTokenValid;
      },
      async getUserInfo() {
        return {
          user: {
            id: socialProfile.sub,
            email: socialProfile.email,
            name: socialProfile.name,
            image: socialProfile.image ?? undefined,
            emailVerified: socialProfile.emailVerified,
          },
          data: {
            sub: socialProfile.sub,
            email: socialProfile.email,
            email_verified: socialProfile.emailVerified,
            name: socialProfile.name,
            picture: socialProfile.image,
          },
        };
      },
      async refreshAccessToken() {
        if (oauthRefreshMode === "error") {
          throw new Error("invalid refresh token");
        }

        return {
          accessToken: "google-access-token",
          refreshToken: "google-refresh-token",
          idToken: "google-id-token",
          accessTokenExpiresAt: new Date(Date.now() + 3600_000),
          refreshTokenExpiresAt: new Date(Date.now() + 7200_000),
          scopes: ["openid", "email", "profile"],
        };
      },
    },
  },
  plugins: [
    lifecycleFixture(),
    admin(),
    apiKey([
      { configId: "default", enableMetadata: true },
      { configId: "secondary", enableMetadata: true },
      { configId: "session", enableSessionForAPIKeys: true, apiKeyHeaders: ["x-api-key", "x-machine-key"] },
      { configId: "shared-first", enableSessionForAPIKeys: true, apiKeyHeaders: "x-shared-key" },
      { configId: "shared-second", enableSessionForAPIKeys: true, apiKeyHeaders: "x-shared-key" },
      { configId: "organization", references: "organization", enableMetadata: true },
    ]),
    deviceAuthorization(),
    organization(),
    passkey(),
    twoFactor({
      otpOptions: {
        async sendOTP({ user, otp }) {
          if (user.email) {
            twoFactorOtpOutbox.set(user.email, { otp });
          }
        },
      },
    }),
    username(),
    genericOAuth({
      config: [
        {
          providerId: "mock",
          authorizationUrl: `${oauthBaseURL}/oauth/authorize`,
          tokenUrl: `${oauthBaseURL}/oauth/token`,
          userInfoUrl: `${oauthBaseURL}/oauth/userinfo`,
          clientId: "mock-client-id",
          clientSecret: "mock-client-secret",
          scopes: ["openid", "email", "profile"],
          pkce: true,
          async getUserInfo() {
            return {
              id: "mock-account-id",
              email: "mock@example.com",
              name: "Mock OAuth User",
              image: null,
              emailVerified: true,
            };
          },
        },
      ],
    }),
  ],
} as const;

const { runMigrations } = await getMigrations(authOptions);
await runMigrations();

// Explicit configuration fixtures invoke the unchanged pinned runtime.
const verificationProfiles = new Map<string, ReturnType<typeof betterAuth>>();
for (const name of ["email-verification-required", "email-verification-no-signup-mail", "email-verification-failing-notifications"]) {
  const path = `/__test/profiles/${name}/api/auth`;
  const instance = betterAuth({
    ...authOptions,
    basePath: path,
    emailAndPassword: { ...authOptions.emailAndPassword, requireEmailVerification: true },
    emailVerification: {
      expiresIn: 90,
      sendOnSignUp: name === "email-verification-no-signup-mail" ? false : undefined,
      sendOnSignIn: true,
      async sendVerificationEmail({ user, url, token }) {
        verificationEmailOutbox.set(user.email, { url, token });
        if (name === "email-verification-failing-notifications") {
          throw new APIError("BAD_REQUEST", { message: "fixture delivery failed" });
        }
      },
    },
    plugins: [],
  });
  verificationProfiles.set(path, instance);
}

for (const name of ["session-deferred", "session-no-refresh", "session-deferred-no-refresh", "session-no-freshness", "session-cookie-cleanup"]) {
  const path = `/__test/profiles/${name}/api/auth`;
  verificationProfiles.set(path, betterAuth({
    ...authOptions,
    basePath: path,
    session: { ...authOptions.session, deferSessionRefresh: name.startsWith("session-deferred"), disableSessionRefresh: name.endsWith("no-refresh"), ...(name === "session-no-freshness" ? { freshAge: 0 } : {}) },
    ...(name === "session-cookie-cleanup" ? { account: { ...authOptions.account, storeAccountCookie: true, storeStateStrategy: "cookie" } } : {}),
  }));
}

const auth = betterAuth(authOptions);
const authContext = await auth.$context;

const OTT_PROFILE_NAMES=["ott-default","ott-hashed","ott-no-cookie","ott-server-header","ott-refresh-disabled","ott-refresh-deferred"] as const;
const ottExposedHeaderFixture: BetterAuthPlugin = {
  id: "ott-exposed-header-fixture",
  hooks: { after: [{ matcher: () => true, handler: createAuthMiddleware(async ctx => {
    ctx.setHeader("access-control-expose-headers", " existing, ,existing, set-ott, set-ott, Existing ");
  }) }] },
};
const ottProfiles=new Map(OTT_PROFILE_NAMES.map(name=>{
  const options={...authOptions,basePath:`/__test/profiles/${name}/api/auth`,session:{disableSessionRefresh:name==="ott-refresh-disabled",deferSessionRefresh:name==="ott-refresh-deferred"},plugins:[...authOptions.plugins,...(name==="ott-server-header" ? [ottExposedHeaderFixture] : []),oneTimeToken({
    storeToken:name==="ott-hashed" ? "hashed" : "plain",
    disableSetSessionCookie:name==="ott-no-cookie",
    disableClientRequest:name==="ott-server-header",
    setOttHeaderOnNewSession:name==="ott-server-header",
  })]};
  return [name,{auth:betterAuth(options),options}] as const;
}));

const RESET_MODELS = [
  "deviceCode",
  "passkey",
  "apikey",
  "invitation",
  "member",
  "organization",
  "verification",
  "account",
  "session",
  "user",
] as const;

async function resetDatabaseState() {
  for (const model of RESET_MODELS) {
    await authContext.adapter.deleteMany({
      model,
      where: [],
    });
  }
}


function controlRecord(value: unknown): value is Record<string,unknown> {
  return value!==null && typeof value==="object" && !Array.isArray(value);
}
async function oneTimeTokenControl(request:Request,url:URL):Promise<Response|undefined> {
  if (url.pathname==="/__test/verification-state" && request.method==="GET") {
    const identifier=url.searchParams.get("identifier");
    if (!identifier) return jsonResponse({message:"identifier is required"},{status:400});
    return jsonResponse(await authContext.adapter.findMany({model:"verification",where:[{field:"identifier",value:identifier}],sortBy:{field:"createdAt",direction:"desc"}}));
  }
  if (request.method!=="POST" || !["/__test/verification-state","/__test/expire-session","/__test/one-time-token"].includes(url.pathname)) return;
  const body:unknown=await readJson(request);
  if (!controlRecord(body)) return jsonResponse({message:"invalid server operation"},{status:400});
  if (url.pathname==="/__test/one-time-token") {
    const selected=ottProfiles.get(typeof body.profile==="string" ? body.profile as typeof OTT_PROFILE_NAMES[number] : "ott-default")?.auth;
    if (!selected || body.operation!=="generate") return jsonResponse({message:"invalid server operation"},{status:400});
    return jsonResponse(await selected.api.generateOneTimeToken({headers:request.headers}));
  }
  if (typeof body.expiresAt!=="string" || !Number.isFinite(Date.parse(body.expiresAt))) return jsonResponse({message:"valid expiresAt is required"},{status:400});
  const expiresAt=new Date(body.expiresAt);
  if (url.pathname==="/__test/expire-session" && typeof body.token==="string") {
    await authContext.adapter.updateMany({model:"session",where:[{field:"token",value:body.token}],update:{expiresAt}});
  } else if (url.pathname==="/__test/verification-state" && typeof body.identifier==="string") {
    if (body.action==="seed" && typeof body.value==="string") await authContext.internalAdapter.createVerificationValue({identifier:body.identifier,value:body.value,expiresAt});
    else if (body.action==="expire") await authContext.adapter.updateMany({model:"verification",where:[{field:"identifier",value:body.identifier}],update:{expiresAt}});
    else return jsonResponse({message:"unknown action"},{status:400});
  } else return jsonResponse({message:"selector is required"},{status:400});
  return jsonResponse({status:true});
}

const server = Bun.serve({
  port: PORT,
  async fetch(request) {
    try {
      const url = new URL(request.url);
      for(const [name,profile] of ottProfiles) {
        if(url.pathname.startsWith(`/__test/profiles/${name}/api/auth/`)) return profile.auth.handler(request);
      }
      const ottControl=await oneTimeTokenControl(request,url);
      if(ottControl) return ottControl;


      if (url.pathname === "/__test/lifecycle" && request.method === "GET") {
        const email = url.searchParams.get("email");
        const user = email ? await authContext.internalAdapter.findUserByEmail(email, {includeAccounts:true}) : null;
        const sessions = user?.user ? await authContext.adapter.findMany({model:"session",where:[{field:"userId",value:user.user.id}]}) : [];
        const state = !email ? null : !user?.user ? {userId:null,accounts:[],sessions:[]} : {
          userId:user.user.id,
          accounts:user.accounts.map(row => ({id:row.id,userId:row.userId,providerId:row.providerId})),
          sessions:sessions.map(row => ({id:row.id,userId:row.userId,token:row.token})),
        };
        return jsonResponse({events:lifecycleEvents.splice(0),state});
      }

      if (url.pathname === "/__health") {
        return jsonResponse({ ok: true, oauthBaseURL });
      }

      if (url.pathname === "/__test/password" && request.method === "POST") {
        const body = (await readJson(request)) as {
          operation?: string;
          password?: string;
          hash?: string;
          email?: string;
        } | null;
        if (body?.operation === "hash" && typeof body.password === "string") {
          return jsonResponse({ hash: await authContext.password.hash(body.password) });
        }
        if (body?.operation === "verify" && typeof body.password === "string" && typeof body.hash === "string") {
          return jsonResponse({
            valid: await authContext.password.verify({ password: body.password, hash: body.hash }),
          });
        }
        if ((body?.operation === "import" || body?.operation === "credential") && typeof body.email === "string") {
          const user = await authContext.internalAdapter.findUserByEmail(body.email, {
            includeAccounts: true,
          });
          const account = user?.accounts.find((entry) => entry.providerId === "credential");
          if (!user?.user || !account) {
            return jsonResponse({ message: "Credential not found" }, { status: 404 });
          }
          if (body.operation === "import") {
            if (typeof body.hash !== "string") {
              return jsonResponse({ message: "hash is required" }, { status: 400 });
            }
            await authContext.internalAdapter.updateAccount(account.id, { password: body.hash });
          }
          const persisted = await authContext.adapter.findOne<typeof account>({
            model: "account",
            where: [{ field: "id", value: account.id }],
          });
          return jsonResponse({ userId: user.user.id, accountId: account.id, hash: persisted?.password ?? null });
        }
        return jsonResponse({ message: "Invalid password operation" }, { status: 400 });
      }

      if (url.pathname === "/__test/api-key/create" && request.method === "POST") {
        return jsonResponse(await auth.api.createApiKey({ body: await readJson(request) }));
      }
      if (url.pathname === "/__test/api-key/update" && request.method === "POST") {
        return jsonResponse(await auth.api.updateApiKey({ body: await readJson(request) }));
      }
      if (url.pathname === "/__test/api-key/verify" && request.method === "POST") {
        return jsonResponse(await auth.api.verifyApiKey({ body: await readJson(request) }));
      }

      if (url.pathname === "/__test/reset-state" && request.method === "POST") {
        await resetDatabaseState();
        resetPasswordOutbox.clear();
        verificationEmailOutbox.clear();
        changeEmailOutbox.clear();
        twoFactorOtpOutbox.clear();
        resetPasswordMode = "capture";
        oauthRefreshMode = "success";
        socialProfile = defaultSocialProfile();
        socialIdTokenValid = true;
        githubProfile = defaultGitHubProfile();
        return jsonResponse({ status: true });
      }

      if (url.pathname === "/__test/organization-timestamps" && request.method === "POST") {
        const body = await readJson(request) as { organizationId: string; memberId: string; createdAt: string };
        const orgWhere = [{ field: "id", value: body.organizationId }];
        const memberWhere = [{ field: "id", value: body.memberId }];
        const org = await authContext.adapter.findOne<Record<string, unknown>>({ model: "organization", where: orgWhere });
        const member = await authContext.adapter.findOne<Record<string, unknown>>({ model: "member", where: memberWhere });
        if (!org || !member || member.organizationId !== org.id) return jsonResponse({ message: "Not found" }, { status: 404 });
        const createdAt = new Date(body.createdAt);
        await authContext.adapter.update({ model: "organization", where: orgWhere, update: { createdAt } });
        await authContext.adapter.update({ model: "member", where: memberWhere, update: { createdAt } });
        const persistedOrg = await authContext.adapter.findOne<Record<string, unknown>>({ model: "organization", where: orgWhere });
        const persistedMember = await authContext.adapter.findOne<Record<string, unknown>>({ model: "member", where: memberWhere });
        return jsonResponse({ organizationId: persistedOrg!.id, memberId: persistedMember!.id, userId: persistedMember!.userId, organizationCreatedAtMillis: new Date(persistedOrg!.createdAt as Date).getTime(), memberCreatedAtMillis: new Date(persistedMember!.createdAt as Date).getTime() });
      }

      if (url.pathname === "/__test/expire-session" && request.method === "POST") {
        const body = await readJson(request);
        if (typeof body?.token !== "string" || typeof body?.expiresAt !== "string") return jsonResponse({ message: "Invalid session clock" }, { status: 400 });
        const result = database.query('UPDATE session SET expiresAt = ? WHERE token = ?').run(new Date(body.expiresAt).toISOString(), body.token);
        if (typeof body.createdAt === "string") database.query('UPDATE session SET createdAt = ? WHERE token = ?').run(new Date(body.createdAt).toISOString(), body.token);
        return jsonResponse({ updated: result.changes });
      }

      if (url.pathname === "/__test/user-state" && request.method === "GET") {
        const userId = url.searchParams.get("userId");
        if (!userId) return jsonResponse({ message: "userId is required" }, { status: 400 });
        const where = [{ field: "userId", value: userId }];
        const [user, accounts, sessions, twoFactor] = await Promise.all([
          authContext.adapter.findOne<Record<string, unknown>>({ model: "user", where: [{ field: "id", value: userId }] }),
          authContext.adapter.findMany<Record<string, unknown>>({ model: "account", where }),
          authContext.adapter.findMany<Record<string, unknown>>({ model: "session", where, sortBy: { field: "createdAt", direction: "asc" } }),
          authContext.adapter.findOne({ model: "twoFactor", where }),
        ]);
        return jsonResponse({
          user: user ? { id: user.id, email: user.email, emailVerified: user.emailVerified, twoFactorEnabled: user.twoFactorEnabled } : null,
          accounts: accounts.sort((left, right) => String(left.providerId).localeCompare(String(right.providerId)) || String(left.accountId).localeCompare(String(right.accountId))).map(account => ({ id: account.id, userId: account.userId, accountId: account.accountId, providerId: account.providerId })),
          sessions: sessions.map(session => ({ id: session.id, token: session.token, userId: session.userId, expiresAt: session.expiresAt })),
          twoFactorExists: twoFactor !== null,
        });
      }

      if (url.pathname === "/__test/verification-email" && request.method === "GET") {
        const email = url.searchParams.get("email");
        const record = email ? verificationEmailOutbox.get(email) ?? null : null;
        return record
          ? jsonResponse(record)
          : jsonResponse({ message: "Not found" }, { status: 404 });
      }

      if (url.pathname === "/__test/change-email-confirmation" && request.method === "GET") {
        const email = url.searchParams.get("email");
        const record = email ? changeEmailOutbox.get(email) ?? null : null;
        return record
          ? jsonResponse(record)
          : jsonResponse({ message: "Not found" }, { status: 404 });
      }

      if (url.pathname === "/__test/reset-password-token" && request.method === "GET") {
        const email = url.searchParams.get("email");
        const record = email ? resetPasswordOutbox.get(email) ?? null : null;
        return record
          ? jsonResponse(record)
          : jsonResponse({ message: "Not found" }, { status: 404 });
      }

      if (url.pathname === "/__test/two-factor-otp" && request.method === "GET") {
        const email = url.searchParams.get("email");
        const record = email ? twoFactorOtpOutbox.get(email) ?? null : null;
        return record
          ? jsonResponse(record)
          : jsonResponse({ message: "Not found" }, { status: 404 });
      }

      if (url.pathname === "/__test/view-backup-codes" && request.method === "GET") {
        const userId = url.searchParams.get("userId");
        if (!userId) {
          return jsonResponse({ message: "userId is required" }, { status: 400 });
        }

        try {
          const result = await auth.api.viewBackupCodes({
            body: {
              userId,
            },
          });
          return jsonResponse(result);
        } catch (error) {
          const message = error instanceof Error ? error.message : "Unknown error";
          return jsonResponse({ message }, { status: 500 });
        }
      }

      if (url.pathname === "/__test/set-reset-password-mode" && request.method === "POST") {
        const body = (await readJson(request)) as { mode?: string } | null;
        resetPasswordMode = body?.mode === "throw" ? "throw" : "capture";
        return jsonResponse({ status: true, mode: resetPasswordMode });
      }

      if (url.pathname === "/__test/seed-reset-password-token" && request.method === "POST") {
        const body = (await readJson(request)) as {
          email?: string;
          token?: string;
          expiresAt?: string;
        } | null;
        const email = body?.email;
        const token = body?.token;
        const expiresAt = body?.expiresAt;
        const user = email
          ? await authContext.internalAdapter.findUserByEmail(email, {
              includeAccounts: true,
            })
          : null;

        if (!user?.user || !token || !expiresAt) {
          return jsonResponse(
            { message: "email, token, and expiresAt are required" },
            { status: 400 },
          );
        }

        await authContext.internalAdapter.createVerificationValue({
          value: user.user.id,
          identifier: `reset-password:${token}`,
          expiresAt: new Date(expiresAt),
        });

        return jsonResponse({ status: true });
      }

      if (url.pathname === "/__test/seed-delete-user-token" && request.method === "POST") {
        const body = (await readJson(request)) as {
          email?: string;
          token?: string;
          expiresAt?: string;
        } | null;
        const email = body?.email;
        const token = body?.token;
        const expiresAt = body?.expiresAt;
        const user = email
          ? await authContext.internalAdapter.findUserByEmail(email, {
              includeAccounts: true,
            })
          : null;

        if (!user?.user || !token || !expiresAt) {
          return jsonResponse(
            { message: "email, token, and expiresAt are required" },
            { status: 400 },
          );
        }

        await authContext.internalAdapter.createVerificationValue({
          value: user.user.id,
          identifier: `delete-account-${token}`,
          expiresAt: new Date(expiresAt),
        });

        return jsonResponse({ status: true });
      }

      if (url.pathname === "/__test/remove-credential-account" && request.method === "POST") {
        const body = (await readJson(request)) as { email?: string } | null;
        const email = body?.email;
        const user = email
          ? await authContext.internalAdapter.findUserByEmail(email, {
              includeAccounts: true,
            })
          : null;

        if (!user?.user) {
          return jsonResponse({ message: "User not found" }, { status: 404 });
        }

        for (const account of user.accounts ?? []) {
          if (account.providerId === "credential") {
            await authContext.internalAdapter.deleteAccount(account.id);
          }
        }

        return jsonResponse({ status: true });
      }

      if (url.pathname === "/__test/promote-admin" && request.method === "POST") {
        const body = (await readJson(request)) as { email?: string } | null;
        const email = body?.email;
        const user = email
          ? await authContext.internalAdapter.findUserByEmail(email, {
              includeAccounts: true,
            })
          : null;

        if (!user?.user) {
          return jsonResponse({ message: "User not found" }, { status: 404 });
        }

        await authContext.internalAdapter.updateUser(user.user.id, {
          role: "admin",
        });

        return jsonResponse({ status: true });
      }

      if (url.pathname === "/__test/set-oauth-refresh-mode" && request.method === "POST") {
        const body = (await readJson(request)) as { mode?: string } | null;
        oauthRefreshMode = body?.mode === "error" ? "error" : "success";
        return jsonResponse({ status: true, mode: oauthRefreshMode });
      }

      if (url.pathname === "/__test/set-social-profile" && request.method === "POST") {
        const body = (await readJson(request)) as Partial<SocialProfile> & {
          idTokenValid?: boolean;
        } | null;
        socialProfile = {
          ...socialProfile,
          ...(body?.sub ? { sub: body.sub } : {}),
          ...(body?.email ? { email: body.email } : {}),
          ...(body?.name ? { name: body.name } : {}),
          ...(body && hasOwn(body, "image") ? { image: body.image ?? null } : {}),
          ...(typeof body?.emailVerified === "boolean"
            ? { emailVerified: body.emailVerified }
            : {}),
        };
        if (typeof body?.idTokenValid === "boolean") {
          socialIdTokenValid = body.idTokenValid;
        }
        return jsonResponse({ status: true, profile: socialProfile, idTokenValid: socialIdTokenValid });
      }

      if (url.pathname === "/__test/set-github-profile" && request.method === "POST") {
        const body = (await readJson(request)) as Partial<GitHubProfile> | null;
        githubProfile = {
          ...githubProfile,
          ...(body?.id ? { id: body.id } : {}),
          ...(body?.login ? { login: body.login } : {}),
          ...(body && hasOwn(body, "name") ? { name: body.name ?? null } : {}),
          ...(body && hasOwn(body, "email") ? { email: body.email ?? null } : {}),
          ...(body && hasOwn(body, "avatarUrl") ? { avatarUrl: body.avatarUrl ?? null } : {}),
          ...(Array.isArray(body?.emails) ? { emails: body.emails } : {}),
        };
        return jsonResponse({ status: true, profile: githubProfile });
      }

      if (url.pathname === "/__test/seed-oauth-account" && request.method === "POST") {
        const body = (await readJson(request)) as {
          email?: string;
          providerId?: string;
          accountId?: string;
          accessToken?: string | null;
          refreshToken?: string | null;
          idToken?: string | null;
          accessTokenExpiresAt?: string | null;
          refreshTokenExpiresAt?: string | null;
          scope?: string | null;
        } | null;
        const email = body?.email;
        const user = email
          ? await authContext.internalAdapter.findUserByEmail(email, {
              includeAccounts: true,
            })
          : null;

        if (!user?.user) {
          return jsonResponse({ message: "User not found" }, { status: 404 });
        }

        const providerId = body?.providerId ?? "mock";
        const accountId = body?.accountId ?? "mock-account-id";
        const existing = user.accounts?.find(
          (account) => account.providerId === providerId && account.accountId === accountId,
        );

        const accountData = {
          accessToken: hasOwn(body, "accessToken") ? body?.accessToken ?? null : "stale-access-token",
          refreshToken: hasOwn(body, "refreshToken") ? body?.refreshToken ?? null : "seed-refresh-token",
          idToken: hasOwn(body, "idToken") ? body?.idToken ?? null : "seed-id-token",
          accessTokenExpiresAt: hasOwn(body, "accessTokenExpiresAt")
            ? body?.accessTokenExpiresAt
              ? new Date(body.accessTokenExpiresAt)
              : null
            : new Date(Date.now() - 60_000),
          refreshTokenExpiresAt: hasOwn(body, "refreshTokenExpiresAt")
            ? body?.refreshTokenExpiresAt
              ? new Date(body.refreshTokenExpiresAt)
              : null
            : null,
          scope: hasOwn(body, "scope") ? body?.scope ?? null : "openid,email,profile",
        };

        let localAccountId = existing?.id;
        if (existing?.id) {
          await authContext.internalAdapter.updateAccount(existing.id, accountData);
        } else {
          const account = await authContext.internalAdapter.createAccount({
            userId: user.user.id,
            providerId,
            accountId,
            ...accountData,
          });
          localAccountId = account.id;
        }

        return jsonResponse({ status: true, accountId: localAccountId });
      }

      for (const [path, instance] of verificationProfiles) {
        if (url.pathname.startsWith(`${path}/`)) return instance.handler(request);
      }
      return auth.handler(request);
    } catch (error) {
      console.error("[reference-server] Error:", error);
      return jsonResponse({ message: "Internal server error" }, { status: 500 });
    }
  },
});

console.log(`[reference-server] Listening on http://localhost:${PORT}`);
console.log("READY");

for (const signal of ["SIGTERM", "SIGINT"]) {
  process.on(signal, () => {
    server.stop(true);
    oauthServer.stop(true);
    process.exit(0);
  });
}
