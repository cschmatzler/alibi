#!/usr/bin/env bun

import { Database } from "bun:sqlite";
import { openApiProfiles } from "./open-api-fixture";
import { passkey } from "@better-auth/passkey";
import { betterAuth, type BetterAuthPlugin } from "better-auth";
import { lifecycleEvents, lifecycleFixture } from "./lifecycle-fixture";
import { createTwoFactorPolicyFixture } from "./two-factor-policy-fixture";
import { createTwoFactorOtpFixture } from "./two-factor-otp-fixture";
import { createTwoFactorTotpFixture } from "./two-factor-totp-fixture";
import { createOrganizationCreationFixture } from "./organization-creation-fixture";
import { createSiweFixture } from "./siwe-fixture";
import { createPhoneFixture } from "./phone-fixture";
import { createAdminPermissionFixture } from "./admin-permission-fixture";
import { createMultipleSessionFixture } from "./multiple-session-fixture";
import { createSessionFieldsFixture } from "./session-fields-fixture";
import { getMigrations } from "better-auth/db/migration";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { apiKey } from "@better-auth/api-key";
import { admin, deviceAuthorization, emailOTP, magicLink, twoFactor, username, jwt, oneTimeToken } from "better-auth/plugins";
import { organization } from "better-auth/plugins/organization";
import { createAccessControl } from "better-auth/plugins/access";
import { defaultStatements } from "better-auth/plugins/organization/access";
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

const magicLinkOutbox=new Map<string,{url:string;token:string;metadata:unknown}>();
const magicPlugin=()=>magicLink({async sendMagicLink({email,url,token,metadata}) {magicLinkOutbox.set(email,{url,token,metadata:metadata ?? null});}});
const emailOtpOutbox=new Map<string,{otp:string}>();
const emailOtp=()=>emailOTP({changeEmail:{enabled:true},async sendVerificationOTP({email,otp,type}) {emailOtpOutbox.set(`${type}:${email}`,{otp});}});

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
    emailOtp(),
    magicPlugin(),
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
const sessionFieldsFixture=await createSessionFieldsFixture(database,authOptions,`http://localhost:${PORT}`);
const siweFixture = await createSiweFixture(database, authOptions, `http://localhost:${PORT}`);
const adminPermissionFixture = createAdminPermissionFixture(authOptions, database);
const multipleSessionFixture = createMultipleSessionFixture(authOptions);
const organizationCreationFixture = createOrganizationCreationFixture(database, authOptions, `http://localhost:${PORT}`);

// Explicit configuration fixtures invoke the unchanged pinned runtime.
const verificationProfiles = new Map<string, ReturnType<typeof betterAuth>>();
for (const [path, instance] of siweFixture.profiles) verificationProfiles.set(path, instance);
for (const [path, instance] of adminPermissionFixture.profiles) verificationProfiles.set(path, instance);
for (const [path, instance] of multipleSessionFixture.profiles) verificationProfiles.set(path, instance);
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

function createOtpProfile(name:string) {
  const proof=name.startsWith("passwordless-proof");
  return betterAuth({
    ...authOptions,
    basePath:`/__test/profiles/${name}/api/auth`,
    verification:{disableCleanup:name==="verification-no-cleanup"},
    emailVerification: name==="passwordless-proof" ? {sendOnSignUp:false,autoSignInAfterVerification:true} : {...authOptions.emailVerification,sendOnSignUp:false,autoSignInAfterVerification:proof},
    plugins:[emailOTP({
      storeOTP:name==="passwordless-hashed" ? "hashed" : name==="passwordless-encrypted-reuse" ? "encrypted" : "plain",
      resendStrategy:name==="passwordless-encrypted-reuse" ? "reuse" : "rotate",
      disableSignUp:name==="passwordless-disabled",overrideDefaultEmailVerification:proof,
      changeEmail:{enabled:true,verifyCurrentEmail:proof},
      async sendVerificationOTP({email,otp,type}) {emailOtpOutbox.set(`${type}:${email}`,{otp});}
    })]
  });
}
const otpProfiles=new Map<string,ReturnType<typeof createOtpProfile>>();
for (const name of ["passwordless-hashed","passwordless-encrypted-reuse","passwordless-proof","passwordless-proof-explicit","passwordless-disabled","verification-cleanup","verification-no-cleanup"]) {
  otpProfiles.set(name,createOtpProfile(name));
}

const magicProfiles = new Map<string, ReturnType<typeof betterAuth>>();
for (const name of ["magic-link-hashed", "magic-link-disabled"]) {
  magicProfiles.set(name, betterAuth({
    ...authOptions,
    basePath: `/__test/profiles/${name}/api/auth`,
    emailVerification: {...authOptions.emailVerification, sendOnSignUp:false},
    plugins: [magicLink({
      storeToken: name === "magic-link-hashed" ? "hashed" : "plain",
      disableSignUp: name === "magic-link-disabled",
      async sendMagicLink({email,url,token,metadata}) {magicLinkOutbox.set(email,{url,token,metadata:metadata ?? null});}
    })],
  }));
}

const phoneFixture = await createPhoneFixture(authOptions, twoFactorOtpOutbox);
const twoFactorTotpFixture = createTwoFactorTotpFixture(authOptions);
const twoFactorPolicyFixture = createTwoFactorPolicyFixture(authOptions, database);
const twoFactorOtpFixture = createTwoFactorOtpFixture(authOptions, database);
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
const deviceProfiles = new Map(["device-custom","device-configured","device-unicode","device-too-long"].map(name => {
  const options = { ...authOptions, basePath:`/__test/profiles/${name}/api/auth`, plugins:[deviceAuthorization({
    ...(name === "device-custom" ? {generateDeviceCode:async()=>"custom-device-🔐",generateUserCode:async()=>" café-Code! "} : {}),
    ...(name === "device-configured" ? {expiresIn:"120s",interval:"2s",verificationUri:"https://verification.fixture/device?keep=a&user_code=old&keep=b&user_code=other#fragment",validateClient:async(clientId:string)=>clientId==="allowed-client"} : {}),
    ...(name === "device-unicode" ? {generateDeviceCode:async()=>"😀".repeat(191),generateUserCode:()=>"boundary-user"} : {}),
    ...(name === "device-too-long" ? {generateDeviceCode:async()=>"😀".repeat(192)} : {}),
  })] };
  return [name,betterAuth(options)] as const;
}));
const JWT_PROFILE_NAMES = ["jwt-default", "jwt-es256", "jwt-es512", "jwt-rs256", "jwt-ps256", "jwt-claims", "jwt-path-header", "jwt-plain-rotation", "jwt-session-normal", "jwt-session-disabled", "jwt-session-deferred"] as const;
const jwtProfiles = new Map(JWT_PROFILE_NAMES.map(name => {
  const sessionProfile = name.startsWith("jwt-session-");
  const options = {
    ...authOptions,
    basePath: `/__test/profiles/${name}/api/auth`,
    session: {...authOptions.session, disableSessionRefresh:name === "jwt-session-disabled", deferSessionRefresh:name === "jwt-session-deferred"},
    plugins: [...authOptions.plugins.filter(plugin => !sessionProfile || plugin.id !== "api-key"),
      ...(sessionProfile ? [apiKey({enableSessionForAPIKeys:true,enableMetadata:true})] : []),
      ...(sessionProfile ? [{id:"jwt-earlier-exposed-headers",hooks:{after:[{matcher:ctx=>ctx.path === "/get-session",handler:createAuthMiddleware(async ctx=>{
        ctx.setHeader("access-control-expose-headers"," existing, ,existing, set-auth-jwt, set-auth-jwt, Existing ");
      })}]}} satisfies BetterAuthPlugin] : []),
      jwt({
      jwks: {
        keyPairConfig: name === "jwt-es256" ? {alg:"ES256",crv:"P-256"} : name === "jwt-es512" ? {alg:"ES512",crv:"P-521"} : name === "jwt-rs256" ? {alg:"RS256"} : name === "jwt-ps256" ? {alg:"PS256"} : {alg:"EdDSA",crv:"Ed25519"},
        ...(name === "jwt-path-header" ? {jwksPath:"/.well-known/jwks.json"} : {}),
        ...(name === "jwt-plain-rotation" ? {disablePrivateKeyEncryption:true,rotationInterval:3600,gracePeriod:3600} : {}),
      },
      ...(name === "jwt-claims" ? {jwt:{issuer:"fixture-issuer",audience:"fixture-audience",expirationTime:"60s"}} : {}),
      ...(sessionProfile ? {jwt:{definePayload:session=>({snapshot:session})}} : {}),
      disableSettingJwtHeader:name === "jwt-path-header",
    })],
  };
  return [name,{auth:betterAuth(options),options}] as const;
}));
await (await getMigrations(jwtProfiles.get("jwt-default")!.options)).runMigrations();

function jwtRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

type RolePolicyBarrier = {entered:Promise<void>; enter:()=>void; released:Promise<void>; release:()=>void};
const rolePolicyBarriers = new Map<string,RolePolicyBarrier>();
async function waitForRolePolicy(promise:Promise<void>, message:string) {
  let timer:ReturnType<typeof setTimeout>|undefined;
  try { await Promise.race([promise,new Promise<void>((_,reject)=>{timer=setTimeout(()=>reject(new Error(message)),10000);})]); }
  finally { if (timer !== undefined) clearTimeout(timer); }
}

const TEAM_PROFILES = ["org-teams", "org-teams-no-default", "org-teams-limited", "org-teams-removable", "org-teams-dynamic", "org-roles-limited", "org-roles-no-ac", "org-roles-delegated", "org-roles-callback"] as const;
const teamProfiles = new Map(TEAM_PROFILES.map(name => {
  const dynamic = name === "org-teams-dynamic" || name.startsWith("org-roles-");
  const statements = name === "org-roles-delegated" ? {...defaultStatements,apiKey:["create","read","update","delete"]} as const : defaultStatements;
  const ac = createAccessControl(statements);
  const options = {
    ...authOptions,
    basePath: `/__test/profiles/${name}/api/auth`,
    ...(name === "org-roles-callback" ? {advanced:{...authOptions.advanced,database:{defaultFindManyLimit:1}}} : {}),
    plugins: [
      ...authOptions.plugins.filter(plugin => plugin.id !== "organization"),
      organization({
        ...(dynamic ? {dynamicAccessControl:{enabled:true,
          ...(name === "org-roles-limited" ? {maximumRolesPerOrganization:1} : {}),
          ...(name === "org-roles-callback" ? {maximumRolesPerOrganization:async (organizationId:string) => {
            const barrier = rolePolicyBarriers.get(organizationId);
            if (barrier) { barrier.enter(); await waitForRolePolicy(barrier.released,"Role policy release timed out"); }
            const row = database.query("SELECT name FROM organization WHERE id=?").get(organizationId) as {name:string}|null;
            if (!row) throw new Error("Organization not found");
            return row.name === "Two role budget" ? 2 : 1;
          }} : {}),
        }} : {}),
        ...(dynamic && name !== "org-roles-no-ac" ? {ac} : {}),
        ...(name === "org-roles-delegated" ? {roles:{
          owner:ac.newRole(statements),
          delegator:ac.newRole({team:["create"],ac:["create","read","update"]}),
          auditor:ac.newRole({member:["update"]}),
          member:ac.newRole({}),
        }} : {}),
        teams:{
        enabled:true,defaultTeam:{enabled:name!=="org-teams-no-default"},allowRemovingAllTeams:name==="org-teams-removable",
        ...(name === "org-teams-limited" ? {
          maximumTeams: async ({session}, ctx) => session?.user.name === "limit-owner" && ctx?.headers?.get("x-team-policy") === "expanded" ? 3 : 1,
          maximumMembersPerTeam: async ({session}) => session.user.name === "limit-owner" ? 1 : 0,
        } : {}),
      }}),
    ],
  };
  return [name, {auth:betterAuth(options),options}] as const;
}));
for (const {options} of teamProfiles.values()) {
  await (await getMigrations(options)).runMigrations();
}

async function teamFixture(request: Request, url: URL): Promise<Response | undefined> {
  const profileName = url.pathname.match(/^\/__test\/profiles\/([^/]+)\/api\/auth(?:\/|$)/)?.[1];
  if (profileName) {
    const profile = [...teamProfiles.entries()].find(([name]) => name === profileName)?.[1];
    return profile?.auth.handler(request);
  }
  if (url.pathname === "/__test/organization-state" && request.method === "GET") {
    const organizationId = url.searchParams.get("organizationId");
    if (!organizationId) return jsonResponse({message:"organizationId is required"},{status:400});
    const profileName = url.searchParams.get("profile") ?? "org-teams";
    const selected = [...teamProfiles.entries()].find(([name]) => name === profileName)?.[1].auth;
    if (!selected) return jsonResponse({message:"Unknown fixture profile"},{status:400});
    const {adapter} = await selected.$context;
    const where = [{field:"organizationId",value:organizationId}];
    const sortBy = {field:"createdAt",direction:"asc"} as const;
    const [teams,members,invitations] = await Promise.all(["team","member","invitation"].map(model=>adapter.findMany<Record<string,unknown>>({model,where,sortBy,limit:10000})));
    if (!teams || !members || !invitations) throw new Error("Organization state query failed");
    const roles = profileName === "org-teams-dynamic" || profileName.startsWith("org-roles-") ? await adapter.findMany<Record<string,unknown>>({model:"organizationRole",where,sortBy,limit:10000}) : [];
    const teamMembers = (await Promise.all(teams.map(team=>adapter.findMany<Record<string,unknown>>({model:"teamMember",where:[{field:"teamId",value:String(team.id)}],sortBy,limit:10000})))).flat();
    return jsonResponse({
      teams:teams.map(team=>({id:team.id,name:team.name,organizationId:team.organizationId,createdAt:team.createdAt,updatedAt:team.updatedAt,memberCount:team.memberCount})),
      teamMembers:teamMembers.map(member=>({id:member.id,teamId:member.teamId,userId:member.userId,createdAt:member.createdAt})),
      roles,members,invitations,
    });
  }
  if (url.pathname === "/__test/organization-api" && request.method === "POST") {
    const body = await readJson(request);
    const profileName = typeof body?.profile === "string" ? body.profile : "org-teams";
    const selected = [...teamProfiles.entries()].find(([name]) => name === profileName)?.[1].auth;
    if (!selected) return jsonResponse({message:"Unknown fixture profile"},{status:400});
    try {

      if (body?.operation === "role-policy" && typeof body.organizationId === "string") {
        if (profileName !== "org-roles-callback" || !database.query("SELECT id FROM organization WHERE id=?").get(body.organizationId)) {
          return jsonResponse({message:"Role policy organization not found"},{status:400});
        }
        if (body.stage === "arm") {
          if (rolePolicyBarriers.has(body.organizationId)) return jsonResponse({message:"Role policy already armed"},{status:400});
          const entered = Promise.withResolvers<void>(), released = Promise.withResolvers<void>();
          rolePolicyBarriers.set(body.organizationId,{entered:entered.promise,enter:entered.resolve,released:released.promise,release:released.resolve});
        } else if (body.stage === "wait") {
          const barrier = rolePolicyBarriers.get(body.organizationId);
          if (!barrier) return jsonResponse({message:"Role policy is not armed"},{status:400});
          await waitForRolePolicy(barrier.entered,"Role policy entry timed out");
        } else if (body.stage === "release") {
          const barrier = rolePolicyBarriers.get(body.organizationId);
          if (!barrier) return jsonResponse({message:"Role policy is not armed"},{status:400});
          rolePolicyBarriers.delete(body.organizationId);
          barrier.release();
        } else return jsonResponse({message:"Invalid role policy stage"},{status:400});
        return jsonResponse({organizationId:body.organizationId,stage:body.stage});
      }
      if (body?.operation === "seed-role" && typeof body.organizationId === "string" && typeof body.role === "string" && body.permission && typeof body.permission === "object") {
        const {adapter} = await selected.$context;
        const role = await adapter.create<Record<string,unknown>>({model:"organizationRole",data:{organizationId:body.organizationId,role:body.role,permission:JSON.stringify(body.permission),createdAt:new Date()}});
        return jsonResponse({roleId:role.id,organizationId:role.organizationId,role:role.role});
      }
      if (body?.operation === "set-member-role" && typeof body.organizationId === "string" && typeof body.memberId === "string" && typeof body.role === "string") {
        const {adapter} = await selected.$context;
        const where = [{field:"organizationId",value:body.organizationId},{field:"id",value:body.memberId}];
        const member = await adapter.findOne<Record<string,unknown>>({model:"member",where});
        if (!member) return jsonResponse({message:"Member not found"},{status:400});
        const updated = await adapter.update<Record<string,unknown>>({model:"member",where,update:{role:body.role}});
        if (!updated) throw new Error("Member role update failed");
        return jsonResponse({memberId:updated.id,organizationId:updated.organizationId,role:updated.role});
      }
      if (body?.operation === "list-user-invitations" && typeof body.email === "string") {
        return jsonResponse(await selected.api.listUserInvitations({query:{email:body.email}}));
      }
      if (body?.operation === "create-team" && typeof body.organizationId === "string" && typeof body.name === "string") {
        return jsonResponse(await selected.api.createTeam({body:{organizationId:body.organizationId,name:body.name}}));
      }
      if (body?.operation === "seed-member" && typeof body.organizationId === "string" && typeof body.id === "string" && typeof body.email === "string" && typeof body.name === "string") {
        const {adapter} = await selected.$context;
        const user = await adapter.create<Record<string,unknown>>({model:"user",forceAllowId:true,data:{id:body.id,email:body.email,name:body.name,emailVerified:true,createdAt:new Date(),updatedAt:new Date()}});
        const member = await selected.api.addMember({body:{organizationId:body.organizationId,userId:String(user.id),role:"member"}});
        return jsonResponse({userId:user.id,memberId:member.id});
      }
      if (body?.operation === "remove-team" && typeof body.organizationId === "string" && typeof body.teamId === "string") {
        return jsonResponse(await selected.api.removeTeam({body:{organizationId:body.organizationId,teamId:body.teamId}}));
      }
      return jsonResponse({message:"Invalid organization operation"},{status:400});
    } catch (error) {
      if (error instanceof APIError) return jsonResponse(error.body,{status:error.statusCode});
      throw error;
    }
  }
}

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
  const {adapter} = await teamProfiles.get("org-teams")!.auth.$context;
  for (const model of ["teamMember","team"]) await adapter.deleteMany({model,where:[]});
  const roleAdapter = (await teamProfiles.get("org-teams-dynamic")!.auth.$context).adapter;
  await roleAdapter.deleteMany({model:"organizationRole",where:[]});
  for (const model of RESET_MODELS) {
    await authContext.adapter.deleteMany({
      model,
      where: [],
    });
  }
  const context = await jwtProfiles.get("jwt-default")!.auth.$context;
  await context.adapter.deleteMany({model:"jwks",where:[]});
}


function controlRecord(value: unknown): value is Record<string,unknown> {
  return value!==null && typeof value==="object" && !Array.isArray(value);
}
async function oneTimeTokenControl(request:Request,url:URL):Promise<Response|undefined> {
  if (url.pathname!=="/__test/one-time-token" || request.method!=="POST") return;
  const body:unknown=await readJson(request);
  if (!controlRecord(body)) return jsonResponse({message:"invalid server operation"},{status:400});
  const selected=ottProfiles.get(typeof body.profile==="string" ? body.profile as typeof OTT_PROFILE_NAMES[number] : "ott-default")?.auth;
  if (!selected || body.operation!=="generate") return jsonResponse({message:"invalid server operation"},{status:400});
  return jsonResponse(await selected.api.generateOneTimeToken({headers:request.headers}));
}

const openApiInstances=openApiProfiles(PORT,database);

const server = Bun.serve({
  port: PORT,
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if(url.pathname==="/__test/session-field-state")return jsonResponse(sessionFieldsFixture.state(url.searchParams.get("email")??""));
      for(const [name,profile] of sessionFieldsFixture.profiles)if(url.pathname.startsWith(`/__test/profiles/${name}/api/auth/`))return profile.handler(request);
      for (const [name, profile] of organizationCreationFixture.profiles) {
        if (url.pathname.startsWith(`/__test/profiles/${name}/api/auth/`)) return profile.handler(request);
      }
      if (url.pathname === "/__test/organization-creation-state" && request.method === "GET") {
        return jsonResponse(organizationCreationFixture.state(url.searchParams.get("email") ?? "", url.searchParams.get("includeMetadata") === "true", url.searchParams.get("includeLogo") === "true"));
      }
      if (url.pathname === "/__test/organization-create" && request.method === "POST") {
        return organizationCreationFixture.server(await request.json() as Record<string,unknown>);
      }
      if (url.pathname === "/__test/organization-metadata-legacy" && request.method === "POST") {
        return organizationCreationFixture.legacyMetadata(await request.json() as Record<string,unknown>);
      }
      for (const [name,profile] of deviceProfiles) if (url.pathname.startsWith(`/__test/profiles/${name}/api/auth/`)) return profile.handler(request);

      if (url.pathname === "/__test/device-state" && request.method === "GET") {
        const deviceCode = url.searchParams.get("deviceCode");
        if (!deviceCode) return jsonResponse({message:"deviceCode is required"},{status:400});
        return jsonResponse(await authContext.adapter.findOne({model:"deviceCode",where:[{field:"deviceCode",value:deviceCode}]}));
      }
      if (url.pathname === "/__test/expire-device" && request.method === "POST") {
        const body:unknown = await readJson(request);
        if (!controlRecord(body) || typeof body.deviceCode!=="string" || typeof body.expiresAt!=="string" || !Number.isFinite(Date.parse(body.expiresAt))) return jsonResponse({message:"deviceCode and valid expiresAt are required"},{status:400});
        await authContext.adapter.updateMany({model:"deviceCode",where:[{field:"deviceCode",value:body.deviceCode}],update:{expiresAt:new Date(body.expiresAt)}});
        return jsonResponse({status:true});
      }
      if (url.pathname === "/__test/expire-invitation" && request.method === "POST") {
        const body = await readJson(request);
        if (typeof body?.invitationId !== "string" || typeof body?.expiresAt !== "string") return jsonResponse({ message: "Invalid invitation clock" }, { status: 400 });
        const result = database.query('UPDATE invitation SET expiresAt = ? WHERE id = ?').run(new Date(body.expiresAt).toISOString(), body.invitationId);
        return jsonResponse({ updated: result.changes });
      }


      for (const [name,instance] of openApiInstances) {
        if(url.pathname.startsWith(`/__test/profiles/${name}/api/auth/`)) return instance.handler(request);
      }
      for(const [name,profile] of ottProfiles) {
        if(url.pathname.startsWith(`/__test/profiles/${name}/api/auth/`)) return profile.auth.handler(request);
      }
      const policyControl = await twoFactorPolicyFixture(request, url);
      if (policyControl) return policyControl;
      const otpControl = await twoFactorOtpFixture(request, url);
      if (otpControl) return otpControl;
      const totpControl = await twoFactorTotpFixture(request, url);
      if (totpControl) return totpControl;
      const ottControl=await oneTimeTokenControl(request,url);
      if(ottControl) return ottControl;

      const teamResponse = await teamFixture(request, url);
      if (teamResponse) return teamResponse;

      const siweResponse = await siweFixture.handle(request);
      if (siweResponse) return siweResponse;

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

      for (const [name,profile] of jwtProfiles) {
        const path = `/__test/profiles/${name}/api/auth`;
        if (url.pathname === path || url.pathname.startsWith(`${path}/`)) return profile.auth.handler(request);
      }
      if (url.pathname === "/__test/jwks-state" && request.method === "GET") {
        const context = await jwtProfiles.get("jwt-default")!.auth.$context;
        const keys = await context.adapter.findMany<{id:string;publicKey:string;privateKey:string;createdAt:Date;expiresAt:Date|null;alg:string|null;crv:string|null}>({model:"jwks",sortBy:{field:"createdAt",direction:"asc"}});
        return jsonResponse(keys.map(key => ({id:key.id,publicKey:JSON.parse(key.publicKey),privateKeyEncrypted:typeof JSON.parse(key.privateKey) === "string",createdAt:key.createdAt,expiresAt:key.expiresAt,alg:key.alg,crv:key.crv})));
      }
      if (url.pathname === "/__test/expire-jwk" && request.method === "POST") {
        const body: unknown = await readJson(request);
        if (!jwtRecord(body) || typeof body.id !== "string" || typeof body.expiresAt !== "string" || !Number.isFinite(Date.parse(body.expiresAt))) return jsonResponse({message:"id and valid expiresAt are required"},{status:400});
        const context = await jwtProfiles.get("jwt-default")!.auth.$context;
        await context.adapter.updateMany({model:"jwks",where:[{field:"id",value:body.id}],update:{expiresAt:new Date(body.expiresAt)}});
        return jsonResponse({status:true});
      }
      if (url.pathname === "/__test/jwt" && request.method === "POST") {
        const body: unknown = await readJson(request);
        if (!jwtRecord(body)) return jsonResponse({message:"invalid server operation"},{status:400});
        const selected = jwtProfiles.get(typeof body.profile === "string" ? body.profile as typeof JWT_PROFILE_NAMES[number] : "jwt-default")?.auth;
        if (!selected) return jsonResponse({message:"unknown fixture profile"},{status:400});
        if (body.operation === "sign" && jwtRecord(body.payload)) return jsonResponse(await selected.api.signJWT({body:{payload:body.payload}}));
        if (body.operation === "verify" && typeof body.token === "string") return jsonResponse(await selected.api.verifyJWT({body:{token:body.token,...(typeof body.issuer === "string" ? {issuer:body.issuer} : {})}}));
        if (body.operation === "session-state" && typeof body.token === "string") {
          const context = await selected.$context;
          return jsonResponse(await context.internalAdapter.findSession(body.token));
        }
        return jsonResponse({message:"invalid server operation"},{status:400});
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

      if (url.pathname==="/__test/magic-link" && request.method==="GET") {
        return jsonResponse(magicLinkOutbox.get(url.searchParams.get("email") ?? "") ?? null);
      }
      if (url.pathname === "/__test/phone-otp" && request.method === "GET") {
        return jsonResponse(phoneFixture.outbox.get(`${url.searchParams.get("type") ?? "verification"}:${url.searchParams.get("phoneNumber")}`) ?? null);
      }
      if (url.pathname === "/__test/phone-callbacks" && request.method === "GET") return jsonResponse(phoneFixture.callbacks);
      if (url.pathname === "/__test/phone-consume-otp" && request.method === "POST") return phoneFixture.consume(await readJson(request));
      if (url.pathname==="/__test/email-otp" && request.method==="GET") {
        return jsonResponse(emailOtpOutbox.get(`${url.searchParams.get("type")}:${url.searchParams.get("email")}`) ?? null);
      }
      if (url.pathname==="/__test/verification-state" && request.method==="GET") {
        const identifier=url.searchParams.get("identifier");
        return jsonResponse(await authContext.adapter.findMany({model:"verification",where:[{field:"identifier",value:identifier}],sortBy:{field:"createdAt",direction:"desc"}}));
      }
      if (url.pathname==="/__test/verification-state" && request.method==="POST") {
        const body:unknown=await readJson(request);
        if (!body || typeof body!=="object" || Array.isArray(body)) return jsonResponse({message:"invalid verification action"},{status:400});
        const record=body as Record<string,unknown>;
        if (typeof record.identifier!=="string" || typeof record.expiresAt!=="string") return jsonResponse({message:"invalid verification action"},{status:400});
        const expiresAt=new Date(record.expiresAt);
        if (record.action==="seed" && typeof record.value==="string") await authContext.internalAdapter.createVerificationValue({identifier:record.identifier,value:record.value,expiresAt});
        else if (record.action==="expire") await authContext.adapter.updateMany({model:"verification",where:[{field:"identifier",value:record.identifier}],update:{expiresAt}});
        else return jsonResponse({message:"invalid verification action"},{status:400});
        return jsonResponse({status:true});
      }
      if (url.pathname==="/__test/server-api" && request.method==="POST") {
        const body:unknown=await readJson(request);
        if (!body || typeof body!=="object" || Array.isArray(body)) return jsonResponse({message:"invalid server operation"},{status:400});
        const record=body as Record<string,unknown>;
        if (typeof record.email!=="string" || !["sign-in","email-verification","forget-password","change-email"].includes(String(record.type))) return jsonResponse({message:"invalid server operation"},{status:400});
        const type=record.type==="email-verification" ? "email-verification" : record.type==="forget-password" ? "forget-password" : record.type==="change-email" ? "change-email" : "sign-in";
        const selected=typeof record.profile==="string" ? otpProfiles.get(record.profile) : auth;
        if (!selected) return jsonResponse({message:"unknown fixture profile"},{status:400});
        try {
          if (record.operation==="create-email-otp") return jsonResponse(await selected.api.createVerificationOTP({body:{email:record.email,type}}));
          if (record.operation==="get-email-otp") return jsonResponse(await selected.api.getVerificationOTP({query:{email:record.email,type}}));
          if (record.operation==="race-email-otp" && typeof record.otp==="string") {
            const email=record.email,otp=record.otp;
            const results=await Promise.all([0,1].map(async()=>{const response=await selected.api.signInEmailOTP({body:{email,otp},asResponse:true});return {status:response.status,body:await response.json()};}));
            return jsonResponse({results:results.sort((left,right)=>left.status-right.status)});
          }
        } catch(error) {
          if (error instanceof APIError) return jsonResponse(error.body,{status:typeof error.status==="number" ? error.status : error.status==="BAD_REQUEST" ? 400 : 500});
          throw error;
        }
        return jsonResponse({message:"unknown server operation"},{status:400});
      }
      if (url.pathname === "/__test/reset-state" && request.method === "POST") {
        siweFixture.reset();
        multipleSessionFixture.reset();
        await resetDatabaseState();
        emailOtpOutbox.clear();
        magicLinkOutbox.clear();
        resetPasswordOutbox.clear();
        verificationEmailOutbox.clear();
        changeEmailOutbox.clear();
        twoFactorOtpOutbox.clear();
        phoneFixture.reset();
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

      const adminRoleStateResponse = adminPermissionFixture.handle(request);
      if (adminRoleStateResponse) return adminRoleStateResponse;

      if (url.pathname === "/__test/user-state" && request.method === "GET") {
        const userId = url.searchParams.get("userId");
        if (!userId) return jsonResponse({ message: "userId is required" }, { status: 400 });
        const profileName = url.searchParams.get("profile");
        const selected = profileName ? phoneFixture.profiles.get(profileName) : auth;
        if (!selected) return jsonResponse({ message: "unknown fixture profile" }, { status: 400 });
        const selectedContext = await selected.$context;
        const where = [{ field: "userId", value: userId }];
        const [user, accounts, sessions, twoFactor] = await Promise.all([
          selectedContext.adapter.findOne<Record<string, unknown>>({ model: "user", where: [{ field: "id", value: userId }] }),
          selectedContext.adapter.findMany<Record<string, unknown>>({ model: "account", where }),
          selectedContext.adapter.findMany<Record<string, unknown>>({ model: "session", where, sortBy: { field: "createdAt", direction: "asc" } }),
          selectedContext.adapter.findOne({ model: "twoFactor", where }),
        ]);
        return jsonResponse({
          user: user ? { id: user.id, email: user.email, emailVerified: user.emailVerified, twoFactorEnabled: user.twoFactorEnabled, ...(profileName ? { phoneNumber: user.phoneNumber, phoneNumberVerified: user.phoneNumberVerified } : {}) } : null,
          accounts: accounts.sort((left, right) => String(left.providerId).localeCompare(String(right.providerId)) || String(left.accountId).localeCompare(String(right.accountId))).map(account => ({ id: account.id, userId: account.userId, accountId: account.accountId, providerId: account.providerId })),
          sessions: sessions.map(session => ({ id: session.id, token: session.token, userId: session.userId, expiresAt: session.expiresAt, activeOrganizationId: session.activeOrganizationId ?? null })),
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

      for (const [name, instance] of phoneFixture.profiles) {
        if (url.pathname.startsWith(`/__test/profiles/${name}/api/auth/`)) return instance.handler(request);
      }
      for (const [name,instance] of magicProfiles) {
        if (url.pathname.startsWith(`/__test/profiles/${name}/api/auth/`)) return instance.handler(request);
      }
      for (const [name,instance] of otpProfiles) {
        if (url.pathname.startsWith(`/__test/profiles/${name}/api/auth/`)) return instance.handler(request);
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
