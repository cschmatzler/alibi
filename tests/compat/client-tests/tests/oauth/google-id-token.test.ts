import { expect } from "bun:test";
import { createHash } from "node:crypto";
import { decodeJwt, decodeProtectedHeader } from "jose";
import { credential, issuedAt, signedRawToken } from "../../support/id-token";
import type { FixtureProfile } from "../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { state } from "../one-tap/helpers";

type Row = Record<string, unknown>;
type Store = {
  users: Row[];
  accounts: Row[];
  sessions: Row[];
  receipts: Row[];
};
async function read(ctx: ScenarioContext) {
  const r = await ctx.rawRequest({ path: "/__test/social-provider/state" });
  expect(r.status).toBe(200);
  return r.body as Store;
}
function proof(token: string) {
  const [header, payload, signature] = token.split(".");
  return {
    token,
    header: decodeProtectedHeader(token),
    payload: decodeJwt(token),
    encodedHeader: header,
    encodedPayload: payload,
    signature: { token: signature },
  };
}
async function setup(ctx: ScenarioContext, profile: FixtureProfile) {
  const foreign = ctx.actor("foreign", profile),
    signup = await foreign.client.signUp.email({
      email: ctx.uniqueEmail("foreign"),
      password: "password123",
      name: "Foreign Principal",
    });
  expect(signup.error).toBeNull();
  return {
    foreign,
    signup,
    foreignBefore: await ctx.readUserState({ userId: signup.data!.user.id }),
    before: await read(ctx),
    fetches: (await state(ctx)).jwksFetches,
  };
}
async function signed(ctx: ScenarioContext, claims: Row = {}, header: Row = {}, wrong = false) {
  return credential(
    {
      aud: "google-default-client",
      sub: ctx.uniqueToken("subject"),
      email: ctx.uniqueEmail("owner"),
      name: "Signed Google Owner",
      email_verified: true,
      picture: "https://images.fixture.test/owner.png",
      ...claims,
    },
    header,
    wrong,
  );
}
compatScenario(
  "Google default signed ID-token sign-in owns sessions and persists only accepted direct token fields",
  async (ctx) => {
    const s = await setup(ctx, "google-id-default"),
      owner = ctx.actor("owner", "google-id-default"),
      token = await signed(ctx, { nonce: "actual-nonce" });
    const submitted = {
      provider: "google" as const,
      idToken: {
        token,
        nonce: "actual-nonce",
        accessToken: "direct-access",
        refreshToken: "ignored-refresh",
        expiresAt: issuedAt + 120,
        user: { name: { firstName: "Body Spoof", lastName: "Foreign" } },
        scopes: ["ignored-scope"],
      },
    };
    const signin = await owner.client.signIn.social(submitted);
    expect(signin.error).toBeNull();
    const current = await owner.client.getSession();
    expect(current.data?.user).toMatchObject({
      email: ctx.uniqueEmail("owner"),
      name: "Signed Google Owner",
      emailVerified: true,
    });
    const stored = await read(ctx),
      account = stored.accounts.find((r) => r.providerId === "google")!;
    expect(account).toMatchObject({
      userId: current.data!.user.id,
      accountId: ctx.uniqueToken("subject"),
      idToken: token,
      accessToken: "direct-access",
      refreshToken: null,
      scope: null,
      accessTokenExpiresAt: null,
      refreshTokenExpiresAt: null,
    });
    expect(stored.users).toHaveLength(s.before.users.length + 1);
    expect(stored.accounts).toHaveLength(s.before.accounts.length + 1);
    expect(stored.sessions).toHaveLength(s.before.sessions.length + 1);
    const ownerBefore = await ctx.readUserState({
      userId: current.data!.user.id,
    });
    const replay = await s.foreign.client.signIn.social({
      provider: "google",
      idToken: { token, nonce: "actual-nonce" },
    });
    expect(replay.error).toBeNull();
    const replaySession = await s.foreign.client.getSession();
    expect(replaySession.data?.user.id).toBe(current.data!.user.id);
    const replayed = await read(ctx);
    expect(replayed.sessions).toHaveLength(stored.sessions.length + 1);
    expect(replayed.accounts.find((r) => r.id === account.id)?.userId).toBe(current.data!.user.id);
    expect(await ctx.readUserState({ userId: s.signup.data!.user.id })).toEqual(s.foreignBefore);
    const signout = await s.foreign.client.signOut();
    expect(signout.error).toBeNull();
    const retired = await s.foreign.client.getSession(),
      original = await owner.client.getSession();
    expect(retired.data).toBeNull();
    expect(original.data?.user.id).toBe(current.data!.user.id);
    expect((await read(ctx)).sessions).toHaveLength(stored.sessions.length);
    return {
      signup: ctx.snapshot(s.signup),
      before: s.before,
      foreignBefore: s.foreignBefore,
      submitted,
      proof: proof(token),
      signin: ctx.snapshot(signin),
      current: ctx.snapshot(current),
      stored,
      ownerBefore,
      replay: ctx.snapshot(replay),
      replaySession: ctx.snapshot(replaySession),
      replayed,
      signout: ctx.snapshot(signout),
      retired: ctx.snapshot(retired),
      original: ctx.snapshot(original),
      after: await read(ctx),
      foreignAfter: await ctx.readUserState({ userId: s.signup.data!.user.id }),
      jwksFetches: (await state(ctx)).jwksFetches - s.fetches,
    };
  },
  ["POST /sign-in/social", "GET /get-session", "POST /sign-out"],
);
const policies: {
  name: string;
  profile: FixtureProfile;
  claims?: Row;
  success?: boolean;
  code?: string;
}[] = [
  {
    name: "secondary audience",
    profile: "google-id-array",
    claims: { aud: "google-secondary-client" },
    success: true,
  },
  {
    name: "audience array",
    profile: "google-id-array",
    claims: { aud: ["foreign-client", "google-secondary-client"] },
    success: true,
  },
  {
    name: "alternate issuer",
    profile: "google-id-default",
    claims: { iss: "accounts.google.com" },
    success: true,
  },
  {
    name: "exact domain",
    profile: "google-id-domain",
    claims: { hd: "workspace.fixture.test" },
    success: true,
  },
  {
    name: "wildcard domain",
    profile: "google-id-domain-any",
    claims: { hd: "other.fixture.test" },
    success: true,
  },
  {
    name: "missing domain",
    profile: "google-id-domain",
    code: "INVALID_TOKEN",
  },
  {
    name: "case distinct domain",
    profile: "google-id-domain",
    claims: { hd: "WORKSPACE.fixture.test" },
    code: "INVALID_TOKEN",
  },
  {
    name: "wildcard requires domain",
    profile: "google-id-domain-any",
    code: "INVALID_TOKEN",
  },
  {
    name: "empty client array",
    profile: "google-id-empty-array",
    claims: { aud: "" },
    code: "INVALID_TOKEN",
  },
  {
    name: "disabled dominates override",
    profile: "google-id-disabled",
    code: "ID_TOKEN_NOT_SUPPORTED",
  },
  {
    name: "application override",
    profile: "google-id-override",
    code: "INVALID_TOKEN",
  },
  {
    name: "missing email",
    profile: "google-id-default",
    claims: { email: undefined },
    code: "USER_EMAIL_NOT_FOUND",
  },
];
for (const p of policies)
  compatScenario(
    `Google default ID-token policy: ${p.name}`,
    async (ctx) => {
      const s = await setup(ctx, p.profile),
        actor = ctx.actor("policy", p.profile),
        token = await signed(ctx, p.claims),
        result = await actor.client.signIn.social({
          provider: "google",
          idToken: { token },
        }),
        current = await actor.client.getSession(),
        after = await read(ctx);
      if (p.success) {
        expect(result.error).toBeNull();
        expect(current.data?.user.email).toBe(ctx.uniqueEmail("owner"));
        expect(after.accounts.find((r) => r.providerId === "google")).toMatchObject({
          userId: current.data!.user.id,
          accountId: ctx.uniqueToken("subject"),
          idToken: token,
        });
      } else {
        expect(result.error).toMatchObject({
          status: p.code === "ID_TOKEN_NOT_SUPPORTED" ? 404 : 401,
          code: p.code,
        });
        expect(current.data).toBeNull();
        expect(after).toEqual(s.before);
      }
      expect(await ctx.readUserState({ userId: s.signup.data!.user.id })).toEqual(s.foreignBefore);
      return {
        signup: ctx.snapshot(s.signup),
        before: s.before,
        proof: proof(token),
        result: ctx.snapshot(result),
        current: ctx.snapshot(current),
        after,
        foreignBefore: s.foreignBefore,
        foreignAfter: await ctx.readUserState({
          userId: s.signup.data!.user.id,
        }),
        jwksFetches: (await state(ctx)).jwksFetches - s.fetches,
      };
    },
    ["POST /sign-in/social", "GET /get-session"],
  );
compatScenario(
  "Google default genuine cryptographic and claim negatives never mutate any principal",
  async (ctx) => {
    const s = await setup(ctx, "google-id-default"),
      actor = ctx.actor("rejected", "google-id-default"),
      outcomes = [];
    const cases: {
      name: string;
      claims?: Row;
      header?: Row;
      wrong?: boolean;
      nonce?: string;
      rawAlgorithm?: string;
    }[] = [
      {
        name: "wrong algorithm",
        header: { alg: "RS384", kid: "one-tap-local-rs256" },
        rawAlgorithm: "RSA-SHA384",
      },
      {
        name: "hashed nonce",
        claims: {
          nonce: createHash("sha256").update("expected").digest("hex"),
        },
        nonce: "expected",
      },
      { name: "wrong signature", wrong: true },
      { name: "unknown key", header: { kid: "unavailable-key" } },
      { name: "wrong audience", claims: { aud: "foreign-client" } },
      { name: "wrong issuer", claims: { iss: "https://foreign.fixture.test" } },
      { name: "expired", claims: { exp: issuedAt - 60 } },
      { name: "old iat", claims: { iat: issuedAt - 7200 } },
      { name: "future iat", claims: { iat: issuedAt + 3600 } },
      { name: "missing iat", claims: { iat: undefined } },
      { name: "future nbf", claims: { nbf: issuedAt + 3600 } },
      { name: "wrong nonce", claims: { nonce: "other" }, nonce: "expected" },
      { name: "missing nonce", nonce: "expected" },
    ];
    for (const p of cases) {
      const token = p.rawAlgorithm
          ? signedRawToken(
              {
                aud: "google-default-client",
                sub: ctx.uniqueToken("subject"),
                email: ctx.uniqueEmail("owner"),
                ...p.claims,
              },
              p.header!,
              p.rawAlgorithm,
            )
          : await signed(ctx, p.claims, p.header, p.wrong),
        submitted = {
          provider: "google" as const,
          idToken: { token, nonce: p.nonce },
        },
        result = await actor.client.signIn.social(submitted);
      expect(result.error).toMatchObject({
        status: 401,
        code: "INVALID_TOKEN",
      });
      const current = await actor.client.getSession(),
        after = await read(ctx);
      expect(current.data).toBeNull();
      expect(after).toEqual(s.before);
      outcomes.push({
        name: p.name,
        submitted,
        proof: proof(token),
        result: ctx.snapshot(result),
        current: ctx.snapshot(current),
        after,
      });
    }
    expect(await ctx.readUserState({ userId: s.signup.data!.user.id })).toEqual(s.foreignBefore);
    return {
      signup: ctx.snapshot(s.signup),
      before: s.before,
      foreignBefore: s.foreignBefore,
      outcomes,
      foreignAfter: await ctx.readUserState({ userId: s.signup.data!.user.id }),
      jwksFetches: (await state(ctx)).jwksFetches - s.fetches,
    };
  },
  ["POST /sign-in/social", "GET /get-session"],
);
