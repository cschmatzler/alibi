import { expect } from "bun:test";
import { createHash } from "node:crypto";

import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";

import { oauthPurposeSecret } from "../../support/oauth-encryption";
import { authProfilePath } from "../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../support/scenario";

const old = "managed-old-reader-key-at-least-32-characters";
const current = "compat-test-only-key-not-real-minimum-32chars";
const legacy = "managed-legacy-reader-key-at-least-32-characters";
const ring = {
  keys: new Map([
    [2, current],
    [0, old],
  ]),
  currentVersion: 2,
  legacySecret: legacy,
};
const purposeRing = (purpose: Parameters<typeof oauthPurposeSecret>[1]) => ({
  keys: new Map(
    [...ring.keys].map(([version, secret]) => [version, oauthPurposeSecret(secret, purpose)]),
  ),
  currentVersion: ring.currentVersion,
  legacySecret: oauthPurposeSecret(legacy, purpose),
});
const path = authProfilePath("managed-proxy");
// Both runtimes receive the same independently Source-encrypted wrong-key vector.
const wrongKeyVector = symmetricEncrypt({
  key: {
    keys: new Map([[2, "wrong-proxy-context-key-at-least-32-characters"]]),
    currentVersion: 2,
  },
  data: JSON.stringify({ authentic: "wrong-key-control" }),
});
const tamperVector = symmetricEncrypt({
  key: purposeRing("oauth-proxy-profile"),
  data: JSON.stringify({ authentic: "tamper-control" }),
}).then((value) => {
  const prefix = "$ba$2$";
  const bytes = Buffer.from(value.slice(prefix.length), "hex");
  bytes[bytes.length - 1]! ^= 1;
  return prefix + bytes.toString("hex");
});
type Rows = {
  users: Record<string, unknown>[];
  accounts: Record<string, unknown>[];
  sessions: Record<string, unknown>[];
  verification: Record<string, unknown>[];
};
type State = {
  preview: Rows;
  production: Rows;
  receipts: {
    stage: string;
    query?: Record<string, string>;
    body?: Record<string, string>;
    authorization?: string;
  }[];
  sessionHooks: unknown[];
  afterRequests: unknown[];
};
async function keys(ctx: ScenarioContext, mode: string, origin?: string) {
  const changed = await ctx.rawRequest({
    path: "/__test/managed-proxy/keys",
    method: "POST",
    json: { mode, ...(origin ? { origin } : {}) },
  });
  expect(changed.status).toBe(200);
  return changed;
}
async function state(ctx: ScenarioContext): Promise<State> {
  const result = await ctx.rawRequest({ path: "/__test/managed-proxy/state" });
  expect(result.status).toBe(200);
  return result.body as State;
}
function observed(value: State) {
  return {
    ...value,
    receipts: value.receipts.map((receipt) => ({
      ...receipt,
      ...(receipt.body?.code_verifier
        ? {
            body: {
              ...receipt.body,
              code_verifier: {
                token: receipt.body.code_verifier,
                length: receipt.body.code_verifier.length,
              },
            },
          }
        : {}),
    })),
  };
}
async function response(value: Response) {
  const text = await value.text();
  let body: unknown = text;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {}
  return { status: value.status, location: value.headers.get("location"), body };
}

compatScenario(
  "managed OAuth proxy decrypts only declared retained versions across real origins and binds completion to saved context",
  async (ctx) => {
    const production = ctx.baseURL.replace("localhost", "127.0.0.1");
    await keys(ctx, "retained");
    const foreign = ctx.actor("managed-proxy-foreign", "managed-proxy");
    const seeded = await foreign.client.signUp.email({
      email: ctx.uniqueEmail("managed-proxy-foreign"),
      password: "password123",
      name: "Foreign Proxy Owner",
    });
    expect(seeded.error).toBeNull();
    const baseline = await state(ctx);
    const journeys = [];
    for (const [index, write, producer, reader, missing] of [
      [0, "old", "old", "retained", "retired"],
      [1, "bare", "bare", "legacy", "retained"],
      [2, "old", "retained", "retired", "retired"],
    ] as const) {
      await keys(ctx, write);
      const owner = ctx.actor(`managed-proxy-${index}`, "managed-proxy");
      const started = await owner.client.signIn.social({
        provider: "gitlab",
        callbackURL: ctx.baseURL + "/managed-proxy-done",
        newUserCallbackURL: ctx.baseURL + "/managed-proxy-new",
        errorCallbackURL: ctx.baseURL + "/managed-proxy-error",
        disableRedirect: true,
        additionalData: {
          serverContext: { anonymousUserId: seeded.data!.user.id },
          application: { kept: true },
        },
      });
      expect(started.error).toBeNull();
      const authorization = new URL(started.data!.url!);
      expect(authorization.searchParams.get("redirect_uri")).toBe(
        production + path + "/callback/gitlab",
      );
      const raw = authorization.searchParams.get("state")!;
      expect(raw.startsWith("$ba$0$")).toBe(write === "old");
      const pack = JSON.parse(
        await symmetricDecrypt({ key: purposeRing("oauth-proxy-package"), data: raw }),
      );
      expect(pack.isOAuthProxy).toBe(true);
      const original = JSON.parse(
        await symmetricDecrypt({ key: purposeRing("oauth-proxy-state"), data: pack.stateCookie }),
      );
      expect(original.oauthState).toBe(pack.state);
      expect(original.serverContext).toBeUndefined();
      expect(original.application).toEqual({ kept: true });
      const issuedState = {
        ...pack,
        stateCookie: {
          token: pack.stateCookie,
          payload: {
            ...original,
            oauthState: { state: original.oauthState },
            codeVerifier: { token: original.codeVerifier },
            expiresAt: new Date(original.expiresAt).toISOString(),
          },
        },
      };
      const saved = await state(ctx);
      expect(saved.preview.verification).toHaveLength(1);
      const approved = await response(await owner.fetch(authorization, { redirect: "manual" }));
      expect(approved.status).toBe(302);
      // Reject on the production reader before its real provider grant is consumed.
      await keys(ctx, missing, production);
      const deniedProduction = await response(
        await owner.fetch(approved.location!, { redirect: "manual", credentials: "omit" }),
      );
      expect(deniedProduction.status).toBe(302);
      expect(new URL(deniedProduction.location!).searchParams.get("error")).toBe("state_mismatch");
      const afterDeniedProduction = await state(ctx);
      expect(afterDeniedProduction.preview).toEqual(saved.preview);
      expect(afterDeniedProduction.production).toEqual(saved.production);
      expect(
        afterDeniedProduction.receipts.filter((receipt) => receipt.stage === "token"),
      ).toHaveLength(saved.receipts.filter((receipt) => receipt.stage === "token").length);
      await keys(ctx, producer, production);
      const forwarded = await response(
        await owner.fetch(approved.location!, { redirect: "manual", credentials: "omit" }),
      );
      expect(forwarded.status).toBe(302);
      const bridge = new URL(forwarded.location!);
      expect(bridge.origin).toBe(ctx.baseURL);
      expect(bridge.pathname).toBe(path + "/callback/gitlab/oauth-proxy");
      const token = bridge.searchParams.get("profile")!;
      if (producer === "bare") expect(token.startsWith("$ba$")).toBe(false);
      else expect(token.startsWith(producer === "old" ? "$ba$0$" : "$ba$2$")).toBe(true);
      const payload = JSON.parse(
        await symmetricDecrypt({ key: purposeRing("oauth-proxy-profile"), data: token }),
      );
      expect(payload.state).toBe(pack.state);
      expect(payload.account.providerId).toBe("gitlab");
      expect(payload.userInfo.email).toBe("proxy-owner@fixture.test");
      const forwardedState = await state(ctx);
      expect(forwardedState.production).toEqual(saved.production);
      expect(forwardedState.preview).toEqual(saved.preview);
      const receipt = forwardedState.receipts
        .filter((receipt) => receipt.stage === "token")
        .at(-1)!;
      expect(receipt.body!.code_verifier).toBe(original.codeVerifier);
      expect(createHash("sha256").update(original.codeVerifier).digest("base64url")).toBe(
        authorization.searchParams.get("code_challenge")!,
      );
      await keys(ctx, missing, ctx.baseURL);
      const deniedCompletion =
        index < 2 ? await response(await owner.fetch(bridge, { redirect: "manual" })) : null;
      if (deniedCompletion) {
        expect(new URL(deniedCompletion.location!).searchParams.get("error")).toBe(
          "invalid_profile",
        );
      }
      const afterDeniedCompletion = await state(ctx);
      expect(afterDeniedCompletion.preview).toEqual(saved.preview);
      expect(afterDeniedCompletion.production).toEqual(saved.production);
      await keys(ctx, reader, ctx.baseURL);
      const rejections = [];
      for (const mode of [
        "foreign-origin",
        "foreign-state",
        "wrong-key",
        "tampered",
        "malformed-version",
      ]) {
        const url = new URL(bridge);
        let rejectedToken = token;
        let submittedPayload = payload;
        if (mode === "foreign-origin") {
          url.searchParams.set("callbackURL", "https://foreign.fixture.test/leak");
        }
        if (mode === "wrong-key") rejectedToken = await wrongKeyVector;
        if (mode === "foreign-state") {
          submittedPayload = { ...payload, state: seeded.data!.token };
          rejectedToken = await symmetricEncrypt({
            key: purposeRing("oauth-proxy-profile"),
            data: JSON.stringify(submittedPayload),
          });
        }
        if (mode === "malformed-version") rejectedToken = "$ba$x$";
        if (mode === "tampered") {
          rejectedToken = await tamperVector;
        }
        url.searchParams.set("profile", rejectedToken);
        const rejected = await response(await owner.fetch(url, { redirect: "manual" }));
        if (mode === "foreign-origin") expect(rejected.status).toBe(403);
        else {
          expect(new URL(rejected.location!).searchParams.get("error")).toBe(
            mode === "foreign-state" ? "state_mismatch" : "invalid_profile",
          );
        }
        const unchanged = await state(ctx);
        expect(unchanged.preview).toEqual(saved.preview);
        expect(unchanged.production).toEqual(saved.production);
        rejections.push({
          mode,
          inputProfile: { token: rejectedToken },
          ...(mode === "foreign-state"
            ? { oauthProxyProfile: { token: rejectedToken, payload: submittedPayload } }
            : {}),
          rejected,
          unchanged: observed(unchanged),
        });
      }
      const completed = await response(await owner.fetch(bridge, { redirect: "manual" }));
      expect(completed.status).toBe(302);
      expect(completed.location).toBe(
        ctx.baseURL + (index === 0 ? "/managed-proxy-new" : "/managed-proxy-done"),
      );
      const currentSession = await owner.client.getSession();
      expect(currentSession.data?.user.email).toBe("proxy-owner@fixture.test");
      expect(currentSession.data?.user.id).not.toBe(seeded.data!.user.id);
      const after = await state(ctx);
      expect(after.preview.verification).toHaveLength(0);
      expect(after.production).toEqual(baseline.production);
      expect(after.preview.users.find((user) => user.id === seeded.data!.user.id)).toEqual(
        baseline.preview.users[0],
      );
      expect(after.preview.sessions.filter((row) => row.userId === seeded.data!.user.id)).toEqual(
        baseline.preview.sessions,
      );
      expect(
        after.preview.accounts.find((account) => account.providerId === "gitlab")?.userId,
      ).toBe(currentSession.data!.user.id);
      expect(
        after.preview.sessions.find((row) => row.token === currentSession.data!.session.token)
          ?.userId,
      ).toBe(currentSession.data!.user.id);
      const replay = await response(await owner.fetch(bridge, { redirect: "manual" }));
      expect(new URL(replay.location!).searchParams.get("error")).toBe("state_mismatch");
      expect((await state(ctx)).preview).toEqual(after.preview);
      const grantReplay = await response(
        await owner.fetch(approved.location!, { redirect: "manual", credentials: "omit" }),
      );
      expect(new URL(grantReplay.location!).searchParams.get("error")).toBe("invalid_code");
      journeys.push({
        write,
        producer,
        reader,
        missing,
        started,
        issuedState,
        saved: observed(saved),
        approved,
        deniedProduction,
        afterDeniedProduction: observed(afterDeniedProduction),
        forwarded,
        oauthProxyProfile: { token, payload },
        forwardedState: observed(forwardedState),
        deniedCompletion,
        afterDeniedCompletion: observed(afterDeniedCompletion),
        rejections,
        completed,
        currentSession,
        after: observed(after),
        replay,
        grantReplay,
        final: observed(await state(ctx)),
      });
    }
    return { seeded, baseline: observed(baseline), journeys };
  },
  [
    "POST /sign-up/email",
    "POST /sign-in/social",
    "GET /callback/{}/oauth-proxy",
    "GET /get-session",
  ],
  30_000,
  {
    oauthProxyProfileManagedKeys: {
      keys: {
        0: oauthPurposeSecret(old, "oauth-proxy-profile"),
        2: oauthPurposeSecret(current, "oauth-proxy-profile"),
      },
      legacySecret: oauthPurposeSecret(legacy, "oauth-proxy-profile"),
    },
  },
);
