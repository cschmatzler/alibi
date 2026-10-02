import { expect } from "bun:test";
import { passkeyClient } from "@better-auth/passkey/client";
import { createAuthClient } from "better-auth/client";
import { z } from "zod";
import { Authenticator } from "../../support/authenticator";
import { authProfilePath } from "../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../support/scenario";

const savedSessions = (state: unknown) =>
  z.object({ sessions: z.array(z.unknown()) }).parse(state).sessions;

async function setup(ctx: ScenarioContext, registeredBackup = {}) {
  const requests: Record<string, any>[] = [];
  const make = (name: string) =>
    createAuthClient({
      baseURL: `${ctx.baseURL}${authProfilePath("passkey-auth-accept")}`,
      plugins: [passkeyClient()],
      fetchOptions: {
        customFetchImpl: async (input, init) => {
          const request = new Request(input, init);
          if (new URL(request.url).pathname.endsWith("/passkey/verify-authentication"))
            requests.push(await request.clone().json());
          return ctx.actor(name, "passkey-auth-accept").fetch(request);
        },
      },
    });
  const owner = make("policy-owner"),
    foreign = make("policy-foreign");
  const signup = await owner.signUp.email({
    email: ctx.uniqueEmail("policy-owner"),
    name: "Policy Owner",
    password: "password123",
  });
  expect(signup.error).toBeNull();
  const foreignSignup = await foreign.signUp.email({
    email: ctx.uniqueEmail("policy-foreign"),
    name: "Policy Foreign",
    password: "password123",
  });
  expect(foreignSignup.error).toBeNull();
  const options = await owner.$fetch("/passkey/generate-register-options", { method: "GET" });
  expect(options.error).toBeNull();
  const device = new Authenticator();
  const registered = await owner.$fetch("/passkey/verify-registration", {
    method: "POST",
    body: {
      response: device.register(options.data, ctx.baseURL, registeredBackup),
      name: "Policy device",
    },
  });
  expect(registered.error).toBeNull();
  const listed = await owner.$fetch("/passkey/list-user-passkeys", { method: "GET" });
  expect(listed.error).toBeNull();
  const foreignBefore = await ctx.readUserState({ userId: foreignSignup.data!.user.id });
  const events = async () => {
    const response = await ctx.rawRequest({ path: "/__test/passkey-authentication-events" });
    expect(response.status).toBe(200);
    return response.body as Record<string, any>[];
  };
  expect(await events()).toEqual([]);
  return {
    owner,
    foreign,
    signup,
    foreignSignup,
    options,
    device,
    registered,
    listed,
    foreignBefore,
    events,
    requests,
  };
}
function assertion(value: Record<string, any>, options: any) {
  const decoded = JSON.parse(Buffer.from(value.response.clientDataJSON, "base64url").toString());
  expect(Buffer.from(JSON.stringify(decoded)).toString("base64url")).toBe(
    value.response.clientDataJSON,
  );
  expect(value.response.userHandle).toBe(options.user.id);
  const generated = Buffer.from(value.response.userHandle, "base64url").toString();
  expect(Buffer.from(generated).toString("base64url")).toBe(value.response.userHandle);
  return {
    ...value,
    response: {
      ...value.response,
      clientDataJSON: { ...decoded, origin: { url: decoded.origin } },
      userHandle: { id: value.response.userHandle, decoded: { id: generated } },
      signature: { token: value.response.signature },
    },
  };
}
function receipts(rows: Record<string, any>[], fixture: Awaited<ReturnType<typeof setup>>) {
  for (const row of rows) {
    const request = fixture.requests.find(
      (request) => request.response.response.signature === row.clientData.response.signature,
    );
    expect(request).toBeDefined();
    expect(row.clientData).toEqual(request!.response);
  }
  return rows.map((row) => ({
    ...row,
    facts: { ...row.facts, origin: { url: row.facts.origin } },
    clientData: assertion(row.clientData, fixture.options.data),
  }));
}
function submitted(fixture: Awaited<ReturnType<typeof setup>>) {
  return fixture.requests.map((row) => ({
    ...row,
    response: assertion(row.response, fixture.options.data),
  }));
}

for (const mode of ["uv-absent", "backup-upgrade-backed", "backup-downgrade"] as const)
  compatScenario(
    `passkey signed ${mode} authenticates original owner without historical verifier restrictions`,
    async (ctx) => {
      const backup = mode === "backup-downgrade" ? { backupEligible: true, backedUp: true } : {};
      const fixture = await setup(ctx, backup);
      await fixture.owner.signOut();
      const before = await ctx.readUserState({ userId: fixture.signup.data!.user.id });
      expect(savedSessions(before)).toEqual([]);
      const outputs = [];
      for (let counter = 1; counter <= 2; counter++) {
        const challenge = await fixture.foreign.$fetch("/passkey/generate-authenticate-options", {
          method: "GET",
        });
        expect(challenge.error).toBeNull();
        const flags =
          mode === "uv-absent"
            ? { userVerified: false }
            : mode === "backup-upgrade-backed"
              ? { backupEligible: true, backedUp: true }
              : {};
        const proof = fixture.device.authenticate(challenge.data, ctx.baseURL, flags);
        const result = await fixture.foreign.$fetch("/passkey/verify-authentication", {
          method: "POST",
          body: { response: proof },
        });
        expect(result.error).toBeNull();
        expect(result.data).toMatchObject({
          user: { id: fixture.signup.data!.user.id },
          session: { userId: fixture.signup.data!.user.id },
        });
        const callback = await fixture.events();
        expect(callback).toHaveLength(counter);
        expect(callback[counter - 1]).toMatchObject({
          facts: {
            newCounter: counter,
            userVerified: mode !== "uv-absent",
            credentialDeviceType: mode === "backup-upgrade-backed" ? "multiDevice" : "singleDevice",
            credentialBackedUp: mode === "backup-upgrade-backed",
          },
          storedPasskey: { userId: fixture.signup.data!.user.id, counter: counter - 1 },
        });
        const listed = await fixture.foreign.$fetch("/passkey/list-user-passkeys", {
          method: "GET",
        });
        expect(listed.data).toMatchObject([
          {
            counter,
            backedUp: mode === "backup-downgrade",
            deviceType: mode === "backup-downgrade" ? "multiDevice" : "singleDevice",
          },
        ]);
        const current = await fixture.foreign.getSession();
        expect(current.data?.user.id).toBe(fixture.signup.data!.user.id);
        const replay = await fixture.foreign.$fetch("/passkey/verify-authentication", {
          method: "POST",
          body: { response: proof },
        });
        expect(replay.error).toMatchObject({ status: 400, code: "CHALLENGE_NOT_FOUND" });
        expect(await fixture.events()).toHaveLength(counter);
        outputs.push({ challenge, result, listed, current, replay });
      }
      const after = await ctx.readUserState({ userId: fixture.signup.data!.user.id });
      expect(savedSessions(after)).toHaveLength(2);
      const foreignAfter = await ctx.readUserState({ userId: fixture.foreignSignup.data!.user.id });
      expect(foreignAfter).toEqual(fixture.foreignBefore);
      return {
        signup: fixture.signup,
        foreignSignup: fixture.foreignSignup,
        registered: fixture.registered,
        listed: fixture.listed,
        before,
        outputs,
        callback: receipts(await fixture.events(), fixture),
        submitted: submitted(fixture),
        after,
        foreignBefore: fixture.foreignBefore,
        foreignAfter,
      };
    },
    ["POST /passkey/verify-authentication", "GET /passkey/list-user-passkeys"],
  );

compatScenario(
  "passkey Source verifier rejects actual signed invalid flags presence RP origins challenge signature and counters before callbacks",
  async (ctx) => {
    const fixture = await setup(ctx);
    await fixture.owner.signOut();
    const before = await ctx.readUserState({ userId: fixture.signup.data!.user.id });
    expect(savedSessions(before)).toEqual([]);
    const outputs = [];
    for (const mode of [
      "backup-flags",
      "presence",
      "rp",
      "origin-host",
      "origin-port",
      "origin-case",
      "challenge",
      "signature",
    ] as const) {
      const challenge = await fixture.owner.$fetch("/passkey/generate-authenticate-options", {
        method: "GET",
      });
      expect(challenge.error).toBeNull();
      const flags =
        mode === "backup-flags"
          ? { backedUp: true }
          : mode === "presence"
            ? { userPresent: false }
            : mode === "rp"
              ? { rpId: "foreign.fixture.test" }
              : {};
      const origin =
        mode === "origin-host"
          ? "http://foreign.fixture.test"
          : mode === "origin-port"
            ? new URL(ctx.baseURL).origin.replace(/:\d+$/, ":1")
            : mode === "origin-case"
              ? ctx.baseURL.replace("localhost", "LOCALHOST")
              : ctx.baseURL;
      const proof = fixture.device.authenticate(
        mode === "challenge"
          ? { ...(challenge.data as object), challenge: "wrong-signed-challenge" }
          : challenge.data,
        origin,
        flags,
      );
      if (mode === "signature") {
        const bytes = Buffer.from(proof.response.signature, "base64url");
        bytes[bytes.length - 1] = bytes[bytes.length - 1]! ^ 1;
        proof.response.signature = bytes.toString("base64url");
      }
      let cookies: string[] = [];
      const result = await fixture.owner.$fetch("/passkey/verify-authentication", {
        method: "POST",
        body: { response: proof },
        onResponse({ response }) {
          cookies = response.headers.getSetCookie();
        },
      });
      expect(result.error).toMatchObject({
        status: mode === "signature" ? 401 : 400,
        code: "AUTHENTICATION_FAILED",
      });
      expect(cookies).toEqual([]);
      expect(await fixture.events()).toEqual([]);
      const replay = await fixture.owner.$fetch("/passkey/verify-authentication", {
        method: "POST",
        body: { response: proof },
      });
      expect(replay.error).toMatchObject({ status: 400, code: "CHALLENGE_NOT_FOUND" });
      expect(await ctx.readUserState({ userId: fixture.signup.data!.user.id })).toEqual(before);
      expect(await ctx.readUserState({ userId: fixture.foreignSignup.data!.user.id })).toEqual(
        fixture.foreignBefore,
      );
      outputs.push({ mode, challenge, result, cookies, replay });
    }
    const relogin = await fixture.owner.signIn.email({
      email: fixture.signup.data!.user.email,
      password: "password123",
    });
    expect(relogin.error).toBeNull();
    const listed = await fixture.owner.$fetch("/passkey/list-user-passkeys", { method: "GET" });
    expect(listed).toEqual(fixture.listed);
    return {
      signup: fixture.signup,
      foreignSignup: fixture.foreignSignup,
      registered: fixture.registered,
      before,
      foreignBefore: fixture.foreignBefore,
      outputs,
      events: await fixture.events(),
      submitted: submitted(fixture),
      relogin,
      listed,
      after: await ctx.readUserState({ userId: fixture.signup.data!.user.id }),
      foreignAfter: await ctx.readUserState({ userId: fixture.foreignSignup.data!.user.id }),
    };
  },
  ["POST /passkey/verify-authentication"],
);

compatScenario(
  "passkey overlapping issued challenges verify against the current saved counter rather than a stale generation snapshot",
  async (ctx) => {
    const fixture = await setup(ctx);
    let firstCookies: string[] = [];
    const first = await fixture.owner.$fetch("/passkey/generate-authenticate-options", {
      method: "GET",
      onResponse({ response }) {
        firstCookies = response.headers.getSetCookie();
      },
    });
    expect(first.error).toBeNull();
    expect(firstCookies).toHaveLength(1);
    const second = await fixture.owner.$fetch("/passkey/generate-authenticate-options", {
      method: "GET",
    });
    expect(second.error).toBeNull();
    const accepted = await fixture.owner.$fetch("/passkey/verify-authentication", {
      method: "POST",
      body: { response: fixture.device.authenticate(second.data, ctx.baseURL) },
    });
    expect(accepted.error).toBeNull();
    const before = await ctx.readUserState({ userId: fixture.signup.data!.user.id });
    expect(savedSessions(before)).toHaveLength(2);
    const proof = fixture.device.authenticate(first.data, ctx.baseURL, { counter: 1 });
    const rejected = await fixture.foreign.$fetch("/passkey/verify-authentication", {
      method: "POST",
      headers: { cookie: firstCookies.map((cookie) => cookie.split(";")[0]).join("; ") },
      body: { response: proof },
    });
    expect(rejected.error).toMatchObject({ status: 400, code: "AUTHENTICATION_FAILED" });
    const callback = await fixture.events();
    expect(callback).toHaveLength(1);
    const replay = await fixture.foreign.$fetch("/passkey/verify-authentication", {
      method: "POST",
      headers: { cookie: firstCookies.map((cookie) => cookie.split(";")[0]).join("; ") },
      body: { response: proof },
    });
    expect(replay.error).toMatchObject({ status: 400, code: "CHALLENGE_NOT_FOUND" });
    const after = await ctx.readUserState({ userId: fixture.signup.data!.user.id });
    expect(after).toEqual(before);
    const listed = await fixture.owner.$fetch("/passkey/list-user-passkeys", { method: "GET" });
    expect(listed.data).toMatchObject([{ counter: 1 }]);
    const foreignAfter = await ctx.readUserState({ userId: fixture.foreignSignup.data!.user.id });
    expect(foreignAfter).toEqual(fixture.foreignBefore);
    // Both actors captured requests independently in dispatch order. Only the real
    // successful request reached the callback; compare it to its actual first input.
    return {
      signup: fixture.signup,
      foreignSignup: fixture.foreignSignup,
      registered: fixture.registered,
      first,
      second,
      accepted,
      before,
      rejected,
      replay,
      callback: receipts(callback, fixture),
      submitted: submitted(fixture),
      after,
      listed,
      foreignBefore: fixture.foreignBefore,
      foreignAfter,
    };
  },
  ["POST /passkey/verify-authentication"],
);

for (const mode of ["increase", "decrease"] as const)
  compatScenario(
    `passkey application public counter ${mode} between issuance and verification remains authoritative over opaque stored history`,
    async (ctx) => {
      const fixture = await setup(ctx);
      const warming = [];
      if (mode === "decrease") {
        const warmChallenge = await fixture.owner.$fetch("/passkey/generate-authenticate-options", {
          method: "GET",
        });
        expect(warmChallenge.error).toBeNull();
        const warm = await fixture.owner.$fetch("/passkey/verify-authentication", {
          method: "POST",
          body: {
            response: fixture.device.authenticate(warmChallenge.data, ctx.baseURL, { counter: 5 }),
          },
        });
        expect(warm.error).toBeNull();
        const warmList = await fixture.owner.$fetch("/passkey/list-user-passkeys", {
          method: "GET",
        });
        expect(warmList.data).toMatchObject([{ counter: 5 }]);
        warming.push({ warmChallenge, warm, warmList });
      }
      const challenge = await fixture.owner.$fetch("/passkey/generate-authenticate-options", {
        method: "GET",
      });
      expect(challenge.error).toBeNull();
      const changed = await ctx.rawRequest({
        path: "/__test/passkey-current-counter",
        method: "POST",
        json: {
          credentialId: (fixture.registered.data as { credentialID: string }).credentialID,
          counter: mode === "increase" ? 5 : 0,
        },
      });
      expect(changed.status).toBe(200);
      expect(changed.body).toEqual({ updated: 1 });
      const selected = await fixture.owner.$fetch("/passkey/list-user-passkeys", { method: "GET" });
      expect(selected.data).toMatchObject([{ counter: mode === "increase" ? 5 : 0 }]);
      const before = await ctx.readUserState({ userId: fixture.signup.data!.user.id });
      const callbacksBefore = await fixture.events();
      const proof = fixture.device.authenticate(challenge.data, ctx.baseURL, { counter: 1 });
      const result = await fixture.owner.$fetch("/passkey/verify-authentication", {
        method: "POST",
        body: { response: proof },
      });
      if (mode === "increase") {
        expect(result.error).toMatchObject({ status: 400, code: "AUTHENTICATION_FAILED" });
        expect(await fixture.events()).toEqual(callbacksBefore);
        expect(await ctx.readUserState({ userId: fixture.signup.data!.user.id })).toEqual(before);
      } else {
        expect(result.error).toBeNull();
        expect(result.data).toMatchObject({
          user: { id: fixture.signup.data!.user.id },
          session: { userId: fixture.signup.data!.user.id },
        });
        expect(
          savedSessions(await ctx.readUserState({ userId: fixture.signup.data!.user.id })),
        ).toHaveLength(savedSessions(before).length + 1);
        expect((await fixture.events()).at(-1)).toMatchObject({
          facts: { newCounter: 1 },
          storedPasskey: { counter: 0, userId: fixture.signup.data!.user.id },
        });
      }
      const listed = await fixture.owner.$fetch("/passkey/list-user-passkeys", { method: "GET" });
      expect(listed.data).toMatchObject([{ counter: mode === "increase" ? 5 : 1 }]);
      const replay = await fixture.owner.$fetch("/passkey/verify-authentication", {
        method: "POST",
        body: { response: proof },
      });
      expect(replay.error).toMatchObject({ status: 400, code: "CHALLENGE_NOT_FOUND" });
      const retryChallenge = await fixture.owner.$fetch("/passkey/generate-authenticate-options", {
        method: "GET",
      });
      expect(retryChallenge.error).toBeNull();
      const retry = await fixture.owner.$fetch("/passkey/verify-authentication", {
        method: "POST",
        body: {
          response: fixture.device.authenticate(retryChallenge.data, ctx.baseURL, {
            counter: mode === "increase" ? 6 : 2,
          }),
        },
      });
      expect(retry.error).toBeNull();
      expect(retry.data).toMatchObject({
        user: { id: fixture.signup.data!.user.id },
        session: { userId: fixture.signup.data!.user.id },
      });
      const finalList = await fixture.owner.$fetch("/passkey/list-user-passkeys", {
        method: "GET",
      });
      expect(finalList.data).toMatchObject([{ counter: mode === "increase" ? 6 : 2 }]);
      const foreignAfter = await ctx.readUserState({ userId: fixture.foreignSignup.data!.user.id });
      expect(foreignAfter).toEqual(fixture.foreignBefore);
      return {
        signup: fixture.signup,
        foreignSignup: fixture.foreignSignup,
        registered: fixture.registered,
        warming,
        challenge,
        changed,
        selected,
        before,
        result,
        listed,
        replay,
        retryChallenge,
        retry,
        finalList,
        callback: receipts(await fixture.events(), fixture),
        submitted: submitted(fixture),
        after: await ctx.readUserState({ userId: fixture.signup.data!.user.id }),
        foreignBefore: fixture.foreignBefore,
        foreignAfter,
      };
    },
    ["POST /passkey/verify-authentication", "GET /passkey/list-user-passkeys"],
  );
