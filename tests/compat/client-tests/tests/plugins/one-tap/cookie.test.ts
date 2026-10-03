import { expect } from "bun:test";
import { hkdfSync } from "node:crypto";

import { makeSignature, symmetricDecodeJWT, symmetricEncodeJWT } from "better-auth/crypto";
import { EncryptJWT } from "jose";

import { credential } from "../../../support/id-token";
import { type FixtureProfile } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import { state, successful } from "./helpers";

const secret = "compat-test-only-key-not-real-minimum-32chars";

compatScenario(
  "One Tap encrypted provider account cookies authenticate token reads and reject altered credentials",
  async (ctx) => {
    const accessToken = "private-provider-access".repeat(350);
    const baseline = await state(ctx);
    const email = ctx.uniqueEmail("encrypted-account-cookie");
    const sub = ctx.uniqueToken("encrypted-account-cookie");
    const token = await credential({ sub, email, email_verified: true });
    const profile = "one-tap-account-cookie" as const;
    const actor = ctx.actor("cookie-owner", profile);
    const local = await actor.client.signUp.email({
      email,
      password: "password123",
      name: "Cookie Owner",
    });
    expect(local.error).toBeNull();

    const sent = await actor.client.sendVerificationEmail({ email });
    expect(sent.error).toBeNull();

    const delivery = (await ctx.readVerificationEmail({ email })) as {
      token: string;
    };
    expect(delivery.token).toBeString();

    const verified = await actor.client.verifyEmail({
      query: { token: delivery.token },
    });
    expect(verified.error).toBeNull();

    const accountId = await ctx.seedOAuthAccount({
      email,
      providerId: "google",
      accountId: sub,
      accessToken,
      refreshToken: "private-provider-refresh",
      accessTokenExpiresAt: "2099-01-01T00:00:00Z",
      refreshTokenExpiresAt: "2099-01-01T00:00:00Z",
      scope: "calendar,drive",
      idToken: token,
    });
    const created = await successful(ctx, token, profile, "cookie-owner");
    const signedIn = await successful(ctx, token, profile, "cookie-owner");
    const cookie = signedIn.accountCookie!;
    expect(cookie.header).toMatchObject({ alg: "dir", enc: "A256CBC-HS512" });
    expect(cookie.token.split(".")).toHaveLength(5);
    expect(cookie.token).not.toContain("private-provider-access");
    expect(cookie.payload).toMatchObject({
      id: accountId,
      userId: created.response.data!.user.id,
      providerId: "google",
      accountId: sub,
      accessToken,
      refreshToken: "private-provider-refresh",
      idToken: token,
      scope: "calendar,drive",
      password: null,
    });
    expect(cookie.payload.exp).toBe(Number(cookie.payload.iat) + 300);
    expect(cookie.payload.jti).toMatch(/^[0-9a-f]{8}-[0-9a-f-]{27}$/);

    const accessed = await actor.client.getAccessToken({
      useAccountCookie: true,
    });
    expect(accessed.error).toBeNull();
    expect(accessed.data?.accessToken).toBe(accessToken);

    const foreign = await ctx.actor("foreign-cookie", profile).client.signUp.email({
      email: ctx.uniqueEmail("foreign-cookie-owner"),
      password: "password123",
      name: "Foreign Cookie Owner",
    });
    expect(foreign.error).toBeNull();
    expect(foreign.data?.token).toBeString();

    const initial = await state(ctx);
    const session = signedIn.response.data!.token;
    const signedSession = encodeURIComponent(
      session + "." + (await makeSignature(session, secret)),
    );
    const request = async (account: string, sessionCookie = signedSession, chunked = false) =>
      actor.fetch(`${ctx.baseURL}/__test/profiles/${profile}/api/auth/get-access-token`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie:
            `better-auth.session_token=${sessionCookie}; ` +
            (chunked
              ? account
                  .split(/(.{0,1700})/)
                  .filter(Boolean)
                  .map(
                    (part, index) =>
                      `better-auth.account_data.${index}=${encodeURIComponent(part)}`,
                  )
                  .reverse()
                  .join("; ")
              : `better-auth.account_data=${encodeURIComponent(account)}`),
        },
        body: JSON.stringify({ useAccountCookie: true }),
      });
    const key = new Uint8Array(
      hkdfSync(
        "sha256",
        secret,
        "better-auth-account",
        "BetterAuth.js Generated Encryption Key",
        64,
      ),
    );
    const compressed = await new EncryptJWT(cookie.payload)
      .setProtectedHeader({ ...cookie.header, zip: "DEF" } as {
        alg: string;
        enc: string;
        zip: string;
      })
      .encrypt(key);
    expect(
      await symmetricDecodeJWT<Record<string, unknown>>(compressed, secret, "better-auth-account"),
    ).toEqual(cookie.payload);
    const compressedRead = await request(compressed);
    expect(compressedRead.status).toBe(200);
    expect((await compressedRead.json()).accessToken).toBe(accessToken);
    expect(signedIn.accountChunkCount).toBeGreaterThan(1);
    const chunkedRead = await request(cookie.token, signedSession, true);
    expect(chunkedRead.status).toBe(200);
    expect((await chunkedRead.json()).accessToken).toBe(accessToken);
    const tooLarge = await new EncryptJWT({ ...cookie.payload, oversized: "x".repeat(250_000) })
      .setProtectedHeader({ alg: "dir", enc: "A256CBC-HS512", zip: "DEF" })
      .encrypt(key);
    expect(await symmetricDecodeJWT(tooLarge, secret, "better-auth-account")).toBeNull();
    expect((await request(tooLarge)).status).toBe(400);
    const leeway = await symmetricEncodeJWT(cookie.payload, secret, "better-auth-account", -10);
    const accepted = await request(leeway);
    expect(accepted.status).toBe(200);

    const leewayBody = await accepted.json();
    expect(leewayBody.accessToken).toBe(accessToken);

    const parts = cookie.token.split(".");
    const ciphertext = Buffer.from(parts[3]!, "base64url");
    ciphertext[0]! ^= 1;
    parts[3] = ciphertext.toString("base64url");
    const wrongSecret = await symmetricEncodeJWT(
      cookie.payload,
      "other-private-cookie-secret",
      "better-auth-account",
      300,
    );
    const wrongSalt = await symmetricEncodeJWT(cookie.payload, secret, "wrong-account-salt", 300);
    const expired = await symmetricEncodeJWT(cookie.payload, secret, "better-auth-account", -60);
    const rejected = [];

    for (const value of [parts.join("."), wrongSecret, wrongSalt, expired]) {
      const response = await request(value);
      expect(response.status).toBe(400);

      const body = await response.json();
      expect(body.code).toBe("ACCOUNT_NOT_FOUND");

      rejected.push({ status: response.status, body });
    }

    const foreignCookie = encodeURIComponent(
      foreign.data!.token! + "." + (await makeSignature(foreign.data!.token!, secret)),
    );
    // Keep the original whole-cookie observation; feed each equivalent wire
    // spelling to the real authenticated endpoint and the published decoder.
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const alias = (index: number, transform: (value: string) => string) => {
      const segments = cookie.token.split(".");
      segments[index] = transform(segments[index]!);
      return segments.join(".");
    };
    const trailingBits = (value: string) =>
      value.slice(0, -1) + alphabet[alphabet.indexOf(value.at(-1)!) + 1];
    const aliases = [
      alias(2, (value) => value + "=="),
      alias(4, (value) => value + "="),
      alias(2, trailingBits),
      alias(4, trailingBits),
      alias(4, (value) => "\t\n\f\r " + value),
    ];
    const aliasReads = [];
    const foreignAliasReads = [];

    for (const value of aliases) {
      const decoded = await symmetricDecodeJWT<Record<string, unknown>>(
        value,
        secret,
        "better-auth-account",
      );
      expect(decoded).toEqual(cookie.payload);

      const response = await request(value);
      expect(response.status).toBe(200);

      const body = await response.json();
      expect(body).toEqual(leewayBody);

      aliasReads.push({ status: response.status, body });
      const denied = await request(value, foreignCookie);
      expect(denied.status).toBe(400);

      const deniedBody = await denied.json();
      expect(deniedBody.code).toBe("ACCOUNT_NOT_FOUND");

      foreignAliasReads.push({ status: denied.status, body: deniedBody });
    }

    const malformedReads = [];

    for (const value of [
      alias(2, (value) => value + "="),
      alias(4, (value) => value + "=="),
      alias(4, (value) => "\v" + value),
      alias(2, (value) => "+" + value.slice(1)),
      alias(1, () => "AA"),
      // Decoding this header yields the same JSON, but its ORIGINAL spelling
      // participates in authentication and must not be canonicalized as AAD.
      alias(0, (value) => " " + value),
    ]) {
      expect(await symmetricDecodeJWT(value, secret, "better-auth-account")).toBeNull();

      const response = await request(value);
      expect(response.status).toBe(400);

      const body = await response.json();
      expect(body.code).toBe("ACCOUNT_NOT_FOUND");

      malformedReads.push({ status: response.status, body });
    }

    expect((await request(compressed, foreignCookie, true)).status).toBe(400);
    expect((await request(cookie.token, foreignCookie, true)).status).toBe(400);
    const foreignRead = await request(cookie.token, foreignCookie);
    expect(foreignRead.status).toBe(400);

    const foreignBody = await foreignRead.json();
    expect(foreignBody.code).toBe("ACCOUNT_NOT_FOUND");

    const persisted = await state(ctx);
    expect(persisted).toEqual(initial);

    await ctx.seedOAuthAccount({
      email,
      providerId: "google",
      accountId: sub,
      accessToken: "small-reissued-grant",
      refreshToken: "private-provider-refresh",
      accessTokenExpiresAt: "2099-01-01T00:00:00Z",
      refreshTokenExpiresAt: "2099-01-01T00:00:00Z",
      scope: "calendar,drive",
      idToken: token,
    });
    const shrunk = await successful(ctx, token, profile, "cookie-owner");
    expect(shrunk.accountChunkCount).toBe(0);
    expect(shrunk.accountCookie!.payload.accessToken).toBe("small-reissued-grant");
    // Published cookies retain the original grant until their expiry even after
    // the physical account is reissued. A live owner's session is still required.
    expect((await request(cookie.token)).status).toBe(200);
    const reissuedState = await state(ctx);
    const revokedResponse = await actor.fetch(
      `${ctx.baseURL}/__test/profiles/${profile}/api/auth/sign-out`,
      {
        method: "POST",
        headers: {
          cookie:
            `better-auth.session_token=${signedSession}; ` +
            cookie.token
              .match(/.{1,1700}/g)!
              .map((part, index) => `better-auth.account_data.${index}=${part}`)
              .join("; "),
        },
      },
    );
    expect(revokedResponse.status).toBe(200);
    const revoked = await revokedResponse.json();
    expect((await request(cookie.token, signedSession, true)).status).toBe(401);
    const revokedState = await state(ctx);
    expect(revokedState.sessions.some((row) => row.token === session)).toBe(false);
    expect(revokedState.accounts).toEqual(reissuedState.accounts);
    return {
      shrunk,
      revoked,
      revokedState: {
        ...revokedState,
        jwksFetches: revokedState.jwksFetches - baseline.jwksFetches,
      },
      local,
      verified,
      created,
      signedIn,
      accessed,
      leewayBody,
      compressed: {
        accountCookie: {
          token: compressed,
          header: { ...cookie.header, zip: "DEF" },
          payload: cookie.payload,
        },
      },
      rejected,
      foreignBody,
      aliasReads,
      foreignAliasReads,
      malformedReads,
      persisted: {
        ...persisted,
        jwksFetches: persisted.jwksFetches - baseline.jwksFetches,
      },
    };
  },
  ["POST /one-tap/callback", "POST /get-access-token"],
);

compatScenario(
  "Account cookie lifetimes retain fractional claims and account-specific attributes",
  async (ctx) => {
    const observations = [];
    for (const [suffix, lifetime] of [
      ["fractional", 1.75],
      ["zero", 300],
      ["negative", -4.25],
      ["nan", 300],
      ["override", 7],
    ] as const) {
      const profile = `one-tap-account-cookie-${suffix}` as FixtureProfile;
      const token = await credential({
        sub: ctx.uniqueToken(suffix),
        email: ctx.uniqueEmail(suffix),
        email_verified: true,
      });
      const actor = ctx.actor(suffix, profile);
      const response = await actor.fetch(
        `${ctx.baseURL}/__test/profiles/${profile}/api/auth/one-tap/callback`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ idToken: token }),
        },
      );
      expect(response.status).toBe(200);
      const raw = response.headers.getSetCookie();
      const account = raw.find((value) => value.startsWith("better-auth.account_data="))!;
      expect(account).toBeString();
      const compact = decodeURIComponent(
        account.split(";")[0]!.slice("better-auth.account_data=".length),
      );
      const payload = await symmetricDecodeJWT<Record<string, unknown>>(
        compact,
        secret,
        "better-auth-account",
      );
      expect(payload).not.toBeNull();
      expect(payload!.exp).toBe(Number(payload!.iat) + lifetime);
      expect(account.includes("Max-Age=")).toBe(lifetime >= 0);
      if (lifetime >= 0) expect(account).toContain(`; Max-Age=${Math.floor(lifetime)};`);
      if (suffix === "override") {
        expect(account).not.toContain("HttpOnly");
        expect(account).toContain("SameSite=Strict");
      }
      if (process.env.COMPAT_OBSERVATIONS_DIR)
        await Bun.write(
          `${process.env.COMPAT_OBSERVATIONS_DIR}/ttl-raw-${new URL(ctx.baseURL).port}-${suffix}.json`,
          JSON.stringify({ raw, compact, payload }, null, 2),
        );
      observations.push({
        suffix,
        lifetime,
        accountCookie: {
          token: compact,
          header: JSON.parse(Buffer.from(compact.split(".")[0]!, "base64url").toString()),
          payload,
        },
        response: await response.json(),
      });
    }
    const profile = "one-tap-account-cookie-infinity" as const;
    const actor = ctx.actor("infinity", profile);
    const token = await credential({
      sub: ctx.uniqueToken("infinity"),
      email: ctx.uniqueEmail("infinity"),
      email_verified: true,
    });
    const response = await actor.fetch(
      `${ctx.baseURL}/__test/profiles/${profile}/api/auth/one-tap/callback`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ idToken: token }),
      },
    );
    expect(response.status).toBe(401);
    expect(
      response.headers.getSetCookie().some((raw) => raw.startsWith("better-auth.account_data=")),
    ).toBe(false);
    return { observations, nonfinite: { status: response.status, body: await response.text() } };
  },
  ["POST /one-tap/callback"],
);
