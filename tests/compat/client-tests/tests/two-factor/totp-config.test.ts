import { expect } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { twoFactorClient } from "better-auth/client/plugins";
import { z } from "zod";
import { authProfilePath, type FixtureProfile } from "../../support/profiles";
import { compatScenario } from "../../support/scenario";
import { generateCurrentTotp, hotpAtCounter, redactTwoFactorPayload } from "./totp-helper";

function clientFor(
  ctx: Parameters<Parameters<typeof compatScenario>[1]>[0],
  profile: FixtureProfile | undefined,
  name = "primary",
) {
  const actor = ctx.actor(name, profile);
  return createAuthClient({
    baseURL: profile ? `${ctx.baseURL}${authProfilePath(profile)}` : ctx.baseURL,
    plugins: [twoFactorClient()],
    fetchOptions: { customFetchImpl: actor.fetch },
  });
}

function uriFields(uri: string) {
  const parsed = new URL(uri);
  expect(parsed.protocol).toBe("otpauth:");
  expect(parsed.hostname).toBe("totp");
  expect(parsed.searchParams.get("secret")).toMatch(/^[A-Z2-7]+$/);
  return {
    label: decodeURIComponent(parsed.pathname.slice(1)),
    issuer: parsed.searchParams.get("issuer"),
    digits: parsed.searchParams.get("digits"),
    period: parsed.searchParams.get("period"),
  };
}

compatScenario(
  "server-only TOTP generation matches independent HMAC for configured and default UTF8 secrets",
  async (ctx) => {
    const results = [];
    for (const [profile, digits, period] of [
      ["two-factor-totp-default", 6, 30],
      ["two-factor-totp-config", 8, 45],
      ["two-factor-totp-zero", 6, 30],
    ] as const) {
      for (const secret of ["a", "密钥🔑", "12345678901234567890"]) {
        const first = Math.floor(Date.now() / 1000 / period);
        const response = await ctx.rawRequest({
          path: "/__test/two-factor-totp",
          method: "POST",
          json: { profile, secret },
        });
        const last = Math.floor(Date.now() / 1000 / period);
        expect(response.status).toBe(200);
        const { code } = z.object({ code: z.string() }).parse(response.body);
        expect(code).toMatch(new RegExp(`^\\d{${digits}}$`));
        const expected = await Promise.all(
          Array.from({ length: last - first + 1 }, (_, index) =>
            hotpAtCounter(new TextEncoder().encode(secret), digits, first + index),
          ),
        );
        expect(expected).toContain(code);
        results.push({ profile, secret, status: response.status, code: "<totp-code>" });
      }
    }
    const publicRequest = await ctx.rawRequest({
      path: `${authProfilePath("two-factor-totp-default")}/totp/generate`,
      method: "POST",
      json: { secret: "a" },
    });
    expect(publicRequest.status).toBe(404);
    const empty = await ctx.rawRequest({
      path: "/__test/two-factor-totp",
      method: "POST",
      json: { secret: "" },
    });
    expect(empty).toMatchObject({ status: 500, body: { message: "Internal server error" } });
    return { results, publicRequest, empty };
  },
);

compatScenario(
  "configured TOTP URI fields and real codes preserve enrollment and sign-in ownership",
  async (ctx) => {
    const results = [];
    for (const [profile, digits, period, providerIssuer] of [
      ["two-factor-totp-config", "8", "45", "Authenticator Issuer"],
      ["two-factor-totp-zero", "6", "0", "Fixture Auth"],
    ] as const) {
      const client = clientFor(ctx, profile);
      const email = ctx.uniqueEmail(`configured-totp-${profile}`);
      const password = "password123";
      const signup = await client.signUp.email({ email, password, name: "Configured Factor" });
      expect(signup.error).toBeNull();
      if (!signup.data) throw new Error("factor owner required");
      const absent = await client.twoFactor.getTotpUri({ password: "wrong-password" });
      expect(absent.error).toMatchObject({ status: 400, code: "TOTP_NOT_ENABLED" });
      const enable = await client.twoFactor.enable({ password, issuer: "" });
      expect(enable.error).toBeNull();
      const enabled = z
        .object({ totpURI: z.string(), backupCodes: z.array(z.string()) })
        .parse(enable.data);
      const enrollment = uriFields(enabled.totpURI);
      expect(enrollment).toEqual({
        label: `Enrollment Issuer:${email}`,
        issuer: "Enrollment Issuer",
        digits,
        period,
      });
      const before = await ctx.readUserState({ userId: signup.data.user.id });
      const wrong = await client.twoFactor.verifyTotp({ code: "invalid-code" });
      expect(wrong.error).toMatchObject({ status: 401, code: "INVALID_CODE" });
      expect(await ctx.readUserState({ userId: signup.data.user.id })).toEqual(before);
      const saved = await client.twoFactor.getTotpUri({ password });
      expect(saved.error).toBeNull();
      const savedURI = z.object({ totpURI: z.string() }).parse(saved.data).totpURI;
      const authenticator = uriFields(savedURI);
      expect(authenticator).toEqual({
        label: `${providerIssuer}:${email}`,
        issuer: providerIssuer,
        digits,
        period: period === "0" ? "30" : period,
      });
      expect(new URL(savedURI).searchParams.get("secret")).toBe(
        new URL(enabled.totpURI).searchParams.get("secret"),
      );
      const verified = await client.twoFactor.verifyTotp({
        code: await generateCurrentTotp(savedURI),
      });
      expect(verified.error).toBeNull();
      const session = await client.getSession();
      expect(session.data?.user.id).toBe(signup.data.user.id);
      expect(session.data?.user.twoFactorEnabled).toBe(true);
      const persisted = z
        .object({
          twoFactorExists: z.literal(true),
          sessions: z.array(z.object({ token: z.string(), userId: z.string() })),
        })
        .parse(await ctx.readUserState({ userId: signup.data.user.id }));
      expect(persisted.sessions).toHaveLength(1);
      expect(persisted.sessions[0]?.token).toBe(session.data?.session.token);
      await client.signOut();
      const redirect = await client.signIn.email({ email, password });
      expect(redirect.error).toBeNull();
      expect(redirect.data).toHaveProperty("twoFactorRedirect", true);
      const login = await client.twoFactor.verifyTotp({
        code: await generateCurrentTotp(savedURI),
      });
      expect(login.error).toBeNull();
      const final = await client.getSession();
      expect(final.data?.user.id).toBe(signup.data.user.id);
      results.push({
        signup: ctx.snapshot(signup),
        absent: ctx.snapshot(absent),
        enable: ctx.snapshot(redactTwoFactorPayload(enable)),
        enrollment,
        wrong: ctx.snapshot(wrong),
        saved: ctx.snapshot(redactTwoFactorPayload(saved)),
        authenticator,
        verified: ctx.snapshot(verified),
        session: ctx.snapshot(session),
        redirect: ctx.snapshot(redirect),
        login: ctx.snapshot(login),
        final: ctx.snapshot(final),
      });
    }
    return results;
  },
  ["POST /two-factor/enable", "POST /two-factor/get-totp-uri", "POST /two-factor/verify-totp"],
);

compatScenario(
  "disabled TOTP rejects generator and verification before touching owner factor state",
  async (ctx) => {
    const profile = "two-factor-totp-disabled";
    const client = clientFor(ctx, profile);
    const password = "password123";
    const signup = await client.signUp.email({
      email: ctx.uniqueEmail("disabled-totp"),
      password,
      name: "Disabled Authenticator",
    });
    expect(signup.error).toBeNull();
    if (!signup.data) throw new Error("factor owner required");
    const before = await ctx.readUserState({ userId: signup.data.user.id });
    const enable = await client.twoFactor.enable({ password });
    expect(enable.error).toMatchObject({
      status: 400,
      code: "TOTP_NOT_CONFIGURED",
      message: "TOTP is not available",
    });
    const get = await client.twoFactor.getTotpUri({ password: "wrong-password" });
    const verify = await client.twoFactor.verifyTotp({ code: "123456" });
    const guest = await clientFor(ctx, profile, "guest").twoFactor.verifyTotp({ code: "123456" });
    const generated = await ctx.rawRequest({
      path: "/__test/two-factor-totp",
      method: "POST",
      json: { profile, secret: "a" },
    });
    for (const result of [get, verify, guest])
      expect(result.error).toMatchObject({
        status: 400,
        code: "TOTP_NOT_CONFIGURED",
        message: "totp isn't configured",
      });
    expect(generated).toMatchObject({
      status: 400,
      body: { code: "TOTP_NOT_CONFIGURED", message: "totp isn't configured" },
    });
    expect(await ctx.readUserState({ userId: signup.data.user.id })).toEqual(before);
    return {
      signup: ctx.snapshot(signup),
      enable: ctx.snapshot(redactTwoFactorPayload(enable)),
      get: ctx.snapshot(get),
      verify: ctx.snapshot(verify),
      guest: ctx.snapshot(guest),
      generated,
    };
  },
  ["POST /two-factor/enable", "POST /two-factor/get-totp-uri", "POST /two-factor/verify-totp"],
);

compatScenario(
  "default TOTP URI preserves reserved issuer bytes and explicit default parameters",
  async (ctx) => {
    const client = clientFor(ctx, undefined);
    const email = ctx.uniqueEmail("default-totp-uri");
    const password = "password123";
    const signup = await client.signUp.email({ email, password, name: "Default Authenticator" });
    expect(signup.error).toBeNull();
    const issuer = "Issuer: !'()*%🍵";
    const enable = await client.twoFactor.enable({ password, issuer });
    expect(enable.error).toBeNull();
    const uri = z.object({ totpURI: z.string() }).parse(enable.data).totpURI;
    const fields = uriFields(uri);
    expect(fields).toEqual({ label: `${issuer}:${email}`, issuer, digits: "6", period: "30" });
    const secret = new URL(uri).searchParams.get("secret")!;
    const query = new URLSearchParams({ secret, issuer, digits: "6", period: "30" });
    expect(uri).toBe(
      `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(email)}?${query}`,
    );
    const saved = await client.twoFactor.getTotpUri({ password });
    expect(saved.error).toBeNull();
    const savedURI = z.object({ totpURI: z.string() }).parse(saved.data).totpURI;
    const savedFields = uriFields(savedURI);
    expect(savedFields).toEqual({
      label: `Better Auth:${email}`,
      issuer: "Better Auth",
      digits: "6",
      period: "30",
    });
    expect(new URL(savedURI).searchParams.get("secret")).toBe(secret);
    return {
      signup: ctx.snapshot(signup),
      enable: ctx.snapshot(redactTwoFactorPayload(enable)),
      fields,
      saved: ctx.snapshot(redactTwoFactorPayload(saved)),
      savedFields,
    };
  },
);
