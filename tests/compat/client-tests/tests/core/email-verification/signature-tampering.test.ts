import { expect } from "bun:test";

import { SignJWT } from "jose";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "verification rejects payload signature and wrong-secret tampering before hooks or sessions",
  async (ctx) => {
    const profile = "user-lifecycle-auto";
    const control = async (action = "state") => {
      const response = await ctx.rawRequest({
        path: "/__test/user-lifecycle/control",
        method: "POST",
        json: { profile: "auto", action },
      });
      expect(response.status).toBe(200);
      return response.body as any;
    };
    await control("reset");
    const email = ctx.uniqueEmail("signature-owner");
    const signup = await ctx
      .actor("owner", profile)
      .client.signUp.email({ email, name: "Proof Owner", password: "password123" });
    expect(signup.error).toBeNull();
    expect(
      (await ctx.actor("owner", profile).client.sendVerificationEmail({ email })).error,
    ).toBeNull();
    const before = await control();
    const delivered = before.events.findLast((event: any) => event.stage === "verification-mail");
    expect(delivered?.token).toBeString();
    const original = delivered.token as string;
    const [header, payload, signature] = original.split(".");
    const claims = JSON.parse(Buffer.from(payload!, "base64url").toString());
    expect(claims.email).toBe(email);
    const now = Math.floor(Date.now() / 1000);
    const secret = new TextEncoder().encode("compat-test-only-key-not-real-minimum-32chars");
    const token = (nbf: number) =>
      new SignJWT({ email, iat: now, nbf, exp: now + 3600 })
        .setProtectedHeader({ alg: "HS256" })
        .sign(secret);
    const guest = ctx.actor("guest", profile);
    let cookies: string[] = [];
    const denied = await guest.client.verifyEmail({
      query: { token: await token(now + 1800) },
      fetchOptions: {
        onResponse({ response }) {
          cookies = response.headers.getSetCookie();
        },
      },
    });
    expect(denied.error).toMatchObject({ status: 401, code: "INVALID_TOKEN" });
    expect(cookies.filter((cookie) => cookie.startsWith("better-auth.session"))).toEqual([]);
    expect(await control()).toEqual(before);
    expect((await guest.client.getSession()).data).toBeNull();
    const accepted = await guest.client.verifyEmail({ query: { token: original } });
    expect(accepted.error).toBeNull();
    const after = await control();
    expect(after.users.find((user: any) => user.id === signup.data!.user.id).emailVerified).toBe(
      true,
    );
    expect(after.accounts).toEqual(before.accounts);
    expect(after.sessions.length).toBe(before.sessions.length + 1);
    expect(
      after.events.filter(
        (event: any) => event.stage.includes("verification") && !event.stage.includes("mail"),
      ).length,
    ).toBeGreaterThan(0);
    const session = await guest.client.getSession();
    expect(session.data!.user.id).toBe(signup.data!.user.id);
    const project = (state: any) => ({
      ...state,
      accounts: state.accounts.map((account: any) => ({
        ...account,
        password: account.password ? { token: account.password } : account.password,
      })),
    });
    return ctx.snapshot({
      signup,
      denied,
      cookies,
      accepted,
      session,
      before: project(before),
      after: project(after),
    });
  },
  ["GET /verify-email", "GET /get-session"],
);
