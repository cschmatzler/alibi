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
    const mutatedPayload = Buffer.from(
      JSON.stringify({ ...claims, email: ctx.uniqueEmail("tampered-address") }),
    ).toString("base64url");
    const mutatedSignature = (signature![0] === "A" ? "B" : "A") + signature!.slice(1);
    const wrongSecret = await new SignJWT(claims)
      .setProtectedHeader({ alg: "HS256" })
      .sign(new TextEncoder().encode("wrong-test-secret-also-at-least-32-characters"));
    const guest = ctx.actor("guest", profile);
    let cookies: string[] = [];
    const denied = [];
    for (const [kind, token] of [
      ["payload", `${header}.${mutatedPayload}.${signature}`],
      ["signature", `${header}.${payload}.${mutatedSignature}`],
      ["wrong-secret", wrongSecret],
    ] as const) {
      expect(token).not.toBe(original);
      const response = await guest.client.verifyEmail({
        query: { token },
        fetchOptions: {
          onResponse({ response }) {
            cookies = response.headers.getSetCookie();
          },
        },
      });
      expect(response.error).toMatchObject({ status: 401, code: "INVALID_TOKEN" });
      expect(cookies.filter((cookie) => cookie.startsWith("better-auth.session"))).toEqual([]);
      expect(await control()).toEqual(before);
      denied.push({ kind, response });
    }
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
