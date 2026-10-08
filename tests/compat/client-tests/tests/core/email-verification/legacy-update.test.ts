import { expect } from "bun:test";

import { SignJWT, jwtVerify } from "jose";
import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
for (const authenticated of [true, false]) {
  compatScenario(
    `legacy verification mailbox update publishes unverified identity then a fresh proof (${authenticated ? "authenticated" : "guest"})`,
    async (ctx) => {
      const profile = "user-lifecycle-auto";
      const control = async (action = "state") => {
        const r = await ctx.rawRequest({
          path: "/__test/user-lifecycle/control",
          method: "POST",
          json: { profile: "auto", action },
        });
        expect(r.status).toBe(200);
        return r.body as any;
      };
      await control("reset");
      const email = ctx.uniqueEmail("legacy-old");
      const next = ctx.uniqueEmail("legacy-new");
      const owner = ctx.actor("owner", profile);
      const signup = await owner.client.signUp.email({
        email,
        name: "Owner",
        password: "password123",
      });
      expect(signup.error).toBeNull();
      expect((await owner.client.sendVerificationEmail({ email })).error).toBeNull();
      const original = (await control()).events
        .filter((e: any) => e.stage === "verification-mail")
        .at(-1).token;
      expect((await owner.client.verifyEmail({ query: { token: original } })).error).toBeNull();
      await control("reset");
      const before = await control();
      expect(before.users.find((u: any) => u.id === signup.data!.user.id).emailVerified).toBe(true);
      const secret = new TextEncoder().encode("compat-test-only-key-not-real-minimum-32chars");
      const proof = await new SignJWT({ email, updateTo: next })
        .setProtectedHeader({ alg: "HS256" })
        .setIssuedAt(946684800)
        .setExpirationTime(4102444800)
        .sign(secret);
      const actor = authenticated ? owner : ctx.actor("guest", profile);
      let rawCookies: string[] = [];
      const updated = await actor.client.verifyEmail({
        query: { token: proof },
        fetchOptions: {
          onResponse({ response }) {
            rawCookies = response.headers.getSetCookie();
          },
        },
      });
      expect(updated.error).toBeNull();
      expect(rawCookies.some((c) => c.startsWith("better-auth.session_token="))).toBe(true);
      const after = await control();
      expect(after.users.find((u: any) => u.id === signup.data!.user.id)).toMatchObject({
        email: next,
        emailVerified: false,
      });
      expect(after.accounts).toEqual(before.accounts);
      expect(after.sessions.length).toBe(before.sessions.length + (authenticated ? 0 : 1));
      const deliveries = after.events.filter((e: any) => e.stage === "verification-mail");
      expect(deliveries).toHaveLength(1);
      expect(deliveries[0].user.email).toBe(next);
      const followup = await jwtVerify(deliveries[0].token, secret, { algorithms: ["HS256"] });
      expect(followup.payload.email).toBe(next);
      expect(followup.payload.exp! - followup.payload.iat!).toBe(3600);
      expect(followup.payload).not.toHaveProperty("updateTo");
      const pending = await actor.client.getSession();
      expect(pending.data!.user).toMatchObject({
        id: signup.data!.user.id,
        email: next,
        emailVerified: false,
      });
      const verified = await actor.client.verifyEmail({ query: { token: deliveries[0].token } });
      expect(verified.error).toBeNull();
      const session = await actor.client.getSession();
      expect(session.data!.user).toMatchObject({
        id: signup.data!.user.id,
        email: next,
        emailVerified: true,
      });
      const final = await control();
      expect(final.accounts).toEqual(before.accounts);
      const cookies = rawCookies.map((raw) => {
        const c = Cookie.parse(raw)!;
        return {
          name: c.key,
          token: decodeURIComponent(c.value),
          maxAge: c.maxAge,
          path: c.path,
          secure: c.secure,
          httpOnly: c.httpOnly,
          sameSite: c.sameSite,
        };
      });
      const project = (s: any) => ({
        ...s,
        accounts: s.accounts.map((a: any) => ({
          ...a,
          password: a.password ? { token: a.password } : a.password,
        })),
      });
      return ctx.snapshot({
        signup,
        updated,
        cookies,
        pending,
        verified,
        session,
        claims: { token: deliveries[0].token },
        before: project(before),
        after: project(after),
        final: project(final),
      });
    },
    ["GET /verify-email", "GET /get-session"],
  );
}
