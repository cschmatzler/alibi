import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import {
  readUserState,
  storedVerification,
  verificationCount,
} from "../../../support/verification";

for (const profile of [undefined, "passwordless-disabled"] as const) {
  compatScenario(
    `server email OTP sign-in preserves owner and creation authority with signup ${profile ? "disabled" : "enabled"}`,
    async (ctx) => {
      const ownerActor = ctx.actor("owner", profile);
      const owner = await ownerActor.client.signUp.email({
        email: ctx.uniqueEmail("server-otp-login-owner"),
        password: "password123",
        name: "Established Owner",
      });
      expect(owner.error).toBeNull();
      const foreign = await ctx
        .actor("foreign", profile)
        .client.signUp.email({
          email: ctx.uniqueEmail("server-otp-login-foreign"),
          password: "password123",
          name: "Foreign",
        });
      expect(foreign.error).toBeNull();
      const email = owner.data!.user.email;
      async function create(email: string, type: string) {
        const result = await ctx.rawRequest({
          path: "/__test/server-api",
          method: "POST",
          json: { operation: "create-email-otp", ...(profile ? { profile } : {}), email, type },
        });
        expect(result.status).toBe(200);
        return result.body as string;
      }
      const verification = await ctx.rawRequest({
        path: "/__test/server-api/email-otp-verify",
        method: "POST",
        json: {
          ...(profile ? { profile } : {}),
          body: { email, otp: await create(email, "email-verification") },
        },
      });
      expect(verification.status).toBe(200);
      const expectedUser = (verification.body as { user: Record<string, unknown> }).user;
      const before = await readUserState(ctx, owner.data!.user.id);
      const foreignBefore = await readUserState(ctx, foreign.data!.user.id);
      async function invoke(body: unknown, actorName = "sign-in-sdk") {
        const response = await ctx
          .actor(actorName, profile)
          .fetch(`${ctx.baseURL}/__test/server-api/email-otp-sign-in`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              ...(profile ? { profile } : {}),
              body,
              headers: {
                "user-agent": "server-email-otp-sign-in",
                "x-forwarded-for": "198.51.100.32",
              },
            }),
          });
        return {
          status: response.status,
          body: (await response.json()) as any,
          cookieCount: response.headers.getSetCookie().length,
        };
      }
      const otp = await create(email, "sign-in");
      const identifier = `sign-in-otp-${email}`;
      const proof = await storedVerification(ctx, identifier);
      const invalid = await invoke({ email, otp: 42 });
      expect(invalid.status).toBe(400);
      expect(invalid.body.code).toBe("VALIDATION_ERROR");
      expect(await storedVerification(ctx, identifier)).toEqual(proof);
      const wrong = await invoke({ email, otp: "wrong" });
      expect(wrong.status).toBe(400);
      expect(wrong.body.code).toBe("INVALID_OTP");
      expect((await storedVerification(ctx, identifier))[0]!.value).toBe(`${otp}:1`);
      const accepted = await invoke({
        email: email.toUpperCase(),
        otp,
        username: 5,
        displayUsername: { unexpected: true },
        name: "Ignored New Name",
        image: "https://ignored.example/image.png",
        userId: foreign.data!.user.id,
      });
      expect(accepted.status).toBe(200);
      expect(accepted.body.user).toEqual(expectedUser);
      expect(accepted.cookieCount).toBeGreaterThan(0);
      const session = await ctx.actor("sign-in-sdk", profile).client.getSession();
      expect(session.data!.user.id).toBe(owner.data!.user.id);
      expect(session.data!.session.token).toBe(accepted.body.token);
      expect(session.data!.session.userAgent).toBe("server-email-otp-sign-in");
      expect(session.data!.session.ipAddress).toBe("198.51.100.32");
      const after = await readUserState(ctx, owner.data!.user.id);
      expect(after.user).toEqual(before.user);
      expect(after.accounts).toEqual(before.accounts);
      expect(after.sessions).toHaveLength(before.sessions.length + 1);
      expect(after.sessions).toEqual(expect.arrayContaining(before.sessions));
      expect(await verificationCount(ctx, identifier)).toBe(0);
      expect((await ownerActor.client.getSession()).data!.user.id).toBe(owner.data!.user.id);
      expect(await readUserState(ctx, foreign.data!.user.id)).toEqual(foreignBefore);
      const replay = await invoke({ email, otp });
      expect(replay.status).toBe(400);
      expect(replay.body.code).toBe("INVALID_OTP");
      expect(await readUserState(ctx, owner.data!.user.id)).toEqual(after);
      const guest = ctx.uniqueEmail("server-otp-login-guest");
      const created = await invoke(
        {
          email: guest,
          otp: await create(guest, "sign-in"),
          name: "Fresh OTP",
          image: "https://images.example/otp.png",
          username: "fresh_otp",
          displayUsername: "Fresh OTP",
        },
        "creation-sdk",
      );
      if (profile) {
        expect(created.status).toBe(400);
        expect(created.body.code).toBe("INVALID_OTP");
        expect(created.cookieCount).toBe(0);
        expect((await ctx.actor("creation-sdk", profile).client.getSession()).data).toBeNull();
        expect(await readUserState(ctx, owner.data!.user.id)).toEqual(after);
      } else {
        expect(created.status).toBe(200);
        expect(created.body.user).toMatchObject({
          email: guest,
          name: "Fresh OTP",
          emailVerified: true,
          username: "fresh_otp",
        });
        const fresh = await ctx.actor("creation-sdk", profile).client.getSession();
        expect(fresh.data!.user.id).toBe(created.body.user.id);
        expect(fresh.data!.session.token).toBe(created.body.token);
        expect((await readUserState(ctx, created.body.user.id)).accounts).toEqual([]);
      }
      expect(await verificationCount(ctx, `sign-in-otp-${guest}`)).toBe(0);
      expect(await readUserState(ctx, foreign.data!.user.id)).toEqual(foreignBefore);
      return ctx.snapshot({ before, invalid, wrong, accepted, session, after, replay, created });
    },
  );
}
