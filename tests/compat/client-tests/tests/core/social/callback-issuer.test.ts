import { expect } from "bun:test";
import { readFileSync } from "node:fs";

import { importPKCS8, SignJWT } from "jose";
import { z } from "zod";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

compatScenario(
  "discovered OAuth callback issuer rejects mixup before exchanging a valid signed grant",
  async (ctx) => {
    const physicalState = z
      .object({
        users: z.array(z.unknown()),
        accounts: z.array(
          z
            .object({ accountId: z.string(), providerId: z.string(), userId: z.string() })
            .passthrough(),
        ),
        sessions: z.array(z.unknown()),
      })
      .passthrough();
    const receiptList = z.array(z.object({ path: z.string() }).passthrough());
    const readState = async () =>
      physicalState.parse((await ctx.rawRequest({ path: "/__test/social-provider/state" })).body);
    const readReceipts = async () =>
      receiptList.parse(
        (await ctx.rawRequest({ path: "/__test/generic-discovery/receipts" })).body,
      );
    const profile = "generic-discovery-oidc";
    const callbackPath = authProfilePath(profile) + "/callback/discovery";
    const issuer = "https://issuer.example.invalid";
    const owner = ctx.actor("owner", profile);
    const foreign = ctx.actor("foreign", profile);
    const foreignEmail = ctx.uniqueEmail("mixup-foreign");
    const signup = await foreign.client.signUp.email({
      email: foreignEmail,
      name: "Foreign",
      password: "Password123!",
    });
    expect(signup.error).toBeNull();
    const foreignBefore = await ctx.readUserState({ userId: signup.data!.user.id });
    const before = await readState();
    const email = ctx.uniqueEmail("mixup-owner");
    const subject = ctx.uniqueToken("mixup-sub");
    const key = await importPKCS8(
      readFileSync("../../../tests/fixtures/one-tap/private-key.pem", "utf8"),
      "RS256",
    );
    const results = [];
    for (const suppliedIssuer of ["https://attacker.example.invalid", issuer]) {
      const start = await owner.client.signIn.social({
        provider: "discovery",
        callbackURL: "/issuer-complete",
        errorCallbackURL: "/issuer-error",
      });
      expect(start.error).toBeNull();
      const authorization = new URL(start.data!.url!);
      const state = authorization.searchParams.get("state")!;
      const nonce = authorization.searchParams.get("nonce")!;
      const signed = await new SignJWT({
        sub: subject,
        email,
        name: "Mixup Owner",
        email_verified: true,
        nonce,
      })
        .setProtectedHeader({ alg: "RS256", kid: "one-tap-local-rs256" })
        .setIssuer(issuer)
        .setAudience("discovery-client")
        .setExpirationTime("5m")
        .sign(key);
      await ctx.rawRequest({
        path: "/__test/generic-discovery/control",
        method: "POST",
        json: {
          profile: { id: subject, sub: subject, email, name: "Mixup Owner", emailVerified: true },
          tokenResponse: {
            access_token: "mixup-access",
            refresh_token: "mixup-refresh",
            id_token: signed,
            token_type: "Bearer",
            expires_in: 3600,
            scope: "openid profile",
          },
        },
      });
      const receiptsBefore = await readReceipts();
      const response = await owner.fetch(
        `${callbackPath}?${new URLSearchParams({ state, code: "mixup-valid-grant", iss: suppliedIssuer })}`,
        { redirect: "manual" },
      );
      expect(response.status).toBe(302);
      const after = await readState();
      const receiptsAfter = await readReceipts();
      const location = response.headers.get("location")!;
      const session = await owner.client.getSession();
      if (suppliedIssuer !== issuer) {
        const error = new URL(location, ctx.baseURL);
        expect(error.pathname).toBe("/issuer-error");
        expect(error.searchParams.get("error")).toBe("issuer_mismatch");
        expect(session.data).toBeNull();
        expect(after).toEqual(before);
        expect(receiptsAfter).toEqual(receiptsBefore);
        expect(
          response.headers
            .getSetCookie()
            .some((cookie) => cookie.includes("state=") && cookie.includes("Max-Age=0")),
        ).toBe(true);
        expect(
          response.headers
            .getSetCookie()
            .some((cookie) => cookie.includes("session_token=") && !cookie.includes("Max-Age=0")),
        ).toBe(false);
      } else {
        expect(location).toBe("/issuer-complete");
        expect(session.data!.user.email).toBe(email);
        expect(after.users).toHaveLength(2);
        expect(after.accounts).toHaveLength(2);
        expect(after.sessions).toHaveLength(2);
        expect(after.accounts.find((account) => account.accountId === subject)).toMatchObject({
          providerId: "discovery",
          userId: session.data!.user.id,
        });
        expect(
          receiptsAfter
            .slice(receiptsBefore.length)
            .filter((receipt) => receipt.path.startsWith("/token/")),
        ).toHaveLength(1);
      }
      expect(await ctx.readVerificationState({ identifier: `auth-state:${state}` })).toEqual([]);
      const replay = await owner.fetch(
        `${callbackPath}?${new URLSearchParams({ state, code: "mixup-valid-grant", iss: issuer })}`,
        { redirect: "manual" },
      );
      expect(new URL(replay.headers.get("location")!, ctx.baseURL).searchParams.get("error")).toBe(
        "state_mismatch",
      );
      expect(await readState()).toEqual(after);
      expect(await readReceipts()).toEqual(receiptsAfter);
      expect(await ctx.readUserState({ userId: signup.data!.user.id })).toEqual(foreignBefore);
      expect((await foreign.client.getSession()).data!.user.id).toBe(signup.data!.user.id);
      results.push({
        suppliedIssuer,
        stateBinding: { idTokenNonce: nonce },
        start: ctx.snapshot(start),
        status: response.status,
        location,
        after,
        session,
      });
    }
    return ctx.snapshot(results);
  },
  ["POST /sign-in/social", "GET /callback/{}"],
);
