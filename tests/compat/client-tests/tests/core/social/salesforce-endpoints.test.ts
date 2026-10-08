import { expect } from "bun:test";
import { createHash } from "node:crypto";

import { TS_BASE_URL } from "../../../support/config";
import { authProfilePath, type FixtureProfile } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

// Independent endpoint contract: explicit nonempty loginUrl wins over environment.
const variants = [
  ["default", "login.salesforce.com"],
  ["sandbox", "test.salesforce.com"],
  ["custom", "login.fixture.test"],
  ["custom-sandbox", "login.fixture.test"],
  ["empty", "login.salesforce.com"],
  ["empty-sandbox", "test.salesforce.com"],
] as const;

type Receipt = {
  destination: string;
  method: string;
  body: Record<string, string> | null;
  authorization: string | null;
  contentType: string | null;
};

compatScenario(
  "Salesforce loginUrl and sandbox select the complete HTTPS endpoint family",
  async (ctx) => {
    // Both runtimes use the same local HTTPS upstream; receipts come from actual TLS requests.
    const transport = async (path: string, input?: unknown) => {
      const response = await fetch(
        `${TS_BASE_URL}/__test/salesforce-transport/${path}`,
        input === undefined
          ? undefined
          : {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify(input),
            },
      );
      expect(response.status).toBe(200);
      return response.json();
    };
    const physical = async () => {
      const response = await fetch(`${ctx.baseURL}/__test/provider-batch/sql-state`);
      expect(response.status).toBe(200);
      const rows = (await response.json()) as Record<string, Array<Record<string, any>>>;
      return {
        users: rows.user ?? rows.users!,
        accounts: rows.account ?? rows.accounts!,
        sessions: rows.session ?? rows.sessions!,
        verifications: rows.verification ?? rows.verifications!,
      };
    };
    const foreignActor = ctx.actor("salesforce-foreign");
    const foreign = await foreignActor.client.signUp.email({
      email: ctx.uniqueEmail("salesforce-foreign"),
      password: "Password123!",
      name: "Foreign Owner",
    });
    expect(foreign.error).toBeNull();
    const foreignBefore = await ctx.readUserState({ userId: foreign.data!.user.id });
    const results = [];
    for (const [mode, host] of variants) {
      const profile = `provider-batch-salesforce-family-${mode}` as FixtureProfile;
      const actor = ctx.actor(`salesforce-${mode}`, profile);
      const email = ctx.uniqueEmail(`salesforce-${mode}`);
      const subject = `salesforce-subject-${mode}`;
      await transport("control", { subject, email });
      expect(
        (
          await ctx.rawRequest({
            path: "/__test/provider-batch/control",
            method: "POST",
            json: { salesforceFamily: true },
          })
        ).status,
      ).toBe(200);
      const before = await physical();
      const start = await actor.client.signIn.social({
        provider: "salesforce",
        callbackURL: "/dashboard",
      });
      expect(start.error).toBeNull();
      const authorization = new URL(start.data!.url!);
      expect(authorization.origin + authorization.pathname).toBe(
        `https://${host}/services/oauth2/authorize`,
      );
      expect(authorization.searchParams.get("client_id")).toBe("batch-client");
      expect(authorization.searchParams.get("scope")).toBe("openid email profile");
      expect(authorization.searchParams.get("code_challenge_method")).toBe("S256");
      const callback = await actor.fetch(
        `${ctx.baseURL}${authProfilePath(profile)}/callback/salesforce?code=family-code&state=${encodeURIComponent(authorization.searchParams.get("state")!)}`,
        { redirect: "manual" },
      );
      expect(callback.status).toBe(302);
      expect(callback.headers.get("location")).toBe("/dashboard");
      expect(
        callback.headers
          .getSetCookie()
          .some((cookie) => cookie.startsWith("better-auth.session_token=")),
      ).toBe(true);
      const session = await actor.client.getSession();
      expect(session.error).toBeNull();
      expect(session.data!.user.email).toBe(email);
      expect(session.data!.user.name).toBe("Salesforce Family Owner");
      const userId = session.data!.user.id;
      const loggedIn = await physical();
      expect(loggedIn.users).toHaveLength(before.users.length + 1);
      expect(loggedIn.accounts).toHaveLength(before.accounts.length + 1);
      expect(loggedIn.sessions).toHaveLength(before.sessions.length + 1);
      expect(loggedIn.users.filter((row) => row.id !== userId)).toEqual(before.users);
      expect(loggedIn.sessions.filter((row) => (row.userId ?? row.user_id) !== userId)).toEqual(
        before.sessions,
      );
      const account = loggedIn.accounts.find((row) => (row.userId ?? row.user_id) === userId)!;
      expect(account).toBeDefined();
      expect(account.providerId ?? account.provider_id).toBe("salesforce");
      expect(account.accountId ?? account.account_id).toBe(subject);
      expect(account.accessToken ?? account.access_token).toBe("family-access");
      expect(account.refreshToken ?? account.refresh_token).toBe("family-refresh");
      expect(loggedIn.accounts.filter((row) => row.id !== account.id)).toEqual(before.accounts);
      const refresh = await actor.client.refreshToken({ accountId: String(account.id) });
      expect(refresh.error).toBeNull();
      expect(refresh.data!.accessToken).toBe("family-refreshed-access");
      expect(refresh.data!.refreshToken).toBe("family-rotated-refresh");
      const wire = (await transport("receipts")) as Receipt[];
      expect(wire.map((row) => row.destination)).toEqual([
        `https://${host}/services/oauth2/token`,
        `https://${host}/services/oauth2/userinfo`,
        `https://${host}/services/oauth2/token`,
      ]);
      expect(wire.map((row) => row.method)).toEqual(["POST", "GET", "POST"]);
      expect(wire[0]!.body!.grant_type).toBe("authorization_code");
      expect(wire[0]!.body!.code).toBe("family-code");
      expect(wire[0]!.body!.client_id).toBe("batch-client");
      expect(wire[0]!.body!.client_secret).toBe("batch-secret");
      expect(wire[0]!.body!.redirect_uri).toBe(
        `${ctx.baseURL}${authProfilePath(profile)}/callback/salesforce`,
      );
      const verifier = wire[0]!.body!.code_verifier!;
      expect(verifier).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(createHash("sha256").update(verifier).digest("base64url")).toBe(
        authorization.searchParams.get("code_challenge")!,
      );
      expect(wire[1]!.authorization).toBe("Bearer family-access");
      expect(wire[1]!.body).toBeNull();
      expect(wire[2]!.body!.grant_type).toBe("refresh_token");
      expect(wire[2]!.body!.refresh_token).toBe("family-refresh");
      expect(wire[2]!.body!.client_id).toBe("batch-client");
      expect(wire[2]!.body!.client_secret).toBe("batch-secret");
      const after = await physical();
      expect(after.users).toEqual(loggedIn.users);
      expect(after.sessions).toEqual(loggedIn.sessions);
      expect(after.verifications).toEqual(loggedIn.verifications);
      expect(after.accounts.filter((row) => row.id !== account.id)).toEqual(before.accounts);
      const updated = after.accounts.find((row) => row.id === account.id)!;
      expect(updated.userId ?? updated.user_id).toBe(userId);
      expect(updated.accountId ?? updated.account_id).toBe(subject);
      expect(updated.accessToken ?? updated.access_token).toBe("family-refreshed-access");
      expect(updated.refreshToken ?? updated.refresh_token).toBe("family-rotated-refresh");
      expect(await ctx.readUserState({ userId: foreign.data!.user.id })).toEqual(foreignBefore);
      expect((await foreignActor.client.getSession()).data!.user.id).toBe(foreign.data!.user.id);
      expect((await actor.client.getSession()).data!.user.id).toBe(userId);
      results.push({
        mode,
        start,
        callback: { status: callback.status, location: callback.headers.get("location") },
        session,
        refresh,
        wire: wire.map((row) => ({
          ...row,
          body: row.body?.code_verifier
            ? {
                ...row.body,
                code_verifier: {
                  token: row.body.code_verifier,
                  length: row.body.code_verifier.length,
                },
              }
            : row.body,
        })),
      });
    }
    return results;
  },
);
