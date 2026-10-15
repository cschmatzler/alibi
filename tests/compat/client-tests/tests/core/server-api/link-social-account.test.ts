import { expect } from "vitest";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import { observeLogicalOAuthState } from "../../../support/server-oauth-state";
import { readUserState } from "../../../support/verification";

compatScenario(
  "server linkSocialAccount binds usable OAuth state to the authenticated owner",
  async (ctx) => {
    const profile = "generic-token-none";
    async function signup(name: string) {
      const actor = ctx.actor(name, profile);
      let headers = new Headers();
      const result = await actor.client.signUp.email({
        name,
        email: ctx.uniqueEmail(name),
        password: "Password123!",
        fetchOptions: {
          onSuccess({ response }) {
            headers = new Headers(response.headers);
          },
        },
      });
      expect(result.error).toBeNull();
      return {
        actor,
        result,
        headers: {
          cookie: headers
            .getSetCookie()
            .map((c) => c.split(";")[0])
            .join("; "),
          origin: "https://untrusted.example.test",
        },
      };
    }
    const owner = await signup("logical-link-owner");
    const foreign = await signup("logical-link-foreign");
    const beforeOwner = await readUserState(ctx, owner.result.data!.user.id);
    const beforeForeign = await readUserState(ctx, foreign.result.data!.user.id);
    async function invoke(logicalBody: unknown, logicalHeaders?: Record<string, string>) {
      const response = await ctx
        .actor("link-control")
        .fetch(ctx.baseURL + "/__test/generic-token/server-api", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            operation: "link-social",
            logicalBody,
            ...(logicalHeaders ? { logicalHeaders } : {}),
          }),
        });
      const text = await response.text();
      return {
        status: response.status,
        body: text ? (JSON.parse(text) as Record<string, unknown>) : null,
        location: response.headers.get("location"),
        ownerEmail: response.headers.get("x-linked-owner"),
        cookies: response.headers.getSetCookie(),
      };
    }
    const denied = [];
    for (const [body, headers, status] of [
      [{ provider: "generic" }, undefined, 400],
      [{ provider: "generic" }, {}, 401],
      [{}, owner.headers, 400],
      [{ provider: 7 }, owner.headers, 400],
      [{ provider: "generic", scopes: 7 }, owner.headers, 400],
      [{ provider: "generic", disableRedirect: null }, owner.headers, 400],
      [{ provider: "generic", additionalParams: { state: "injected" } }, owner.headers, 400],
      [{ provider: "missing-provider" }, owner.headers, 404],
      [{ provider: "generic", idToken: { token: "unsupported" } }, owner.headers, 404],
    ] as const) {
      const response = await invoke(body, headers);
      expect(response.status).toBe(status);
      denied.push(response);
      expect(await readUserState(ctx, owner.result.data!.user.id)).toEqual(beforeOwner);
      expect(await readUserState(ctx, foreign.result.data!.user.id)).toEqual(beforeForeign);
    }
    expect(denied[0]!.body).toEqual({ code: "VALIDATION_ERROR", message: "Headers is required" });
    expect(denied[1]!.body).toEqual({ code: "UNAUTHORIZED", message: "Unauthorized" });
    const starts = [];
    let first: { state: string; verifier: string; cookie: string } | undefined;
    for (const [round, disableRedirect] of [true, false].entries()) {
      const callbackURL = round === 0 ? "/linked-logical" : "https://external.example.test/linked";
      const startedAt = Date.now();
      const start = await invoke(
        {
          provider: "generic",
          callbackURL,
          errorCallbackURL: callbackURL,
          disableRedirect,
          scopes: ["profile", "calendar"],
          loginHint: "Owner+link@example.test",
          requestSignUp: true,
          additionalParams: { prompt: "consent :+&" },
          additionalData: { application: "linked", nested: { round } },
          userId: foreign.result.data!.user.id,
          link: { userId: foreign.result.data!.user.id, email: foreign.result.data!.user.email },
          authorizationParams: { state: "ignored-field" },
        },
        owner.headers,
      );
      const finishedAt = Date.now();
      expect(start.status).toBe(200);
      expect(start.ownerEmail).toBe(owner.result.data!.user.email);
      const url = new URL(start.body!.url as string);
      expect(start.body!.redirect).toBe(!disableRedirect);
      expect(start.location).toBe(disableRedirect ? null : url.toString());
      expect(url.searchParams.get("scope")).toBe("profile calendar profile");
      expect(url.searchParams.get("login_hint")).toBe("Owner+link@example.test");
      expect(url.searchParams.get("prompt")).toBe("consent :+&");
      const proof = await observeLogicalOAuthState(ctx, start, startedAt, finishedAt, {
        callbackURL,
        errorURL: callbackURL,
        requestSignUp: true,
        application: "linked",
        nested: { round },
        link: { userId: owner.result.data!.user.id, email: owner.result.data!.user.email },
      });
      starts.push(proof.observation);
      expect(await readUserState(ctx, owner.result.data!.user.id)).toEqual(beforeOwner);
      expect(await readUserState(ctx, foreign.result.data!.user.id)).toEqual(beforeForeign);
      if (round === 0) {
        first = {
          state: proof.state,
          verifier: proof.payload.codeVerifier,
          cookie: start.cookies.map((c) => c.split(";")[0]).join("; "),
        };
      }
    }
    const subject = ctx.uniqueToken("logical-linked-subject");
    expect(
      (
        await ctx.rawRequest({
          path: "/__test/generic-token/control",
          method: "POST",
          json: {
            profile: {
              id: subject,
              email: owner.result.data!.user.email,
              name: "Remote linked profile",
              email_verified: true,
            },
          },
        })
      ).status,
    ).toBe(200);
    const callbackPath =
      authProfilePath(profile) +
      `/callback/generic?code=logical-link-code&state=${encodeURIComponent(first!.state)}`;
    const callback = await owner.actor.fetch(ctx.baseURL + callbackPath, {
      headers: { cookie: first!.cookie },
      redirect: "manual",
    });
    expect(callback.status).toBe(302);
    expect(callback.headers.get("location")).toBe("/linked-logical");
    const linked = await readUserState(ctx, owner.result.data!.user.id);
    expect(linked.accounts).toHaveLength(beforeOwner.accounts.length + 1);
    expect(linked.sessions).toEqual(beforeOwner.sessions);
    expect(linked.user).toEqual(beforeOwner.user);
    expect(linked.accounts.find((a) => a.providerId === "generic")).toMatchObject({
      userId: owner.result.data!.user.id,
      accountId: subject,
    });
    expect(await readUserState(ctx, foreign.result.data!.user.id)).toEqual(beforeForeign);
    const physical = (await ctx.rawRequest({ path: "/__test/social-provider/state" })).body as {
      accounts: Record<string, unknown>[];
    };
    expect(physical.accounts.find((a) => a.providerId === "generic")).toMatchObject({
      userId: owner.result.data!.user.id,
      accountId: subject,
      accessToken: "generic-access",
      refreshToken: "generic-refresh",
    });
    const grants = (await ctx.rawRequest({ path: "/__test/generic-token/receipts" })).body as {
      body: [string, string][];
    }[];
    expect(grants).toHaveLength(1);
    expect(Object.fromEntries(grants[0]!.body)).toMatchObject({
      code: "logical-link-code",
      code_verifier: first!.verifier,
    });
    const replay = await owner.actor.fetch(ctx.baseURL + callbackPath, {
      headers: { cookie: first!.cookie },
      redirect: "manual",
    });
    expect(replay.status).toBe(302);
    expect(await readUserState(ctx, owner.result.data!.user.id)).toEqual(linked);
    expect((await ctx.rawRequest({ path: "/__test/generic-token/receipts" })).body).toEqual(grants);
    return ctx.snapshot({
      owner: owner.result,
      foreign: foreign.result,
      denied,
      starts,
      beforeOwner,
      beforeForeign,
      linked,
    });
  },
  [],
  30_000,
);
