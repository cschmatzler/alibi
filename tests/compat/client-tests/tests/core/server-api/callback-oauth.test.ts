import { expect } from "bun:test";
import { createHmac } from "node:crypto";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import { readUserState } from "../../../support/verification";

compatScenario(
  "server callbackOAuth validates logical input and redeems one-time provider state without a fabricated request",
  async (ctx) => {
    const profile = "generic-token-none";
    const actor = ctx.actor("logical-callback-owner", profile);
    let headers = new Headers();
    const owner = await actor.client.signUp.email({
      email: ctx.uniqueEmail("logical-callback-owner"),
      password: "Password123!",
      name: "Logical Callback Owner",
      fetchOptions: {
        onSuccess({ response }) {
          headers = new Headers(response.headers);
        },
      },
    });
    expect(owner.error).toBeNull();
    const cookie = headers
      .getSetCookie()
      .map((c) => c.split(";")[0])
      .join("; ");
    const before = await readUserState(ctx, owner.data!.user.id);
    async function invoke(input: Record<string, unknown>) {
      const response = await ctx
        .actor("callback-control")
        .fetch(ctx.baseURL + "/__test/generic-token/server-api", {
          method: "POST",
          redirect: "manual",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ operation: "callback-oauth", ...input }),
        });
      const text = await response.text();
      return {
        status: response.status,
        location: response.headers.get("location"),
        body: text ? (JSON.parse(text) as unknown) : null,
        cookies: response.headers.getSetCookie(),
      };
    }
    const denials = [];
    for (const input of [
      { logicalQuery: null },
      { logicalQuery: 7 },
      { logicalQuery: { state: 7 } },
      { logicalQuery: { code: ["duplicate"] } },
      { logicalQuery: {}, logicalBody: null },
      { logicalQuery: {}, logicalBody: { error: false } },
    ]) {
      const response = await invoke(input);
      expect(response.status).toBe(400);
      expect(response.body).toMatchObject({ code: "VALIDATION_ERROR" });
      denials.push(response);
    }
    const missing = [];
    for (const input of [
      {},
      { logicalBody: { code: "ignored-body" } },
      { logicalQuery: {} },
      { logicalQuery: { state: "" } },
      { logicalQuery: { state: "missing-state" } },
      { logicalMethod: "PUT", logicalQuery: { state: "missing-state" } },
    ]) {
      const response = await invoke(input);
      expect(response.status).toBe(302);
      expect(response.body).toBeNull();
      const error = new URL(response.location!, ctx.baseURL).searchParams.get("error");
      expect(error).toBe(
        Object.hasOwn(input, "logicalQuery")
          ? "logicalMethod" in input
            ? "invalid_callback_request"
            : "state" in input.logicalQuery! && input.logicalQuery!.state
              ? "state_mismatch"
              : "state_not_found"
          : "invalid_callback_request",
      );
      missing.push(response);
    }
    const post = await invoke({
      logicalMethod: "POST",
      logicalBody: {
        code: "body-code",
        state: "body-state",
        error_description: "body description",
        extra: "ignored",
      },
      logicalQuery: { code: "query-code", device_id: "device :+&", extra: "ignored" },
    });
    expect(post.status).toBe(302);
    expect(post.body).toBeNull();
    const postURL = new URL(post.location!);
    expect(postURL.pathname).toBe(authProfilePath(profile) + "/callback/generic");
    expect(Object.fromEntries(postURL.searchParams)).toEqual({
      code: "query-code",
      device_id: "device :+&",
      error_description: "body description",
      state: "body-state",
    });
    expect(await readUserState(ctx, owner.data!.user.id)).toEqual(before);
    async function start(link: boolean) {
      const response = await ctx
        .actor("state-control")
        .fetch(ctx.baseURL + "/__test/generic-token/server-api", {
          method: "POST",
          redirect: "manual",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            operation: link ? "link-social" : "sign-in-social",
            logicalBody: {
              provider: "generic",
              callbackURL: "/logical-callback-done",
              errorCallbackURL: "/logical-callback-error?keep=yes#panel",
              disableRedirect: true,
            },
            ...(link ? { logicalHeaders: { cookie } } : {}),
          }),
        });
      expect(response.status).toBe(200);
      const value = (await response.json()) as { url: string };
      const state = new URL(value.url).searchParams.get("state")!;
      return {
        state,
        cookie: response.headers
          .getSetCookie()
          .map((c) => c.split(";")[0])
          .join("; "),
      };
    }
    const rejected = [];
    for (const query of [
      { code: "valid-code", error: "access_denied", error_description: "" },
      { code: "" },
    ]) {
      const proof = await start(true);
      const response = await invoke({
        logicalQuery: { state: proof.state, ...query },
        logicalHeaders: { cookie: proof.cookie },
      });
      expect(response.status).toBe(302);
      const location = new URL(response.location!, ctx.baseURL);
      expect(location.searchParams.get("error")).toBe(
        "error" in query ? "access_denied" : "no_code",
      );
      expect(location.searchParams.has("error_description")).toBe(false);
      expect(await ctx.readVerificationState({ identifier: `auth-state:${proof.state}` })).toEqual(
        [],
      );
      rejected.push(response);
    }
    const proof = await start(true);
    const mismatched = await invoke({
      logicalQuery: { state: proof.state, code: "ignored-code" },
      logicalHeaders: { cookie: "better-auth.state=invalid" },
    });
    expect(new URL(mismatched.location!, ctx.baseURL).searchParams.get("error")).toBe(
      "state_mismatch",
    );
    expect(
      (await ctx.readVerificationState({ identifier: `auth-state:${proof.state}` })) as unknown[],
    ).toHaveLength(1);
    const subject = ctx.uniqueToken("logical-callback-subject");
    expect(
      (
        await ctx.rawRequest({
          path: "/__test/generic-token/control",
          method: "POST",
          json: {
            profile: {
              id: subject,
              email: owner.data!.user.email,
              name: "Provider Owner",
              email_verified: true,
            },
          },
        })
      ).status,
    ).toBe(200);
    const linked = await invoke({
      logicalQuery: {
        state: proof.state,
        code: "logical-link-code",
        error: "",
        extra: { userId: "ignored-foreign" },
      },
      logicalBody: { state: "ignored-body-state", code: "ignored-body-code" },
      logicalHeaders: { cookie: proof.cookie },
    });
    expect(linked.status).toBe(302);
    expect(linked.location).toBe("/logical-callback-done");
    expect(await ctx.readVerificationState({ identifier: `auth-state:${proof.state}` })).toEqual(
      [],
    );
    const afterLink = await readUserState(ctx, owner.data!.user.id);
    expect(afterLink.accounts).toHaveLength(before.accounts.length + 1);
    expect(afterLink.sessions).toEqual(before.sessions);
    expect(afterLink.user).toEqual(before.user);
    expect(afterLink.accounts.find((a) => a.providerId === "generic")).toMatchObject({
      userId: owner.data!.user.id,
      accountId: subject,
    });
    const replay = await invoke({
      logicalQuery: { state: proof.state, code: "replayed" },
      logicalHeaders: { cookie: proof.cookie },
    });
    expect(new URL(replay.location!, ctx.baseURL).searchParams.get("error")).toBe("state_mismatch");
    expect(await readUserState(ctx, owner.data!.user.id)).toEqual(afterLink);
    const loginProof = await start(false);
    const loggedIn = await invoke({
      logicalQuery: { state: loginProof.state, code: "logical-sign-in-code" },
      logicalHeaders: { cookie: loginProof.cookie, "user-agent": "Logical Callback Agent" },
    });
    expect(loggedIn.status).toBe(302);
    expect(loggedIn.location).toBe("/logical-callback-done");
    const authenticated = await actor.fetch(
      ctx.baseURL + authProfilePath(profile) + "/get-session",
      { headers: { cookie: loggedIn.cookies.map((c) => c.split(";")[0]).join("; ") } },
    );
    expect(authenticated.status).toBe(200);
    const session = (await authenticated.json()) as {
      user: { id: string; email: string };
      session: { id: string; userId: string; token: string };
    };
    expect(session.user.id).toBe(owner.data!.user.id);
    expect(session.session.userId).toBe(owner.data!.user.id);
    const primary = loggedIn.cookies.find((cookie) =>
      cookie.startsWith("better-auth.session_token="),
    )!;
    const encoded = primary.split(";")[0]!.slice("better-auth.session_token=".length);
    expect(decodeURIComponent(encoded)).toBe(
      `${session.session.token}.${createHmac("sha256", "compat-test-only-key-not-real-minimum-32chars").update(session.session.token).digest("base64")}`,
    );
    const published = {
      ...loggedIn,
      cookies: loggedIn.cookies.map((cookie) =>
        cookie === primary
          ? { token: session.session.token, attributes: cookie.slice(cookie.indexOf(";")) }
          : cookie,
      ),
    };

    const after = await readUserState(ctx, owner.data!.user.id);
    expect(after.accounts).toEqual(afterLink.accounts);
    expect(after.sessions).toHaveLength(before.sessions.length + 1);
    const receipts = (await ctx.rawRequest({ path: "/__test/generic-token/receipts" })).body as {
      body: [string, string][];
    }[];
    expect(receipts).toHaveLength(2);
    expect(receipts.map((r) => Object.fromEntries(r.body).code)).toEqual([
      "logical-link-code",
      "logical-sign-in-code",
    ]);
    return ctx.snapshot({
      owner,
      before,
      denials,
      missing,
      post,
      rejected,
      mismatched,
      linked,
      afterLink,
      replay,
      loggedIn: published,
      session,
      after,
    });
  },
  [],
  30_000,
);
