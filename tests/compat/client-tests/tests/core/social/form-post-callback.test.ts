import { expect } from "bun:test";
import { createHash } from "node:crypto";

import { symmetricDecrypt } from "better-auth/crypto";

import { oauthPurposeSecret } from "../../../support/oauth-encryption";
import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
for (const mode of ["valid", "query-overrides", "missing-state", "wrong-state"] as const) {
  compatScenario(
    `OAuth form-post callback ${mode} redirects to validated state-bound GET before any account write`,
    async (ctx) => {
      const profile = "generic-token-none";
      const actor = ctx.actor("owner", profile);
      const email = ctx.uniqueEmail("form-post-owner");
      await ctx.rawRequest({
        path: "/__test/generic-token/control",
        method: "POST",
        json: { profile: { id: "form-subject", email, name: "Form owner", email_verified: true } },
      });
      const before = (await ctx.rawRequest({ path: "/__test/social-provider/state" })).body;
      const start = await actor.client.signIn.social({
        provider: "generic",
        callbackURL: "/dashboard",
      });
      expect(start.error).toBeNull();
      const state = new URL(start.data!.url!).searchParams.get("state")!;
      const code = "form :+&=/%é";
      const body = new URLSearchParams({
        code,
        user: JSON.stringify({ name: { firstName: "Élodie &", lastName: "Form <Owner>" }, email }),
        ...(mode === "missing-state"
          ? {}
          : {
              state:
                mode === "wrong-state" || mode === "query-overrides" ? "unissued-state" : state,
            }),
      });
      const query =
        mode === "query-overrides"
          ? `?code=${encodeURIComponent("query-code")}&state=${encodeURIComponent(state)}`
          : "";
      const posted = await actor.fetch(
        ctx.baseURL + authProfilePath(profile) + "/callback/generic" + query,
        {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: body.toString(),
          redirect: "manual",
        },
      );
      expect(posted.status).toBe(302);
      const redirect = new URL(posted.headers.get("location")!, ctx.baseURL);
      expect(redirect.pathname).toBe(authProfilePath(profile) + "/callback/generic");
      expect(redirect.searchParams.get("user")).toBe(body.get("user"));
      expect(redirect.searchParams.get("code")).toBe(
        mode === "query-overrides" ? "query-code" : code,
      );
      expect(redirect.searchParams.get("state")).toBe(
        mode === "missing-state"
          ? null
          : mode === "query-overrides" || mode === "valid"
            ? state
            : "unissued-state",
      );
      expect((await ctx.rawRequest({ path: "/__test/social-provider/state" })).body).toEqual(
        before,
      );
      expect((await ctx.rawRequest({ path: "/__test/generic-token/receipts" })).body).toEqual([]);
      const followed = await actor.fetch(redirect, { redirect: "manual" });
      expect(followed.status).toBe(302);
      const followedLocation = followed.headers.get("location")!;
      const negative = mode === "missing-state" || mode === "wrong-state";
      if (negative) {
        expect(new URL(followedLocation, ctx.baseURL).searchParams.get("error")).toBe(
          mode === "missing-state" ? "state_not_found" : "state_mismatch",
        );
        expect((await ctx.rawRequest({ path: "/__test/social-provider/state" })).body).toEqual(
          before,
        );
        expect((await actor.client.getSession()).data).toBeNull();
        const recovered = await actor.fetch(
          ctx.baseURL +
            authProfilePath(profile) +
            `/callback/generic?code=recovered-code&state=${encodeURIComponent(state)}`,
          { redirect: "manual" },
        );
        expect(recovered.headers.get("location")).toBe("/dashboard");
      } else expect(followedLocation).toBe("/dashboard");
      const session = await actor.client.getSession();
      expect(session.data!.user.email).toBe(email);
      const after = (await ctx.rawRequest({ path: "/__test/social-provider/state" })).body as any;
      expect(after.users).toHaveLength(1);
      expect(after.accounts).toHaveLength(1);
      expect(after.sessions).toHaveLength(1);
      const receipts = (await ctx.rawRequest({ path: "/__test/generic-token/receipts" }))
        .body as any[];
      const exchange = receipts.find((r) => r.path === "/token");
      expect(new Map(exchange.body).get("code")).toBe(
        negative ? "recovered-code" : mode === "query-overrides" ? "query-code" : code,
      );
      return ctx.snapshot({
        posted: { status: posted.status, location: posted.headers.get("location") },
        followed: { status: followed.status, location: followedLocation },
        session,
        before,
        after,
      });
    },
    ["POST /callback/{}", "GET /callback/{}"],
  );
}

for (const mode of ["valid", "missing-state", "wrong-state"] as const) {
  compatScenario(
    `OAuth proxy form-post ${mode} preserves user payload and admits only issued state`,
    async (ctx) => {
      const path = authProfilePath("oauth-proxy");
      const owner = ctx.actor("owner", "oauth-proxy");
      const state = async () =>
        (await ctx.rawRequest({ path: "/__test/oauth-proxy/state" })).body as any;
      expect(
        (
          await ctx.rawRequest({
            path: "/__test/oauth-proxy/options",
            method: "POST",
            json: { mode: "form-post" },
          })
        ).status,
      ).toBe(200);
      const before = await state();
      const start = await owner.client.signIn.social({
        provider: "gitlab",
        callbackURL: ctx.baseURL + "/form-done",
        disableRedirect: true,
      });
      expect(start.error).toBeNull();
      const authorization = new URL(start.data!.url!);
      expect(authorization.searchParams.get("response_mode")).toBe("form_post");
      const provided = await owner.fetch(authorization, { redirect: "manual" });
      expect(provided.status).toBe(200);
      expect(provided.headers.get("content-type")).toContain("text/html");
      let action = "";
      const fields = new URLSearchParams();
      await new HTMLRewriter()
        .on("form", {
          element(el) {
            action = el.getAttribute("action")!;
            expect(el.getAttribute("method")).toBe("post");
          },
        })
        .on("input", {
          element(el) {
            fields.set(el.getAttribute("name")!, el.getAttribute("value")!);
          },
        })
        .transform(provided)
        .text();
      // HTMLRewriter retains entity spellings in attribute values.
      const decode = (value: string) =>
        value.replaceAll("&quot;", '"').replaceAll("&lt;", "<").replaceAll("&amp;", "&");
      action = decode(action);
      for (const [key, value] of fields) fields.set(key, decode(value));
      const payload = JSON.parse(fields.get("user")!);
      expect(payload).toEqual({
        name: { firstName: "Élodie &", lastName: "Form <Owner>" },
        email: "proxy-owner@fixture.test",
      });
      const originalState = fields.get("state")!;
      expect(originalState).toBe(authorization.searchParams.get("state")!);
      const saved = await state();
      expect(saved.preview.verification).toHaveLength(1);
      const post = async () =>
        owner.fetch(action, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: fields.toString(),
          redirect: "manual",
          credentials: "omit",
        });
      if (mode === "missing-state") fields.delete("state");
      if (mode === "wrong-state") fields.set("state", "unissued-state");
      const posted = await post();
      expect(posted.status).toBe(302);
      let exchanged = posted;
      if (mode !== "valid") {
        expect(new URL(posted.headers.get("location")!).pathname).toBe(path + "/callback/gitlab");
        exchanged = await owner.fetch(posted.headers.get("location")!, {
          redirect: "manual",
          credentials: "omit",
        });
        expect(
          new URL(exchanged.headers.get("location")!, ctx.baseURL).searchParams.get("error"),
        ).toBe(mode === "missing-state" ? "state_not_found" : "state_mismatch");
        expect(await state()).toEqual(saved);
        expect((await owner.client.getSession()).data).toBeNull();
        fields.set("state", originalState);
        exchanged = await post();
      }
      expect(exchanged.status).toBe(302);
      const bridge = new URL(exchanged.headers.get("location")!);
      expect(bridge.origin).toBe(ctx.baseURL);
      expect(bridge.pathname).toBe(path + "/callback/gitlab/oauth-proxy");
      const token = bridge.searchParams.get("profile")!;
      const signedPayload = JSON.parse(
        await symmetricDecrypt({
          key: oauthPurposeSecret(
            "local-fixture-dedicated-oauth-proxy-secret-32",
            "oauth-proxy-profile",
          ),
          data: token,
        }),
      );
      expect(signedPayload.userInfo.email).toBe("proxy-owner@fixture.test");
      expect(signedPayload.account.providerId).toBe("gitlab");
      expect(signedPayload.callbackURL).toBe(ctx.baseURL + "/form-done");
      const forwarded = await state();
      expect(forwarded.production).toEqual(before.production);
      expect(forwarded.preview).toEqual(saved.preview);
      const receipts = forwarded.receipts.filter((r: any) => r.stage === "token");
      expect(receipts).toHaveLength(1);
      expect(receipts[0].body.code).toBe(fields.get("code"));
      expect(createHash("sha256").update(receipts[0].body.code_verifier).digest("base64url")).toBe(
        authorization.searchParams.get("code_challenge")!,
      );
      const observe = (state: any) => ({
        ...state,
        receipts: state.receipts.map((r: any) =>
          r.body?.code_verifier
            ? {
                ...r,
                body: {
                  ...r.body,
                  code_verifier: {
                    token: r.body.code_verifier,
                    length: r.body.code_verifier.length,
                  },
                },
              }
            : r,
        ),
      });
      const completed = await owner.fetch(bridge, { redirect: "manual" });
      expect(completed.status).toBe(302);
      expect(completed.headers.get("location")).toBe(ctx.baseURL + "/form-done");
      const session = await owner.client.getSession();
      expect(session.data!.user.email).toBe("proxy-owner@fixture.test");
      const after = await state();
      expect(after.preview.users).toHaveLength(1);
      expect(after.preview.accounts).toHaveLength(1);
      expect(after.preview.sessions).toHaveLength(1);
      expect(after.preview.verification).toEqual([]);
      expect(after.production).toEqual(before.production);
      return ctx.snapshot({
        start,
        posted: { status: posted.status, location: posted.headers.get("location") },
        payload,
        oauthProxyProfile: { token, payload: signedPayload },
        session,
        before,
        saved,
        forwarded: observe(forwarded),
        after: observe(after),
      });
    },
    ["POST /callback/{}", "GET /callback/{}"],
    undefined,
    {
      oauthProxyProfileSecret: oauthPurposeSecret(
        "local-fixture-dedicated-oauth-proxy-secret-32",
        "oauth-proxy-profile",
      ),
    },
  );
}
