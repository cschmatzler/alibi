import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Configured SSO state rejects changed authority and recovers with fresh state",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>, changed = false) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ...input, mode: changed ? "configured-changed" : "configured" }),
        redirect: "manual",
      });
    const cookies = (response: Response) =>
      response.headers
        .getSetCookie()
        .filter((raw) => Boolean(Cookie.parse(raw)?.value))
        .map((raw) => raw.split(";")[0])
        .join("; ");
    const observed = [];
    for (const saml of [false, true]) {
      const providerId = saml ? "configured-saml" : "configured-oidc";
      const email = ctx.uniqueEmail(`configured-change-${saml}`);
      const accountId = saml ? email : "changed-configured-subject";
      await control({
        action: "idp",
        profile: { sub: accountId, email, email_verified: false, name: "Configured employee" },
      });
      for (const stale of [true, false]) {
        const started = await control(
          {
            action: "sign-in",
            body: {
              providerId,
              callbackURL: `${ctx.baseURL}/complete`,
              errorCallbackURL: `${ctx.baseURL}/failed`,
            },
          },
          !stale,
        );
        expect(started.status).toBe(200);
        const authorization = ((await started.json()) as any).url;
        let input: any;
        let state: string;
        let assertion: string | undefined;
        if (saml) {
          const grant = (await (
            await control({ action: "saml-grant", authorization, email })
          ).json()) as any;
          state = grant.RelayState;
          assertion = grant.assertionId;
          input = { action: "acs", params: { providerId }, body: grant };
        } else {
          const grant = await fetch(authorization, { redirect: "manual" });
          expect(grant.status).toBe(302);
          const query = Object.fromEntries(new URL(grant.headers.get("location")!).searchParams);
          state = query.state!;
          input = { action: "callback", params: { providerId }, query };
        }
        const completed = await control({ ...input, headers: { cookie: cookies(started) } }, true);
        expect(completed.status).toBe(302);
        const location = new URL(completed.headers.get("location")!);
        if (stale) {
          expect(location.pathname).toBe("/failed");
          expect(Object.fromEntries(location.searchParams)).toEqual({
            error: "invalid_state",
            error_description: "sso_provider_changed_during_authentication",
          });
          expect(await (await control({ action: "user-row", email }, true)).json()).toBe(null);
          expect(
            await (await control({ action: "account-row", providerId, accountId }, true)).json(),
          ).toBe(null);
          if (!saml) {
            expect(await (await control({ action: "idp-exchanges" }, true)).json()).toEqual([]);
          }
          if (assertion) {
            expect(
              await (
                await control(
                  { action: "proof", identifier: `saml-used-assertion:${assertion}` },
                  true,
                )
              ).json(),
            ).toBe(null);
          }
        } else {
          expect(location.pathname).toBe("/complete");
          expect(location.searchParams.has("error")).toBe(false);
          const session = (await (
            await control({ action: "session", headers: { cookie: cookies(completed) } }, true)
          ).json()) as any;
          expect(session.user.email).toBe(email);
          expect(
            await (await control({ action: "account-row", providerId, accountId }, true)).json(),
          ).not.toBe(null);
        }
        expect(
          await (
            await control({ action: "proof", identifier: `auth-state:${state}` }, true)
          ).json(),
        ).toBe(null);
        expect(await (await control({ action: "row", providerId }, true)).json()).toBe(null);
        observed.push({
          saml,
          stale,
          error: location.searchParams.get("error"),
          path: location.pathname,
        });
      }
    }
    return observed;
  },
);
