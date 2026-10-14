import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import type { ScenarioContext } from "../../../support/scenario";
export async function idpInitiatedFlow(
  ctx: ScenarioContext,
  global?: "relative" | "absolute" | "unsafe",
) {
  const actor = ctx.actor();
  const control = (input: Record<string, unknown>) =>
    actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(input),
      redirect: "manual",
    });
  const cookies = (response: Response) =>
    response.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
  const cert = await Bun.file(
    new URL("../../../../fixtures/salesforce-transport/leaf.pem", import.meta.url),
  ).text();
  const observations = [];
  for (const allowed of [true, false]) {
    const mode = global ? `idp-global-${global}-${allowed}` : allowed ? "idp-initiated" : "default";
    const owner = await control({
      mode,
      action: "signup",
      body: {
        email: ctx.uniqueEmail(`unsolicited-owner-${allowed}`),
        name: "Owner",
        password: "password123",
      },
    });
    expect(owner.status).toBe(200);
    const providerId = `unsolicited-${global ?? "default"}-${allowed}`;
    const created = await control({
      mode,
      headers: { cookie: cookies(owner) },
      body: {
        providerId,
        issuer: "https://idp.example.test/entity",
        domain: "company.test",
        samlConfig: {
          entryPoint: "https://idp.example.test/sso",
          cert,
          idpMetadata: { entityID: "https://idp.example.test/entity" },
          ...(global
            ? { callbackUrl: "/legacy-complete" }
            : { idpInitiatedCallbackUrl: "/idp-complete" }),
        },
      },
    });
    expect(created.status).toBe(200);
    for (const [http, wrongKey] of [
      [false, false],
      [false, true],
      [true, false],
      [true, true],
    ]) {
      if (global && http) {
        const updated = await control({
          mode,
          action: "update",
          headers: { cookie: cookies(owner) },
          body: { providerId, samlConfig: { idpInitiatedCallbackUrl: "/provider-complete" } },
        });
        expect(updated.status).toBe(200);
      }
      const email = ctx.uniqueEmail(`unsolicited-${allowed}-${http}-${wrongKey}`);
      const started = await control({
        mode,
        action: "sign-in",
        body: { providerId, providerType: "saml", callbackURL: `${ctx.baseURL}/unused-relay` },
      });
      expect(started.status).toBe(200);
      const authorization = ((await started.json()) as any).url;
      const grant = (await (
        await control({
          mode,
          action: "saml-grant",
          authorization,
          email,
          wrongKey,
          unsolicited: true,
        })
      ).json()) as any;
      expect(Buffer.from(grant.SAMLResponse, "base64").toString()).not.toContain("InResponseTo=");
      const input = {
        mode,
        action: http ? "acs-http" : "acs",
        params: { providerId },
        body: { SAMLResponse: grant.SAMLResponse },
        headers: http ? { origin: "https://idp.example.test" } : {},
      };
      const completed = await control(input);
      expect(completed.status).toBe(302);
      const location = new URL(completed.headers.get("location")!, ctx.baseURL);
      expect(location.pathname).toBe(
        !global
          ? "/idp-complete"
          : http
            ? "/provider-complete"
            : global === "unsafe"
              ? "/legacy-complete"
              : "/global-complete",
      );
      const used = (await (
        await control({
          mode,
          action: "proof",
          identifier: `saml-used-assertion:${grant.assertionId}`,
        })
      ).json()) as any;
      const account = await (
        await control({ mode, action: "saml-account-row", providerId, accountId: email })
      ).json();
      if (wrongKey || !allowed) {
        expect(location.searchParams.get("error")).toBe(
          wrongKey ? "saml_error" : "unsolicited_response",
        );
        expect(used).toBe(null);
        expect(account).toBe(null);
        expect(
          completed.headers
            .getSetCookie()
            .some((raw) => raw.startsWith("better-auth.session_token=")),
        ).toBe(false);
      } else {
        expect(location.search).toBe("");
        expect(account).not.toBe(null);
        expect(JSON.parse(used.value).assertionId).toBe(grant.assertionId);
        const session = (await (
          await control({ mode, action: "session", headers: { cookie: cookies(completed) } })
        ).json()) as any;
        expect(session.user.email).toBe(email);
        const replay = await control(input);
        expect(replay.status).toBe(302);
        expect(
          new URL(replay.headers.get("location")!, ctx.baseURL).searchParams.get("error"),
        ).toBe("replay_detected");
      }
      expect(
        await (
          await control({
            mode,
            action: "proof",
            identifier: `saml-authn-request:${grant.requestId}`,
          })
        ).json(),
      ).not.toBe(null);
      expect(
        await (
          await control({ mode, action: "proof", identifier: `auth-state:${grant.RelayState}` })
        ).json(),
      ).not.toBe(null);
      if (allowed && !http && !wrongKey) {
        await control({
          mode,
          action: "expire-proof",
          identifier: `saml-authn-request:${grant.requestId}`,
        });
        const correlatedEmail = ctx.uniqueEmail("expired-correlated");
        const correlated = (await (
          await control({ mode, action: "saml-grant", authorization, email: correlatedEmail })
        ).json()) as any;
        const denied = await control({
          mode,
          action: "acs",
          params: { providerId },
          body: { SAMLResponse: correlated.SAMLResponse },
        });
        expect(denied.status).toBe(302);
        const failed = new URL(denied.headers.get("location")!, ctx.baseURL);
        expect(failed.searchParams.get("error")).toBe("invalid_saml_response");
        expect(failed.searchParams.get("error_description")).toBe("Unknown or expired request ID");
        expect(
          await (
            await control({
              mode,
              action: "saml-account-row",
              providerId,
              accountId: correlatedEmail,
            })
          ).json(),
        ).toBe(null);
        expect(
          await (
            await control({
              mode,
              action: "proof",
              identifier: `saml-used-assertion:${correlated.assertionId}`,
            })
          ).json(),
        ).toBe(null);
      }
      observations.push({ allowed, http, wrongKey, error: location.searchParams.get("error") });
    }
  }
  return observations;
}
