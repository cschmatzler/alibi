import { readFile as readFixtureFile } from "node:fs/promises";

import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "Trusted SAML verification requires mapping and exact first true attribute",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ...input, mode: "trusted-claims" }),
        redirect: "manual",
      });
    const cookies = (response: Response) =>
      response.headers
        .getSetCookie()
        .filter((raw) => Boolean(Cookie.parse(raw)?.value))
        .map((raw) => raw.split(";")[0])
        .join("; ");
    const owner = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("trusted-saml-owner"),
        name: "Native owner",
        password: "password123",
      },
    });
    expect(owner.status).toBe(200);
    const cert = await readFixtureFile(
      new URL("../../../../fixtures/salesforce-transport/leaf.pem", import.meta.url),
      "utf8",
    );
    const observed = [];
    for (const mapped of [true, false]) {
      const providerId = mapped ? "trusted-saml-provider" : "unmapped-saml-provider";
      const mapping: any = { email: "email", name: "displayName" };
      if (mapped) mapping.emailVerified = "verified-mailbox";
      expect(
        (
          await control({
            headers: { cookie: cookies(owner) },
            body: {
              providerId,
              issuer: "https://sp.example.test/entity",
              domain: "example.test",
              samlConfig: {
                entryPoint: "https://idp.example.test/sso",
                cert,
                idpMetadata: { entityID: "https://idp.example.test/entity" },
                wantAssertionsSigned: true,
                mapping,
              },
            },
          })
        ).status,
      ).toBe(200);
      const claims: Array<[string[], boolean]> = mapped
        ? [
            [["true"], true],
            [["false"], false],
            [["TRUE"], false],
            [["1"], false],
            [["true", "false"], true],
            [["false", "true"], false],
          ]
        : [[["true"], false]];
      for (const [index, [verified, expected]] of claims.entries()) {
        const email = ctx.uniqueEmail(`trusted-saml-${mapped}-${index}`);
        const started = await control({
          action: "sign-in",
          body: { providerId, callbackURL: `${ctx.baseURL}/complete` },
        });
        expect(started.status).toBe(200);
        const grant = await (
          await control({
            action: "saml-grant",
            authorization: ((await started.json()) as any).url,
            email,
            verified,
          })
        ).json();
        const completed = await control({
          action: "acs",
          params: { providerId },
          body: grant,
          headers: {},
        });
        expect(completed.status).toBe(302);
        expect(completed.headers.get("location")).toBe(`${ctx.baseURL}/complete`);
        const session = (await (
          await control({ action: "session", headers: { cookie: cookies(completed) } })
        ).json()) as any;
        expect(session.user.email).toBe(email);
        expect(session.user.emailVerified).toBe(expected);
        observed.push({ mapped, index, verified: session.user.emailVerified });
      }
    }
    return observed;
  },
);
