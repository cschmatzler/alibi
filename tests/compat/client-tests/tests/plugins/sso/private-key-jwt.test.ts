import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SSO private_key_jwt authenticates real token requests and rejects missing keys",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>, key = true) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ...input, mode: key ? "configured-jwt" : "configured-jwt-missing" }),
        redirect: "manual",
      });
    const cookies = (response: Response) =>
      response.headers
        .getSetCookie()
        .filter((raw) => Boolean(Cookie.parse(raw)?.value))
        .map((raw) => raw.split(";")[0])
        .join("; ");
    const jtis = new Set<string>();
    const observed = [];
    for (const [index, key] of [
      [0, true],
      [1, true],
      [2, false],
    ] as const) {
      const email = ctx.uniqueEmail(`private-jwt-${index}`);
      const accountId = `private-jwt-subject-${index}`;
      await control(
        {
          action: "idp",
          email,
          profile: { sub: accountId, email, email_verified: false, name: "Private JWT employee" },
        },
        key,
      );
      const started = await control(
        {
          action: "sign-in",
          body: {
            providerId: "configured-jwt",
            callbackURL: `${ctx.baseURL}/complete`,
            errorCallbackURL: `${ctx.baseURL}/failed`,
          },
        },
        key,
      );
      expect(started.status).toBe(200);
      const grant = await fetch(((await started.json()) as any).url, { redirect: "manual" });
      expect(grant.status).toBe(302);
      const query = Object.fromEntries(new URL(grant.headers.get("location")!).searchParams);
      const completed = await control(
        {
          action: "callback",
          params: { providerId: "configured-jwt" },
          query,
          headers: { cookie: cookies(started) },
        },
        key,
      );
      expect(completed.status).toBe(302);
      const location = new URL(completed.headers.get("location")!);
      const exchanges = (await (await control({ action: "idp-exchanges" }, key)).json()) as any[];
      if (!key) {
        expect(location.pathname).toBe("/failed");
        expect(location.searchParams.get("error_description")).toBe("no_private_key_available");
        expect(exchanges).toEqual([]);
        expect(await (await control({ action: "user-row", email }, key)).json()).toBe(null);
        expect(
          await (
            await control({ action: "account-row", providerId: "configured-jwt", accountId }, key)
          ).json(),
        ).toBe(null);
      } else {
        expect(location.pathname).toBe("/complete");
        const session = (await (
          await control({ action: "session", headers: { cookie: cookies(completed) } }, key)
        ).json()) as any;
        expect(session.user.email).toBe(email);
        expect(exchanges).toHaveLength(1);
        expect(exchanges[0].authorization).toBe(null);
        expect(exchanges[0].form.client_secret).toBeUndefined();
        expect(exchanges[0].form.client_id).toBe("enterprise-client");
        expect(exchanges[0].form.client_assertion_type).toBe(
          "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        );
        const claims = JSON.parse(
          Buffer.from(exchanges[0].form.client_assertion.split(".")[1], "base64url").toString(),
        );
        expect(jtis.has(claims.jti)).toBe(false);
        jtis.add(claims.jti);
        expect(
          await (
            await control({ action: "account-row", providerId: "configured-jwt", accountId }, key)
          ).json(),
        ).not.toBe(null);
      }
      expect(
        await (await control({ action: "row", providerId: "configured-jwt" }, key)).json(),
      ).toBe(null);
      observed.push({
        key,
        path: location.pathname,
        error: location.searchParams.get("error_description"),
      });
    }
    return observed;
  },
);
