import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SSO private_key_jwt authenticates real token requests and rejects missing keys",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>, mode = "configured-jwt") =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ...input, mode }),
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
    for (const [index, mode] of [
      [0, "configured-jwt"],
      [1, "configured-jwt"],
      [2, "configured-jwt-missing"],
      [3, "configured-jwt-jwk"],
      [4, "configured-jwt-precedence"],
    ] as const) {
      const key = mode !== "configured-jwt-missing";
      await control({ action: "key-reset" }, mode);
      await control({ action: "key-enabled", enabled: false }, mode);
      const email = ctx.uniqueEmail(`private-jwt-${index}`);
      const accountId = `private-jwt-subject-${index}`;
      await control(
        {
          action: "idp",
          email,
          profile: { sub: accountId, email, email_verified: false, name: "Private JWT employee" },
        },
        mode,
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
        mode,
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
        mode,
      );
      expect(completed.status).toBe(302);
      const location = new URL(completed.headers.get("location")!);
      const exchanges = (await (await control({ action: "idp-exchanges" }, mode)).json()) as any[];
      if (!key) {
        expect(location.pathname).toBe("/failed");
        expect(location.searchParams.get("error_description")).toBe("no_private_key_available");
        expect(exchanges).toEqual([]);
        expect(await (await control({ action: "user-row", email }, mode)).json()).toBe(null);
        expect(
          await (
            await control({ action: "account-row", providerId: "configured-jwt", accountId }, mode)
          ).json(),
        ).toBe(null);
      } else {
        expect(location.pathname).toBe("/complete");
        const session = (await (
          await control({ action: "session", headers: { cookie: cookies(completed) } }, mode)
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
            await control({ action: "account-row", providerId: "configured-jwt", accountId }, mode)
          ).json(),
        ).not.toBe(null);
      }
      expect(
        await (await control({ action: "row", providerId: "configured-jwt" }, mode)).json(),
      ).toBe(null);
      expect(await (await control({ action: "key-events" }, mode)).json()).toEqual([]);
      observed.push({
        mode,
        path: location.pathname,
        error: location.searchParams.get("error_description"),
      });
    }
    return observed;
  },
);
