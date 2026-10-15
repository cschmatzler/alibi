import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "bearer authenticates server calls and publishes signed session tokens",
  async (ctx) => {
    const actor = ctx.actor();
    for (const profile of ["bearer-default", "bearer-signed"]) {
      const control = (input: unknown) =>
        actor.fetch(`${ctx.baseURL}/__test/server-api/bearer`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ profile, ...(input as any) }),
        });
      const owners = [] as { token: string; signed: string; email: string }[];
      for (const name of ["owner", "other"]) {
        const email = ctx.uniqueEmail(`${profile}-${name}`);
        const response = await control({
          action: "sign-up",
          body: { email, name, password: "a-native-password-123" },
        });
        expect(response.status).toBe(200);
        const value = (await response.json()) as any;
        const signed = response.headers.get("set-auth-token");
        expect(signed).not.toBeNull();
        expect(response.headers.get("access-control-expose-headers")?.split(", ")).toContain(
          "set-auth-token",
        );
        if (profile === "bearer-signed") {
          expect(response.headers.get("access-control-expose-headers")).toBe(
            "X-First, X-Second, set-auth-token",
          );
        }
        owners.push({ token: value.token, signed: signed!, email });
      }
      const [owner, other] = owners as [
        { token: string; signed: string; email: string },
        { token: string; signed: string; email: string },
      ];
      const unsigned = await control({ headers: { authorization: `Bearer ${owner.token}` } });
      expect(unsigned.status).toBe(200);
      const unverified = (await unsigned.json()) as any;
      if (profile === "bearer-signed") {
        expect(unverified).toBeNull();
      } else {
        expect(unverified.user.email).toBe(owner.email);
      }
      const verified = await control({ headers: { authorization: `Bearer ${owner.signed}` } });
      expect(verified.status).toBe(200);
      expect(((await verified.json()) as any).user.email).toBe(owner.email);
      const cookie = `better-auth.session_token=${owner.signed}`;
      const forged = await control({
        headers: { authorization: "Bearer forged.signature", cookie },
      });
      expect(forged.status).toBe(200);
      expect(((await forged.json()) as any).user.email).toBe(owner.email);
      const replaced = await control({
        headers: { authorization: `Bearer ${other.signed}`, cookie },
      });
      expect(replaced.status).toBe(200);
      expect(((await replaced.json()) as any).user.email).toBe(other.email);
      const preferred = await control({
        headers: { authorization: `Bearer ${owner.signed}` },
        requestHeaders: { authorization: `Bearer ${other.signed}` },
      });
      expect(preferred.status).toBe(200);
      expect(((await preferred.json()) as any).user.email).toBe(other.email);
      const requestOnly = await control({
        requestHeaders: { authorization: `Bearer ${owner.signed}` },
      });
      expect(requestOnly.status).toBe(200);
      expect(((await requestOnly.json()) as any).user.email).toBe(owner.email);
    }
    return { middleware: true, signedIssuance: true, requestPriority: true };
  },
);
