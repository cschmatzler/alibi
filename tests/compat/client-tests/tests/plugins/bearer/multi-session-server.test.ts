import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "multi-session server issuance delivers usable proofs and logout retires them",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: unknown) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/bearer`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ profile: "bearer-composition", ...(input as any) }),
      });
    const proofs: string[] = [];
    const tokens: string[] = [];
    for (const name of ["owner", "other"]) {
      const response = await control({
        action: "sign-up",
        headers: { cookie: proofs.join("; ") },
        body: {
          email: ctx.uniqueEmail(`sdk-multi-${name}`),
          name,
          password: "a-native-password-123",
        },
      });
      expect(response.status).toBe(200);
      const value = (await response.json()) as any;
      const prefix = `better-auth.session_token_multi-${value.token.toLowerCase()}=`;
      const proof = response.headers.getSetCookie().find((cookie) => cookie.startsWith(prefix));
      expect(proof).toBeDefined();
      proofs.push(proof!.split(";")[0]!);
      tokens.push(value.token);
    }
    const headers = { cookie: proofs.join("; ") };
    const listed = await control({ action: "list", headers });
    expect(listed.status).toBe(200);
    const sessions = (await listed.json()) as any[];
    expect(sessions).toHaveLength(2);
    for (const token of tokens) {
      expect(sessions.some((entry) => entry.session.token === token)).toBe(true);
    }
    const logout = await control({ action: "sign-out", headers, body: {} });
    expect(logout.status).toBe(200);
    for (const token of tokens) {
      const prefix = `better-auth.session_token_multi-${token.toLowerCase()}=;`;
      expect(
        logout.headers
          .getSetCookie()
          .some((cookie) => cookie.startsWith(prefix) && cookie.includes("Max-Age=0")),
      ).toBe(true);
      const session = await control({ headers: { authorization: `Bearer ${token}` } });
      expect(await session.json()).toBeNull();
    }
    const retired = await control({ action: "list", headers });
    expect(retired.status).toBe(200);
    expect(await retired.json()).toEqual([]);
    return { usableProofs: true, retired: true };
  },
);
