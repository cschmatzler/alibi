import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "one-time-token server headers deliver redeemable single-use credentials",
  async (ctx) => {
    const actor = ctx.actor();
    for (const profile of ["ott-default", "ott-custom-header"]) {
      const control = (action: string, body: unknown) =>
        actor.fetch(`${ctx.baseURL}/__test/server-api/one-time-token`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ profile, action, body }),
        });
      const response = await control("sign-up", {
        email: ctx.uniqueEmail(`sdk-${profile}`),
        name: "Owner",
        password: "a-native-password-123",
      });
      expect(response.status).toBe(200);
      if (profile === "ott-default") {
        expect(response.headers.get("set-ott")).toBeNull();
        continue;
      }
      const owner = (await response.json()) as any;
      const token = response.headers.get("set-ott");
      expect(token).toBe("ott-header-token-1");
      expect(response.headers.get("access-control-expose-headers")).toBe("set-ott");
      const transferred = await control("verify", { token });
      expect(transferred.status).toBe(200);
      const session = (await transferred.json()) as any;
      expect(session.session.token).toBe(owner.token);
      expect(session.user.id).toBe(owner.user.id);
      const replacement = transferred.headers.get("set-ott");
      expect(replacement).toBe("ott-header-token-2");
      const replay = await control("verify", { token });
      expect(replay.status).toBe(400);
      expect(await replay.json()).toEqual({ message: "Invalid token" });
      expect(replay.headers.get("set-ott")).toBeNull();
      expect((await control("verify", { token: replacement })).status).toBe(200);
    }
    return { delivered: true, singleUse: true };
  },
);
