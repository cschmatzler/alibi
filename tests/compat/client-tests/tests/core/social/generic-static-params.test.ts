import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

compatScenario(
  "generic OAuth static authorization parameters preserve reserved scope and request parameters override static values",
  async (ctx) => {
    const profile = "generic-discovery-static-params" as const;
    const client = createAuthClient({
      baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
      fetchOptions: { customFetchImpl: ctx.actor("static-params", profile).fetch },
    });
    const observations = [];
    for (const additionalParams of [
      undefined,
      { audience: "request-audience", prompt: "login", resource: "request-resource" },
    ]) {
      const result = await client.signIn.social({
        provider: "discovery",
        callbackURL: "/return",
        disableRedirect: true,
        scopes: ["request-scope"],
        additionalParams,
      });
      expect(result.error).toBeNull();
      const url = new URL(result.data!.url!);
      expect(url.searchParams.getAll("scope")).toEqual(["request-scope profile"]);
      expect(url.searchParams.getAll("audience")).toEqual([
        additionalParams ? "request-audience" : "static-audience",
      ]);
      expect(url.searchParams.getAll("prompt")).toEqual([additionalParams ? "login" : "consent"]);
      expect(url.searchParams.get("resource")).toBe(additionalParams ? "request-resource" : null);
      expect(url.searchParams.get("state")).toBeTruthy();
      observations.push(result);
    }
    return ctx.snapshot(observations);
  },
  ["POST /sign-in/social"],
);
