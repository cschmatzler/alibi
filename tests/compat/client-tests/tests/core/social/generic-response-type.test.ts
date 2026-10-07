import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

compatScenario(
  "generic OAuth configured response type reaches authorization URL and preserves state binding",
  async (ctx) => {
    const observations = [];
    for (const profile of [
      "generic-discovery-success",
      "generic-discovery-response-type",
    ] as const) {
      const client = createAuthClient({
        baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
        fetchOptions: { customFetchImpl: ctx.actor(profile, profile).fetch },
      });
      const started = await client.signIn.social({
        provider: "discovery",
        callbackURL: "/generic-return",
        disableRedirect: true,
      });
      expect(started.error).toBeNull();
      const url = new URL(started.data!.url!);
      expect(url.searchParams.getAll("response_type")).toEqual([
        profile.endsWith("response-type") ? "token" : "code",
      ]);
      expect(url.searchParams.get("client_id")).toBe("discovery-client");
      expect(url.searchParams.get("state")).toBeTruthy();
      expect(url.searchParams.get("redirect_uri")).toBe(
        `${ctx.baseURL}${authProfilePath(profile)}/callback/discovery`,
      );
      observations.push(started);
    }
    return ctx.snapshot(observations);
  },
  ["POST /sign-in/social"],
);
