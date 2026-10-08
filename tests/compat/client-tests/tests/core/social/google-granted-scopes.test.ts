import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";

for (const profile of [
  "google-granted-scopes-enabled",
  "google-granted-scopes-disabled",
] as const) {
  compatScenario(
    `google ${profile} controls incremental authorization without changing requested scopes`,
    async (ctx) => {
      const actor = ctx.actor("google-scopes", profile);
      const result = await actor.client.signIn.social({
        provider: "google",
        disableRedirect: true,
        callbackURL: "/scope-callback",
        scopes: ["https://www.googleapis.com/auth/calendar.readonly"],
      });
      expect(result.error).toBeNull();
      const url = new URL(result.data!.url!);
      expect(url.origin).toBe("https://accounts.google.com");
      expect(url.searchParams.get("include_granted_scopes")).toBe(
        profile.endsWith("enabled") ? "true" : null,
      );
      expect(url.searchParams.getAll("include_granted_scopes")).toHaveLength(
        profile.endsWith("enabled") ? 1 : 0,
      );
      expect(url.searchParams.get("scope")?.split(" ")).toContain(
        "https://www.googleapis.com/auth/calendar.readonly",
      );
      expect(url.searchParams.get("client_id")).toBe("google-default-client");
      expect(url.searchParams.get("response_type")).toBe("code");
      expect(url.searchParams.get("state")).toBeTruthy();
      return ctx.snapshot({ result });
    },
    ["POST /sign-in/social"],
  );
}
