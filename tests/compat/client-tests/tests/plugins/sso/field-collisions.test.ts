import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SSO rejects provider field collisions during application initialization",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ action: "field-collision", ...input }),
      });
    const outcomes: unknown[] = [];
    for (const name of [
      "id",
      "issuer",
      "domain",
      "providerId",
      "userId",
      "organizationId",
      "oidcConfig",
      "samlConfig",
      "domainVerified",
      "type",
      "redirectURI",
      "spMetadataUrl",
      "domainVerificationToken",
      "custom",
    ]) {
      const response = await control({ name, physical: name === "custom" ? "domain" : undefined });
      expect(response.status).toBe(200);
      const outcome = (await response.json()) as any;
      const expected =
        name === "custom"
          ? 'ssoProvider additional field "custom" maps to built-in field "domain"'
          : ["type", "redirectURI", "spMetadataUrl", "domainVerificationToken"].includes(name)
            ? `ssoProvider additional field "${name}" conflicts with a returned provider field`
            : `ssoProvider additional field "${name}" conflicts with a built-in field`;
      expect(outcome).toEqual({ accepted: false, error: expected });
      outcomes.push(outcome);
    }
    for (const [physical, accepted] of [
      ["application_domain", false],
      ["domain", true],
    ] as const) {
      const response = await control({ name: "custom", physical, mapped: true });
      expect(response.status).toBe(200);
      const outcome = await response.json();
      expect(outcome).toEqual({
        accepted,
        error: accepted
          ? null
          : 'ssoProvider additional field "custom" maps to built-in field "application_domain"',
      });
      outcomes.push(outcome);
    }
    return outcomes;
  },
);
