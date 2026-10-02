import { expect } from "bun:test";
import { compatScenario } from "../../support/scenario";
import { FIXTURE_PROFILES, authProfilePath } from "../../support/profiles";

// Every configuration profile the scenarios can address must be served by both
// fixture servers. A profile that exists on one side only would otherwise go
// unnoticed until a scenario happened to use it, and a scenario that compared
// two 404s would still pass.
compatScenario("every declared fixture profile is served by both runtimes", async (ctx) => {
  const statuses: Record<string, number> = {};
  const missing: string[] = [];
  for (const profile of FIXTURE_PROFILES) {
    const response = await ctx.rawRequest({ actor: "probe", path: `${authProfilePath(profile)}/ok`, method: "GET", ...(profile === "captcha-turnstile-custom" ? { headers: { "x-captcha-response": "valid" } } : {}) });
    statuses[profile] = response.status;
    if (response.status !== 200) missing.push(`${profile} -> ${response.status}`);
  }
  expect(missing, `${ctx.baseURL} does not serve every declared profile`).toEqual([]);
  expect(new Set(FIXTURE_PROFILES).size).toBe(FIXTURE_PROFILES.length);
  return { profiles: FIXTURE_PROFILES.length, statuses };
});
