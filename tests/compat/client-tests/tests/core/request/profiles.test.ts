import { expect } from "bun:test";

import { authProfilePath, FIXTURE_PROFILES } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

// Every configuration profile the scenarios can address must be served by both
// fixture servers. A profile that exists on one side only would otherwise go
// unnoticed until a scenario happened to use it, and a scenario that compared
// two 404s would still pass.
compatScenario("every declared fixture profile is served by both runtimes", async (ctx) => {
  // A repeated profile probe consumes its genuine rate policy twice. Reject
  // duplicate declarations before traffic can obscure this registry invariant.
  expect(new Set(FIXTURE_PROFILES).size).toBe(FIXTURE_PROFILES.length);

  const statuses: Record<string, number> = {};
  const missing: string[] = [];

  for (const profile of FIXTURE_PROFILES) {
    // The installed runtime shares memory rate buckets across auth instances.
    // Give availability probes their own client, separate from scenario traffic.
    const response = await ctx.rawRequest({
      actor: "probe",
      path: `${authProfilePath(profile)}/ok`,
      method: "GET",
      headers: {
        "x-forwarded-for": "192.0.2.254",
        ...(profile === "captcha-turnstile-custom" ? { "x-captcha-response": "valid" } : {}),
      },
    });
    statuses[profile] = response.status;
    if (response.status !== 200) {
      missing.push(`${profile} -> ${response.status}`);
    }
  }

  expect(missing, `${ctx.baseURL} does not serve every declared profile`).toEqual([]);

  return { profiles: FIXTURE_PROFILES.length, statuses };
});
