import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario("SCIM projection reconciliation requires application configuration", async (ctx) => {
  const actor = ctx.actor();
  const response = await actor.fetch(
    `${ctx.baseURL}/__test/server-api/scim?operation=reconcileSCIMProjection`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ body: { provisioningDomainId: "  tenant-a  " } }),
    },
  );
  expect(response.status).toBe(200);
  const error = await response.json();
  expect(error).toEqual({
    failed: true,
    message: "SCIM projection reconciliation requires projection.reconcileUser to be configured.",
  });
  return error;
});
