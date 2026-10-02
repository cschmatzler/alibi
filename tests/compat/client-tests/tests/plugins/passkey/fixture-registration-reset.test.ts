import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "passkey application fixture reset clears actual completed enrollment resolver receipts",
  async (ctx) => {
    const owner = ctx.actor("reset-registration-owner", "passkey-first");
    const signup = await owner.client.signUp.email({
      email: ctx.uniqueEmail("reset-registration-owner"),
      name: "Reset Registration Owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();

    const context = ctx.uniqueToken("reset-enrollment");
    const enrolled = await owner.fetch(`${ctx.baseURL}/__test/passkey-enrollment`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ context }),
    });
    expect(enrolled.status).toBe(200);

    const enrollment = await enrolled.json();
    expect(enrollment.userId).toBe(signup.data!.user.id);

    await owner.client.signOut();
    const options = await owner.client.$fetch("/passkey/generate-register-options", {
      method: "GET",
      query: { context },
    });
    expect(options.error).toBeNull();

    const reset = await ctx.rawRequest({ path: "/__test/reset-state", method: "POST" });
    expect(reset.status).toBe(200);

    const receipt = await ctx.rawRequest({ path: "/__test/passkey-registration-events" });
    expect(receipt.status).toBe(200);
    expect(receipt.body).toEqual({ events: [] });

    return { signup, enrollment, options, reset, receipt };
  },
);
