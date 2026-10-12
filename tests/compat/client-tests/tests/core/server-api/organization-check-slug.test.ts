import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "organization slug checks admit headerless server calls and authenticate attached credentials",
  async (ctx) => {
    let cookie = "";
    const owner = await ctx.actor("slug-owner", "server-dispatch").client.signUp.email({
      email: ctx.uniqueEmail("slug-owner"),
      name: "Slug Owner",
      password: "Password123!",
      fetchOptions: {
        onSuccess({ response }) {
          cookie = response.headers
            .getSetCookie()
            .map((raw) => raw.split(";")[0])
            .join("; ");
        },
      },
    });
    expect(owner.error).toBeNull();
    const slug = ctx.uniqueToken("stored-slug");
    async function call(operation: string, input: Record<string, unknown>) {
      const response = await ctx.rawRequest({
        path: "/__test/server-dispatch/call",
        method: "POST",
        json: { operation, ...input },
      });
      expect(response.status).toBe(200);
      return response.body as {
        result: {
          ok: boolean;
          status?: number;
          body?: { code: string };
          value?: { response: unknown };
        };
        events: { stage: string; request: unknown; session: unknown }[];
      };
    }
    const created = await call("createOrganization", {
      body: { name: "Stored slug", slug },
      headers: { cookie },
    });
    expect(created.result.ok).toBe(true);
    const before = (await ctx.rawRequest({ path: "/__test/server-dispatch/state" })).body;
    const available = [];
    for (const value of [ctx.uniqueToken("available-slug"), "", "UPPER/slash space"]) {
      const observed = await call("checkOrganizationSlug", {
        body: { slug: value },
        query: { slug },
      });
      expect(observed.result.ok).toBe(true);
      expect(observed.result.value!.response).toEqual({ status: true });
      const after = observed.events.find((event) => event.stage === "user-after")!;
      expect(after.request).toBeNull();
      expect(after.session).toBeNull();
      available.push(observed);
    }
    const taken = await call("checkOrganizationSlug", { body: { slug } });
    expect(taken.result.ok).toBe(false);
    expect(taken.result.status).toBe(400);
    expect(taken.result.body!.code).toBe("ORGANIZATION_SLUG_ALREADY_TAKEN");
    const authenticated = await call("checkOrganizationSlug", {
      body: { slug: ctx.uniqueToken("authenticated-free") },
      headers: { cookie },
    });
    expect(authenticated.result.ok).toBe(true);
    expect(authenticated.result.value!.response).toEqual({ status: true });
    const denials = [];
    for (const input of [{ headers: {} }, { physicalRequest: true }]) {
      const denied = await call("checkOrganizationSlug", { body: { slug }, ...input });
      expect(denied.result.ok).toBe(false);
      expect(denied.result.status).toBe(401);
      expect(denied.result.body!.code).toBe("UNAUTHORIZED");
      if ("physicalRequest" in input) {
        const after = denied.events.find((event) => event.stage === "user-after")!;
        expect(after.request).not.toBeNull();
        expect(after.session).toBeNull();
        // Fixture listeners use independent ports. Check the actual request
        // presence, then compare the endpoint result and callback stages.
        denials.push({ result: denied.result, stages: denied.events.map((event) => event.stage) });
      } else {
        denials.push(denied);
      }
    }
    const after = (await ctx.rawRequest({ path: "/__test/server-dispatch/state" })).body;
    expect(after).toEqual(before);
    return ctx.snapshot({
      owner,
      created,
      before,
      available,
      taken,
      authenticated,
      denials,
      after,
    });
  },
);
