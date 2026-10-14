import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SSO mutation guards share database rollback and provider namespace retirement",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: Record<string, unknown>) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: "mutation-guard", ...input }),
      });
    expect((await control({ action: "mutation-policy", denied: true, clear: true })).status).toBe(
      200,
    );
    const owner = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("mutation-owner"),
        name: "Mutation owner",
        password: "password123",
      },
    });
    expect(owner.status).toBe(200);
    const user = ((await owner.clone().json()) as any).user;
    const cookie = owner.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const headers = { cookie };
    const providerId = "guard-provider";
    const created = await control({
      headers,
      body: {
        providerId,
        issuer: "https://idp.example.com",
        domain: "original.test",
        oidcConfig: {
          clientId: "client",
          clientSecret: "original-secret",
          skipDiscovery: true,
          authorizationEndpoint: "https://idp.example.com/authorize",
          tokenEndpoint: "https://idp.example.com/token",
          jwksEndpoint: "https://idp.example.com/jwks",
        },
      },
    });
    expect(created.status).toBe(200);
    expect(await (await control({ action: "mutation-events" })).json()).toEqual([]);
    const original = (await (await control({ action: "row", providerId })).json()) as any;
    expect(
      (
        await control({
          action: "create-account",
          body: { userId: user.id, providerId, accountId: "linked-subject" },
        })
      ).status,
    ).toBe(200);
    const update = {
      action: "update",
      headers,
      body: { providerId, oidcConfig: { clientSecret: "rotated-secret" } },
    };
    const denial = {
      code: "SSO_PROVIDER_MUTATION_REJECTED",
      message: "SSO provider mutation is not allowed",
    };
    const denied = await control(update);
    expect(denied.status).toBe(409);
    expect(await denied.json()).toEqual(denial);
    expect(await (await control({ action: "row", providerId })).json()).toEqual(original);
    expect(
      await (await control({ action: "proof", identifier: "sso-guard-write:update:1" })).json(),
    ).toBe(null);
    expect((await control({ action: "mutation-policy", denied: false })).status).toBe(200);
    const allowed = await control(update);
    expect(allowed.status).toBe(200);
    const rotated = (await (await control({ action: "row", providerId })).json()) as any;
    expect(JSON.parse(rotated.oidcConfig).clientSecret).toBe("rotated-secret");
    expect(
      (
        (await (
          await control({ action: "proof", identifier: "sso-guard-write:update:2" })
        ).json()) as any
      ).value,
    ).toBe("original.test");
    const boundary = await control({
      action: "update",
      headers,
      body: { providerId, oidcConfig: { clientId: "changed-client" } },
    });
    expect(boundary.status).toBe(409);
    expect(await boundary.json()).toEqual({
      message: "Cannot change SSO provider identity fields while linked accounts exist",
    });
    expect(
      await (await control({ action: "proof", identifier: "sso-guard-write:update:3" })).json(),
    ).toBe(null);
    expect(await (await control({ action: "row", providerId })).json()).toEqual(rotated);
    expect((await control({ action: "mutation-policy", denied: true })).status).toBe(200);
    const refused = await control({ action: "delete", headers, body: { providerId } });
    expect(refused.status).toBe(409);
    expect(await refused.json()).toEqual(denial);
    expect(
      await (await control({ action: "proof", identifier: "sso-guard-write:delete:4" })).json(),
    ).toBe(null);
    expect(await (await control({ action: "row", providerId })).json()).toEqual(rotated);
    expect(
      await (
        await control({ action: "account-row", providerId, accountId: "linked-subject" })
      ).json(),
    ).not.toBe(null);
    expect((await control({ action: "mutation-policy", denied: false })).status).toBe(200);
    const removed = await control({ action: "delete", headers, body: { providerId } });
    expect(removed.status).toBe(200);
    expect(await removed.json()).toEqual({ success: true });
    expect(await (await control({ action: "row", providerId })).json()).toBe(null);
    expect(
      await (
        await control({ action: "account-row", providerId, accountId: "linked-subject" })
      ).json(),
    ).toBe(null);
    expect(
      (
        (await (
          await control({ action: "proof", identifier: "sso-guard-write:delete:5" })
        ).json()) as any
      ).value,
    ).toBe("original.test");
    const events = (await (await control({ action: "mutation-events" })).json()) as any[];
    expect(events).toHaveLength(5);
    for (const [index, event] of events.entries()) {
      expect(event.domain).toBe("original.test");
      expect(event.mutation.provider).toEqual({
        id: original.id,
        providerId,
        organizationId: null,
      });
      expect(event.mutation.providerReference.source).toEqual({
        type: "persisted",
        recordId: original.id,
      });
      expect(event.mutation.providerReference.providerId).toBe(providerId);
      expect(event.mutation.providerReference.authenticationConfigurationFingerprint).toMatch(
        /^[A-Za-z0-9_-]{43}$/,
      );
      expect(Object.keys(event.mutation)).toHaveLength(index < 3 ? 4 : 3);
    }
    expect(events[0].mutation.isAuthenticationBoundaryChange).toBe(false);
    expect(events[1].mutation.isAuthenticationBoundaryChange).toBe(false);
    expect(events[2].mutation.isAuthenticationBoundaryChange).toBe(true);
    expect(events[3].mutation.action).toBe("delete");
    expect(events[0].mutation.providerReference).toEqual(events[4].mutation.providerReference);
    const retained = (await (await control({ action: "session", headers })).json()) as any;
    expect(retained.user.email).toBe(user.email);
    return events.map((event) => ({
      ...event,
      mutation: {
        ...event.mutation,
        providerReference: {
          ...event.mutation.providerReference,
          source: {
            type: event.mutation.providerReference.source.type,
            recordIdMatchesProvider:
              event.mutation.providerReference.source.recordId === event.mutation.provider.id,
          },
        },
      },
    }));
  },
);
