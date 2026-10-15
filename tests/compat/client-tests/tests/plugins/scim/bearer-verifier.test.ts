import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM external bearer verification resolves connections over the application database",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (operation: string, input: unknown = {}) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/scim?operation=${operation}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    expect(await (await control("configure-verifier")).json()).toEqual({ configured: true });
    expect(await (await control("seed-verifier-groups")).json()).toEqual({ seeded: true });
    const read = (id: string, token: string) =>
      control("getSCIMGroup", { params: { groupId: id }, query: {}, token });
    const inputs = async () => (await (await control("verifier-inputs")).json()) as any;
    expect((await read("declared", "static-token")).status).toBe(200);
    expect(await inputs()).toEqual([]);
    expect((await read("declared", "ba_scim_credential_invalid")).status).toBe(401);
    expect(await inputs()).toEqual([]);
    const declared = await read("declared", "oauth-declared");
    expect(declared.status).toBe(200);
    expect(((await declared.json()) as any).id).toBe("declared");
    const dynamic = await read("dynamic", "oauth-dynamic");
    expect(dynamic.status).toBe(200);
    expect(((await dynamic.json()) as any).id).toBe("dynamic");
    const observed = await inputs();
    expect(observed.map((input: any) => input.token)).toEqual(["oauth-declared", "oauth-dynamic"]);
    for (const input of observed) {
      expect(input.method).toBe("GET");
      expect(input.path).toBe("/scim/v2/Groups/:groupId");
      expect(input.headers.authorization).toBe(`Bearer ${input.token}`);
    }
    expect(await (await control("verifier-user")).json()).toEqual({ name: "Verified remote" });
    const setClaims = async (claims: unknown, sdkDate = false) =>
      expect(await (await control("verifier-claims", { claims, sdkDate })).json()).toEqual({
        changed: true,
      });
    for (const invalid of [
      null,
      { connectionId: "unknown", credentialId: "remote", scopes: ["scim.groups.read"] },
      {
        connectionId: "declared",
        connection: null,
        credentialId: "remote",
        scopes: ["scim.groups.read"],
      },
      {
        connection: { id: "declared", provisioningDomainId: "tenant-declared" },
        credentialId: "remote",
        scopes: ["scim.groups.read"],
      },
      {
        connection: { id: "ba_scim_connection_reserved", provisioningDomainId: "tenant-dynamic" },
        credentialId: "remote",
        scopes: ["scim.groups.read"],
      },
      { connectionId: "declared", credentialId: " remote ", scopes: ["scim.groups.read"] },
      { connectionId: "declared", credentialId: "remote", scopes: [] },
      {
        connectionId: "declared",
        credentialId: "remote",
        scopes: ["scim.groups.read", "scim.groups.read"],
      },
      { connectionId: "declared", credentialId: "remote", scopes: ["unsupported"] },
      {
        connectionId: "declared",
        credentialId: "remote",
        scopes: ["scim.groups.read"],
        expiresAt: "2035-01-02T03:04:05.000Z",
      },
    ]) {
      await setClaims(invalid);
      expect((await read("declared", "oauth-test")).status).toBe(401);
    }
    await setClaims({
      connectionId: "declared",
      credentialId: "remote",
      scopes: ["scim.users.read"],
    });
    expect((await read("declared", "oauth-test")).status).toBe(403);
    for (const [expiresAt, status] of [
      ["2000-01-01T00:00:00Z", 401],
      ["2035-01-02T03:04:05Z", 200],
    ] as const) {
      await setClaims(
        {
          connectionId: "declared",
          credentialId: "remote",
          scopes: ["scim.groups.read"],
          expiresAt,
        },
        true,
      );
      expect((await read("declared", "oauth-test")).status).toBe(status);
    }
    const http = await actor.fetch(
      `${ctx.baseURL}/__test/profiles/scim/api/auth/scim/v2/Groups/declared`,
      { headers: { authorization: "Bearer oauth-test" } },
    );
    expect(http.status).toBe(200);
    expect(((await http.json()) as any).id).toBe("declared");
    return { declared: true, dynamic: true, database: true, precedence: true };
  },
);
