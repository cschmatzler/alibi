import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM User deletion preserves tombstones and retires only inactive identity sessions",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (operation: string, input: unknown = {}) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/scim?operation=${operation}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const remove = (id: string, token?: string) =>
      control("deleteSCIMUser", {
        params: { userId: id },
        query: { attributes: 1 },
        ...(token === undefined ? {} : { token }),
      });
    const state = async () => (await (await control("user-delete-state")).json()) as any;
    expect((await remove("missing")).status).toBe(401);
    expect(await (await control("seed-group-create")).json()).toEqual({ seeded: true });
    expect(await (await control("prepare-user-delete")).json()).toEqual({ prepared: true });
    const group = (await (
      await control("createSCIMGroup", {
        body: {
          schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
          displayName: "User members",
          members: [{ value: "member-a" }, { value: "member-c" }],
        },
        query: {},
        token: "group-reader",
      })
    ).json()) as any;
    expect((await remove("member-a", "users-reader")).status).toBe(403);
    expect((await remove("member-a", "other-reader")).status).toBe(404);
    expect((await remove("member-c", "group-reader")).status).toBe(409);
    expect(await (await control("configure-user-delete")).json()).toEqual({ configured: true });
    expect(await (await control("group-create-projection-fails")).json()).toEqual({
      failing: true,
    });
    const before = await state();
    const projectionFailure = await remove("member-a", "group-reader");
    expect(projectionFailure.status).toBe(500);
    expect(((await projectionFailure.json()) as any).detail).toBe(
      "SCIM projection reconciliation failed",
    );
    expect(await state()).toEqual(before);
    expect(await (await control("group-create-projection-fails", { fail: false })).json()).toEqual({
      failing: false,
    });
    expect(await (await control("identity-toggle-failure", { fail: true })).json()).toEqual({
      failing: true,
    });
    const identityFailure = await remove("member-a", "group-reader");
    expect(identityFailure.status).toBe(500);
    expect(((await identityFailure.json()) as any).detail).toBe(
      "SCIM identity reconciliation failed",
    );
    expect(await state()).toEqual(before);
    expect(await (await control("identity-toggle-failure", { fail: false })).json()).toEqual({
      failing: false,
    });
    const removed = await remove("member-a", "group-reader");
    expect(removed.status).toBe(204);
    expect(await removed.text()).toBe("");
    const active = await state();
    expect(active.tombstones).toHaveLength(1);
    expect(active.tombstones[0]).toMatchObject({
      connectionId: "conn-a",
      provisioningDomainId: "tenant-a",
      externalId: "external-a",
      profile: "manage",
    });
    expect(active.subjects).toEqual([{ revision: 3, profileSourceId: null }]);
    expect(active.sessions.n).toBe(1);
    expect(active.owner).toEqual({ name: "Identity active" });
    const identityStates = (await (await control("identity-states")).json()) as any[];
    expect(identityStates.at(-1).active).toBe(true);
    expect(identityStates.at(-1).profileSourceId).toBeUndefined();
    const read = await control("getSCIMGroup", {
      params: { groupId: group.id },
      query: {},
      token: "group-reader",
    });
    expect(((await read.json()) as any).members.map((member: any) => member.value)).toEqual([
      "member-c",
    ]);
    expect((await remove("member-a", "group-reader")).status).toBe(404);
    expect(await (await control("reuse-user-delete-tombstone")).json()).toEqual({ changed: true });
    const http = await actor.fetch(
      `${ctx.baseURL}/__test/profiles/scim/api/auth/scim/v2/Users/member-c`,
      { method: "DELETE", headers: { authorization: "Bearer group-reader" } },
    );
    expect(http.status).toBe(204);
    expect(await http.text()).toBe("");
    expect(http.headers.get("content-type")).toBe("application/scim+json");
    const reused = await state();
    expect(reused.tombstones).toHaveLength(1);
    expect(reused.tombstones[0]).toMatchObject({
      connectionId: "legacy-connection",
      provisioningDomainId: "legacy-domain",
      externalId: "legacy-external",
      profile: "preserve",
    });
    expect(reused.members).toEqual([]);
    expect((await remove("member-b", "other-reader")).status).toBe(204);
    const inactive = await state();
    expect(inactive.users).toEqual([]);
    expect(inactive.sessions.n).toBe(0);
    expect(inactive.owner).toEqual({ name: "Identity inactive" });
    expect(inactive.subjects).toEqual([{ revision: 5, profileSourceId: null }]);
    const states = (await (await control("identity-states")).json()) as any[];
    expect(states.at(-1).active).toBe(false);
    expect(states.at(-1).sources).toEqual([]);
    return {
      deleted: true,
      tombstones: true,
      profileCleared: true,
      globalSessions: true,
      rollback: true,
    };
  },
);
