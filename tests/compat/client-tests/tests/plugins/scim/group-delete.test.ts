import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM Group deletion reconciles members and rolls back callback failure",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (operation: string, input: unknown = {}) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/scim?operation=${operation}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const remove = (id: string, token?: string) =>
      control("deleteSCIMGroup", {
        params: { groupId: id },
        query: { attributes: 1 },
        ...(token === undefined ? {} : { token }),
      });
    const schema = "urn:ietf:params:scim:schemas:core:2.0:Group";
    expect((await remove("missing")).status).toBe(401);
    expect(await (await control("seed-group-create")).json()).toEqual({ seeded: true });
    const input = {
      schemas: [schema],
      displayName: "Delete me",
      members: [{ value: "member-a" }, { value: "member-c" }],
    };
    const created = await control("createSCIMGroup", {
      body: input,
      query: {},
      token: "group-reader",
    });
    expect(created.status).toBe(201);
    const group = (await created.json()) as any;
    expect((await remove(group.id, "users-reader")).status).toBe(403);
    expect((await remove(group.id, "other-reader")).status).toBe(404);
    expect(await (await control("configure-group-create-projection")).json()).toEqual({
      configured: true,
    });
    expect(await (await control("group-create-projection-fails")).json()).toEqual({
      failing: true,
    });
    const state = await (await control("group-create-state")).json();
    const failed = await remove(group.id, "group-reader");
    expect(failed.status).toBe(500);
    expect(((await failed.json()) as any).detail).toBe("SCIM projection reconciliation failed");
    expect(await (await control("group-create-state")).json()).toEqual(state);
    expect(await (await control("group-create-projection-fails", { fail: false })).json()).toEqual({
      failing: false,
    });
    const removed = await remove(group.id, "group-reader");
    expect(removed.status).toBe(204);
    expect(await removed.text()).toBe("");
    expect(removed.headers.get("content-type")).toBe("application/json");
    expect(await (await control("group-create-state")).json()).toEqual({
      groups: { n: 0 },
      members: { n: 0 },
      subject: { revision: 2 },
    });
    expect(await (await control("group-create-owner")).json()).toEqual({
      name: "Projected inactive",
    });
    expect((await remove(group.id, "group-reader")).status).toBe(404);
    const empty = { schemas: [schema], displayName: "HTTP delete" };
    const second = (await (
      await control("createSCIMGroup", { body: empty, query: {}, token: "group-reader" })
    ).json()) as any;
    const http = await actor.fetch(
      `${ctx.baseURL}/__test/profiles/scim/api/auth/scim/v2/Groups/${second.id}`,
      { method: "DELETE", headers: { authorization: "Bearer group-reader" } },
    );
    expect(http.status).toBe(204);
    expect(await http.text()).toBe("");
    expect(http.headers.get("content-type")).toBe("application/scim+json");
    const drift = (await (
      await control("createSCIMGroup", {
        body: { schemas: [schema], displayName: "Drift" },
        query: {},
        token: "group-reader",
      })
    ).json()) as any;
    expect(await (await control("drift-created-group", { id: drift.id })).json()).toEqual({
      changed: true,
    });
    expect((await remove(drift.id, "group-reader")).status).toBe(409);
    return { deleted: true, membersRemoved: true, callbackRollback: true, isolated: true };
  },
);
