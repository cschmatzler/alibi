import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { organizationActions } from "./organization-actions";
compatScenario(
  "organization key deletion requires the delete action and revokes only the selected key",
  async (ctx) => {
    const s = await organizationActions(ctx, "org-delete");
    const reader = await s.member("member");
    const deleter = await s.member("deleter");
    const key = await s.create("Selected key");
    const sibling = await s.create("Sibling key");
    const query = { id: key.data!.id, configId: "organization" };
    const siblingQuery = { id: sibling.data!.id, configId: "organization" };
    const before = await s.owner.apiKey.get({ query });
    const siblingBefore = await s.owner.apiKey.get({ query: siblingQuery });
    expect(before.error).toBeNull();
    expect(siblingBefore.error).toBeNull();
    const denied = await reader.actor.apiKey.delete({
      keyId: key.data!.id,
      configId: "organization",
    });
    expect(denied.error).toMatchObject({ status: 403, code: "INSUFFICIENT_API_KEY_PERMISSIONS" });
    expect(await s.owner.apiKey.get({ query })).toEqual(before);
    expect((await s.verify(key.data!.key)).valid).toBe(true);
    const deleted = await deleter.actor.apiKey.delete({
      keyId: key.data!.id,
      configId: "organization",
    });
    expect(deleted.error).toBeNull();
    const after = await s.owner.apiKey.get({ query });
    expect(after.error).toMatchObject({ status: 404, code: "KEY_NOT_FOUND" });
    const revoked = await s.verify(key.data!.key);
    expect(revoked.valid).toBe(false);
    expect(await s.owner.apiKey.get({ query: siblingQuery })).toEqual(siblingBefore);
    const retained = await s.verify(sibling.data!.key);
    expect(retained.valid).toBe(true);
    expect(retained.key).toMatchObject({
      id: sibling.data!.id,
      referenceId: s.organizationId,
      configId: "organization",
    });
    return ctx.snapshot({
      org: s.org,
      key,
      sibling,
      reader: reader.accepted,
      deleter: deleter.accepted,
      before,
      denied,
      deleted,
      after,
      revoked,
      retained,
    });
  },
  ["POST /api-key/delete", "GET /api-key/get"],
);
